// Package auth provides the authentication middleware and handlers.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"github.com/spruceid/siwe-go"

	"github.com/oasisprotocol/rofl-app-backend/api/common"
	"github.com/oasisprotocol/rofl-app-backend/api/recaptcha"
	"github.com/oasisprotocol/rofl-app-backend/config"
)

type ctxKey string

const (
	ctxKeyEthAddress ctxKey = "eth_address"

	nonceTTL = 60 * time.Second
	jwtTTL   = 30 * time.Minute

	siweStatement = "Sign in to ROFL App Backend"
)

// CustomClaims are the claims for the JWT.
type CustomClaims struct {
	// Address is the authenticated Ethereum address of the user.
	Address string `json:"address"`
	jwt.RegisteredClaims
}

// JWTAuthMiddleware is a middleware that authenticates the user using a JWT.
func JWTAuthMiddleware(jwtSecret []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authz := r.Header.Get("Authorization")
			if authz == "" || !strings.HasPrefix(authz, "Bearer ") {
				slog.Error("missing authorization token", "authz", authz)
				common.WriteError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
				return
			}

			// Parse and validate the token.
			token := strings.TrimPrefix(authz, "Bearer ")
			claim, err := parseAndValidateJWT(token, jwtSecret)
			if err != nil {
				slog.Error("invalid authorization token", "error", err)
				common.WriteError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
				return
			}

			// Set the user in the request context.
			ctx := context.WithValue(r.Context(), ctxKeyEthAddress, claim.Address)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func parseAndValidateJWT(tokenStr string, jwtSecret []byte) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(_ *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	if token.Method != jwt.SigningMethodHS256 {
		return nil, fmt.Errorf("invalid token method: %s", token.Method)
	}
	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}
	return claims, nil
}

// EthAddress returns the authenticated Ethereum address from the request context.
func EthAddress(ctx context.Context) (string, error) {
	addr, ok := ctx.Value(ctxKeyEthAddress).(string)
	if !ok {
		return "", errors.New("no eth address in context")
	}
	return addr, nil
}

// NonceHandler is a handler that returns a nonce for a user.
func NonceHandler(redis *redis.Client) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		address := r.URL.Query().Get("address")
		if address == "" {
			http.Error(w, "missing address query parameter", http.StatusBadRequest)
			return
		}

		// Ensure the address is a valid Ethereum address.
		if !isEthAddress(address) {
			http.Error(w, "invalid address", http.StatusBadRequest)
			return
		}
		address = strings.ToLower(address)

		// Generate a nonce.
		b := make([]byte, 16)
		_, err := rand.Read(b)
		if err != nil {
			slog.Error("failed to generate nonce", "error", err)
			common.WriteError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
			return
		}
		nonce := hex.EncodeToString(b)

		res := redis.Set(r.Context(), nonceKey(address, nonce), nonce, nonceTTL)
		if err := res.Err(); err != nil {
			slog.Error("failed to set nonce", "error", err)
			common.WriteError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
			return
		}

		// Return the nonce.
		common.WriteJSON(w, http.StatusOK, map[string]string{
			"nonce": nonce,
		})
	}
}

func isEthAddress(s string) bool {
	if len(s) != 42 || !strings.HasPrefix(s, "0x") {
		return false
	}
	_, err := hex.DecodeString(s[2:])
	return err == nil
}

// SIWELoginHandler is a handler that logs in a user using a SIWE message.
func SIWELoginHandler(redisClient *redis.Client, cfg *config.AuthConfig) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// Verify the recaptcha token if configured.
		if cfg.RecaptchaSecret != "" {
			if err := recaptcha.CheckRecaptcha(r.Context(), cfg.RecaptchaSecret, r.FormValue(recaptcha.FormField)); err != nil {
				common.WriteError(w, http.StatusUnauthorized, "invalid recaptcha token")
				return
			}
		}

		// Read and parse raw signed message.
		var body struct {
			Message string `json:"message"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			common.WriteError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		// Parse the SIWE message.
		msg, err := siwe.ParseMessage(body.Message)
		if err != nil {
			common.WriteError(w, http.StatusBadRequest, "invalid SIWE message")
			return
		}
		sig := r.URL.Query().Get("sig")
		if sig == "" {
			common.WriteError(w, http.StatusBadRequest, "missing signature")
			return
		}

		// Fetch the nonce.
		rsp := redisClient.GetDel(r.Context(), nonceKey(msg.GetAddress().String(), msg.GetNonce()))
		switch {
		case errors.Is(rsp.Err(), redis.Nil):
			common.WriteError(w, http.StatusUnauthorized, "invalid nonce")
			return
		case rsp.Err() != nil:
			slog.Error("failed to get nonce", "error", rsp.Err())
			common.WriteError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
			return
		}
		nonce := rsp.Val()

		// Verify the message signature.
		if _, err := msg.Verify(sig /* We validate the domain below, since we allow multiple domains. */, nil, &nonce, nil /* nil uses time.Now() */); err != nil {
			common.WriteError(w, http.StatusUnauthorized, "invalid SIWE signature")
			return
		}

		// Verify the domain.
		domain := msg.GetDomain()
		if domain == "" {
			common.WriteError(w, http.StatusUnauthorized, "missing domain")
		}
		if !slices.Contains(cfg.SIWEDomains, domain) {
			common.WriteError(w, http.StatusUnauthorized, "invalid SIWE domain")
			return
		}

		// Verify the statement.
		statement := msg.GetStatement()
		if statement == nil {
			common.WriteError(w, http.StatusUnauthorized, "missing statement")
			return
		}
		if *statement != siweStatement {
			common.WriteError(w, http.StatusUnauthorized, "invalid statement")
			return
		}

		// Verify the Chain ID if set.
		if cfg.SIWEChainID != 0 && msg.GetChainID() != cfg.SIWEChainID {
			common.WriteError(w, http.StatusUnauthorized, "invalid SIWE chain ID")
			return
		}
		if cfg.SIWEVersion != "" && msg.GetVersion() != cfg.SIWEVersion {
			common.WriteError(w, http.StatusUnauthorized, "invalid SIWE version")
			return
		}

		// Create a new session token.
		claims := CustomClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(jwtTTL)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
			Address: msg.GetAddress().String(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		// Sign the token.
		tokenString, err := token.SignedString([]byte(cfg.JWTSecret))
		if err != nil {
			common.WriteError(w, http.StatusInternalServerError, "internal error")
			return
		}

		// Return the token.
		common.WriteJSON(w, http.StatusOK, map[string]string{
			"token":   tokenString,
			"address": claims.Address,
		})
	}
}

func nonceKey(address, nonce string) string {
	return fmt.Sprintf("siwe:%s:%s", strings.ToLower(address), nonce)
}
