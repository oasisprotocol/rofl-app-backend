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
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"github.com/spruceid/siwe-go"

	"github.com/oasisprotocol/rofl-app-backend/api/common"
)

type ctxKey string

const (
	ctxKeyEthAddress ctxKey = "eth_address"

	nonceTTL = 60 * time.Second
	jwtTTL   = 15 * time.Minute
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
func SIWELoginHandler(redisClient *redis.Client, jwtSecret []byte, domain string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// Read and parse raw signed message.
		var body struct {
			Message string `json:"message"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		// Parse the SIWE message.
		msg, err := siwe.ParseMessage(body.Message)
		if err != nil {
			http.Error(w, "invalid SIWE message", http.StatusBadRequest)
			return
		}
		sig := r.URL.Query().Get("sig")
		if sig == "" {
			http.Error(w, "missing signature", http.StatusBadRequest)
		}

		// Fetch the nonce.
		rsp := redisClient.GetDel(r.Context(), nonceKey(msg.GetAddress().String(), msg.GetNonce()))
		switch {
		case errors.Is(rsp.Err(), redis.Nil):
			http.Error(w, "invalid nonce", http.StatusUnauthorized)
			return
		case rsp.Err() != nil:
			slog.Error("failed to get nonce", "error", rsp.Err())
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		nonce := rsp.Val()

		// Verify the message signature.
		if _, err := msg.Verify(sig, &domain, &nonce, nil /* nil uses time.Now() */); err != nil {
			slog.Error("invalid SIWE signature", "error", err, "msg", msg.String())
			http.Error(w, "invalid SIWE signature", http.StatusUnauthorized)
			return
		}
		// TODO: Also validate chain id?

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
		tokenString, err := token.SignedString(jwtSecret)
		if err != nil {
			http.Error(w, "Internal error.", http.StatusInternalServerError)
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
