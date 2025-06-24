// Package recaptcha implements the recaptcha verification.
package recaptcha

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/context/ctxhttp"
)

const verifyURL = "https://www.google.com/recaptcha/api/siteverify"

// FormField is the form field name for the recaptcha token.
const FormField = "g-recaptcha-response"

// client is the default HTTP client for recaptcha requests.
var client = &http.Client{
	Timeout: 5 * time.Second,
}

type recaptchaResponse struct {
	Success     bool     `json:"success"`
	Score       *float64 `json:"score,omitempty"` // Only in v3.
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes,omitempty"`
}

// CheckRecaptcha verifies the recaptcha token.
func CheckRecaptcha(ctx context.Context, secretKey, token string) error {
	resp, err := ctxhttp.PostForm(
		ctx,
		client,
		verifyURL,
		url.Values{
			"secret":   {secretKey},
			"response": {token},
		})
	if err != nil {
		return fmt.Errorf("failed to verify recaptcha: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read recaptcha response: %w", err)
	}

	var recaptchaResponse recaptchaResponse
	if err := json.Unmarshal(body, &recaptchaResponse); err != nil {
		return fmt.Errorf("failed to unmarshal recaptcha response: %w", err)
	}

	if !recaptchaResponse.Success {
		return fmt.Errorf("recaptcha verification failed: %v", recaptchaResponse.ErrorCodes)
	}

	if recaptchaResponse.Score != nil && *recaptchaResponse.Score < 0.5 {
		return fmt.Errorf("recaptcha verification failed: %v", recaptchaResponse.ErrorCodes)
	}

	return nil
}
