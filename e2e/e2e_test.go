package e2e

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	siwe "github.com/spruceid/siwe-go"
	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/rofl-app-backend/tasks"
)

const (
	backendURL = "http://localhost:8899"

	siweDomain = "localhost"
)

//go:embed testdata/*
var testFiles embed.FS

func TestE2E(t *testing.T) {
	client := &http.Client{}

	var jwt string

	t.Run("SIWELogin", func(t *testing.T) {
		require := require.New(t)
		// Test SIWE login.
		jwt = doSIWELogin(t, client)

		// Verify the JWT.
		meResp := doRequest(t, client, http.MethodGet, backendURL+"/me", &jwt, nil)
		require.Equal(http.StatusOK, meResp.StatusCode, "failed to fetch /me")
		require.NoError(meResp.Body.Close(), "failed to close response body")
	})

	t.Run("Artifacts", func(t *testing.T) {
		require := require.New(t)

		testArtifactID := "test_123"
		testArtifactContent := []byte("test-artifact")

		// Test upload/download an artifact.
		resp := doRequest(t, client, http.MethodPut, backendURL+"/artifacts/"+testArtifactID, &jwt, bytes.NewReader(testArtifactContent))
		require.Equal(http.StatusOK, resp.StatusCode, "failed to upload artifact")
		_ = resp.Body.Close()

		// Test non-existing artifact.
		resp = doRequest(t, client, http.MethodGet, backendURL+"/artifacts/test_456", &jwt, nil)
		require.Equal(http.StatusNotFound, resp.StatusCode, "downloading non-existing artifact should return 404")
		_ = resp.Body.Close()

		resp = doRequest(t, client, http.MethodGet, backendURL+"/artifacts/"+testArtifactID, &jwt, nil)
		require.Equal(http.StatusOK, resp.StatusCode, "failed to download artifact")
		body, err := io.ReadAll(resp.Body)
		require.NoError(err, "failed to read response body")
		require.Equal(testArtifactContent, body, "downloaded artifact does not match")
		require.NoError(resp.Body.Close(), "failed to close response body")
	})

	t.Run("ROFL Build", func(t *testing.T) {
		require := require.New(t)

		// Setup the payload.
		manifest, err := testFiles.ReadFile("testdata/rofl.yaml")
		require.NoError(err)
		compose, err := testFiles.ReadFile("testdata/compose.yaml")
		require.NoError(err)
		payload := map[string]string{
			"manifest": string(manifest),
			"compose":  string(compose),
		}
		buf := new(bytes.Buffer)
		require.NoError(json.NewEncoder(buf).Encode(payload))

		// Test build a ROFL build.
		resp := doRequest(t, client, http.MethodPost, backendURL+"/rofl/build", &jwt, buf)
		require.Equal(http.StatusOK, resp.StatusCode, "failed to submit a ROFL build request")
		body, err := io.ReadAll(resp.Body)
		require.NoError(err, "failed to read response body")
		require.NoError(resp.Body.Close(), "failed to close response body")

		var buildRes struct {
			TaskID string `json:"task_id"`
		}
		require.NoError(json.Unmarshal(body, &buildRes), "failed to unmarshal response body")
		require.NotEmpty(buildRes.TaskID, "no task ID in response body")

		// Poll for the build results.
		timeout := time.After(5 * time.Minute)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-timeout:
				require.FailNow("build timed out")
			case <-ticker.C:
				t.Logf("polling for build results: %s", buildRes.TaskID)
			}

			resp := doRequest(t, client, http.MethodGet, backendURL+"/rofl/build/"+buildRes.TaskID+"/results", &jwt, nil)
			switch resp.StatusCode {
			case http.StatusAccepted:
				// Build is still running.
				continue
			case http.StatusOK:
				// Continues below.
			default:
				require.FailNow("unexpected status code: %d", resp.StatusCode)
			}

			t.Log("task completed")

			// Ensure build succeeded.
			body, err := io.ReadAll(resp.Body)
			require.NoError(err, "failed to read response body")
			_ = resp.Body.Close()

			var result tasks.RoflBuildResult
			require.NoError(json.Unmarshal(body, &result), "failed to unmarshal response body")
			if result.Err != "" {
				slog.Debug("build failed", "error", result.Err, "logs", string(result.Logs))
				require.FailNow(result.Err, "build failed", result.Err)
			}
			require.NotEmpty(result.Logs, "no logs in response body")
			require.NotEmpty(result.Manifest, "no manifest in response body")
			require.NotEmpty(result.ManifestHash, "no manifest hash in response body")
			require.NotEmpty(result.OciReference, "no OCI reference in response body")
			break
		}
	})
}

func doSIWELogin(t *testing.T, client *http.Client) string {
	require := require.New(t)

	// Generate ephemeral key.
	privKey, err := crypto.GenerateKey()
	require.NoError(err, "failed to generate ephemeral key")
	addr := crypto.PubkeyToAddress(privKey.PublicKey)

	// Fetch nonce.
	resp := doRequest(t, client, http.MethodGet, backendURL+"/auth/nonce?address="+addr.Hex(), nil, nil)
	require.Equal(http.StatusOK, resp.StatusCode, "failed to fetch nonce")
	var nonceRes struct {
		Nonce string `json:"nonce"`
	}
	require.NoError(json.NewDecoder(resp.Body).Decode(&nonceRes), "failed to decode nonce response")
	require.NoError(resp.Body.Close(), "failed to close response body")

	// Build and sign the SIWE message.
	msg, err := siwe.InitMessage(siweDomain, addr.Hex(), "http://"+siweDomain, nonceRes.Nonce, map[string]interface{}{
		"chainId":   1,
		"version":   "1",
		"statement": "Sign in to localhost",
	})
	require.NoError(err, "failed to build SIWE message")
	msgHash := signHash([]byte(msg.String()))
	sig, err := crypto.Sign(msgHash.Bytes(), privKey)
	require.NoError(err, "failed to sign message")

	// Authenticate with the backend.
	loginPayload := map[string]string{
		"message": msg.String(),
	}
	buf := new(bytes.Buffer)
	_ = json.NewEncoder(buf).Encode(loginPayload)
	resp = doRequest(t, client, http.MethodPost, backendURL+"/auth/login?sig=0x"+common.Bytes2Hex(sig), nil, buf)
	require.Equal(http.StatusOK, resp.StatusCode, "login failed")

	// Ensure a JWT is returned.
	var jwtRes struct {
		Token   string `json:"token"`
		Address string `json:"address"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&jwtRes)
	_ = resp.Body.Close()
	require.NotEmpty(jwtRes.Token, "no token in response body")
	require.Equal(addr.Hex(), jwtRes.Address, "address in response body does not match")

	return jwtRes.Token
}

func signHash(data []byte) common.Hash {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256Hash([]byte(msg))
}

func doRequest(t *testing.T, client *http.Client, method string, url string, jwt *string, body io.Reader) *http.Response {
	t.Helper()

	req, err := http.NewRequest(method, url, body)
	require.NoError(t, err, "failed to create request")
	if jwt != nil {
		req.Header.Set("Authorization", "Bearer "+*jwt)
		if body != nil {
			req.Header.Set("Content-Type", "application/octet-stream")
		}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	require.NoError(t, err, "failed to perform request")
	return resp
}
