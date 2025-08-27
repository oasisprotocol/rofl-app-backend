package e2e

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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
		if testing.Short() {
			t.Skip("skipping slow ROFL Build test in short mode")
		}
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
		start := time.Now()
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

			t.Log("task completed", "after", time.Since(start))

			// Ensure build succeeded.
			body, err := io.ReadAll(resp.Body)
			require.NoError(err, "failed to read response body")
			_ = resp.Body.Close()

			var result tasks.RoflBuildResult
			require.NoError(json.Unmarshal(body, &result), "failed to unmarshal response body")
			if result.Err != "" {
				// XXX: CI seems to slow to push the image to registry, so the build timeouts, don't fail the test in that case.
				// Remove this in future, if the timeotus get adjusted.
				if strings.Contains(result.Logs, "response status code 524") {
					t.Log("build timed out, not failing the test")
					return
				}
				require.FailNow(result.Err, "build failed", result.Err)
			}
			require.NotEmpty(result.Logs, "no logs in response body")
			require.NotEmpty(result.Manifest, "no manifest in response body")
			require.NotEmpty(result.ManifestHash, "no manifest hash in response body")
			require.NotEmpty(result.OciReference, "no OCI reference in response body")
			break
		}
	})

	t.Run("ROFL Validate", func(t *testing.T) {
		t.Run("ValidCase", func(t *testing.T) {
			require := require.New(t)

			// Setup the payload with valid data.
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

			// Test validate a ROFL manifest.
			resp := doRequest(t, client, http.MethodPost, backendURL+"/rofl/validate", &jwt, buf)
			require.Equal(http.StatusOK, resp.StatusCode, "failed to submit a ROFL validate request")
			body, err := io.ReadAll(resp.Body)
			require.NoError(err, "failed to read response body")
			require.NoError(resp.Body.Close(), "failed to close response body")

			var validateRes tasks.RoflValidateResult
			require.NoError(json.Unmarshal(body, &validateRes), "failed to unmarshal response body")
			require.True(validateRes.Valid, "validation should succeed for valid manifest")
			require.Empty(validateRes.Err, "no error should be present for valid manifest")
			require.NotEmpty(validateRes.Logs, "logs should be present")
		})

		// Invalid test cases.
		invalidCases := []struct {
			name        string
			modifyFunc  func(string) string
			description string
		}{
			{
				name:        "InvalidMemoryField",
				description: "invalid memory field type",
				modifyFunc: func(manifest string) string {
					return strings.Replace(manifest, "memory: 512", "memory: invalid-memory-value", 1)
				},
			},
			{
				name:        "MissingNameField",
				description: "missing required name field",
				modifyFunc: func(manifest string) string {
					return strings.Replace(manifest, "name: rofl-app-backend-test-e2e\n", "", 1)
				},
			},
			{
				name:        "InvalidRepositoryURL",
				description: "invalid repository URL format",
				modifyFunc: func(manifest string) string {
					return strings.Replace(manifest, "name: rofl-app-backend-test-e2e\n", "name: rofl-app-backend-test-e2e\nrepository: ht[tp://invalid\n", 1)
				},
			},
			{
				name:        "InvalidTEEType",
				description: "invalid TEE type",
				modifyFunc: func(manifest string) string {
					return strings.Replace(manifest, "tee: tdx", "tee: ABC", 1)
				},
			},
			{
				name:        "MissingNetwork",
				description: "missing required network field",
				modifyFunc: func(manifest string) string {
					return strings.Replace(manifest, "    network: testnet\n", "", 1)
				},
			},
		}

		for _, tc := range invalidCases {
			t.Run(tc.name, func(t *testing.T) {
				require := require.New(t)

				// Start with valid files.
				manifest, err := testFiles.ReadFile("testdata/rofl.yaml")
				require.NoError(err)
				compose, err := testFiles.ReadFile("testdata/compose.yaml")
				require.NoError(err)

				// Apply the specific modification for this test case.
				invalidManifest := tc.modifyFunc(string(manifest))

				payload := map[string]string{
					"manifest": invalidManifest,
					"compose":  string(compose),
				}
				buf := new(bytes.Buffer)
				require.NoError(json.NewEncoder(buf).Encode(payload))

				// Test validate the invalid ROFL manifest.
				resp := doRequest(t, client, http.MethodPost, backendURL+"/rofl/validate", &jwt, buf)
				require.Equal(http.StatusOK, resp.StatusCode, "failed to submit a ROFL validate request")
				body, err := io.ReadAll(resp.Body)
				require.NoError(err, "failed to read response body")
				require.NoError(resp.Body.Close(), "failed to close response body")

				var validateRes tasks.RoflValidateResult
				require.NoError(json.Unmarshal(body, &validateRes), "failed to unmarshal response body")
				require.False(validateRes.Valid, "validation should fail for %s", tc.description)
				require.NotEmpty(validateRes.Err, "error should be present for %s", tc.description)
				require.NotEmpty(validateRes.Logs, "logs should be present for %s", tc.description)

				t.Logf("Test case '%s' failed as expected with error: %s", tc.description, validateRes.Err)
			})
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
		"chainId":   0x5aff,
		"version":   "1",
		"statement": "Sign in to ROFL App Backend",
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
