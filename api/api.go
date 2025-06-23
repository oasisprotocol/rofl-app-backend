// Package api implements the API server.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"cloud.google.com/go/storage"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/httplog/v3"
	"github.com/hibiken/asynq"
	"github.com/redis/go-redis/v9"
	"google.golang.org/api/option"

	"github.com/oasisprotocol/rofl-app-backend/api/auth"
	"github.com/oasisprotocol/rofl-app-backend/api/common"
	"github.com/oasisprotocol/rofl-app-backend/config"
	"github.com/oasisprotocol/rofl-app-backend/tasks"
)

const (
	defaultTimeout = 10 * time.Second

	artifactsMaxIDLength = 64
)

var artifactsValidID = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// Server is the API server.
type Server struct {
	cfg *config.ServerConfig
}

// Run implements the Service interface.
func (s *Server) Run(ctx context.Context) error {
	// Setup a redis client.
	opts, err := redis.ParseURL(s.cfg.Redis.Endpoint)
	if err != nil {
		return fmt.Errorf("invalid redis endpoint url: %w", err)
	}
	redisClient := redis.NewClient(opts)
	defer func() {
		_ = redisClient.Close()
	}()

	// Setup an asynq client.
	asynqClient := asynq.NewClientFromRedisClient(redisClient)
	defer func() {
		_ = asynqClient.Close()
	}()

	// Setup a GCS client (In production workload identity should be used, so no need to pass credentials).
	gcsOpts := []option.ClientOption{}
	switch s.cfg.GCSConfig.FakeGCSAddress {
	case "":
		// Client documentation recommends using JSON reads, however, it's not currently supported in the fake GCS server.
		gcsOpts = append(gcsOpts, storage.WithJSONReads())
	default:
		gcsOpts = append(gcsOpts,
			option.WithEndpoint(s.cfg.GCSConfig.FakeGCSAddress),
			option.WithoutAuthentication(),
		)
	}

	gcsClient, err := storage.NewClient(ctx, gcsOpts...)
	if err != nil {
		return fmt.Errorf("failed to initialize GCS client: %w", err)
	}
	defer func() {
		_ = gcsClient.Close()
	}()

	r := chi.NewRouter()
	// Setup CORS.
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   s.cfg.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	}))

	// Setup global middlewares.
	timeout := defaultTimeout
	if s.cfg.RequestTimeout != nil {
		timeout = *s.cfg.RequestTimeout
	}
	r.Use(
		middleware.RequestID,
		middleware.RealIP,
		httplog.RequestLogger(slog.Default(), &httplog.Options{}),
		middleware.Recoverer,
		middleware.Timeout(timeout),
		MaxBytesMiddleware(10*1024*1024), // 10 MB.
	)

	// Health check.
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Login routes.
	r.Route("/auth", func(r chi.Router) {
		r.Get("/nonce", auth.NonceHandler(redisClient))
		// Issues a short-lived JWT for the user (15mins).
		// TODO: We should add a refresh token via secure cookie.
		r.Post("/login", auth.SIWELoginHandler(redisClient, []byte(s.cfg.Auth.JWTSecret), s.cfg.Auth.SIWEDomain))
	})

	// Authenticated routes.
	r.Group(func(r chi.Router) {
		// Ensure the request is authenticated.
		r.Use(auth.JWTAuthMiddleware([]byte(s.cfg.Auth.JWTSecret)))

		r.Get("/me", func(w http.ResponseWriter, r *http.Request) {
			addr, err := auth.EthAddress(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			common.WriteJSON(w, http.StatusOK, map[string]string{"address": addr})
		})

		// TODO: Need to coordinate with frontend here, do we want such general storage, or more specific.
		r.Route("/artifacts", func(r chi.Router) {
			// User can store arbitrary artifacts here.
			r.Put("/{id}", func(w http.ResponseWriter, r *http.Request) {
				id := chi.URLParam(r, "id")
				if id == "" {
					common.WriteError(w, http.StatusBadRequest, "missing id")
					return
				}
				if err := validateArtifactsID(id); err != nil {
					common.WriteError(w, http.StatusBadRequest, err.Error())
					return
				}

				addr, err := auth.EthAddress(r.Context())
				if err != nil {
					http.Error(w, err.Error(), http.StatusUnauthorized)
					return
				}

				// Store the artifact in GCS.
				wc := gcsClient.Bucket(s.cfg.GCSConfig.Bucket).Object(artifactsGKEPath(addr, id)).NewWriter(r.Context())

				if _, err := io.Copy(wc, r.Body); err != nil {
					slog.Error("failed to write to GCS", "err", err)
					common.WriteError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
					return
				}
				if err := wc.Close(); err != nil {
					slog.Error("failed to close GCS writer", "err", err)
					common.WriteError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
					return
				}

				common.WriteJSON(w, http.StatusOK, map[string]string{})
			})

			// User can fetch the stored arbitrary artifacts here.
			r.Get("/{id}", func(w http.ResponseWriter, r *http.Request) {
				id := chi.URLParam(r, "id")
				if id == "" {
					common.WriteError(w, http.StatusBadRequest, "missing id")
					return
				}
				if err := validateArtifactsID(id); err != nil {
					common.WriteError(w, http.StatusBadRequest, err.Error())
					return
				}

				addr, err := auth.EthAddress(r.Context())
				if err != nil {
					http.Error(w, err.Error(), http.StatusUnauthorized)
					return
				}

				// Fetch the data from the GCS.
				rc, err := gcsClient.Bucket(s.cfg.GCSConfig.Bucket).Object(artifactsGKEPath(addr, id)).NewReader(r.Context())
				if err != nil {
					slog.Error("failed to get GCS object reader", "err", err)
					http.NotFound(w, r)
					return
				}
				defer func() {
					_ = rc.Close()
				}()

				// Stream the content to the response.
				w.Header().Set("Content-Type", "application/octet-stream")
				if _, err := io.Copy(w, rc); err != nil {
					slog.Error("failed to stream object from GCS", "err", err)
				}
			})
		})

		// ROFL routes.
		r.Route("/rofl", func(r chi.Router) {
			r.Post("/build", func(w http.ResponseWriter, r *http.Request) {
				type buildRequest struct {
					// TODO: maybe we will accept a single file.
					Manifest []byte `json:"manifest"`
					Compose  []byte `json:"compose"`
				}
				req, err := common.DecodeJSON[buildRequest](r)
				if err != nil {
					slog.Error("failed to decode build request", "err", err)
					common.WriteError(w, http.StatusBadRequest, "invalid input")
					return
				}
				// TODO: Validate the manifest here: https://github.com/oasisprotocol/cli/issues/499

				addr, err := auth.EthAddress(r.Context())
				if err != nil {
					http.Error(w, err.Error(), http.StatusUnauthorized)
					return
				}

				// Create a build task.
				task, err := tasks.NewRoflBuildTask(addr, req.Manifest, req.Compose)
				if err != nil {
					slog.Error("failed to create build task", "err", err)
					common.WriteError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
					return
				}
				// TODO: could also ensure only one job per user, via a separate redis lock.
				info, err := asynqClient.EnqueueContext(r.Context(), task, asynq.Unique(5*time.Minute), asynq.MaxRetry(0), asynq.Timeout(5*time.Minute), asynq.Retention(1*time.Hour), asynq.Queue(tasks.RoflBuildQueue))
				if err != nil {
					if errors.Is(err, asynq.ErrDuplicateTask) {
						common.WriteError(w, http.StatusConflict, "build already in progress")
						return
					}
					slog.Error("failed to enqueue build task", "err", err)
					common.WriteError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
					return
				}
				// TODO: Could also store the task ID so we can fetch the status without the client knowing the task ID.
				common.WriteJSON(w, http.StatusOK, map[string]string{"task_id": info.ID})
			})

			// User can fetch the results of the build task.
			r.Get("/build/{task_id}/results", func(w http.ResponseWriter, r *http.Request) {
				taskID := chi.URLParam(r, "task_id")
				if taskID == "" {
					common.WriteError(w, http.StatusBadRequest, "missing task_id")
					return
				}

				addr, err := auth.EthAddress(r.Context())
				if err != nil {
					http.Error(w, err.Error(), http.StatusUnauthorized)
					return
				}

				results, err := redisClient.Get(r.Context(), tasks.RoflBuildResultsKey(addr, taskID)).Result()
				switch {
				case errors.Is(err, redis.Nil):
					http.NotFound(w, r)
					return
				case err != nil:
					slog.Error("failed to get build task results", "err", err)
					common.WriteError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
					return
				default:
				}

				var result tasks.RoflBuildResult
				if err := json.Unmarshal([]byte(results), &result); err != nil {
					slog.Error("failed to unmarshal build task results", "err", err)
					common.WriteError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
					return
				}

				common.WriteJSON(w, http.StatusOK, result)
			})
		})
	})

	server := &http.Server{
		Addr:           s.cfg.Endpoint,
		Handler:        r,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   timeout + 5*time.Second, // Write timeout should be a bit longer than the request timeout.
		MaxHeaderBytes: 1 << 20,                 // 1 MB.
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("starting server", "address", s.cfg.Endpoint)
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("server error: %w", err)
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("shutting down server")
		if err := server.Shutdown(context.Background()); err != nil {
			slog.Error("server shutdown error", "err", err)
		}
	}
	return nil
}

// NewServer creates a new API server.
func NewServer(cfg *config.ServerConfig) *Server {
	return &Server{
		cfg: cfg,
	}
}

// validateArtifactsID validates the id for the artifacts endpoint.
func validateArtifactsID(id string) error {
	if len(id) == 0 || len(id) > artifactsMaxIDLength {
		return fmt.Errorf("id too long")
	}
	if !artifactsValidID.MatchString(id) {
		return fmt.Errorf("id contains invalid characters")
	}
	return nil
}

// artifactsGKEPath returns the GKE path for the artificat of the giver user address and artifact id.
//
// The GKE object name is limited to 1024 bytes. Address is 42 bytes and artifact ID is limited to 64 bytes.
func artifactsGKEPath(userAddress, artifactID string) string {
	return fmt.Sprintf("artifacts/%s/%s", userAddress, artifactID)
}
