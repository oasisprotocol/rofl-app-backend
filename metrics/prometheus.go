// Package metrics implements a Prometheus server.
package metrics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/oasisprotocol/rofl-app-backend/config"
)

// Server is the Prometheus server.
type Server struct {
	cfg    *config.MetricsConfig
	logger *slog.Logger
}

// NewServer creates a new Prometheus server.
func NewServer(cfg *config.MetricsConfig, logger *slog.Logger) *Server {
	return &Server{cfg: cfg, logger: logger}
}

// Run implements the Service interface.
func (s *Server) Run(ctx context.Context) error {
	http.Handle("/metrics", promhttp.Handler())

	server := &http.Server{
		Addr:           s.cfg.PullEndpoint,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("starting server", "address", s.cfg.PullEndpoint)
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("server error: %w", err)
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		s.logger.Info("shutting down server")
		if err := server.Shutdown(context.Background()); err != nil {
			s.logger.Error("server shutdown error", "err", err)
		}
	}

	return nil
}
