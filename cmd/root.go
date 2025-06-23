// Package cmd implements commands for the executable.
package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/oasisprotocol/rofl-app-backend/api"
	"github.com/oasisprotocol/rofl-app-backend/config"
	"github.com/oasisprotocol/rofl-app-backend/worker"
)

var (
	// Path to the configuration file.
	configFile string

	rootCmd = &cobra.Command{
		Use:   "rofl-app",
		Short: "Oasis ROFL App",
		Run:   rootMain,
	}
)

// shutdownTimeout is the timeout for the services to shutdown.
const shutdownTimeout = 15 * time.Second

// Service is an interface that defines a that can be run.
type Service interface {
	// Run runs the service.
	Run(ctx context.Context) error
}

func rootMain(_ *cobra.Command, _ []string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Load config.
	cfg, err := config.InitConfig(configFile)
	if err != nil {
		fmt.Printf("Failed to load config: '%v'\n", err)
		os.Exit(1)
	}

	// Setup logger.
	slog.SetDefault(cfg.Log.GetLogger())

	// Spin up services.
	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	if cfg.Server != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			server := api.NewServer(cfg.Server)
			if err := server.Run(ctx); err != nil {
				errCh <- err
			}
		}()
	}
	if cfg.Worker != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker := worker.NewWorker(cfg.Worker, cfg.Log)
			if err := worker.Run(ctx); err != nil {
				errCh <- err
			}
		}()
	}

	// Ensure clean shutdown.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)
	select {
	case err := <-errCh:
		slog.Error("service stopped", "error", err)
	case <-stop:
		slog.Info("received shutdown signal")
	}
	slog.Info("shutting down services")
	cancel()

	// Allow a bit time for services to shutdown.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		slog.Info("services shut down")
	case <-time.After(shutdownTimeout):
		slog.Error("services did not shutdown in time, forcing exit")
		os.Exit(1)
	}
}

// Execute spawns the main entry point after handing the config file.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVar(&configFile, "config", "config.yml", "path to the config.yml file")
}
