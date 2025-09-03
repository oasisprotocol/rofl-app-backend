// Package worker implements the worker for the ROFL build task.
package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/hibiken/asynq"
	"github.com/redis/go-redis/v9"

	"github.com/oasisprotocol/rofl-app-backend/config"
	"github.com/oasisprotocol/rofl-app-backend/tasks"
	"github.com/oasisprotocol/rofl-app-backend/worker/oasiscli"
)

const (
	defaultOasisCLIPath = "/usr/local/bin/oasis"

	// For now, only a single worker per process is supported.
	// This is because the build command uses all available CPU cores,
	// and limiting to one simplifies CLI command caching.
	// To parallelize, deploy multiple separate worker processes.
	numWorkers = 1

	// shutdownTimeout is the timeout for the asynq server to wait for in-progress tasks to complete,
	// before stopping them and returning the tasks in queue.
	// This should be less than the shutdown timeout of the application in root.go.
	shutdownTimeout = 10 * time.Second
)

// ErrInternalError is the error returned when an internal error occurs during task processing.
var ErrInternalError = fmt.Errorf("internal error")

// Worker is the worker for the ROFL build task.
type Worker struct {
	cfg         *config.WorkerConfig
	logger      *slog.Logger
	asynqLogger *asynqLogger
}

// Run implements the Service interface.
func (w *Worker) Run(ctx context.Context) error {
	w.logger.Info("starting worker")

	// Setup the Oasis CLI runner.
	oasisCLIPath := defaultOasisCLIPath
	if w.cfg.OasisCLIPath != nil {
		oasisCLIPath = *w.cfg.OasisCLIPath
	}
	workDir, err := os.MkdirTemp("", "rofl-builder-")
	if err != nil {
		return fmt.Errorf("failed to create work directory: %w", err)
	}
	var cacheDir string
	if w.cfg.CacheDir == nil {
		// Use a temporary directory if no cache dir is configured.
		cacheDir = filepath.Join(os.TempDir(), fmt.Sprintf("rofl-builder-cache-%d", time.Now().UnixNano()))
	}
	// Ensure the cache directory exists.
	if err := os.MkdirAll(cacheDir, 0o750); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Setup the Oasis CLI runner.
	cli, err := oasiscli.NewRunner(oasisCLIPath, workDir, cacheDir)
	if err != nil {
		return fmt.Errorf("failed to create oasis CLI runner: %w", err)
	}
	w.logger.Info("oasis CLI runner created", "version", cli.Version())

	// Connect to redis.
	opts, err := redis.ParseURL(w.cfg.Redis.Endpoint)
	if err != nil {
		return fmt.Errorf("invalid redis endpoint url: %w", err)
	}
	redisClient := redis.NewClient(opts)
	defer func() {
		_ = redisClient.Close()
	}()

	// Setup the asynq server.
	server := asynq.NewServerFromRedisClient(
		redisClient,
		asynq.Config{
			Concurrency: numWorkers,
			Queues: map[string]int{
				tasks.RoflBuildQueue:    1,
				tasks.RoflValidateQueue: 3, // A bit higher priority for (fast) validate tasks.
			},
			Logger:          w.asynqLogger,
			ShutdownTimeout: shutdownTimeout,
		},
	)
	mux := asynq.NewServeMux()
	processor := &roflProcessor{cli: cli, redis: redisClient, logger: w.logger.With("component", "processor")}
	mux.Handle(tasks.RoflBuildTask, newMetricsWrapper(tasks.RoflBuildQueue, processor))
	mux.Handle(tasks.RoflValidateTask, newMetricsWrapper(tasks.RoflValidateQueue, processor))

	errCh := make(chan error, 1)
	go func() {
		if err := server.Start(mux); err != nil {
			errCh <- fmt.Errorf("worker error: %w", err)
		}
	}()

	select {
	case err := <-errCh:
		server.Shutdown()
		return err
	case <-ctx.Done():
		w.logger.Info("shutting down worker")
		server.Shutdown()
	}
	return nil
}

// NewWorker creates a new worker.
func NewWorker(cfg *config.WorkerConfig, logger *slog.Logger, logConfig config.LogConfig) *Worker {
	return &Worker{
		cfg:    cfg,
		logger: logger,
		asynqLogger: &asynqLogger{
			// Ideally we would construct logger with unwind from the provided existing logger, but it's currently not possible
			// to take an existing slog logger and update it with a new unwind.
			logger: logConfig.GetLoggerWithUnwind(9).With("service", "worker", "component", "asynq"),
		},
	}
}

// roflProcessor is the processor for ROFL tasks (build and validate).
type roflProcessor struct {
	cli    *oasiscli.Runner
	redis  *redis.Client
	logger *slog.Logger
}

var _ asynq.Handler = (*roflProcessor)(nil)

// Implement the asynq.Handler interface.
func (p *roflProcessor) ProcessTask(ctx context.Context, t *asynq.Task) error {
	switch t.Type() {
	case tasks.RoflBuildTask:
		return p.processBuildTaskWrapper(ctx, t)
	case tasks.RoflValidateTask:
		return p.processValidateTaskWrapper(ctx, t)
	default:
		p.logger.Error("unknown task type", "type", t.Type())
		return ErrInternalError
	}
}

func (p *roflProcessor) processBuildTaskWrapper(ctx context.Context, t *asynq.Task) error {
	taskID := t.ResultWriter().TaskID()
	p.logger.Debug("processing build task", "task_id", taskID)

	// Unmarshal the payload.
	var payload tasks.RoflBuildPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		p.logger.Error("failed to unmarshal build task payload", "error", err)
		return ErrInternalError
	}

	// Process the build task.
	result := p.processBuildTask(ctx, taskID, payload)

	// Release the lock for the user.
	if err := p.redis.Del(ctx, tasks.RoflBuildLockKey(payload.UserAddress)).Err(); err != nil {
		p.logger.Error("failed to release build lock", "error", err)
		// Don't return an error here, because we don't want to fail the task in the rare case we could not release the lock.
	}

	// Report the results.
	resultsJSON, err := json.Marshal(result)
	if err != nil {
		p.logger.Error("failed to marshal result", "error", err)
		return err
	}
	// We don't use the result asynq.ResultWriter to write the results, because we want to have this namespaced by the payload address,
	// not only the Task ID, so that the authenticated user can only access their own results.
	if err := p.redis.Set(ctx, tasks.RoflBuildResultsKey(payload.UserAddress, taskID), resultsJSON, time.Hour).Err(); err != nil {
		p.logger.Error("failed to save OCI-reference to redis", "error", err)
		return err
	}

	p.logger.Debug("build task processed", "task_id", taskID)
	return nil
}

func writeFile(path string, data []byte) error {
	file, err := os.Create(path) //nolint:gosec // We control the file path.
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to close file: %w", err)
	}
	return nil
}

func (p *roflProcessor) processBuildTask(ctx context.Context, taskID string, payload tasks.RoflBuildPayload) tasks.RoflBuildResult {
	var result tasks.RoflBuildResult

	// Setup work directory and files.
	workDir, cleanup, err := p.setupWorkDir(taskID, payload.Manifest, payload.Compose)
	if err != nil {
		p.logger.Error("failed to setup work directory", "error", err)
		result.Err = ErrInternalError.Error()
		return result
	}
	defer cleanup()

	// Run the build command.
	buildResult, err := p.cli.Run(ctx, oasiscli.RunInput{
		Command: oasiscli.CommandBuild,
		WorkDir: workDir,
	})
	if err != nil {
		p.logger.Error("failed to run build command", "error", err)
		result.Err = ErrInternalError.Error()
		return result
	}
	result.Stdout = string(buildResult.Stdout)
	result.Stderr = string(buildResult.Stderr)

	// Propagate the build command error if it failed.
	if buildResult.Err != nil {
		p.logger.Error("build command failed", "error", buildResult.Err, "stdout", buildResult.Stdout, "stderr", buildResult.Stderr)
		result.Err = buildResult.Err.Error()
		return result
	}

	if buildResult.Build == nil {
		p.logger.Error("build result is nil, but no error was returned", "stdout", buildResult.Stdout, "stderr", buildResult.Stderr)
		result.Err = ErrInternalError.Error()
		return result
	}

	// Run the push command.
	pushResult, err := p.cli.Run(ctx, oasiscli.RunInput{
		Command: oasiscli.CommandPush,
		WorkDir: workDir,
	})
	if err != nil {
		p.logger.Error("failed to run push command", "error", err)
		result.Err = ErrInternalError.Error()
		return result
	}
	result.Stdout += "\n" + string(pushResult.Stdout)
	result.Stderr += "\n" + string(pushResult.Stderr)

	// Propagate the push command error if it failed.
	if pushResult.Err != nil {
		p.logger.Error("push command failed", "error", pushResult.Err, "stdout", pushResult.Stdout, "stderr", pushResult.Stderr)
		result.Err = pushResult.Err.Error()
		return result
	}

	if pushResult.Push == nil {
		p.logger.Error("push result is nil, but no error was returned", "stdout", pushResult.Stdout, "stderr", pushResult.Stderr)
		result.Err = ErrInternalError.Error()
		return result
	}

	result.Manifest = buildResult.Build.Manifest
	result.ManifestHash = pushResult.Push.ManifestHash
	result.OciReference = pushResult.Push.OciReference
	return result
}

func (p *roflProcessor) processValidateTaskWrapper(ctx context.Context, t *asynq.Task) error {
	taskID := t.ResultWriter().TaskID()
	p.logger.Debug("processing validate task", "task_id", taskID)

	// Unmarshal the payload.
	var payload tasks.RoflValidatePayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		p.logger.Error("failed to unmarshal validate task payload", "error", err)
		return ErrInternalError
	}

	// Process the validate task.
	result := p.processValidateTask(ctx, taskID, payload)

	// Report the results.
	resultsJSON, err := json.Marshal(result)
	if err != nil {
		p.logger.Error("failed to marshal validate result", "error", err)
		return err
	}
	// Store results in Redis for the API to retrieve.
	if err := p.redis.Set(ctx, tasks.RoflValidateResultsKey(payload.UserAddress, taskID), resultsJSON, 1*time.Minute).Err(); err != nil {
		p.logger.Error("failed to save validate results to redis", "error", err)
		return err
	}

	p.logger.Debug("validate task processed", "task_id", taskID)
	return nil
}

func (p *roflProcessor) processValidateTask(ctx context.Context, taskID string, payload tasks.RoflValidatePayload) tasks.RoflValidateResult {
	var result tasks.RoflValidateResult

	// Setup work directory and files.
	workDir, cleanup, err := p.setupWorkDir(taskID, payload.Manifest, payload.Compose)
	if err != nil {
		p.logger.Error("failed to setup work directory", "error", err)
		result.Err = ErrInternalError.Error()
		return result
	}
	defer cleanup()

	// Run the validate command.
	validateResult, err := p.cli.Run(ctx, oasiscli.RunInput{
		Command: oasiscli.CommandValidate,
		WorkDir: workDir,
	})
	if err != nil {
		p.logger.Error("failed to run validate command", "error", err)
		result.Err = ErrInternalError.Error()
		return result
	}
	result.Stdout = string(validateResult.Stdout)
	result.Stderr = string(validateResult.Stderr)

	// Check if validation succeeded.
	if validateResult.Err != nil {
		p.logger.Debug("validate command failed", "error", validateResult.Err, "stdout", validateResult.Stdout, "stderr", validateResult.Stderr)
		result.Valid = false
		result.Err = validateResult.Err.Error()
	} else {
		result.Valid = true
	}

	return result
}

// setupWorkDir creates a work directory and writes the manifest and compose files.
// Returns the work directory path and a cleanup function.
func (p *roflProcessor) setupWorkDir(taskID string, manifest, compose []byte) (string, func(), error) {
	workDir, err := p.cli.NewWorkDir(taskID)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create work directory: %w", err)
	}

	cleanup := func() {
		if err := os.RemoveAll(workDir); err != nil {
			p.logger.Error("failed to remove work directory", "error", err, "work_dir", workDir)
		}
	}

	if err := writeFile(filepath.Join(workDir, "compose.yaml"), compose); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("failed to setup compose.yaml file: %w", err)
	}
	if err := writeFile(filepath.Join(workDir, "rofl.yaml"), manifest); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("failed to setup rofl.yaml file: %w", err)
	}

	return workDir, cleanup, nil
}

var _ asynq.Logger = (*asynqLogger)(nil)

// asynqLogger is an slog wrapper for the asynq.Logger interface.
type asynqLogger struct {
	logger *slog.Logger
}

func (l *asynqLogger) Debug(args ...interface{}) {
	l.logger.Debug(fmt.Sprint(args...))
}

func (l *asynqLogger) Info(args ...interface{}) {
	l.logger.Info(fmt.Sprint(args...))
}

func (l *asynqLogger) Warn(args ...interface{}) {
	l.logger.Warn(fmt.Sprint(args...))
}

func (l *asynqLogger) Error(args ...interface{}) {
	l.logger.Error(fmt.Sprint(args...))
}

func (l *asynqLogger) Fatal(args ...interface{}) {
	l.logger.Error(fmt.Sprint(args...))
}
