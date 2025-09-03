// Package oasiscli provides a wrapper around the oasis CLI.
package oasiscli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// Command is the command to run.
type Command string

const (
	// CommandBuild is the command to build a ROFL app.
	CommandBuild Command = "build"
	// CommandPush is the command to push the previously built OCI image.
	CommandPush Command = "push"
	// CommandValidate is the command to validate the manifest.
	CommandValidate Command = "validate"
)

// RunInput is the input for a command.
type RunInput struct {
	// Command is the command to run.
	Command Command
	// WorkDir is the work directory for the command.
	WorkDir string
}

// CommandResult is the result of running a command.
type CommandResult struct {
	// Build is the result of the build command.
	Build *CommandBuildResult `json:"build,omitempty"`
	// Push is the result of the push command.
	Push *CommandPushResult `json:"push,omitempty"`
	// Validate is the result of the validate command.
	Validate *CommandValidateResult `json:"validate,omitempty"`

	// Stdout is the standard output from the command.
	Stdout []byte `json:"stdout"`
	// Stderr is the error output from the command.
	Stderr []byte `json:"stderr"`
	// Err contains the error during execution of the command.
	Err error `json:"err,omitempty"`
}

// CommandBuildResult is the result of the build command.
type CommandBuildResult struct {
	// Manifest is the updated manifest (rofl.yaml) of the built ROFL app.
	Manifest []byte `json:"manifest"`
}

// CommandPushResult is the result of the push command.
type CommandPushResult struct {
	// OciReference is the reference of the pushed OCI image.
	OciReference string `json:"oci_reference"`
	// ManifestHash is the hash of the manifest of the pushed OCI image.
	ManifestHash string `json:"manifest_hash"`
}

// CommandValidateResult is the result of the validate command.
type CommandValidateResult struct{}

// Runner is a runner for the oasis CLI.
type Runner struct {
	cliPath  string
	workDir  string
	cacheDir string

	version string
}

// Version returns the version of the oasis CLI.
func (r *Runner) Version() string {
	return r.version
}

// NewWorkDir creates a new work directory for the command.
func (r *Runner) NewWorkDir(identifier string) (string, error) {
	t := time.Now().Format("20060102-150405")
	suffix := rand.Intn(1e6)
	dirName := fmt.Sprintf("%s-%s-%06d", identifier, t, suffix)
	runDir := filepath.Join(r.workDir, dirName)

	if err := os.MkdirAll(runDir, 0o750); err != nil {
		return "", fmt.Errorf("failed to create workdir: %w", err)
	}
	return runDir, nil
}

// Run executes the given Oasis CLI command.
// It returns the result of the command. If the command exits with a non-zero status,
// the error is stored in the result's Err field. A non-nil return error indicates an internal or unexpected failure.
func (r *Runner) Run(ctx context.Context, input RunInput) (*CommandResult, error) {
	// Setup the command arguments.
	var args []string
	switch input.Command {
	case CommandBuild:
		args = []string{"rofl", "build"}
	case CommandPush:
		args = []string{"rofl", "push", "--format", "json"}
	case CommandValidate:
		args = []string{"rofl", "build", "--only-validate"}
	default:
		return nil, fmt.Errorf("unsupported command: %s", input.Command)
	}

	c := exec.CommandContext(ctx, r.cliPath, args...) //nolint:gosec // We control the command path.
	c.Dir = input.WorkDir
	// Setup clean environment.
	c.Env = []string{
		"HOME=" + input.WorkDir,
		"XDG_CACHE_HOME=" + r.cacheDir, // Some CLI commands use XDG cache.
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	c.SysProcAttr = getSysProcAttr()

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	c.Stdout = &stdoutBuf
	c.Stderr = &stderrBuf

	results := &CommandResult{}
	if err := c.Start(); err != nil {
		return nil, fmt.Errorf("failed to start command: %w", err)
	}

	done := make(chan error, 1)
	go func() { done <- c.Wait() }()

	select {
	case <-ctx.Done():
		// Kill the entire process group
		if c.Process != nil {
			_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
		}
		<-done
		slog.Error("command timed out", "command", c.String(), "stdout", stdoutBuf.String(), "stderr", stderrBuf.String(), "error", ctx.Err())
		return nil, ctx.Err()
	case err := <-done:
		results.Stdout = stdoutBuf.Bytes()
		results.Stderr = stderrBuf.Bytes()
		if err != nil {
			results.Err = fmt.Errorf("command '%s' failed: %w", c.String(), err)
			return results, nil
		}
	}

	// Parse the output.
	switch input.Command {
	case CommandBuild:
		// Parse the updated manifest yaml file.
		data, err := os.ReadFile(filepath.Join(input.WorkDir, "rofl.yaml"))
		if err != nil {
			return nil, fmt.Errorf("failed to read manifest: %w", err)
		}
		results.Build = &CommandBuildResult{
			Manifest: data,
		}
	case CommandPush:
		// The output should be a JSON object with the OCI digest and manifest hash.
		var parsed map[string]string
		if err := json.Unmarshal(results.Stdout, &parsed); err != nil {
			slog.Error("failed to parse push output", "error", err, "stdout", results.Stdout, "stderr", results.Stderr)
			return nil, fmt.Errorf("failed to parse push output: %w", err)
		}
		if parsed["oci_reference"] == "" {
			return nil, fmt.Errorf("oci reference not found in push output")
		}
		if parsed["manifest_hash"] == "" {
			return nil, fmt.Errorf("manifest hash not found in push output")
		}
		results.Push = &CommandPushResult{
			OciReference: parsed["oci_reference"],
			ManifestHash: parsed["manifest_hash"],
		}
	case CommandValidate:
		results.Validate = &CommandValidateResult{}
	}

	return results, nil
}

// NewRunner creates a new oasis CLI runner.
func NewRunner(cliPath, workDir, cacheDir string) (*Runner, error) {
	// Ensure the oasis CLI path exists and is executable.
	if _, err := os.Stat(cliPath); err != nil {
		return nil, fmt.Errorf("oasis CLI path does not exist: %w", err)
	}

	// Try running the oasis CLI to ensure it's working.
	cmd := exec.CommandContext(context.Background(), cliPath, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("oasis CLI is not working: %w", err)
	}

	return &Runner{
		cliPath:  cliPath,
		workDir:  workDir,
		cacheDir: cacheDir,
		version:  string(out),
	}, nil
}
