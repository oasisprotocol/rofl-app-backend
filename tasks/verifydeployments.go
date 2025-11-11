// Package tasks implements the asynq task types.
package tasks

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hibiken/asynq"
)

const (
	// VerifyDeploymentsTask is the name of the verify deployments task.
	VerifyDeploymentsTask = "rofl:verify_deployments"

	// VerifyDeploymentsQueue is the queue used for verifying deployments.
	VerifyDeploymentsQueue = "rofl_verify_deployments"
)

// VerifyDeploymentsOptions returns the default options for the verify deployments task.
func VerifyDeploymentsOptions() []asynq.Option {
	return []asynq.Option{
		// Task should complete within 15 minutes and stay unique for the same duration.
		asynq.Timeout(15 * time.Minute),
		asynq.Unique(15 * time.Minute),

		// Task shouldn't be retried if it fails.
		asynq.MaxRetry(0),

		// Enqueue the task in the verify deployments queue.
		asynq.Queue(VerifyDeploymentsQueue),

		// Retain the task results for 1 hour in redis.
		asynq.Retention(1 * time.Hour),
	}
}

// VerifyDeploymentsPayload is the payload of the verify deployments task.
type VerifyDeploymentsPayload struct {
	// UserAddress is the address of the user who requested the verification.
	UserAddress string `json:"user_address"`

	// RepositoryURL is the GitHub repository containing the ROFL deployment.
	RepositoryURL string `json:"repository_url"`
	// Ref is the git ref (branch, tag, or commit) to check out prior to verification.
	Ref string `json:"ref"`
	// DeploymentName is the deployment to verify.
	DeploymentName string `json:"deployment_name"`
}

// VerifyDeploymentsResult are the results of the verify deployments task.
type VerifyDeploymentsResult struct {
	Verified  bool   `json:"verified"`
	CommitSHA string `json:"commit_sha"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	Err       string `json:"err"`
}

// VerifyDeploymentsResultsKey is the redis key for the results of the verify deployments task.
func VerifyDeploymentsResultsKey(address, taskID string) string {
	return fmt.Sprintf("rofl:verify_deployments:%s:%s:results", strings.ToLower(address), taskID)
}

// NewVerifyDeploymentsTask creates a new verify deployments task.
func NewVerifyDeploymentsTask(userAddress, repoURL, ref, deploymentName string) (*asynq.Task, error) {
	payload, err := json.Marshal(VerifyDeploymentsPayload{
		UserAddress:    userAddress,
		RepositoryURL:  repoURL,
		Ref:            ref,
		DeploymentName: deploymentName,
	})
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(VerifyDeploymentsTask, payload), nil
}
