// Package tasks implements the asynq task types.
package tasks

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hibiken/asynq"
)

// RoflBuildTask is the name of the rofl build task.
const RoflBuildTask = "rofl:build"

// RoflBuildQueue is the name of the queue for the rofl build task.
const RoflBuildQueue = "rofl_build"

// RoflBuildOptions returns the default options for the rofl build task.
func RoflBuildOptions() []asynq.Option {
	return []asynq.Option{
		// Task should be unique and complete within 10 minutes.
		asynq.Timeout(10 * time.Minute),
		asynq.Unique(10 * time.Minute),

		// Task shouldn't be retried if it fails.
		asynq.MaxRetry(0),

		// Enqueue the task in the rofl build queue.
		asynq.Queue(RoflBuildQueue),

		// Retain the task results for 1 hour in redis.
		// Note that this doesn't affect the Uniqness, a processed task can
		// be re-queued regardless of the retention period.
		asynq.Retention(1 * time.Hour),
	}
}

// RoflBuildPayload is the payload of the rofl build task.
type RoflBuildPayload struct {
	// UserAddress is the address of the user who is building the ROFL app.
	UserAddress string `json:"user_address"`

	// Manifest is the manifest of the ROFL app.
	Manifest []byte `json:"manifest"`
	// Compose is the compose file of the ROFL app.
	Compose []byte `json:"compose"`
}

// RoflBuildResult are the results of the rofl build task.
type RoflBuildResult struct {
	Manifest     []byte `json:"manifest"`
	OciReference string `json:"oci_reference"`
	ManifestHash string `json:"manifest_hash"`

	Logs []byte `json:"logs"`

	Err string `json:"err"`
}

// RoflBuildResultsKey is the redis key for the results of the rofl build task.
func RoflBuildResultsKey(address, taskID string) string {
	return fmt.Sprintf("rofl:build:%s:%s:results", strings.ToLower(address), taskID)
}

// NewRoflBuildTask creates a new rofl build task.
func NewRoflBuildTask(userAddress string, manifest, compose []byte) (*asynq.Task, error) {
	payload, err := json.Marshal(RoflBuildPayload{
		UserAddress: userAddress,
		Manifest:    manifest,
		Compose:     compose,
	})
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(RoflBuildTask, payload), nil
}
