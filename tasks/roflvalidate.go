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
	// RoflValidateTask is the name of the rofl validate task.
	RoflValidateTask = "rofl:validate"

	// RoflValidateQueue is the name of the queue for the rofl validate task.
	RoflValidateQueue = "rofl_validate"
)

// RoflValidateOptions returns the default options for the rofl validate task.
func RoflValidateOptions() []asynq.Option {
	return []asynq.Option{
		// Validation should complete within 20 seconds.
		asynq.Timeout(20 * time.Second),
		asynq.Unique(20 * time.Second),

		// Task shouldn't be retried if it fails.
		asynq.MaxRetry(0),

		// Enqueue the task in the rofl validate queue.
		asynq.Queue(RoflValidateQueue),
	}
}

// RoflValidatePayload is the payload of the rofl validate task.
type RoflValidatePayload struct {
	// UserAddress is the address of the user who is validating the ROFL app.
	UserAddress string `json:"user_address"`

	// Manifest is the manifest of the ROFL app.
	Manifest []byte `json:"manifest"`
	// Compose is the compose file of the ROFL app.
	Compose []byte `json:"compose"`
}

// RoflValidateResult are the results of the rofl validate task.
type RoflValidateResult struct {
	Valid  bool   `json:"valid"`
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
	Err    string `json:"err"`
}

// RoflValidateResultsKey is the redis key for the results of the rofl validate task.
func RoflValidateResultsKey(address, taskID string) string {
	return fmt.Sprintf("rofl:validate:%s:%s:results", strings.ToLower(address), taskID)
}

// NewRoflValidateTask creates a new rofl validate task.
func NewRoflValidateTask(userAddress string, manifest, compose []byte) (*asynq.Task, error) {
	payload, err := json.Marshal(RoflValidatePayload{
		UserAddress: userAddress,
		Manifest:    manifest,
		Compose:     compose,
	})
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(RoflValidateTask, payload), nil
}
