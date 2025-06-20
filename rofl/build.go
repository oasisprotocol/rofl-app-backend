// Package rofl implements the ROFL build task.
package rofl

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hibiken/asynq"
)

// TypeBuildTask is the type of the build task.
const TypeBuildTask = "rofl:build"

// QueueName is the name of the queue for the build task.
const QueueName = "rofl_build"

// BuildTaskPayload is the payload of the build task.
type BuildTaskPayload struct {
	// UserAddress is the address of the user who is building the ROFL app.
	UserAddress string `json:"user_address"`

	// Manifest is the manifest of the ROFL app.
	Manifest []byte `json:"manifest"`
	// Compose is the compose file of the ROFL app.
	Compose []byte `json:"compose"`
}

// BuildTaskResult are the results of the build task.
type BuildTaskResult struct {
	Manifest     []byte `json:"manifest"`
	OciReference string `json:"oci_reference"`
	ManifestHash string `json:"manifest_hash"`

	Logs []byte `json:"logs"`

	Err string `json:"err"`
}

// TaskResultsKey is the redis key for the results of the build task.
func TaskResultsKey(address, taskID string) string {
	return fmt.Sprintf("rofl:build:%s:%s:results", strings.ToLower(address), taskID)
}

// NewBuildTask creates a new build task.
func NewBuildTask(userAddress string, manifest, compose []byte) (*asynq.Task, error) {
	payload, err := json.Marshal(BuildTaskPayload{
		UserAddress: userAddress,
		Manifest:    manifest,
		Compose:     compose,
	})
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(TypeBuildTask, payload), nil
}
