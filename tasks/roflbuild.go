// Package tasks implements the asynq task types.
package tasks

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hibiken/asynq"
)

// RoflBuildTask is the name of the rofl build task.
const RoflBuildTask = "rofl:build"

// RoflBuildQueue is the name of the queue for the rofl build task.
const RoflBuildQueue = "rofl_build"

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
