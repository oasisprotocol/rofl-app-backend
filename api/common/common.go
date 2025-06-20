// Package common provides common utilities for the API.
package common

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
)

// DecodeJSON decodes the request body into the given type.
func DecodeJSON[T any](r *http.Request) (T, error) {
	var t T

	if r.Header.Get("Content-Type") != "application/json" {
		return t, fmt.Errorf("expected application/json")
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return t, err
	}
	if dec.More() {
		return t, fmt.Errorf("unexpected extra JSON input")
	}
	return t, nil
}

// WriteError writes an error response to the response writer.
func WriteError(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, map[string]string{"error": msg})
}

// WriteJSON writes a JSON response to the response writer.
func WriteJSON[T any](w http.ResponseWriter, status int, v T) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("failed to write JSON", "error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}
