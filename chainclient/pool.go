package chainclient

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/connection"
)

// Pool manages long-lived connections to supported chains.
type Pool struct {
	mu          sync.RWMutex
	connections map[int]*connection.RuntimeClient
	logger      *slog.Logger
}

// NewPool creates and initializes a new connection pool.
func NewPool(ctx context.Context, logger *slog.Logger) (*Pool, error) {
	pool := &Pool{
		connections: make(map[int]*connection.RuntimeClient),
		logger:      logger,
	}

	for chainID := range SupportedChainIDs {
		client, err := New(ctx, chainID)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize connection for chain %d: %w", chainID, err)
		}
		pool.connections[chainID] = client
		logger.Debug("initialized chain connection", "chain_id", chainID)
	}

	return pool, nil
}

// Get returns a connection for the specified chain ID.
func (p *Pool) Get(chainID int) (*connection.RuntimeClient, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	client, ok := p.connections[chainID]
	if !ok {
		return nil, fmt.Errorf("unsupported chain ID: %d", chainID)
	}
	return client, nil
}

// GetWithRetry returns a connection for the specified chain ID, with automatic retry on failure.
// The callback function should perform the operation using the client. If it returns an error,
// the connection will be recreated once and the callback retried.
func (p *Pool) GetWithRetry(ctx context.Context, chainID int, callback func(*connection.RuntimeClient) error) error {
	client, err := p.Get(chainID)
	if err != nil {
		return err
	}

	// Try the operation with the current connection.
	if err := callback(client); err == nil {
		return nil
	}

	p.logger.Debug("operation failed, recreating chain connection", "chain_id", chainID, "error", err)

	// Recreate the connection.
	if err := p.recreate(ctx, chainID); err != nil {
		return fmt.Errorf("failed to recreate connection: %w", err)
	}

	// Get the new connection and retry.
	client, err = p.Get(chainID)
	if err != nil {
		return err
	}

	return callback(client)
}

// recreate recreates the connection for the specified chain ID.
func (p *Pool) recreate(ctx context.Context, chainID int) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	client, err := New(ctx, chainID)
	if err != nil {
		return fmt.Errorf("failed to recreate connection for chain %d: %w", chainID, err)
	}

	p.connections[chainID] = client
	p.logger.Debug("recreated chain connection", "chain_id", chainID)
	return nil
}
