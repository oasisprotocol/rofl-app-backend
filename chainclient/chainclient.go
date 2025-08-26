// Package chainclient provides a client for connecting to the Oasis Sapphire ParaTime.
package chainclient

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/config"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/connection"
)

// SupportedChainIDs maps supported Oasis Chain IDs and their network names.
var SupportedChainIDs = map[int]string{
	0x5aff: "testnet",
	0x5afe: "mainnet",
}

// New creates a new connection to the specified network and returns a RuntimeClient.
func New(ctx context.Context, chainId int) (*connection.RuntimeClient, error) {
	network, ok := SupportedChainIDs[chainId]
	if !ok {
		return nil, fmt.Errorf("unsupported chain ID: %d", chainId)
	}

	cfg, ok := config.DefaultNetworks.All[network]
	if !ok {
		return nil, fmt.Errorf("unknown network: %s", network)
	}
	if len(cfg.ParaTimes.All) == 0 {
		return nil, fmt.Errorf("no ParaTimes configured for network %s", network)
	}
	sapphire, ok := cfg.ParaTimes.All["sapphire"]
	if !ok {
		return nil, fmt.Errorf("sapphire ParaTime not found in network %s", network)
	}

	conn, err := connection.ConnectNoVerify(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to network %s: %w", network, err)
	}

	client := conn.Runtime(sapphire)
	return &client, nil
}
