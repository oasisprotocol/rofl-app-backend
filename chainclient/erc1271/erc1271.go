// Package erc1271 provides utilities for verifying signatures using the ERC-1271 standard.
package erc1271

import (
	"bytes"
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/client"
)

var (
	// keccak256("isValidSignature(bytes32,bytes)")[:4]
	selectorIsValidSignatureBytes32 = [4]byte{0x16, 0x26, 0xba, 0x7e}
	// EIP-1271 magic return value for valid signatures.
	magicValueIsValidSignature = [4]byte{0x16, 0x26, 0xba, 0x7e}
)

// Caller is an interface that defines the methods required for querying calls on EVM.
type Caller interface {
	SimulateCall(ctx context.Context, round uint64, gasPrice []byte, gasLimit uint64,
		caller []byte, address []byte, value []byte, data []byte) ([]byte, error)
}

// CallVerify calls isValidSignature(bytes32,bytes) to verify a signature.
func CallVerify(
	ctx context.Context,
	v Caller,
	contractAddr common.Address,
	hash [32]byte,
	signature []byte,
) error {
	// Prepare the data for the isValidSignature call.
	tHash, err := abi.NewType("bytes32", "", nil)
	if err != nil {
		return fmt.Errorf("new type bytes32: %w", err)
	}
	tBytes, err := abi.NewType("bytes", "", nil)
	if err != nil {
		return fmt.Errorf("new type bytes: %w", err)
	}
	args := abi.Arguments{
		{Type: tHash},
		{Type: tBytes},
	}
	encodedArgs, err := args.Pack(hash, signature)
	if err != nil {
		return fmt.Errorf("pack args: %w", err)
	}
	data := append(selectorIsValidSignatureBytes32[:], encodedArgs...)

	zeroAddr := make([]byte, 20)

	// Call the contract to verify the signature.
	ret, err := v.SimulateCall(
		ctx,
		client.RoundLatest,
		zeroAddr, // gas price.
		64_000,   // gas limit.
		zeroAddr, // caller.
		contractAddr.Bytes(),
		zeroAddr, // amount.
		data,
	)
	if err != nil {
		return fmt.Errorf("erc-1271: simulate call error: %w", err)
	}
	if len(ret) < 4 || !bytes.Equal(ret[:4], magicValueIsValidSignature[:]) {
		return fmt.Errorf("erc-1271: signature verification failed, response: %x", ret[:4])
	}

	// Valid signature.
	return nil
}

// Eip191Hash computes the EIP-191 hash of a given SIWE message.
func Eip191Hash(siweMessage string) common.Hash {
	data := []byte(siweMessage)
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256Hash([]byte(msg))
}
