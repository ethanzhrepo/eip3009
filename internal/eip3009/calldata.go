package eip3009

import (
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

const eip3009ABIJSON = `[
	{
		"name": "transferWithAuthorization",
		"type": "function",
		"inputs": [
			{"name":"from","type":"address"},
			{"name":"to","type":"address"},
			{"name":"value","type":"uint256"},
			{"name":"validAfter","type":"uint256"},
			{"name":"validBefore","type":"uint256"},
			{"name":"nonce","type":"bytes32"},
			{"name":"v","type":"uint8"},
			{"name":"r","type":"bytes32"},
			{"name":"s","type":"bytes32"}
		],
		"outputs": []
	},
	{
		"name": "receiveWithAuthorization",
		"type": "function",
		"inputs": [
			{"name":"from","type":"address"},
			{"name":"to","type":"address"},
			{"name":"value","type":"uint256"},
			{"name":"validAfter","type":"uint256"},
			{"name":"validBefore","type":"uint256"},
			{"name":"nonce","type":"bytes32"},
			{"name":"v","type":"uint8"},
			{"name":"r","type":"bytes32"},
			{"name":"s","type":"bytes32"}
		],
		"outputs": []
	},
	{
		"name": "cancelAuthorization",
		"type": "function",
		"inputs": [
			{"name":"authorizer","type":"address"},
			{"name":"nonce","type":"bytes32"},
			{"name":"v","type":"uint8"},
			{"name":"r","type":"bytes32"},
			{"name":"s","type":"bytes32"}
		],
		"outputs": []
	},
	{
		"name": "authorizationState",
		"type": "function",
		"stateMutability": "view",
		"inputs": [
			{"name":"authorizer","type":"address"},
			{"name":"nonce","type":"bytes32"}
		],
		"outputs": [
			{"name":"","type":"bool"}
		]
	},
	{
		"name": "TRANSFER_WITH_AUTHORIZATION_TYPEHASH",
		"type": "function",
		"stateMutability": "view",
		"inputs": [],
		"outputs": [
			{"name":"","type":"bytes32"}
		]
	},
	{
		"name": "RECEIVE_WITH_AUTHORIZATION_TYPEHASH",
		"type": "function",
		"stateMutability": "view",
		"inputs": [],
		"outputs": [
			{"name":"","type":"bytes32"}
		]
	},
	{
		"name": "CANCEL_AUTHORIZATION_TYPEHASH",
		"type": "function",
		"stateMutability": "view",
		"inputs": [],
		"outputs": [
			{"name":"","type":"bytes32"}
		]
	}
]`

var EIP3009ABI = mustParseABI(eip3009ABIJSON)

func EncodeExecuteCalldata(signed SignedAuthorization) ([]byte, error) {
	if signed.Signature == nil {
		return nil, errors.New("signature is required")
	}
	switch signed.Authorization.Kind {
	case TransferAuthorization, ReceiveAuthorization:
		return EIP3009ABI.Pack(
			string(signed.Authorization.Kind),
			signed.Authorization.From,
			signed.Authorization.To,
			signed.Authorization.Value,
			new(big.Int).SetUint64(signed.Authorization.ValidAfter),
			new(big.Int).SetUint64(signed.Authorization.ValidBefore),
			signed.Authorization.Nonce,
			signed.Signature.V,
			signed.Signature.R,
			signed.Signature.S,
		)
	case CancelAuthorization:
		return EIP3009ABI.Pack(
			string(CancelAuthorization),
			signed.Authorization.Authorizer,
			signed.Authorization.Nonce,
			signed.Signature.V,
			signed.Signature.R,
			signed.Signature.S,
		)
	default:
		return nil, fmt.Errorf("unsupported authorization type %q", signed.Authorization.Kind)
	}
}

func DecodeExecuteCalldata(data []byte) (*SignedAuthorization, error) {
	if len(data) < 4 {
		return nil, errors.New("calldata is shorter than 4-byte selector")
	}
	method, err := EIP3009ABI.MethodById(data[:4])
	if err != nil {
		return nil, err
	}
	values, err := method.Inputs.Unpack(data[4:])
	if err != nil {
		return nil, err
	}
	switch method.Name {
	case string(TransferAuthorization), string(ReceiveAuthorization):
		if len(values) != 9 {
			return nil, fmt.Errorf("%s decoded %d inputs, want 9", method.Name, len(values))
		}
		value, ok := values[2].(*big.Int)
		if !ok {
			return nil, fmt.Errorf("value decoded as %T", values[2])
		}
		validAfter, err := bigToUint64(values[3])
		if err != nil {
			return nil, fmt.Errorf("validAfter: %w", err)
		}
		validBefore, err := bigToUint64(values[4])
		if err != nil {
			return nil, fmt.Errorf("validBefore: %w", err)
		}
		return &SignedAuthorization{
			Authorization: Authorization{
				Kind:        AuthorizationKind(method.Name),
				From:        values[0].(common.Address),
				To:          values[1].(common.Address),
				Value:       value,
				ValidAfter:  validAfter,
				ValidBefore: validBefore,
				Nonce:       bytes32ToHash(values[5]),
			},
			Signature: &Signature{
				V: values[6].(uint8),
				R: bytes32ToHash(values[7]),
				S: bytes32ToHash(values[8]),
			},
		}, nil
	case string(CancelAuthorization):
		if len(values) != 5 {
			return nil, fmt.Errorf("%s decoded %d inputs, want 5", method.Name, len(values))
		}
		return &SignedAuthorization{
			Authorization: Authorization{
				Kind:       CancelAuthorization,
				Authorizer: values[0].(common.Address),
				Nonce:      bytes32ToHash(values[1]),
			},
			Signature: &Signature{
				V: values[2].(uint8),
				R: bytes32ToHash(values[3]),
				S: bytes32ToHash(values[4]),
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported method %s", method.Name)
	}
}

func mustParseABI(definition string) abi.ABI {
	parsed, err := abi.JSON(strings.NewReader(definition))
	if err != nil {
		panic(err)
	}
	return parsed
}

func bytes32ToHash(value any) common.Hash {
	switch v := value.(type) {
	case common.Hash:
		return v
	case [32]byte:
		return common.BytesToHash(v[:])
	default:
		return common.Hash{}
	}
}

func bigToUint64(value any) (uint64, error) {
	intValue, ok := value.(*big.Int)
	if !ok {
		return 0, fmt.Errorf("decoded as %T", value)
	}
	if !intValue.IsUint64() {
		return 0, fmt.Errorf("%s overflows uint64", intValue.String())
	}
	return intValue.Uint64(), nil
}
