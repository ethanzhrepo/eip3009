package eip3009

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestEncodeAndDecodeTransferWithAuthorizationCalldata(t *testing.T) {
	msg := SignedAuthorization{
		Domain: Domain{
			Name:              "USD Coin",
			Version:           "2",
			ChainID:           big.NewInt(1),
			VerifyingContract: common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
		},
		Authorization: Authorization{
			Kind:        TransferAuthorization,
			From:        common.HexToAddress("0x1111111111111111111111111111111111111111"),
			To:          common.HexToAddress("0x2222222222222222222222222222222222222222"),
			Value:       big.NewInt(1000000),
			ValidAfter:  0,
			ValidBefore: 1740000000,
			Nonce:       common.HexToHash("0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"),
		},
		Signature: &Signature{
			V: 27,
			R: common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
			S: common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222"),
		},
	}

	data, err := EncodeExecuteCalldata(msg)
	if err != nil {
		t.Fatalf("EncodeExecuteCalldata returned error: %v", err)
	}
	got, err := DecodeExecuteCalldata(data)
	if err != nil {
		t.Fatalf("DecodeExecuteCalldata returned error: %v", err)
	}
	if got.Authorization.Kind != TransferAuthorization {
		t.Fatalf("kind = %s, want transfer", got.Authorization.Kind)
	}
	if got.Authorization.Nonce != msg.Authorization.Nonce {
		t.Fatalf("nonce = %s, want %s", got.Authorization.Nonce.Hex(), msg.Authorization.Nonce.Hex())
	}
	if got.Signature == nil || got.Signature.V != 27 {
		t.Fatalf("signature = %+v", got.Signature)
	}
}
