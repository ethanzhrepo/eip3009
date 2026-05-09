package eip3009

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestParseMessageJSONReadsUnsignedEIP712TypedData(t *testing.T) {
	input := []byte(`{
		"primaryType": "TransferWithAuthorization",
		"domain": {
			"name": "USD Coin",
			"version": "2",
			"chainId": 1,
			"verifyingContract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
		},
		"message": {
			"from": "0x1111111111111111111111111111111111111111",
			"to": "0x2222222222222222222222222222222222222222",
			"value": "1000000",
			"validAfter": 0,
			"validBefore": 1740000000,
			"nonce": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
		}
	}`)

	got, err := ParseMessageJSON(input)
	if err != nil {
		t.Fatalf("ParseMessageJSON returned error: %v", err)
	}
	if got.Authorization.Kind != TransferAuthorization {
		t.Fatalf("kind = %s, want transfer", got.Authorization.Kind)
	}
	if got.Authorization.Nonce != common.HexToHash("0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd") {
		t.Fatalf("nonce = %s", got.Authorization.Nonce.Hex())
	}
	if got.Authorization.Value.Cmp(big.NewInt(1000000)) != 0 {
		t.Fatalf("value = %s, want 1000000", got.Authorization.Value.String())
	}
	if got.Domain.Name != "USD Coin" || got.Domain.Version != "2" || got.Domain.ChainID.String() != "1" {
		t.Fatalf("domain = %+v", got.Domain)
	}
}

func TestParseMessageJSONReadsSignedWrapperAndSignature(t *testing.T) {
	input := []byte(`{
		"authorizationType": "transferWithAuthorization",
		"domain": {
			"name": "USD Coin",
			"version": "2",
			"chainId": "1",
			"verifyingContract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
		},
		"message": {
			"from": "0x1111111111111111111111111111111111111111",
			"to": "0x2222222222222222222222222222222222222222",
			"value": "1000000",
			"validAfter": "0",
			"validBefore": "1740000000",
			"nonce": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
		},
		"signature": {
			"v": 27,
			"r": "0x1111111111111111111111111111111111111111111111111111111111111111",
			"s": "0x2222222222222222222222222222222222222222222222222222222222222222"
		}
	}`)

	got, err := ParseMessageJSON(input)
	if err != nil {
		t.Fatalf("ParseMessageJSON returned error: %v", err)
	}
	if got.Signature == nil {
		t.Fatal("signature is nil")
	}
	if got.Signature.V != 27 {
		t.Fatalf("v = %d, want 27", got.Signature.V)
	}
	if got.Signature.R.Hex() != "0x1111111111111111111111111111111111111111111111111111111111111111" {
		t.Fatalf("r = %s", got.Signature.R.Hex())
	}
}
