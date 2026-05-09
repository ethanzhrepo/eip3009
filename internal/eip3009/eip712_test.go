package eip3009

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestEIP3009TypeHashesMatchSpec(t *testing.T) {
	cases := []struct {
		name string
		got  common.Hash
		want string
	}{
		{
			name: "transfer",
			got:  TransferWithAuthorizationTypeHash,
			want: "0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267",
		},
		{
			name: "receive",
			got:  ReceiveWithAuthorizationTypeHash,
			want: "0xd099cc98ef71107a616c4f0f941f04c322d8e254fe26b3c6668db87aae413de8",
		},
		{
			name: "cancel",
			got:  CancelAuthorizationTypeHash,
			want: "0x158b0a9edf7a828aad02f63cd515c68ef2f50ba807396f6d12842833a1597429",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got.Hex() != tc.want {
				t.Fatalf("type hash = %s, want %s", tc.got.Hex(), tc.want)
			}
		})
	}
}

func TestSignAndRecoverTransferAuthorization(t *testing.T) {
	privateKey, err := crypto.HexToECDSA("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("HexToECDSA returned error: %v", err)
	}
	from := crypto.PubkeyToAddress(privateKey.PublicKey)
	auth := Authorization{
		Kind:        TransferAuthorization,
		From:        from,
		To:          common.HexToAddress("0x2222222222222222222222222222222222222222"),
		Value:       big.NewInt(1000000),
		ValidAfter:  0,
		ValidBefore: 1740000000,
		Nonce:       common.HexToHash("0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"),
	}
	domain := Domain{
		Name:              "USD Coin",
		Version:           "2",
		ChainID:           big.NewInt(1),
		VerifyingContract: common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
	}

	signed, err := SignAuthorization(domain, auth, privateKey)
	if err != nil {
		t.Fatalf("SignAuthorization returned error: %v", err)
	}
	if signed.Signature.V != 27 && signed.Signature.V != 28 {
		t.Fatalf("v = %d, want 27 or 28", signed.Signature.V)
	}

	recovered, err := RecoverAuthorizationSigner(signed)
	if err != nil {
		t.Fatalf("RecoverAuthorizationSigner returned error: %v", err)
	}
	if recovered != from {
		t.Fatalf("recovered = %s, want %s", recovered.Hex(), from.Hex())
	}
}

func TestNormalizeSignatureVForSolidityDoesNotChangeRecoveredSigner(t *testing.T) {
	privateKey, err := crypto.HexToECDSA("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("HexToECDSA returned error: %v", err)
	}
	from := crypto.PubkeyToAddress(privateKey.PublicKey)
	auth := Authorization{
		Kind:        TransferAuthorization,
		From:        from,
		To:          common.HexToAddress("0x2222222222222222222222222222222222222222"),
		Value:       big.NewInt(1000000),
		ValidAfter:  0,
		ValidBefore: 1740000000,
		Nonce:       common.HexToHash("0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"),
	}
	domain := Domain{
		Name:              "USD Coin",
		Version:           "2",
		ChainID:           big.NewInt(1),
		VerifyingContract: common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
	}
	signed, err := SignAuthorization(domain, auth, privateKey)
	if err != nil {
		t.Fatalf("SignAuthorization returned error: %v", err)
	}

	signed.Signature.V -= 27
	recoveredBefore, err := RecoverAuthorizationSigner(signed)
	if err != nil {
		t.Fatalf("RecoverAuthorizationSigner before normalize returned error: %v", err)
	}
	changed, err := NormalizeSignatureVForSolidity(signed.Signature)
	if err != nil {
		t.Fatalf("NormalizeSignatureVForSolidity returned error: %v", err)
	}
	recoveredAfter, err := RecoverAuthorizationSigner(signed)
	if err != nil {
		t.Fatalf("RecoverAuthorizationSigner after normalize returned error: %v", err)
	}

	if !changed {
		t.Fatal("NormalizeSignatureVForSolidity changed = false, want true")
	}
	if signed.Signature.V != 27 && signed.Signature.V != 28 {
		t.Fatalf("normalized v = %d, want 27 or 28", signed.Signature.V)
	}
	if recoveredBefore != from || recoveredAfter != from {
		t.Fatalf("recovered before/after = %s/%s, want %s", recoveredBefore.Hex(), recoveredAfter.Hex(), from.Hex())
	}
}
