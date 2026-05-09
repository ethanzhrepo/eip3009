package eip3009

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	abiAddress, _ = abi.NewType("address", "", nil)
	abiUint256, _ = abi.NewType("uint256", "", nil)
	abiBytes32, _ = abi.NewType("bytes32", "", nil)
)

func DomainSeparator(domain Domain) (common.Hash, error) {
	if err := validateDomain(domain); err != nil {
		return common.Hash{}, err
	}
	args := abi.Arguments{
		{Type: abiBytes32},
		{Type: abiBytes32},
		{Type: abiBytes32},
		{Type: abiUint256},
		{Type: abiAddress},
	}
	packed, err := args.Pack(
		eip712DomainTypeHash,
		crypto.Keccak256Hash([]byte(domain.Name)),
		crypto.Keccak256Hash([]byte(domain.Version)),
		domain.ChainID,
		domain.VerifyingContract,
	)
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(packed), nil
}

func AuthorizationStructHash(auth Authorization) (common.Hash, error) {
	if err := validateAuthorization(auth); err != nil {
		return common.Hash{}, err
	}
	typeHash, err := auth.Kind.TypeHash()
	if err != nil {
		return common.Hash{}, err
	}
	if auth.Kind == CancelAuthorization {
		args := abi.Arguments{
			{Type: abiBytes32},
			{Type: abiAddress},
			{Type: abiBytes32},
		}
		packed, err := args.Pack(typeHash, auth.Authorizer, auth.Nonce)
		if err != nil {
			return common.Hash{}, err
		}
		return crypto.Keccak256Hash(packed), nil
	}

	args := abi.Arguments{
		{Type: abiBytes32},
		{Type: abiAddress},
		{Type: abiAddress},
		{Type: abiUint256},
		{Type: abiUint256},
		{Type: abiUint256},
		{Type: abiBytes32},
	}
	packed, err := args.Pack(
		typeHash,
		auth.From,
		auth.To,
		auth.Value,
		new(big.Int).SetUint64(auth.ValidAfter),
		new(big.Int).SetUint64(auth.ValidBefore),
		auth.Nonce,
	)
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(packed), nil
}

func TypedDataHash(domain Domain, auth Authorization) (common.Hash, error) {
	domainSeparator, err := DomainSeparator(domain)
	if err != nil {
		return common.Hash{}, err
	}
	structHash, err := AuthorizationStructHash(auth)
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash([]byte{0x19, 0x01}, domainSeparator.Bytes(), structHash.Bytes()), nil
}

func VerifySignedAuthorization(signed *SignedAuthorization) error {
	recovered, err := RecoverAuthorizationSigner(signed)
	if err != nil {
		return err
	}
	want, err := signed.Authorization.signerAddress()
	if err != nil {
		return err
	}
	if recovered != want {
		return fmt.Errorf("signature recovers %s, want %s", recovered.Hex(), want.Hex())
	}
	return nil
}
