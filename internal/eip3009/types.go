package eip3009

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type AuthorizationKind string

const (
	TransferAuthorization AuthorizationKind = "transferWithAuthorization"
	ReceiveAuthorization  AuthorizationKind = "receiveWithAuthorization"
	CancelAuthorization   AuthorizationKind = "cancelAuthorization"
)

var (
	TransferWithAuthorizationTypeHash = crypto.Keccak256Hash([]byte("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"))
	ReceiveWithAuthorizationTypeHash  = crypto.Keccak256Hash([]byte("ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"))
	CancelAuthorizationTypeHash       = crypto.Keccak256Hash([]byte("CancelAuthorization(address authorizer,bytes32 nonce)"))
	eip712DomainTypeHash              = crypto.Keccak256Hash([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"))
)

type Domain struct {
	Name              string
	Version           string
	ChainID           *big.Int
	VerifyingContract common.Address
}

type Authorization struct {
	Kind        AuthorizationKind
	From        common.Address
	To          common.Address
	Value       *big.Int
	ValidAfter  uint64
	ValidBefore uint64
	Nonce       common.Hash
	Authorizer  common.Address
}

type Signature struct {
	V uint8
	R common.Hash
	S common.Hash
}

type SignedAuthorization struct {
	Authorization Authorization
	Domain        Domain
	Signature     *Signature
}

func NormalizeSignatureVForSolidity(signature *Signature) (bool, error) {
	if signature == nil {
		return false, errors.New("signature is required")
	}
	switch signature.V {
	case 0, 1:
		signature.V += 27
		return true, nil
	case 27, 28:
		return false, nil
	default:
		return false, fmt.Errorf("invalid v %d", signature.V)
	}
}

func NormalizeAuthorizationKind(value string) (AuthorizationKind, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "transfer", "transferwithauthorization", "transfer_with_authorization":
		return TransferAuthorization, nil
	case "receive", "receivewithauthorization", "receive_with_authorization":
		return ReceiveAuthorization, nil
	case "cancel", "cancelauthorization", "cancel_authorization":
		return CancelAuthorization, nil
	default:
		return "", fmt.Errorf("unsupported authorization type %q", value)
	}
}

func (k AuthorizationKind) PrimaryType() (string, error) {
	switch k {
	case TransferAuthorization:
		return "TransferWithAuthorization", nil
	case ReceiveAuthorization:
		return "ReceiveWithAuthorization", nil
	case CancelAuthorization:
		return "CancelAuthorization", nil
	default:
		return "", fmt.Errorf("unsupported authorization type %q", k)
	}
}

func (k AuthorizationKind) TypeHash() (common.Hash, error) {
	switch k {
	case TransferAuthorization:
		return TransferWithAuthorizationTypeHash, nil
	case ReceiveAuthorization:
		return ReceiveWithAuthorizationTypeHash, nil
	case CancelAuthorization:
		return CancelAuthorizationTypeHash, nil
	default:
		return common.Hash{}, fmt.Errorf("unsupported authorization type %q", k)
	}
}

func (a Authorization) signerAddress() (common.Address, error) {
	switch a.Kind {
	case TransferAuthorization, ReceiveAuthorization:
		if a.From == (common.Address{}) {
			return common.Address{}, errors.New("from address is required")
		}
		return a.From, nil
	case CancelAuthorization:
		if a.Authorizer == (common.Address{}) {
			return common.Address{}, errors.New("authorizer address is required")
		}
		return a.Authorizer, nil
	default:
		return common.Address{}, fmt.Errorf("unsupported authorization type %q", a.Kind)
	}
}

func SignAuthorization(domain Domain, auth Authorization, privateKey *ecdsa.PrivateKey) (*SignedAuthorization, error) {
	if privateKey == nil {
		return nil, errors.New("private key is required")
	}
	if err := validateDomain(domain); err != nil {
		return nil, err
	}
	if err := validateAuthorization(auth); err != nil {
		return nil, err
	}
	hash, err := TypedDataHash(domain, auth)
	if err != nil {
		return nil, err
	}
	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		return nil, err
	}
	return &SignedAuthorization{
		Domain:        domain,
		Authorization: auth,
		Signature: &Signature{
			V: signature[64] + 27,
			R: common.BytesToHash(signature[0:32]),
			S: common.BytesToHash(signature[32:64]),
		},
	}, nil
}

func RecoverAuthorizationSigner(signed *SignedAuthorization) (common.Address, error) {
	if signed == nil {
		return common.Address{}, errors.New("signed authorization is required")
	}
	if signed.Signature == nil {
		return common.Address{}, errors.New("signature is required")
	}
	hash, err := TypedDataHash(signed.Domain, signed.Authorization)
	if err != nil {
		return common.Address{}, err
	}
	sig := make([]byte, 65)
	copy(sig[0:32], signed.Signature.R.Bytes())
	copy(sig[32:64], signed.Signature.S.Bytes())
	switch signed.Signature.V {
	case 27, 28:
		sig[64] = signed.Signature.V - 27
	case 0, 1:
		sig[64] = signed.Signature.V
	default:
		return common.Address{}, fmt.Errorf("invalid v %d", signed.Signature.V)
	}
	pub, err := crypto.SigToPub(hash.Bytes(), sig)
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(*pub), nil
}

func validateDomain(domain Domain) error {
	if domain.Name == "" {
		return errors.New("domain name is required")
	}
	if domain.Version == "" {
		return errors.New("domain version is required")
	}
	if domain.ChainID == nil || domain.ChainID.Sign() <= 0 {
		return errors.New("chain id is required")
	}
	if domain.VerifyingContract == (common.Address{}) {
		return errors.New("token/verifyingContract is required")
	}
	return nil
}

func validateAuthorization(auth Authorization) error {
	switch auth.Kind {
	case TransferAuthorization, ReceiveAuthorization:
		if auth.From == (common.Address{}) {
			return errors.New("from address is required")
		}
		if auth.To == (common.Address{}) {
			return errors.New("to address is required")
		}
		if auth.Value == nil || auth.Value.Sign() < 0 {
			return errors.New("value must be a non-negative integer")
		}
	case CancelAuthorization:
		if auth.Authorizer == (common.Address{}) {
			return errors.New("authorizer address is required")
		}
	default:
		return fmt.Errorf("unsupported authorization type %q", auth.Kind)
	}
	return nil
}
