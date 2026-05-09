package eip3009

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

const erc20MetadataABIJSON = `[
	{"name":"decimals","type":"function","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"uint8"}]},
	{"name":"symbol","type":"function","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"string"}]},
	{"name":"name","type":"function","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"string"}]},
	{"name":"version","type":"function","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"string"}]}
]`

var ERC20MetadataABI = mustParseABI(erc20MetadataABIJSON)

type ContractCaller interface {
	CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
}

type TxClient interface {
	ContractCaller
	ChainID(ctx context.Context) (*big.Int, error)
	PendingNonceAt(ctx context.Context, account common.Address) (uint64, error)
	SuggestGasPrice(ctx context.Context) (*big.Int, error)
	EstimateGas(ctx context.Context, msg ethereum.CallMsg) (uint64, error)
	SendTransaction(ctx context.Context, tx *types.Transaction) error
}

type FeatureCheck struct {
	OK    bool   `json:"ok"`
	Value string `json:"value,omitempty"`
	Error string `json:"error,omitempty"`
}

type SupportReport struct {
	Token                    string       `json:"token"`
	Supported                bool         `json:"supported"`
	AuthorizationState       FeatureCheck `json:"authorizationState"`
	TransferTypeHash         FeatureCheck `json:"transferTypeHash"`
	ReceiveTypeHash          FeatureCheck `json:"receiveTypeHash"`
	CancelAuthorization      FeatureCheck `json:"cancelAuthorization"`
	CancelAuthorizationNotes string       `json:"cancelAuthorizationNotes,omitempty"`
}

func CheckEIP3009Support(ctx context.Context, caller ContractCaller, token common.Address) SupportReport {
	report := SupportReport{Token: token.Hex()}
	report.AuthorizationState = checkAuthorizationState(ctx, caller, token)
	report.TransferTypeHash = checkTypeHash(ctx, caller, token, "TRANSFER_WITH_AUTHORIZATION_TYPEHASH", TransferWithAuthorizationTypeHash)
	report.ReceiveTypeHash = checkTypeHash(ctx, caller, token, "RECEIVE_WITH_AUTHORIZATION_TYPEHASH", ReceiveWithAuthorizationTypeHash)
	report.CancelAuthorization = checkTypeHash(ctx, caller, token, "CANCEL_AUTHORIZATION_TYPEHASH", CancelAuthorizationTypeHash)
	if !report.CancelAuthorization.OK {
		report.CancelAuthorizationNotes = "cancelAuthorization support is needed for emergency nonce cancellation"
	}
	report.Supported = report.AuthorizationState.OK && report.TransferTypeHash.OK && report.ReceiveTypeHash.OK
	return report
}

func TokenDecimals(ctx context.Context, caller ContractCaller, token common.Address) (uint8, error) {
	values, err := callView(ctx, caller, ERC20MetadataABI, token, "decimals")
	if err != nil {
		return 0, err
	}
	decimals, ok := values[0].(uint8)
	if !ok {
		return 0, fmt.Errorf("decimals decoded as %T", values[0])
	}
	return decimals, nil
}

func TokenSymbol(ctx context.Context, caller ContractCaller, token common.Address) (string, error) {
	return tokenString(ctx, caller, token, "symbol")
}

func TokenName(ctx context.Context, caller ContractCaller, token common.Address) (string, error) {
	return tokenString(ctx, caller, token, "name")
}

func TokenVersion(ctx context.Context, caller ContractCaller, token common.Address) (string, error) {
	return tokenString(ctx, caller, token, "version")
}

func BroadcastAuthorization(ctx context.Context, client TxClient, signed SignedAuthorization, privateKey *ecdsa.PrivateKey) (common.Hash, error) {
	if privateKey == nil {
		return common.Hash{}, errors.New("transaction private key is required")
	}
	if signed.Signature == nil {
		return common.Hash{}, errors.New("signed message is missing signature")
	}
	from := crypto.PubkeyToAddress(privateKey.PublicKey)
	if signed.Authorization.Kind == ReceiveAuthorization && from != signed.Authorization.To {
		return common.Hash{}, fmt.Errorf("receiveWithAuthorization must be submitted by recipient %s, tx sender is %s", signed.Authorization.To.Hex(), from.Hex())
	}
	data, err := EncodeExecuteCalldata(signed)
	if err != nil {
		return common.Hash{}, err
	}
	chainID, err := client.ChainID(ctx)
	if err != nil {
		return common.Hash{}, err
	}
	nonce, err := client.PendingNonceAt(ctx, from)
	if err != nil {
		return common.Hash{}, err
	}
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return common.Hash{}, err
	}
	to := signed.Domain.VerifyingContract
	call := ethereum.CallMsg{From: from, To: &to, Data: data}
	gasLimit, err := client.EstimateGas(ctx, call)
	if err != nil {
		return common.Hash{}, err
	}
	gasLimit += gasLimit / 5
	tx := types.NewTransaction(nonce, to, big.NewInt(0), gasLimit, gasPrice, data)
	signedTx, err := types.SignTx(tx, types.LatestSignerForChainID(chainID), privateKey)
	if err != nil {
		return common.Hash{}, err
	}
	if err := client.SendTransaction(ctx, signedTx); err != nil {
		return common.Hash{}, err
	}
	return signedTx.Hash(), nil
}

func checkAuthorizationState(ctx context.Context, caller ContractCaller, token common.Address) FeatureCheck {
	values, err := callView(ctx, caller, EIP3009ABI, token, "authorizationState", common.Address{}, common.Hash{})
	if err != nil {
		return FeatureCheck{OK: false, Error: err.Error()}
	}
	if _, ok := values[0].(bool); !ok {
		return FeatureCheck{OK: false, Error: fmt.Sprintf("decoded as %T", values[0])}
	}
	return FeatureCheck{OK: true}
}

func checkTypeHash(ctx context.Context, caller ContractCaller, token common.Address, method string, want common.Hash) FeatureCheck {
	values, err := callView(ctx, caller, EIP3009ABI, token, method)
	if err != nil {
		return FeatureCheck{OK: false, Error: err.Error()}
	}
	got := bytes32ToHash(values[0])
	if got != want {
		return FeatureCheck{OK: false, Value: got.Hex(), Error: fmt.Sprintf("want %s", want.Hex())}
	}
	return FeatureCheck{OK: true, Value: got.Hex()}
}

func tokenString(ctx context.Context, caller ContractCaller, token common.Address, method string) (string, error) {
	values, err := callView(ctx, caller, ERC20MetadataABI, token, method)
	if err != nil {
		return "", err
	}
	value, ok := values[0].(string)
	if !ok {
		return "", fmt.Errorf("%s decoded as %T", method, values[0])
	}
	return value, nil
}

func callView(ctx context.Context, caller ContractCaller, contractABI abi.ABI, token common.Address, method string, args ...any) ([]any, error) {
	data, err := contractABI.Pack(method, args...)
	if err != nil {
		return nil, err
	}
	out, err := caller.CallContract(ctx, ethereum.CallMsg{To: &token, Data: data}, nil)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("empty return data")
	}
	return contractABI.Unpack(method, out)
}

func IsMethodNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "execution reverted") ||
		strings.Contains(text, "no contract code") ||
		strings.Contains(text, "empty return data")
}
