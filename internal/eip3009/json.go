package eip3009

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

func TypedDataObject(signed SignedAuthorization) (map[string]any, error) {
	primaryType, err := signed.Authorization.Kind.PrimaryType()
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"types":       typedDataTypes(signed.Authorization.Kind),
		"primaryType": primaryType,
		"domain":      domainObject(signed.Domain),
		"message":     messageObject(signed.Authorization),
	}, nil
}

func SignedAuthorizationObject(signed SignedAuthorization, signatureValid *bool) (map[string]any, error) {
	typedData, err := TypedDataObject(signed)
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"authorizationType": string(signed.Authorization.Kind),
		"domain":            domainObject(signed.Domain),
		"message":           messageObject(signed.Authorization),
		"typedData":         typedData,
	}
	if signed.Signature != nil {
		out["signature"] = signatureObject(*signed.Signature)
	}
	if signatureValid != nil {
		out["signatureValid"] = *signatureValid
	}
	return out, nil
}

func ExtractionObject(signed SignedAuthorization, decimals *uint8, symbol string, signatureValid *bool) (map[string]any, error) {
	out, err := SignedAuthorizationObject(signed, signatureValid)
	if err != nil {
		return nil, err
	}
	msg, _ := out["message"].(map[string]any)
	if signed.Authorization.Value != nil {
		msg["valueRaw"] = signed.Authorization.Value.String()
		if decimals != nil {
			formatted := FormatTokenValue(signed.Authorization.Value, *decimals)
			msg["valueFormatted"] = formatted
			if symbol != "" {
				msg["amount"] = fmt.Sprintf("%s %s", formatted, symbol)
			}
		}
	}
	if decimals != nil || symbol != "" {
		meta := map[string]any{}
		if decimals != nil {
			meta["decimals"] = *decimals
		}
		if symbol != "" {
			meta["symbol"] = symbol
		}
		out["tokenMetadata"] = meta
	}
	return out, nil
}

func typedDataTypes(kind AuthorizationKind) map[string]any {
	types := map[string]any{
		"EIP712Domain": []map[string]string{
			{"name": "name", "type": "string"},
			{"name": "version", "type": "string"},
			{"name": "chainId", "type": "uint256"},
			{"name": "verifyingContract", "type": "address"},
		},
	}
	switch kind {
	case CancelAuthorization:
		types["CancelAuthorization"] = []map[string]string{
			{"name": "authorizer", "type": "address"},
			{"name": "nonce", "type": "bytes32"},
		}
	case ReceiveAuthorization:
		types["ReceiveWithAuthorization"] = transferFields()
	default:
		types["TransferWithAuthorization"] = transferFields()
	}
	return types
}

func transferFields() []map[string]string {
	return []map[string]string{
		{"name": "from", "type": "address"},
		{"name": "to", "type": "address"},
		{"name": "value", "type": "uint256"},
		{"name": "validAfter", "type": "uint256"},
		{"name": "validBefore", "type": "uint256"},
		{"name": "nonce", "type": "bytes32"},
	}
}

func domainObject(domain Domain) map[string]any {
	chainID := "0"
	if domain.ChainID != nil {
		chainID = domain.ChainID.String()
	}
	return map[string]any{
		"name":              domain.Name,
		"version":           domain.Version,
		"chainId":           chainID,
		"verifyingContract": domain.VerifyingContract.Hex(),
	}
}

func messageObject(auth Authorization) map[string]any {
	if auth.Kind == CancelAuthorization {
		return map[string]any{
			"authorizer": auth.Authorizer.Hex(),
			"nonce":      auth.Nonce.Hex(),
		}
	}
	value := "0"
	if auth.Value != nil {
		value = auth.Value.String()
	}
	return map[string]any{
		"from":        auth.From.Hex(),
		"to":          auth.To.Hex(),
		"value":       value,
		"validAfter":  new(big.Int).SetUint64(auth.ValidAfter).String(),
		"validBefore": new(big.Int).SetUint64(auth.ValidBefore).String(),
		"nonce":       auth.Nonce.Hex(),
	}
}

func signatureObject(sig Signature) map[string]any {
	return map[string]any{
		"v":         sig.V,
		"r":         sig.R.Hex(),
		"s":         sig.S.Hex(),
		"signature": "0x" + hex.EncodeToString(SignatureBytes(sig)),
	}
}

func SignatureBytes(sig Signature) []byte {
	out := make([]byte, 65)
	copy(out[0:32], sig.R.Bytes())
	copy(out[32:64], sig.S.Bytes())
	out[64] = sig.V
	return out
}

func ParseAddressValue(value string) (common.Address, error) {
	return parseAddress(mustRawString(value))
}

func ParseHashValue(value string) (common.Hash, error) {
	return parseHash(mustRawString(value))
}

func ParseBigIntValue(value string) (*big.Int, error) {
	return parseBigInt(mustRawString(value))
}

func ParseUint64Value(value string) (uint64, error) {
	return parseUint64(mustRawString(value))
}

func mustRawString(value string) []byte {
	return []byte(fmt.Sprintf("%q", value))
}
