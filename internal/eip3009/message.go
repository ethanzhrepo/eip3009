package eip3009

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

func ParseMessageJSON(input []byte) (*SignedAuthorization, error) {
	input = bytes.TrimSpace(input)
	if len(input) == 0 {
		return nil, errors.New("message is empty")
	}

	var root map[string]json.RawMessage
	if err := json.Unmarshal(input, &root); err != nil {
		return nil, err
	}
	signature, err := parseSignature(root["signature"])
	if err != nil {
		return nil, err
	}

	if rawTypedData, ok := root["typedData"]; ok {
		var typed map[string]json.RawMessage
		if err := json.Unmarshal(rawTypedData, &typed); err != nil {
			return nil, fmt.Errorf("parse typedData: %w", err)
		}
		root = typed
	}

	kind, err := parseKind(root)
	if err != nil {
		return nil, err
	}
	domain, err := parseDomain(root["domain"])
	if err != nil {
		return nil, err
	}
	auth, err := parseAuthorization(kind, root["message"])
	if err != nil {
		return nil, err
	}
	return &SignedAuthorization{
		Domain:        domain,
		Authorization: auth,
		Signature:     signature,
	}, nil
}

func parseKind(root map[string]json.RawMessage) (AuthorizationKind, error) {
	for _, key := range []string{"authorizationType", "primaryType"} {
		raw, ok := root[key]
		if !ok {
			continue
		}
		text, err := parseStringLike(raw)
		if err != nil {
			return "", err
		}
		return NormalizeAuthorizationKind(text)
	}
	return TransferAuthorization, nil
}

func parseDomain(raw json.RawMessage) (Domain, error) {
	if len(raw) == 0 {
		return Domain{}, errors.New("domain is required")
	}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(raw, &data); err != nil {
		return Domain{}, err
	}
	name, err := parseOptionalString(data["name"])
	if err != nil {
		return Domain{}, fmt.Errorf("parse domain.name: %w", err)
	}
	version, err := parseOptionalString(data["version"])
	if err != nil {
		return Domain{}, fmt.Errorf("parse domain.version: %w", err)
	}
	chainID, err := parseBigInt(data["chainId"])
	if err != nil {
		return Domain{}, fmt.Errorf("parse domain.chainId: %w", err)
	}
	token, err := parseAddress(data["verifyingContract"])
	if err != nil {
		return Domain{}, fmt.Errorf("parse domain.verifyingContract: %w", err)
	}
	return Domain{
		Name:              name,
		Version:           version,
		ChainID:           chainID,
		VerifyingContract: token,
	}, nil
}

func parseAuthorization(kind AuthorizationKind, raw json.RawMessage) (Authorization, error) {
	if len(raw) == 0 {
		return Authorization{}, errors.New("message is required")
	}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(raw, &data); err != nil {
		return Authorization{}, err
	}
	nonce, err := parseHash(data["nonce"])
	if err != nil {
		return Authorization{}, fmt.Errorf("parse message.nonce: %w", err)
	}
	auth := Authorization{Kind: kind, Nonce: nonce}
	if kind == CancelAuthorization {
		authorizer, err := parseAddress(firstRaw(data, "authorizer", "from"))
		if err != nil {
			return Authorization{}, fmt.Errorf("parse message.authorizer: %w", err)
		}
		auth.Authorizer = authorizer
		return auth, nil
	}

	from, err := parseAddress(data["from"])
	if err != nil {
		return Authorization{}, fmt.Errorf("parse message.from: %w", err)
	}
	to, err := parseAddress(data["to"])
	if err != nil {
		return Authorization{}, fmt.Errorf("parse message.to: %w", err)
	}
	value, err := parseBigInt(data["value"])
	if err != nil {
		return Authorization{}, fmt.Errorf("parse message.value: %w", err)
	}
	validAfter, err := parseUint64(data["validAfter"])
	if err != nil {
		return Authorization{}, fmt.Errorf("parse message.validAfter: %w", err)
	}
	validBefore, err := parseUint64(data["validBefore"])
	if err != nil {
		return Authorization{}, fmt.Errorf("parse message.validBefore: %w", err)
	}
	auth.From = from
	auth.To = to
	auth.Value = value
	auth.ValidAfter = validAfter
	auth.ValidBefore = validBefore
	return auth, nil
}

func parseSignature(raw json.RawMessage) (*Signature, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	if raw[0] == '"' {
		value, err := parseStringLike(raw)
		if err != nil {
			return nil, err
		}
		bytesValue, err := decodeHex(value)
		if err != nil {
			return nil, err
		}
		if len(bytesValue) != 65 {
			return nil, fmt.Errorf("signature has %d bytes, want 65", len(bytesValue))
		}
		return &Signature{
			V: bytesValue[64],
			R: common.BytesToHash(bytesValue[0:32]),
			S: common.BytesToHash(bytesValue[32:64]),
		}, nil
	}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}
	v, err := parseUint64(data["v"])
	if err != nil {
		return nil, fmt.Errorf("parse signature.v: %w", err)
	}
	r, err := parseHash(data["r"])
	if err != nil {
		return nil, fmt.Errorf("parse signature.r: %w", err)
	}
	s, err := parseHash(data["s"])
	if err != nil {
		return nil, fmt.Errorf("parse signature.s: %w", err)
	}
	if v > 255 {
		return nil, fmt.Errorf("signature.v %d overflows uint8", v)
	}
	return &Signature{V: uint8(v), R: r, S: s}, nil
}

func firstRaw(data map[string]json.RawMessage, keys ...string) json.RawMessage {
	for _, key := range keys {
		if raw, ok := data[key]; ok {
			return raw
		}
	}
	return nil
}

func parseAddress(raw json.RawMessage) (common.Address, error) {
	value, err := parseStringLike(raw)
	if err != nil {
		return common.Address{}, err
	}
	if !common.IsHexAddress(value) {
		return common.Address{}, fmt.Errorf("invalid address %q", value)
	}
	return common.HexToAddress(value), nil
}

func parseHash(raw json.RawMessage) (common.Hash, error) {
	value, err := parseStringLike(raw)
	if err != nil {
		return common.Hash{}, err
	}
	decoded, err := decodeHex(value)
	if err != nil {
		return common.Hash{}, err
	}
	if len(decoded) > 32 {
		return common.Hash{}, fmt.Errorf("hex value has %d bytes, want at most 32", len(decoded))
	}
	return common.HexToHash(value), nil
}

func parseBigInt(raw json.RawMessage) (*big.Int, error) {
	value, err := parseStringLike(raw)
	if err != nil {
		return nil, err
	}
	base := 10
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		base = 16
		value = value[2:]
	}
	if value == "" {
		return nil, errors.New("empty integer")
	}
	out, ok := new(big.Int).SetString(value, base)
	if !ok {
		return nil, fmt.Errorf("invalid integer %q", value)
	}
	return out, nil
}

func parseUint64(raw json.RawMessage) (uint64, error) {
	value, err := parseBigInt(raw)
	if err != nil {
		return 0, err
	}
	if !value.IsUint64() {
		return 0, fmt.Errorf("integer %s overflows uint64", value.String())
	}
	return value.Uint64(), nil
}

func parseOptionalString(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	return parseStringLike(raw)
}

func parseStringLike(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", errors.New("value is required")
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return "", errors.New("value is required")
	}
	if raw[0] == '"' {
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return "", err
		}
		return strings.TrimSpace(value), nil
	}
	return string(raw), nil
}

func decodeHex(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(strings.TrimPrefix(value, "0x"), "0X")
	if len(value)%2 == 1 {
		value = "0" + value
	}
	return hex.DecodeString(value)
}
