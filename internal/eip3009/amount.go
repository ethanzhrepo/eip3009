package eip3009

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
)

func ParseTokenValue(valueArg string, amountArg string, decimals *uint8) (*big.Int, error) {
	valueArg = strings.TrimSpace(valueArg)
	amountArg = strings.TrimSpace(amountArg)

	switch {
	case valueArg != "" && amountArg != "":
		return nil, errors.New("--value and --amount are mutually exclusive")
	case valueArg == "" && amountArg == "":
		return nil, errors.New("one of --value or --amount is required")
	case valueArg != "":
		value, ok := new(big.Int).SetString(valueArg, 10)
		if !ok || value.Sign() < 0 {
			return nil, fmt.Errorf("invalid --value %q", valueArg)
		}
		return value, nil
	default:
		if decimals == nil {
			return nil, errors.New("--decimals is required when using --amount")
		}
		return parseHumanAmount(amountArg, *decimals)
	}
}

func parseHumanAmount(amount string, decimals uint8) (*big.Int, error) {
	if amount == "" {
		return nil, errors.New("amount is required")
	}
	if strings.HasPrefix(amount, "-") {
		return nil, errors.New("amount must be non-negative")
	}
	if strings.Count(amount, ".") > 1 {
		return nil, fmt.Errorf("invalid amount %q", amount)
	}
	parts := strings.SplitN(amount, ".", 2)
	whole := parts[0]
	fractional := ""
	if len(parts) == 2 {
		fractional = parts[1]
	}
	if whole == "" {
		whole = "0"
	}
	if whole == "" && fractional == "" {
		return nil, fmt.Errorf("invalid amount %q", amount)
	}
	if !isDecimalDigits(whole) || (fractional != "" && !isDecimalDigits(fractional)) {
		return nil, fmt.Errorf("invalid amount %q", amount)
	}
	if len(fractional) > int(decimals) {
		return nil, fmt.Errorf("amount %q has more fractional digits than decimals %d", amount, decimals)
	}

	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)
	wholeValue, ok := new(big.Int).SetString(whole, 10)
	if !ok {
		return nil, fmt.Errorf("invalid amount %q", amount)
	}
	value := wholeValue.Mul(wholeValue, scale)
	if fractional != "" {
		fractional += strings.Repeat("0", int(decimals)-len(fractional))
		fractionalValue, ok := new(big.Int).SetString(fractional, 10)
		if !ok {
			return nil, fmt.Errorf("invalid amount %q", amount)
		}
		value.Add(value, fractionalValue)
	}
	return value, nil
}

func FormatTokenValue(value *big.Int, decimals uint8) string {
	if value == nil {
		return "0"
	}
	if decimals == 0 {
		return value.String()
	}
	sign := ""
	work := new(big.Int).Set(value)
	if work.Sign() < 0 {
		sign = "-"
		work.Abs(work)
	}
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)
	whole := new(big.Int).Quo(work, scale)
	fractional := new(big.Int).Mod(work, scale).String()
	fractional = strings.Repeat("0", int(decimals)-len(fractional)) + fractional
	fractional = strings.TrimRight(fractional, "0")
	if fractional == "" {
		return sign + whole.String()
	}
	return sign + whole.String() + "." + fractional
}

func isDecimalDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
