package eip3009

import (
	"math/big"
	"strings"
	"testing"
)

func TestParseTokenValueUsesRawValueWithoutDecimals(t *testing.T) {
	got, err := ParseTokenValue("1000000", "", nil)
	if err != nil {
		t.Fatalf("ParseTokenValue returned error: %v", err)
	}
	if got.String() != "1000000" {
		t.Fatalf("value = %s, want 1000000", got.String())
	}
}

func TestParseTokenValueConvertsHumanAmountWithDecimals(t *testing.T) {
	decimals := uint8(6)
	got, err := ParseTokenValue("", "100.25", &decimals)
	if err != nil {
		t.Fatalf("ParseTokenValue returned error: %v", err)
	}
	if got.String() != "100250000" {
		t.Fatalf("value = %s, want 100250000", got.String())
	}
}

func TestParseTokenValueRejectsAmbiguousOrInexactInput(t *testing.T) {
	decimals := uint8(6)
	cases := []struct {
		name   string
		value  string
		amount string
	}{
		{name: "both value and amount", value: "1", amount: "1"},
		{name: "neither value nor amount"},
		{name: "too many fractional digits", amount: "0.0000001"},
		{name: "negative amount", amount: "-1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseTokenValue(tc.value, tc.amount, &decimals)
			if err == nil {
				t.Fatal("ParseTokenValue returned nil error")
			}
		})
	}
}

func TestFormatTokenValueShowsHumanAmountWithoutLosingRawPrecision(t *testing.T) {
	cases := []struct {
		value    string
		decimals uint8
		want     string
	}{
		{value: "100250000", decimals: 6, want: "100.25"},
		{value: "1", decimals: 6, want: "0.000001"},
		{value: "1000000", decimals: 6, want: "1"},
		{value: "0", decimals: 18, want: "0"},
	}

	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			value, ok := new(big.Int).SetString(tc.value, 10)
			if !ok {
				t.Fatalf("invalid fixture value %s", tc.value)
			}
			if got := FormatTokenValue(value, tc.decimals); got != tc.want {
				t.Fatalf("FormatTokenValue = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseTokenValueRequiresDecimalsForHumanAmount(t *testing.T) {
	_, err := ParseTokenValue("", "100", nil)
	if err == nil || !strings.Contains(err.Error(), "decimals") {
		t.Fatalf("error = %v, want decimals error", err)
	}
}
