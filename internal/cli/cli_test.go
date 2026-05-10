package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"eip3009/internal/eip3009"

	"github.com/ethereum/go-ethereum/common"
)

func TestSignDryRunPrintsUnsignedTypedData(t *testing.T) {
	args := []string{
		"eip3009", "sign",
		"--token", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
		"--name", "USD Coin",
		"--version", "2",
		"--chain-id", "1",
		"--from", "0x1111111111111111111111111111111111111111",
		"--to", "0x2222222222222222222222222222222222222222",
		"--value", "1000000",
		"--valid-before", "1740000000",
		"--nonce", "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
		"--dry-run",
	}
	var out, errOut bytes.Buffer

	code := Run(args, strings.NewReader(""), &out, &errOut)
	if code != 0 {
		t.Fatalf("Run exit code = %d, stderr = %s", code, errOut.String())
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out.String())
	}
	if got["primaryType"] != "TransferWithAuthorization" {
		t.Fatalf("primaryType = %v", got["primaryType"])
	}
	if _, ok := got["signature"]; ok {
		t.Fatalf("dry-run output included signature: %s", out.String())
	}
}

func TestCommandHelpExitsZeroAndDoesNotPrintError(t *testing.T) {
	for _, command := range []string{"check", "sign", "extract", "cancel", "broadcast"} {
		t.Run(command, func(t *testing.T) {
			var out, errOut bytes.Buffer

			code := Run([]string{"eip3009", command, "--help"}, strings.NewReader(""), &out, &errOut)
			if code != 0 {
				t.Fatalf("Run exit code = %d, stderr = %s", code, errOut.String())
			}
			if !strings.Contains(out.String(), "Usage of "+command) {
				t.Fatalf("stdout = %q, want command usage", out.String())
			}
			if strings.Contains(errOut.String(), "error:") {
				t.Fatalf("stderr = %q, want no error", errOut.String())
			}
		})
	}
}

func TestSignWithStdinPrivateKeyVerifiesAndPrintsSignedWrapper(t *testing.T) {
	privateKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	args := []string{
		"eip3009", "sign",
		"--token", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
		"--name", "USD Coin",
		"--version", "2",
		"--chain-id", "1",
		"--to", "0x2222222222222222222222222222222222222222",
		"--value", "1000000",
		"--valid-before", "1740000000",
		"--nonce", "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
		"--stdin-private-key",
		"--verify",
	}
	var out, errOut bytes.Buffer

	code := Run(args, strings.NewReader(privateKey), &out, &errOut)
	if code != 0 {
		t.Fatalf("Run exit code = %d, stderr = %s", code, errOut.String())
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out.String())
	}
	if got["authorizationType"] != "transferWithAuthorization" {
		t.Fatalf("authorizationType = %v", got["authorizationType"])
	}
	if got["signature"] == nil {
		t.Fatalf("signature missing: %s", out.String())
	}
	if got["signatureValid"] != true {
		t.Fatalf("signatureValid = %v, output = %s", got["signatureValid"], out.String())
	}
}

func TestResolveSignatureVForBroadcastNormalizesWithExplicitFlag(t *testing.T) {
	sig := &eip3009.Signature{V: 1, R: common.Hash{1}, S: common.Hash{2}}
	var errOut bytes.Buffer

	err := resolveSignatureVForBroadcast(sig, signatureVOptions{normalizeV: true}, strings.NewReader(""), &errOut)
	if err != nil {
		t.Fatalf("resolveSignatureVForBroadcast returned error: %v", err)
	}
	if sig.V != 28 {
		t.Fatalf("v = %d, want 28", sig.V)
	}
	if !strings.Contains(errOut.String(), "warning") {
		t.Fatalf("stderr = %q, want warning", errOut.String())
	}
}

func TestResolveSignatureVForBroadcastKeepsWithExplicitFlag(t *testing.T) {
	sig := &eip3009.Signature{V: 0, R: common.Hash{1}, S: common.Hash{2}}

	err := resolveSignatureVForBroadcast(sig, signatureVOptions{keepV: true}, strings.NewReader(""), &bytes.Buffer{})
	if err != nil {
		t.Fatalf("resolveSignatureVForBroadcast returned error: %v", err)
	}
	if sig.V != 0 {
		t.Fatalf("v = %d, want 0", sig.V)
	}
}

func TestResolveSignatureVForBroadcastRequiresPolicyWhenNonInteractive(t *testing.T) {
	sig := &eip3009.Signature{V: 0, R: common.Hash{1}, S: common.Hash{2}}

	err := resolveSignatureVForBroadcast(sig, signatureVOptions{}, strings.NewReader(""), &bytes.Buffer{})
	if err == nil {
		t.Fatal("resolveSignatureVForBroadcast returned nil error")
	}
	if !strings.Contains(err.Error(), "--normalize-v") || !strings.Contains(err.Error(), "--keep-v") {
		t.Fatalf("error = %q, want flag guidance", err.Error())
	}
}
