package cli

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"eip3009/internal/eip3009"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/term"
)

func Run(args []string, in io.Reader, out io.Writer, errOut io.Writer) int {
	if len(args) < 2 {
		printUsage(errOut)
		return 2
	}
	ctx := context.Background()
	var err error
	switch args[1] {
	case "check":
		err = runCheck(ctx, args[2:], out, errOut)
	case "sign":
		err = runSign(args[2:], in, out, errOut)
	case "extract":
		err = runExtract(ctx, args[2:], in, out, errOut)
	case "cancel":
		err = runCancel(ctx, args[2:], in, out, errOut)
	case "broadcast":
		err = runBroadcast(ctx, args[2:], in, out, errOut)
	case "help", "-h", "--help":
		printUsage(out)
		return 0
	default:
		fmt.Fprintf(errOut, "unknown command %q\n", args[1])
		printUsage(errOut)
		return 2
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	return 0
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `usage: eip3009 <command> [flags]

commands:
  check      detect whether a token contract exposes EIP-3009 methods
  sign       create offline EIP-3009 typed data or signature
  extract    decode signed/unsigned message JSON or execution calldata
  cancel     sign and broadcast cancelAuthorization for a nonce
  broadcast  broadcast a signed transfer/receive authorization`)
}

type rpcFlags struct {
	rpc      string
	rpcShort string
}

func (r *rpcFlags) add(fs *flag.FlagSet) {
	fs.StringVar(&r.rpc, "rpc", "", "RPC URL")
	fs.StringVar(&r.rpcShort, "R", "", "RPC URL")
}

func (r rpcFlags) value() string {
	if r.rpc != "" {
		return r.rpc
	}
	return r.rpcShort
}

func newFlagSet(name string, errOut io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(errOut)
	return fs
}

func parseFlags(fs *flag.FlagSet, args []string, helpOut io.Writer) error {
	if isHelpRequest(args) {
		fs.SetOutput(helpOut)
	}
	return fs.Parse(args)
}

func isHelpRequest(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			return true
		}
	}
	return false
}

func runCheck(ctx context.Context, args []string, out io.Writer, errOut io.Writer) error {
	fs := newFlagSet("check", errOut)
	var rpc rpcFlags
	var tokenArg string
	var pretty bool
	rpc.add(fs)
	fs.StringVar(&tokenArg, "token", "", "token contract address")
	fs.BoolVar(&pretty, "pretty", false, "pretty-print JSON")
	if err := parseFlags(fs, args, out); err != nil {
		return err
	}
	rpcURL := rpc.value()
	if rpcURL == "" {
		return errors.New("--rpc/-R is required")
	}
	token, err := eip3009.ParseAddressValue(tokenArg)
	if err != nil {
		return fmt.Errorf("--token: %w", err)
	}
	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return err
	}
	defer client.Close()
	return writeJSON(out, eip3009.CheckEIP3009Support(ctx, client, token), pretty)
}

func runSign(args []string, in io.Reader, out io.Writer, errOut io.Writer) error {
	fs := newFlagSet("sign", errOut)
	opts := signOptions{}
	opts.addFlags(fs, true)
	if err := parseFlags(fs, args, out); err != nil {
		return err
	}
	signed, signatureValid, err := buildSignedAuthorization(opts, in, errOut)
	if err != nil {
		return err
	}
	if opts.dryRun {
		object, err := eip3009.TypedDataObject(*signed)
		if err != nil {
			return err
		}
		return writeOutput(out, opts.output, object, opts.pretty)
	}
	object, err := eip3009.SignedAuthorizationObject(*signed, signatureValid)
	if err != nil {
		return err
	}
	return writeOutput(out, opts.output, object, opts.pretty)
}

func runExtract(ctx context.Context, args []string, in io.Reader, out io.Writer, errOut io.Writer) error {
	fs := newFlagSet("extract", errOut)
	var rpc rpcFlags
	var messageArg, calldataArg, tokenArg, symbol string
	var decimals int
	var pretty bool
	rpc.add(fs)
	fs.StringVar(&messageArg, "message", "", "message JSON, @file, file path, or - for stdin")
	fs.StringVar(&calldataArg, "calldata", "", "execution calldata hex, @file, file path, or - for stdin")
	fs.StringVar(&tokenArg, "token", "", "token address override")
	fs.IntVar(&decimals, "decimals", -1, "manual decimals fallback")
	fs.StringVar(&symbol, "symbol", "", "manual symbol fallback")
	fs.BoolVar(&pretty, "pretty", false, "pretty-print JSON")
	if err := parseFlags(fs, args, out); err != nil {
		return err
	}
	signed, err := readAuthorizationInput(messageArg, calldataArg, in)
	if err != nil {
		return err
	}
	token := signed.Domain.VerifyingContract
	if tokenArg != "" {
		token, err = eip3009.ParseAddressValue(tokenArg)
		if err != nil {
			return fmt.Errorf("--token: %w", err)
		}
		signed.Domain.VerifyingContract = token
	}
	var decimalsPtr *uint8
	if decimals >= 0 {
		if decimals > math.MaxUint8 {
			return errors.New("--decimals must fit uint8")
		}
		d := uint8(decimals)
		decimalsPtr = &d
	}
	if rpc.value() != "" && token != (common.Address{}) {
		client, err := ethclient.DialContext(ctx, rpc.value())
		if err != nil {
			return err
		}
		defer client.Close()
		if decimalsPtr == nil {
			d, err := eip3009.TokenDecimals(ctx, client, token)
			if err != nil {
				return fmt.Errorf("fetch decimals: %w", err)
			}
			decimalsPtr = &d
		}
		if symbol == "" {
			symbol, err = eip3009.TokenSymbol(ctx, client, token)
			if err != nil {
				return fmt.Errorf("fetch symbol: %w", err)
			}
		}
	}
	var signatureValid *bool
	if signed.Signature != nil {
		ok := eip3009.VerifySignedAuthorization(signed) == nil
		signatureValid = &ok
	}
	object, err := eip3009.ExtractionObject(*signed, decimalsPtr, symbol, signatureValid)
	if err != nil {
		return err
	}
	return writeJSON(out, object, pretty)
}

func runCancel(ctx context.Context, args []string, in io.Reader, out io.Writer, errOut io.Writer) error {
	fs := newFlagSet("cancel", errOut)
	var rpc rpcFlags
	opts := cancelOptions{}
	rpc.add(fs)
	opts.addFlags(fs)
	if err := parseFlags(fs, args, out); err != nil {
		return err
	}
	rpcURL := rpc.value()
	if rpcURL == "" {
		return errors.New("--rpc/-R is required")
	}
	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return err
	}
	defer client.Close()

	cancelSigned, privateKey, err := buildCancelAuthorization(ctx, client, opts, in, errOut)
	if err != nil {
		return err
	}
	if opts.verify {
		if err := eip3009.VerifySignedAuthorization(cancelSigned); err != nil {
			return err
		}
	}
	signatureValid := opts.verify
	object, err := eip3009.SignedAuthorizationObject(*cancelSigned, &signatureValid)
	if err != nil {
		return err
	}
	if opts.dryRun {
		return writeOutput(out, opts.output, object, opts.pretty)
	}
	txHash, err := eip3009.BroadcastAuthorization(ctx, client, *cancelSigned, privateKey)
	if err != nil {
		return err
	}
	object["txHash"] = txHash.Hex()
	return writeOutput(out, opts.output, object, opts.pretty)
}

func runBroadcast(ctx context.Context, args []string, in io.Reader, out io.Writer, errOut io.Writer) error {
	fs := newFlagSet("broadcast", errOut)
	var rpc rpcFlags
	var messageArg, keyArg, keystorePath, passwordArg, output string
	var stdinKey, stdinPassword, verify, pretty bool
	var vOpts signatureVOptions
	rpc.add(fs)
	fs.StringVar(&messageArg, "message", "", "signed message JSON, @file, file path, or - for stdin")
	fs.StringVar(&keyArg, "private-key", "", "transaction private key")
	fs.BoolVar(&stdinKey, "stdin-private-key", false, "read transaction private key from stdin")
	fs.StringVar(&keystorePath, "keystore", "", "transaction keystore JSON path")
	fs.StringVar(&passwordArg, "password", "", "keystore password")
	fs.BoolVar(&stdinPassword, "stdin-password", false, "read keystore password from stdin")
	fs.BoolVar(&verify, "verify", false, "verify authorization signature before broadcasting")
	fs.StringVar(&output, "output", "", "write JSON output to file")
	fs.BoolVar(&pretty, "pretty", false, "pretty-print JSON")
	fs.BoolVar(&vOpts.normalizeV, "normalize-v", false, "normalize imported signature v=0/1 to v=27/28 before broadcasting")
	fs.BoolVar(&vOpts.keepV, "keep-v", false, "broadcast imported signature v=0/1 unchanged")
	fs.BoolVar(&vOpts.yes, "yes", false, "accept recommended non-destructive prompts")
	if err := parseFlags(fs, args, out); err != nil {
		return err
	}
	if err := vOpts.validate(); err != nil {
		return err
	}
	if rpc.value() == "" {
		return errors.New("--rpc/-R is required")
	}
	if messageArg == "" {
		return errors.New("--message is required")
	}
	messageBytes, err := readInputArg(in, messageArg)
	if err != nil {
		return err
	}
	signed, err := eip3009.ParseMessageJSON(messageBytes)
	if err != nil {
		return err
	}
	if verify {
		if err := eip3009.VerifySignedAuthorization(signed); err != nil {
			return err
		}
	}
	if err := resolveSignatureVForBroadcast(signed.Signature, vOpts, in, errOut); err != nil {
		return err
	}
	privateKey, err := loadPrivateKey(keyArg, stdinKey, keystorePath, passwordArg, stdinPassword, in, errOut)
	if err != nil {
		return err
	}
	client, err := ethclient.DialContext(ctx, rpc.value())
	if err != nil {
		return err
	}
	defer client.Close()
	txHash, err := eip3009.BroadcastAuthorization(ctx, client, *signed, privateKey)
	if err != nil {
		return err
	}
	signatureValid := verify
	object, err := eip3009.SignedAuthorizationObject(*signed, &signatureValid)
	if err != nil {
		return err
	}
	object["txHash"] = txHash.Hex()
	return writeOutput(out, output, object, pretty)
}

type signatureVOptions struct {
	normalizeV bool
	keepV      bool
	yes        bool
}

func (o signatureVOptions) validate() error {
	if o.normalizeV && o.keepV {
		return errors.New("--normalize-v and --keep-v are mutually exclusive")
	}
	if o.yes && o.keepV {
		return errors.New("--yes cannot be combined with --keep-v")
	}
	return nil
}

func resolveSignatureVForBroadcast(signature *eip3009.Signature, opts signatureVOptions, in io.Reader, errOut io.Writer) error {
	if signature == nil {
		return nil
	}
	switch signature.V {
	case 27, 28:
		return nil
	case 0, 1:
	default:
		return fmt.Errorf("invalid signature v %d", signature.V)
	}

	normalizedV := signature.V + 27
	fmt.Fprintf(
		errOut,
		"warning: imported signature uses v=%d. Most EIP-3009 Solidity contracts expect v=%d for the same recovery id.\n",
		signature.V,
		normalizedV,
	)

	if opts.keepV {
		fmt.Fprintf(errOut, "warning: keeping v=%d unchanged; the transaction may revert on-chain.\n", signature.V)
		return nil
	}
	if opts.normalizeV || opts.yes {
		signature.V = normalizedV
		return nil
	}
	if !canPrompt(in) {
		return fmt.Errorf("signature v=%d needs a broadcast policy; rerun with --normalize-v to send v=%d or --keep-v to send v=%d unchanged", signature.V, normalizedV, signature.V)
	}
	normalize, err := promptNormalizeSignatureV(in, errOut, signature.V, normalizedV)
	if err != nil {
		return err
	}
	if normalize {
		signature.V = normalizedV
	} else {
		fmt.Fprintf(errOut, "warning: keeping v=%d unchanged; the transaction may revert on-chain.\n", signature.V)
	}
	return nil
}

func canPrompt(in io.Reader) bool {
	file, ok := in.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}

func promptNormalizeSignatureV(in io.Reader, errOut io.Writer, originalV uint8, normalizedV uint8) (bool, error) {
	fmt.Fprintf(errOut, "Send normalized v=%d instead of v=%d? [Y/n] ", normalizedV, originalV)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	switch answer {
	case "", "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	default:
		return false, fmt.Errorf("invalid answer %q; use y or n", strings.TrimSpace(line))
	}
}

type signOptions struct {
	token         string
	name          string
	version       string
	chainID       string
	from          string
	to            string
	value         string
	amount        string
	decimals      int
	validAfter    uint64
	validBefore   uint64
	ttl           uint64
	nonce         string
	privateKey    string
	stdinKey      bool
	keystorePath  string
	password      string
	stdinPassword bool
	output        string
	pretty        bool
	dryRun        bool
	verify        bool
	kind          string
	requireSigner bool
	loadedPrivKey *ecdsa.PrivateKey
}

func (o *signOptions) addFlags(fs *flag.FlagSet, requireSigner bool) {
	o.requireSigner = requireSigner
	o.decimals = -1
	o.nonce = "random"
	fs.StringVar(&o.token, "token", "", "token contract address")
	fs.StringVar(&o.name, "name", "", "EIP-712 domain name")
	fs.StringVar(&o.version, "version", "", "EIP-712 domain version")
	fs.StringVar(&o.chainID, "chain-id", "", "chain ID")
	fs.StringVar(&o.from, "from", "", "signer/from address")
	fs.StringVar(&o.to, "to", "", "recipient address")
	fs.StringVar(&o.value, "value", "", "raw token amount in smallest unit")
	fs.StringVar(&o.amount, "amount", "", "human token amount")
	fs.IntVar(&o.decimals, "decimals", -1, "decimals for --amount")
	fs.Uint64Var(&o.validAfter, "valid-after", 0, "earliest valid timestamp")
	fs.Uint64Var(&o.validBefore, "valid-before", 0, "expiration timestamp")
	fs.Uint64Var(&o.ttl, "ttl", 0, "seconds from now until expiration")
	fs.StringVar(&o.nonce, "nonce", "random", "bytes32 nonce or random")
	fs.StringVar(&o.privateKey, "private-key", "", "signer private key")
	fs.BoolVar(&o.stdinKey, "stdin-private-key", false, "read signer private key from stdin")
	fs.StringVar(&o.keystorePath, "keystore", "", "signer keystore JSON path")
	fs.StringVar(&o.password, "password", "", "keystore password")
	fs.BoolVar(&o.stdinPassword, "stdin-password", false, "read keystore password from stdin")
	fs.StringVar(&o.output, "output", "", "write JSON output to file")
	fs.BoolVar(&o.pretty, "pretty", false, "pretty-print JSON")
	fs.BoolVar(&o.dryRun, "dry-run", false, "print typed data without signing")
	fs.BoolVar(&o.verify, "verify", false, "recover and verify signature")
	fs.StringVar(&o.kind, "type", "transfer", "authorization type: transfer or receive")
}

func buildSignedAuthorization(opts signOptions, in io.Reader, errOut io.Writer) (*eip3009.SignedAuthorization, *bool, error) {
	kind, err := eip3009.NormalizeAuthorizationKind(opts.kind)
	if err != nil {
		return nil, nil, err
	}
	if kind == eip3009.CancelAuthorization {
		return nil, nil, errors.New("sign command supports transfer/receive; use cancel command for cancelAuthorization")
	}
	domain, err := domainFromArgs(opts.token, opts.name, opts.version, opts.chainID)
	if err != nil {
		return nil, nil, err
	}
	to, err := eip3009.ParseAddressValue(opts.to)
	if err != nil {
		return nil, nil, fmt.Errorf("--to: %w", err)
	}
	var decimalsPtr *uint8
	if opts.decimals >= 0 {
		if opts.decimals > math.MaxUint8 {
			return nil, nil, errors.New("--decimals must fit uint8")
		}
		d := uint8(opts.decimals)
		decimalsPtr = &d
	}
	value, err := eip3009.ParseTokenValue(opts.value, opts.amount, decimalsPtr)
	if err != nil {
		return nil, nil, err
	}
	validBefore, err := resolveValidBefore(opts.validBefore, opts.ttl)
	if err != nil {
		return nil, nil, err
	}
	nonce, err := resolveNonce(opts.nonce)
	if err != nil {
		return nil, nil, err
	}

	var privateKey *ecdsa.PrivateKey
	if !opts.dryRun {
		privateKey, err = loadPrivateKey(opts.privateKey, opts.stdinKey, opts.keystorePath, opts.password, opts.stdinPassword, in, errOut)
		if err != nil {
			return nil, nil, err
		}
	}
	var from common.Address
	if opts.from != "" {
		from, err = eip3009.ParseAddressValue(opts.from)
		if err != nil {
			return nil, nil, fmt.Errorf("--from: %w", err)
		}
	}
	if privateKey != nil {
		keyAddress := crypto.PubkeyToAddress(privateKey.PublicKey)
		if from == (common.Address{}) {
			from = keyAddress
		} else if from != keyAddress {
			return nil, nil, fmt.Errorf("--from %s does not match private key address %s", from.Hex(), keyAddress.Hex())
		}
	}
	if from == (common.Address{}) {
		return nil, nil, errors.New("--from is required when --dry-run is used")
	}

	auth := eip3009.Authorization{
		Kind:        kind,
		From:        from,
		To:          to,
		Value:       value,
		ValidAfter:  opts.validAfter,
		ValidBefore: validBefore,
		Nonce:       nonce,
	}
	if opts.dryRun {
		return &eip3009.SignedAuthorization{Domain: domain, Authorization: auth}, nil, nil
	}
	signed, err := eip3009.SignAuthorization(domain, auth, privateKey)
	if err != nil {
		return nil, nil, err
	}
	var signatureValid *bool
	if opts.verify {
		ok := eip3009.VerifySignedAuthorization(signed) == nil
		signatureValid = &ok
		if !ok {
			return nil, nil, errors.New("signature verification failed")
		}
	}
	return signed, signatureValid, nil
}

type cancelOptions struct {
	messageArg    string
	token         string
	name          string
	version       string
	chainID       string
	authorizer    string
	nonce         string
	privateKey    string
	stdinKey      bool
	keystorePath  string
	password      string
	stdinPassword bool
	output        string
	pretty        bool
	dryRun        bool
	verify        bool
}

func (o *cancelOptions) addFlags(fs *flag.FlagSet) {
	fs.StringVar(&o.messageArg, "message", "", "message JSON to extract token/domain/from/nonce")
	fs.StringVar(&o.token, "token", "", "token contract address")
	fs.StringVar(&o.name, "name", "", "EIP-712 domain name")
	fs.StringVar(&o.version, "version", "", "EIP-712 domain version")
	fs.StringVar(&o.chainID, "chain-id", "", "chain ID")
	fs.StringVar(&o.authorizer, "from", "", "authorizer address")
	fs.StringVar(&o.authorizer, "authorizer", "", "authorizer address")
	fs.StringVar(&o.nonce, "nonce", "", "nonce to cancel")
	fs.StringVar(&o.privateKey, "private-key", "", "authorizer private key")
	fs.BoolVar(&o.stdinKey, "stdin-private-key", false, "read authorizer private key from stdin")
	fs.StringVar(&o.keystorePath, "keystore", "", "authorizer keystore JSON path")
	fs.StringVar(&o.password, "password", "", "keystore password")
	fs.BoolVar(&o.stdinPassword, "stdin-password", false, "read keystore password from stdin")
	fs.StringVar(&o.output, "output", "", "write JSON output to file")
	fs.BoolVar(&o.pretty, "pretty", false, "pretty-print JSON")
	fs.BoolVar(&o.dryRun, "dry-run", false, "sign cancelAuthorization but do not broadcast")
	fs.BoolVar(&o.verify, "verify", false, "recover and verify cancel signature")
}

func buildCancelAuthorization(ctx context.Context, client *ethclient.Client, opts cancelOptions, in io.Reader, errOut io.Writer) (*eip3009.SignedAuthorization, *ecdsa.PrivateKey, error) {
	var source *eip3009.SignedAuthorization
	var err error
	if opts.messageArg != "" {
		bytes, err := readInputArg(in, opts.messageArg)
		if err != nil {
			return nil, nil, err
		}
		source, err = eip3009.ParseMessageJSON(bytes)
		if err != nil {
			return nil, nil, err
		}
	}
	privateKey, err := loadPrivateKey(opts.privateKey, opts.stdinKey, opts.keystorePath, opts.password, opts.stdinPassword, in, errOut)
	if err != nil {
		return nil, nil, err
	}
	keyAddress := crypto.PubkeyToAddress(privateKey.PublicKey)

	domain, err := cancelDomain(ctx, client, opts, source)
	if err != nil {
		return nil, nil, err
	}
	nonce, err := cancelNonce(opts, source)
	if err != nil {
		return nil, nil, err
	}
	authorizer := keyAddress
	if opts.authorizer != "" {
		authorizer, err = eip3009.ParseAddressValue(opts.authorizer)
		if err != nil {
			return nil, nil, fmt.Errorf("--from/--authorizer: %w", err)
		}
	}
	if source != nil && opts.authorizer == "" {
		if source.Authorization.Kind == eip3009.CancelAuthorization {
			authorizer = source.Authorization.Authorizer
		} else {
			authorizer = source.Authorization.From
		}
	}
	if authorizer != keyAddress {
		return nil, nil, fmt.Errorf("authorizer %s does not match private key address %s", authorizer.Hex(), keyAddress.Hex())
	}
	auth := eip3009.Authorization{Kind: eip3009.CancelAuthorization, Authorizer: authorizer, Nonce: nonce}
	signed, err := eip3009.SignAuthorization(domain, auth, privateKey)
	if err != nil {
		return nil, nil, err
	}
	return signed, privateKey, nil
}

func cancelDomain(ctx context.Context, client *ethclient.Client, opts cancelOptions, source *eip3009.SignedAuthorization) (eip3009.Domain, error) {
	domain := eip3009.Domain{}
	if source != nil {
		domain = source.Domain
	}
	var err error
	if opts.token != "" {
		domain.VerifyingContract, err = eip3009.ParseAddressValue(opts.token)
		if err != nil {
			return domain, fmt.Errorf("--token: %w", err)
		}
	}
	if opts.name != "" {
		domain.Name = opts.name
	}
	if opts.version != "" {
		domain.Version = opts.version
	}
	if opts.chainID != "" {
		domain.ChainID, err = eip3009.ParseBigIntValue(opts.chainID)
		if err != nil {
			return domain, fmt.Errorf("--chain-id: %w", err)
		}
	}
	if domain.VerifyingContract == (common.Address{}) {
		return domain, errors.New("--token is required when --message does not include domain.verifyingContract")
	}
	if domain.ChainID == nil {
		domain.ChainID, err = client.ChainID(ctx)
		if err != nil {
			return domain, err
		}
	}
	if domain.Name == "" {
		domain.Name, err = eip3009.TokenName(ctx, client, domain.VerifyingContract)
		if err != nil {
			return domain, fmt.Errorf("fetch token name or provide --name: %w", err)
		}
	}
	if domain.Version == "" {
		domain.Version, err = eip3009.TokenVersion(ctx, client, domain.VerifyingContract)
		if err != nil {
			return domain, fmt.Errorf("fetch token version or provide --version: %w", err)
		}
	}
	return domain, nil
}

func cancelNonce(opts cancelOptions, source *eip3009.SignedAuthorization) (common.Hash, error) {
	if opts.nonce != "" {
		return eip3009.ParseHashValue(opts.nonce)
	}
	if source != nil {
		return source.Authorization.Nonce, nil
	}
	return common.Hash{}, errors.New("--nonce or --message is required")
}

func domainFromArgs(tokenArg, name, version, chainIDArg string) (eip3009.Domain, error) {
	token, err := eip3009.ParseAddressValue(tokenArg)
	if err != nil {
		return eip3009.Domain{}, fmt.Errorf("--token: %w", err)
	}
	chainID, err := eip3009.ParseBigIntValue(chainIDArg)
	if err != nil {
		return eip3009.Domain{}, fmt.Errorf("--chain-id: %w", err)
	}
	return eip3009.Domain{Name: name, Version: version, ChainID: chainID, VerifyingContract: token}, nil
}

func resolveValidBefore(validBefore uint64, ttl uint64) (uint64, error) {
	if validBefore != 0 && ttl != 0 {
		return 0, errors.New("--valid-before and --ttl are mutually exclusive")
	}
	if validBefore == 0 && ttl == 0 {
		return 0, errors.New("one of --valid-before or --ttl is required")
	}
	if validBefore != 0 {
		return validBefore, nil
	}
	now := uint64(time.Now().Unix())
	if math.MaxUint64-now < ttl {
		return 0, errors.New("--ttl overflows timestamp")
	}
	return now + ttl, nil
}

func resolveNonce(value string) (common.Hash, error) {
	if value == "" || strings.EqualFold(value, "random") {
		return eip3009.RandomNonce()
	}
	return eip3009.ParseHashValue(value)
}

func readAuthorizationInput(messageArg string, calldataArg string, in io.Reader) (*eip3009.SignedAuthorization, error) {
	if messageArg != "" && calldataArg != "" {
		return nil, errors.New("--message and --calldata are mutually exclusive")
	}
	if messageArg == "" && calldataArg == "" {
		return nil, errors.New("one of --message or --calldata is required")
	}
	if calldataArg != "" {
		raw, err := readInputArg(in, calldataArg)
		if err != nil {
			return nil, err
		}
		data, err := decodeHexString(strings.TrimSpace(string(raw)))
		if err != nil {
			return nil, err
		}
		return eip3009.DecodeExecuteCalldata(data)
	}
	raw, err := readInputArg(in, messageArg)
	if err != nil {
		return nil, err
	}
	return eip3009.ParseMessageJSON(raw)
}

func loadPrivateKey(privateKeyArg string, stdinKey bool, keystorePath string, passwordArg string, stdinPassword bool, in io.Reader, errOut io.Writer) (*ecdsa.PrivateKey, error) {
	sources := 0
	for _, ok := range []bool{privateKeyArg != "", stdinKey, keystorePath != ""} {
		if ok {
			sources++
		}
	}
	if sources > 1 {
		return nil, errors.New("use only one of --private-key, --stdin-private-key, or --keystore")
	}
	if privateKeyArg != "" {
		return parsePrivateKey(privateKeyArg)
	}
	if stdinKey {
		bytes, err := io.ReadAll(in)
		if err != nil {
			return nil, err
		}
		return parsePrivateKey(strings.TrimSpace(string(bytes)))
	}
	if keystorePath != "" {
		password, err := readPassword(passwordArg, stdinPassword, in, errOut)
		if err != nil {
			return nil, err
		}
		bytes, err := os.ReadFile(keystorePath)
		if err != nil {
			return nil, err
		}
		key, err := keystore.DecryptKey(bytes, password)
		if err != nil {
			return nil, err
		}
		return key.PrivateKey, nil
	}
	return readInteractivePrivateKey(in, errOut)
}

func parsePrivateKey(value string) (*ecdsa.PrivateKey, error) {
	value = strings.TrimSpace(strings.TrimPrefix(value, "0x"))
	if value == "" {
		return nil, errors.New("private key is empty")
	}
	return crypto.HexToECDSA(value)
}

func readPassword(passwordArg string, stdinPassword bool, in io.Reader, errOut io.Writer) (string, error) {
	if passwordArg != "" {
		return passwordArg, nil
	}
	if stdinPassword {
		bytes, err := io.ReadAll(in)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(bytes)), nil
	}
	return readSecret(in, errOut, "Enter keystore password: ")
}

func readInteractivePrivateKey(in io.Reader, errOut io.Writer) (*ecdsa.PrivateKey, error) {
	secret, err := readSecret(in, errOut, "Enter private key: ")
	if err != nil {
		return nil, err
	}
	return parsePrivateKey(secret)
}

func readSecret(in io.Reader, errOut io.Writer, prompt string) (string, error) {
	if file, ok := in.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		fmt.Fprint(errOut, prompt)
		bytes, err := term.ReadPassword(int(file.Fd()))
		fmt.Fprintln(errOut)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(bytes)), nil
	}
	reader := bufio.NewReader(in)
	fmt.Fprint(errOut, prompt)
	value, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("secret input is empty")
	}
	return value, nil
}

func readInputArg(in io.Reader, value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("input is required")
	}
	if value == "-" {
		return io.ReadAll(in)
	}
	if strings.HasPrefix(value, "@") {
		return os.ReadFile(strings.TrimPrefix(value, "@"))
	}
	if looksLikeInlineData(value) {
		return []byte(value), nil
	}
	if bytes, err := os.ReadFile(value); err == nil {
		return bytes, nil
	}
	return []byte(value), nil
}

func looksLikeInlineData(value string) bool {
	return strings.HasPrefix(value, "{") ||
		strings.HasPrefix(value, "[") ||
		strings.HasPrefix(value, "0x")
}

func decodeHexString(value string) ([]byte, error) {
	value = strings.TrimPrefix(strings.TrimPrefix(value, "0x"), "0X")
	if len(value)%2 == 1 {
		value = "0" + value
	}
	return hex.DecodeString(value)
}

func writeOutput(out io.Writer, path string, object any, pretty bool) error {
	if path == "" {
		return writeJSON(out, object, pretty)
	}
	var bytes []byte
	var err error
	if pretty {
		bytes, err = json.MarshalIndent(object, "", "  ")
	} else {
		bytes, err = json.Marshal(object)
	}
	if err != nil {
		return err
	}
	bytes = append(bytes, '\n')
	return os.WriteFile(path, bytes, 0600)
}

func writeJSON(out io.Writer, object any, pretty bool) error {
	encoder := json.NewEncoder(out)
	if pretty {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(object)
}

func parseUint64Flag(value string, name string) (uint64, error) {
	out, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}
