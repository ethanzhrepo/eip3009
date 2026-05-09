# eip3009

Go CLI for EIP-3009 authorization messages.

## Status

This project contains a CLI for EIP-3009 workflows and a standalone reference
token contract. Review all transaction output before broadcasting. The reference
token is not audited.

## Build

```bash
go build ./cmd/eip3009
```

## Test

```bash
go test ./...
go build ./cmd/eip3009
```

Run the local Anvil end-to-end test:

```bash
./scripts/e2e-anvil.sh
```

The E2E test deploys the reference token, mints test tokens, signs and
broadcasts `transferWithAuthorization`, signs and broadcasts
`receiveWithAuthorization`, cancels a nonce, and verifies the canceled
authorization cannot be broadcast.

## Solidity Test Token

The standalone Forge/OpenZeppelin token project lives in
`solidity-eip3009-token/`.

```bash
cd solidity-eip3009-token
forge install foundry-rs/forge-std@v1.16.1 --no-git --shallow
forge install OpenZeppelin/openzeppelin-contracts@v5.6.1 --no-git --shallow
forge fmt --check
forge build
forge test
```

## Commands

All commands that read or write chain state require `--rpc` or `-R`.

### Check Support

```bash
./eip3009 check -R "$RPC_URL" --token 0xToken --pretty
```

Checks `authorizationState`, `TRANSFER_WITH_AUTHORIZATION_TYPEHASH`,
`RECEIVE_WITH_AUTHORIZATION_TYPEHASH`, and `CANCEL_AUTHORIZATION_TYPEHASH`.

### Sign Offline

Raw value:

```bash
./eip3009 sign \
  --token 0xToken \
  --name "USD Coin" \
  --version 2 \
  --chain-id 1 \
  --to 0xRecipient \
  --value 1000000 \
  --valid-before 1740000000 \
  --stdin-private-key \
  --verify \
  --pretty
```

Human amount:

```bash
./eip3009 sign \
  --token 0xToken \
  --name "USD Coin" \
  --version 2 \
  --chain-id 1 \
  --to 0xRecipient \
  --amount 100 \
  --decimals 6 \
  --ttl 300
```

Use `--dry-run` to print unsigned typed data only. If no private key source is
provided, the CLI prompts for the private key with hidden input. Keystores are
supported with `--keystore`, `--password`, or `--stdin-password`.

### Extract Message

```bash
./eip3009 extract -R "$RPC_URL" --message @signed.json --pretty
```

This decodes signed or unsigned message JSON and fetches token `decimals` and
`symbol` from the ERC-20 contract when RPC is supplied. Execution calldata can
also be decoded:

```bash
./eip3009 extract --calldata 0x... --token 0xToken --decimals 6 --symbol USDC
```

### Emergency Cancel

```bash
./eip3009 cancel \
  -R "$RPC_URL" \
  --message @bad-signed-message.json \
  --stdin-private-key \
  --verify \
  --pretty
```

The cancel command signs `CancelAuthorization(authorizer, nonce)` and broadcasts
`cancelAuthorization(authorizer, nonce, v, r, s)` to consume the nonce. You can
also provide `--nonce` directly with `--token`, `--name`, `--version`, and
`--chain-id`.

### Broadcast Transfer

```bash
./eip3009 broadcast \
  -R "$RPC_URL" \
  --message @signed.json \
  --stdin-private-key \
  --verify \
  --pretty
```

The private key here is the transaction sender that pays gas. For
`receiveWithAuthorization`, it must be the recipient address.

If an imported signed message uses `v = 0` or `v = 1`, the CLI warns before
broadcasting because most Solidity EIP-3009 contracts expect `v = 27` or
`v = 28`. In an interactive terminal, the recommended default is to normalize
the value before sending. For scripts, pass one of:

```bash
--normalize-v  # send 0/1 as 27/28
--keep-v       # send 0/1 unchanged; likely to revert on standard contracts
--yes          # accept the recommended normalization prompt
```

## Contributing

See `CONTRIBUTING.md` for development setup and pull request expectations.
Report security-sensitive issues using `SECURITY.md`.

## License

MIT. See `LICENSE`.
