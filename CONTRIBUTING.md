# Contributing

Thanks for contributing. This project has two parts:

- Go CLI under `cmd/` and `internal/`
- Solidity reference token under `solidity-eip3009-token/`

## Development Setup

Requirements:

- Go 1.25 or newer
- Foundry
- Git

Install Solidity dependencies:

```bash
cd solidity-eip3009-token
forge install foundry-rs/forge-std@v1.16.1 --no-git --shallow
forge install OpenZeppelin/openzeppelin-contracts@v5.6.1 --no-git --shallow
```

## Test

From the repository root:

```bash
go test ./...
go build ./cmd/eip3009
./scripts/e2e-anvil.sh
```

From the Solidity project:

```bash
cd solidity-eip3009-token
forge fmt --check
forge build
forge test
```

## Pull Requests

Keep changes focused. For behavior changes:

- Add or update tests.
- Explain EIP-3009 compatibility impact.
- Include CLI examples if user-facing flags or output change.

For security-sensitive changes, include a short note on key handling, signature validation, or transaction broadcasting risk.

## Code Style

- Go code must be `gofmt` formatted.
- Solidity code must pass `forge fmt --check`.
- Avoid committing generated files such as Go binaries, Forge `out/`, Forge `cache/`, or deployment `broadcast/`.

## Reporting Security Issues

Use the process in `SECURITY.md`. Do not disclose vulnerabilities in public issues.
