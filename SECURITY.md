# Security Policy

## Scope

This repository contains:

- A Go CLI for EIP-3009 typed data, signatures, nonce cancellation, and transaction broadcasting.
- A standalone Forge/OpenZeppelin reference token that implements EIP-3009.

The Solidity token is a reference and test contract. It has not been audited and should not be used as production token infrastructure without independent review.

## Private Keys

The CLI can read private keys from flags, stdin, keystores, or interactive hidden input. Prefer keystores or stdin in scripts. Avoid shell history exposure from `--private-key`.

Always verify:

- The RPC URL points to the intended chain.
- `--chain-id` matches the intended chain.
- `--token` is the intended verifying contract.
- `--name` and `--version` match the token contract's EIP-712 domain.
- The message nonce and validity window are expected before signing.

## Reporting Vulnerabilities

Do not open public issues for vulnerabilities that could lead to fund loss, signature misuse, or private key disclosure.

Report privately by emailing the maintainer listed on the GitHub repository. If no maintainer email is listed, open a GitHub Security Advisory for the repository.

Please include:

- Affected command, package, or contract.
- Reproduction steps.
- Expected and actual behavior.
- Impact assessment.
- Suggested fix, if known.

## Supported Versions

Security fixes target the latest released version. Older versions are best-effort only unless a release branch is explicitly maintained.

## Disclaimer

This software is provided as-is. It handles signatures and transactions that may move real assets. Review output carefully before broadcasting transactions.
