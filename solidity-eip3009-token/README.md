# EIP-3009 Token

Standalone Forge project for an ERC-20 token that supports EIP-3009
authorizations.

## Layout

- `src/EIP3009Token.sol`: OpenZeppelin ERC20 + EIP712 + Ownable token
- `test/EIP3009Token.t.sol`: Foundry tests for transfer, receive, cancel, replay, and time windows
- `script/Deploy.s.sol`: minimal deployment script

## Contract Features

- `transferWithAuthorization(from,to,value,validAfter,validBefore,nonce,v,r,s)`
- `receiveWithAuthorization(from,to,value,validAfter,validBefore,nonce,v,r,s)`
- `cancelAuthorization(authorizer,nonce,v,r,s)`
- `authorizationState(authorizer,nonce)`
- EIP-3009 type hash constants
- `DOMAIN_SEPARATOR()`
- ERC-20 metadata: `name`, `symbol`, `decimals`, `version`
- Owner-only `mint`

## Test

Install dependencies first:

```bash
forge install foundry-rs/forge-std@v1.16.1 --no-git --shallow
forge install OpenZeppelin/openzeppelin-contracts@v5.6.1 --no-git --shallow
```

Then run:

```bash
forge fmt --check
forge build
forge test
```

`foundry.toml` sets `offline = true` so Foundry does not try to contact OpenChain
for signature decoding during local tests.

## Deploy

```bash
PRIVATE_KEY=0x... forge script script/Deploy.s.sol:Deploy \
  --rpc-url "$RPC_URL" \
  --broadcast
```

The deployment script creates:

- name: `Example USD`
- symbol: `xUSD`
- version: `1`
- decimals: `6`
- owner: deployer address
