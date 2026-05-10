#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOKEN_DIR="$ROOT_DIR/solidity-eip3009-token"
TMP_DIR="$(mktemp -d)"
ANVIL_PORT="${ANVIL_PORT:-18545}"
RPC_URL="${RPC_URL:-http://127.0.0.1:${ANVIL_PORT}}"
CHAIN_ID="${CHAIN_ID:-31337}"

DEPLOYER_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
AUTHORIZER_KEY="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
RECIPIENT_KEY="0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
RELAYER_KEY="0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"

CLI_BIN="$TMP_DIR/eip3009"
ANVIL_LOG="$TMP_DIR/anvil.log"
ANVIL_PID=""

export GOCACHE="${GOCACHE:-$TMP_DIR/go-build-cache}"

cleanup() {
  if [[ -n "$ANVIL_PID" ]]; then
    kill "$ANVIL_PID" >/dev/null 2>&1 || true
    wait "$ANVIL_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

wait_for_anvil() {
  for _ in $(seq 1 80); do
    if cast chain-id --rpc-url "$RPC_URL" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  echo "anvil did not become ready; log follows:" >&2
  cat "$ANVIL_LOG" >&2 || true
  exit 1
}

call_uint() {
  cast call "$1" "$2" "${@:3}" --rpc-url "$RPC_URL" | awk '{print $1}'
}

call_bool() {
  cast call "$1" "$2" "${@:3}" --rpc-url "$RPC_URL" | awk '{print $1}'
}

assert_eq() {
  local got="$1"
  local want="$2"
  local label="$3"
  if [[ "$got" != "$want" ]]; then
    echo "assertion failed for $label: got $got, want $want" >&2
    exit 1
  fi
}

need anvil
need cast
need forge
need go

if [[ ! -d "$TOKEN_DIR/lib/forge-std" || ! -d "$TOKEN_DIR/lib/openzeppelin-contracts" ]]; then
  echo "missing Forge dependencies; run:" >&2
  echo "  cd solidity-eip3009-token" >&2
  echo "  forge install foundry-rs/forge-std@v1.16.1 --no-git --shallow" >&2
  echo "  forge install OpenZeppelin/openzeppelin-contracts@v5.6.1 --no-git --shallow" >&2
  exit 1
fi

echo "building CLI"
go build -o "$CLI_BIN" "$ROOT_DIR/cmd/eip3009"

echo "building Solidity test token"
(
  cd "$TOKEN_DIR"
  forge build
)

echo "starting anvil on $RPC_URL"
anvil --host 127.0.0.1 --port "$ANVIL_PORT" --chain-id "$CHAIN_ID" >"$ANVIL_LOG" 2>&1 &
ANVIL_PID="$!"
wait_for_anvil

DEPLOYER="$(cast wallet address --private-key "$DEPLOYER_KEY")"
AUTHORIZER="$(cast wallet address --private-key "$AUTHORIZER_KEY")"
RECIPIENT="$(cast wallet address --private-key "$RECIPIENT_KEY")"

echo "deploying EIP3009Token"
DEPLOY_OUTPUT="$(
  cd "$TOKEN_DIR"
  forge create \
    --rpc-url "$RPC_URL" \
    --private-key "$DEPLOYER_KEY" \
    --broadcast \
    --offline \
    src/EIP3009Token.sol:EIP3009Token \
    --constructor-args "Example USD" "xUSD" "1" 6 "$DEPLOYER"
)"
TOKEN="$(printf '%s\n' "$DEPLOY_OUTPUT" | awk '/Deployed to:/ {print $3; exit}')"
if [[ -z "$TOKEN" ]]; then
  echo "failed to parse deployed token address" >&2
  printf '%s\n' "$DEPLOY_OUTPUT" >&2
  exit 1
fi

echo "minting to authorizer"
cast send "$TOKEN" "mint(address,uint256)" "$AUTHORIZER" 1000000000 \
  --rpc-url "$RPC_URL" \
  --private-key "$DEPLOYER_KEY" >/dev/null

TRANSFER_JSON="$TMP_DIR/transfer.json"
TRANSFER_NONCE="0x1111111111111111111111111111111111111111111111111111111111111111"
TRANSFER_VALUE="100000000"

echo "signing transferWithAuthorization"
"$CLI_BIN" sign \
  --token "$TOKEN" \
  --name "Example USD" \
  --version "1" \
  --chain-id "$CHAIN_ID" \
  --to "$RECIPIENT" \
  --value "$TRANSFER_VALUE" \
  --valid-before 4102444800 \
  --nonce "$TRANSFER_NONCE" \
  --private-key "$AUTHORIZER_KEY" \
  --verify \
  --output "$TRANSFER_JSON" \
  --pretty

echo "broadcasting transferWithAuthorization"
"$CLI_BIN" broadcast \
  -R "$RPC_URL" \
  --message "@$TRANSFER_JSON" \
  --private-key "$RELAYER_KEY" \
  --verify \
  --normalize-v \
  --pretty >/dev/null

RECIPIENT_BALANCE="$(call_uint "$TOKEN" "balanceOf(address)(uint256)" "$RECIPIENT")"
assert_eq "$RECIPIENT_BALANCE" "$TRANSFER_VALUE" "recipient balance after transferWithAuthorization"

RECEIVE_JSON="$TMP_DIR/receive.json"
RECEIVE_NONCE="0x2222222222222222222222222222222222222222222222222222222222222222"
RECEIVE_VALUE="25000000"

echo "signing receiveWithAuthorization"
"$CLI_BIN" sign \
  --type receive \
  --token "$TOKEN" \
  --name "Example USD" \
  --version "1" \
  --chain-id "$CHAIN_ID" \
  --to "$RECIPIENT" \
  --value "$RECEIVE_VALUE" \
  --valid-before 4102444800 \
  --nonce "$RECEIVE_NONCE" \
  --private-key "$AUTHORIZER_KEY" \
  --verify \
  --output "$RECEIVE_JSON" \
  --pretty

echo "broadcasting receiveWithAuthorization as recipient"
"$CLI_BIN" broadcast \
  -R "$RPC_URL" \
  --message "@$RECEIVE_JSON" \
  --private-key "$RECIPIENT_KEY" \
  --verify \
  --normalize-v \
  --pretty >/dev/null

RECIPIENT_BALANCE="$(call_uint "$TOKEN" "balanceOf(address)(uint256)" "$RECIPIENT")"
assert_eq "$RECIPIENT_BALANCE" "125000000" "recipient balance after receiveWithAuthorization"

CANCEL_JSON="$TMP_DIR/cancel-target.json"
CANCEL_NONCE="0x3333333333333333333333333333333333333333333333333333333333333333"

echo "signing transfer target for cancellation"
"$CLI_BIN" sign \
  --token "$TOKEN" \
  --name "Example USD" \
  --version "1" \
  --chain-id "$CHAIN_ID" \
  --to "$RECIPIENT" \
  --value 1 \
  --valid-before 4102444800 \
  --nonce "$CANCEL_NONCE" \
  --private-key "$AUTHORIZER_KEY" \
  --verify \
  --output "$CANCEL_JSON" \
  --pretty

echo "broadcasting cancelAuthorization"
"$CLI_BIN" cancel \
  -R "$RPC_URL" \
  --message "@$CANCEL_JSON" \
  --private-key "$AUTHORIZER_KEY" \
  --verify \
  --pretty >/dev/null

AUTH_STATE="$(call_bool "$TOKEN" "authorizationState(address,bytes32)(bool)" "$AUTHORIZER" "$CANCEL_NONCE")"
assert_eq "$AUTH_STATE" "true" "authorizationState after cancelAuthorization"

echo "confirming canceled authorization cannot be broadcast"
set +e
"$CLI_BIN" broadcast \
  -R "$RPC_URL" \
  --message "@$CANCEL_JSON" \
  --private-key "$RELAYER_KEY" \
  --verify \
  --normalize-v \
  --pretty >/dev/null 2>"$TMP_DIR/canceled-broadcast.err"
CANCELED_STATUS="$?"
set -e
if [[ "$CANCELED_STATUS" -eq 0 ]]; then
  echo "expected canceled authorization broadcast to fail" >&2
  exit 1
fi

echo "e2e anvil test passed"
