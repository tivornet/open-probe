#!/bin/sh
set -eu

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
CARGO_NET_OFFLINE=true cargo test --workspace --all-targets --locked

cargo run -q --offline --locked -p tivor-probe-cli -- registry list --kind all >/dev/null
cargo run -q --offline --locked -p tivor-probe-cli -- validate fixtures/results/complete.private.v0.1.json
cargo run -q --offline --locked -p tivor-probe-cli -- validate fixtures/results/partial.private.v0.1.json
cargo run -q --offline --locked -p tivor-probe-cli -- validate fixtures/exports/safe.redacted.v0.1.json --profile public-export

if cargo run -q --offline --locked -p tivor-probe-cli -- validate fixtures/exports/unsafe.exact-ip.json --profile public-export >/dev/null 2>&1; then
  echo "unsafe exact-IP fixture was accepted" >&2
  exit 1
fi
if cargo run -q --offline --locked -p tivor-probe-cli -- validate fixtures/exports/unsafe.token.json --profile public-export >/dev/null 2>&1; then
  echo "unsafe token fixture was accepted" >&2
  exit 1
fi

jq -e '.endpoints | all(.url == null and .review_status == "pending_review")' registry/endpoints.v0.1.json >/dev/null
test "$(cargo run -q --offline --locked -p tivor-probe-cli -- plan --format json | jq -r .network_execution)" = false
echo "SLICE_2_CHECKS_PASS"
