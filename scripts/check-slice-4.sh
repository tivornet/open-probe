#!/bin/sh
set -eu

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
CARGO_NET_OFFLINE=true cargo test --workspace --all-targets --locked

summary="$(cargo run -q --offline --locked -p tivor-probe-cli -- doctor --local)"
printf '%s\n' "$summary" | grep -q '^local_only=true$'
printf '%s\n' "$summary" | grep -q '^provider_network_execution=false$'
printf '%s\n' "$summary" | grep -q '^provider_checks=not_executed'
jq -e '.endpoints | all(.url == null and .review_status == "pending_review")' registry/endpoints.v0.1.json >/dev/null
echo "SLICE_4_CHECKS_PASS"
