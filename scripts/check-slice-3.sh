#!/bin/sh
set -eu

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
CARGO_NET_OFFLINE=true cargo test --workspace --all-targets --locked
cargo test --offline --locked -p probe-platform-macos

jq -e '.endpoints | all(.url == null and .review_status == "pending_review")' registry/endpoints.v0.1.json >/dev/null
echo "SLICE_3_CHECKS_PASS"
