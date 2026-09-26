#!/bin/sh
set -eu

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets

echo "SLICE_7_OFFLINE_GATES=PASS"
