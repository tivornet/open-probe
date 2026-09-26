#!/bin/sh
set -eu

cargo test --workspace
endpoint_output=$(cargo run -q -p tivor-probe-cli -- registry list --kind endpoints)
printf '%s\n' "$endpoint_output" | grep -q 'openai.primary_https approved_canary'
doctor_output=$(cargo run -q -p tivor-probe-cli -- doctor --local)
printf '%s\n' "$doctor_output" | grep -q 'live_canary=false'
# Do not make real network calls in ordinary CI. Verify the opt-in surface statically.
cargo run -q -p tivor-probe-cli -- doctor --help | grep -q -- '--live-canary'
grep -q 'live_canary=true' crates/tivor-probe-cli/src/main.rs
grep -q 'UNSUPPORTED_LIVE_CANARY' crates/tivor-probe-cli/src/main.rs
echo SLICE_5_OFFLINE_CHECKS_PASS
