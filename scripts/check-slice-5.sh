#!/bin/sh
set -eu

cargo test --workspace
endpoint_output=$(cargo run -q -p tivor-probe-cli -- registry list --kind endpoints)
printf '%s\n' "$endpoint_output" | grep -q 'openai.primary_https approved_canary'
doctor_output=$(cargo run -q -p tivor-probe-cli -- doctor --local)
printf '%s\n' "$doctor_output" | grep -q 'provider_network_execution=false'
printf '%s\n' "$doctor_output" | grep -q 'provider_path_execution=false'
# Do not make real network calls in ordinary CI. Verify the opt-in surface statically.
cargo run -q -p tivor-probe-cli -- doctor --help | grep -q -- '--provider-path'
grep -q 'if live_canary' crates/tivor-probe-cli/src/main.rs
cargo run -q -p tivor-probe-cli -- doctor --help | grep -q -- 'alias: --live-canary'
echo SLICE_5_OFFLINE_CHECKS_PASS
