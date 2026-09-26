#!/bin/sh
set -eu

cargo test --workspace --all-targets
local_output=$(cargo run -q -p tivor-probe-cli -- doctor --local)
printf '%s\n' "$local_output" | grep -q 'local_only=true'
printf '%s\n' "$local_output" | grep -q 'provider_network_execution=false'
printf '%s\n' "$local_output" | grep -q 'live_canary=false'
cargo run -q -p tivor-probe-cli -- doctor --help | grep -q -- '--live-canary'
grep -q 'approved-401.json' crates/probe-core/src/lib.rs
grep -q 'provider_health_verdict' crates/probe-core/src/lib.rs
echo SLICE_6_OFFLINE_CHECKS_PASS
