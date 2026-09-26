#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --locked
cargo run -q -p tivor-probe-cli -- doctor >/dev/null
cargo run -q -p tivor-probe-cli -- validate fixtures/results/complete.private.v0.2.json
cargo run -q -p tivor-probe-cli -- validate fixtures/exports/safe.redacted.v0.1.json --profile public-export

test -f INSTALL.md
test -f UNINSTALL.md
test -f LICENSE
test -f NOTICE
test -f SECURITY.md
test -f PRIVACY.md
test -f KNOWN-ISSUES.md
test -f CHANGELOG.md
test -f RELEASE-NOTES-V0.1.0-BETA.md
test -f release/VERSION.json
test -f release/public-beta-readiness.v0.1.json
! rg -n '/opt/homebrew|s_client|accept_invalid|danger_accept_invalid' crates
! rg -n 'launchd|LaunchAgent|daemonize|background service' crates
jq -e '.contract == "PUBLIC_BETA_READINESS_V0.1" and .status == "NOT_READY" and .gates.package_safe_tls == "PASS" and (.blocking_gates == ["signing","notarization"])' release/public-beta-readiness.v0.1.json >/dev/null

./scripts/build-release-v0.1.sh
archive=dist/tivor-open-probe-v0.1.0-beta.1-darwin-arm64.tar.gz
test -s "$archive"
(cd dist && shasum -a 256 -c tivor-open-probe-v0.1.0-beta.1-darwin-arm64.tar.gz.sha256)

./scripts/audit-public-repository-v0.1.sh

echo "RELEASE_CHECKS=PASS"
echo "PUBLIC_BETA_READINESS=NOT_READY"
