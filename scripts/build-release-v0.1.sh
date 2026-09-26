#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=0.1.0-beta.1
archive_base="tivor-open-probe-v${version}-darwin-arm64"
dist_dir="$repo_dir/dist"
stage_dir=$(mktemp -d "${TMPDIR:-/tmp}/tivor-release.XXXXXX")
trap 'rm -rf "$stage_dir"' EXIT HUP INT TERM

cd "$repo_dir"
cargo build --release --locked -p tivor-probe-cli
file target/release/tivor | grep -q 'arm64'

mkdir -p "$stage_dir/$archive_base" "$dist_dir"
cp target/release/tivor release/VERSION.json LICENSE NOTICE SECURITY.md README.md INSTALL.md UNINSTALL.md PRIVACY.md KNOWN-ISSUES.md RELEASE-NOTES-V0.1.0-BETA.md "$stage_dir/$archive_base/"
chmod 755 "$stage_dir/$archive_base/tivor"
chmod 644 "$stage_dir/$archive_base/"*.md "$stage_dir/$archive_base/LICENSE" "$stage_dir/$archive_base/NOTICE" "$stage_dir/$archive_base/VERSION.json"

COPYFILE_DISABLE=1 tar -C "$stage_dir" -czf "$dist_dir/$archive_base.tar.gz" "$archive_base"
(cd "$dist_dir" && shasum -a 256 "$archive_base.tar.gz" > "$archive_base.tar.gz.sha256")

echo "ARTIFACT=$dist_dir/$archive_base.tar.gz"
echo "SIGNING_STATUS=UNSIGNED_ENGINEERING_CANDIDATE_NOT_FOR_DISTRIBUTION"
