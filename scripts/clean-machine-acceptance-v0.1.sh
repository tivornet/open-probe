#!/bin/sh
set -eu

archive=${1:?usage: clean-machine-acceptance-v0.1.sh SIGNED_ARCHIVE [CHECKSUM_FILE]}
checksum=${2:-"$archive.sha256"}
test "$(uname -s)" = Darwin
test "$(uname -m)" = arm64
sw_vers -productVersion | awk -F. '$1 >= 13 { ok=1 } END { exit !ok }'
(cd "$(dirname "$archive")" && shasum -a 256 -c "$(basename "$checksum")")

stage=$(mktemp -d "${TMPDIR:-/tmp}/tivor-clean-machine.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
tar -xzf "$archive" -C "$stage"
binary=$(find "$stage" -type f -name tivor -perm -111 -print -quit)
test -n "$binary"
file "$binary" | grep -q arm64
codesign --verify --deep --strict --verbose=2 "$binary"
spctl --assess --type execute --verbose=2 "$binary"
if otool -L "$binary" | tail -n +2 | grep -vE '^\s+/(usr/lib|System/Library)/' | grep -q .; then
  echo "CLEAN_MACHINE_ACCEPTANCE=FAIL reason=NON_SYSTEM_DYLIB" >&2
  exit 1
fi
"$binary" version
"$binary" doctor
if test "${TIVOR_OWNER_APPROVES_PROVIDER_PATH:-0}" = 1; then
  "$binary" doctor --provider-path
else
  echo "PROVIDER_PATH=SKIPPED_OWNER_APPROVAL_REQUIRED"
fi
echo "CLEAN_MACHINE_ACCEPTANCE=PASS"
