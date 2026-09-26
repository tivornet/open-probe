#!/bin/sh
set -eu

archive=${1:?usage: clean-machine-acceptance-v0.1.sh SIGNED_ZIP}
expected_archive_sha=60d882ff510cacb1ada490cf3e1e5af1fb4aea09fe96e86226b15421d4e68f24
expected_binary_sha=45a88a17ff1ae31eb8d72a1d92c4cd026188a6d1c93a9856bc656d5d7ffcc043
test "$(uname -s)" = Darwin
test "$(uname -m)" = arm64
sw_vers -productVersion | awk -F. '$1 >= 13 { ok=1 } END { exit !ok }'

actual_archive_sha=$(shasum -a 256 "$archive" | awk '{print $1}')
test "$actual_archive_sha" = "$expected_archive_sha"

stage=$(mktemp -d "${TMPDIR:-/tmp}/tivor-clean-machine.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
ditto -x -k "$archive" "$stage"
binary=$(find "$stage" -type f -name tivor -perm -111 -print -quit)
test -n "$binary"
actual_binary_sha=$(shasum -a 256 "$binary" | awk '{print $1}')
test "$actual_binary_sha" = "$expected_binary_sha"
file "$binary" | grep -q arm64
codesign --verify --deep --strict --verbose=2 "$binary"
codesign --verify --deep --strict --verbose=2 -R='notarized' "$binary"
signature=$(codesign -dv --verbose=4 "$binary" 2>&1)
printf '%s\n' "$signature" | grep -Fq 'Authority=Developer ID Application: JIANG FEI (UU965PWVJS)'
printf '%s\n' "$signature" | grep -Fq 'TeamIdentifier=UU965PWVJS'
printf '%s\n' "$signature" | grep -Eq '^Timestamp=.+$'
printf '%s\n' "$signature" | grep -Eq '^Runtime Version=.+$'
if otool -L "$binary" | tail -n +2 | grep -vE '^\s+/(usr/lib|System/Library)/' | grep -q .; then
  echo "M1_CROSS_MACHINE_ACCEPTANCE=FAIL reason=NON_SYSTEM_DYLIB" >&2
  exit 1
fi
version_output=$("$binary" version)
doctor_output=$("$binary" doctor)
provider_output=$("$binary" doctor --provider-path)
printf '%s\n' "$version_output"
printf '%s\n' "$doctor_output"
printf '%s\n' "$provider_output"
printf '%s\n' "$version_output" | grep -Fq '0.1.0'
printf '%s\n' "$doctor_output" | grep -Fq 'local_only=true'
printf '%s\n' "$doctor_output" | grep -Fq 'score=not_computed'
printf '%s\n' "$doctor_output" | grep -Fq 'root_cause=not_inferred'
printf '%s\n' "$provider_output" | grep -Fq 'OpenAI / ChatGPT / Codex: evidence recorded; provider verdict WITHHELD'
printf '%s\n' "$provider_output" | grep -Fq 'Claude / Claude Code: evidence recorded; provider verdict WITHHELD'
printf '%s\n' "$provider_output" | grep -Fq 'score=not_computed'
printf '%s\n' "$provider_output" | grep -Fq 'root_cause=not_inferred'
if pgrep -x tivor >/dev/null 2>&1; then
  echo "M1_CROSS_MACHINE_ACCEPTANCE=FAIL reason=BACKGROUND_PROCESS" >&2
  exit 1
fi
echo "ZIP_SHA256=$actual_archive_sha"
echo "BINARY_SHA256=$actual_binary_sha"
echo "SILENT_UPLOAD=NOT_OBSERVED_LOCAL_ONLY_CONTRACT_PASS"
echo "REDACTION_PRIVACY=PASS_BY_FROZEN_CONTRACT_AND_LOCAL_ONLY_RUNTIME"
echo "M1_CROSS_MACHINE_ACCEPTANCE=PASS"
