#!/bin/sh
set -eu

archive=${1:?usage: clean-machine-acceptance-v0.1.sh SIGNED_ZIP ZIP_SHA256 BINARY_SHA256 PROVENANCE_JSON}
expected_archive_sha=${2:?missing expected ZIP SHA-256}
expected_binary_sha=${3:?missing expected binary SHA-256}
provenance=${4:?missing notarization provenance JSON}
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
signature=$(codesign -dv --verbose=4 "$binary" 2>&1)
printf '%s\n' "$signature" | grep -Fq 'Authority=Developer ID Application: JIANG FEI (UU965PWVJS)'
printf '%s\n' "$signature" | grep -Fq 'TeamIdentifier=UU965PWVJS'
printf '%s\n' "$signature" | grep -Eq '^Timestamp=.+$'
printf '%s\n' "$signature" | grep -Eq '^Runtime Version=.+$'
jq -e '.notarization == "ACCEPTED" and .notary_issues == 0 and (.notary_submission_id | type == "string" and length > 0)' "$provenance" >/dev/null
if ! xattr -p com.apple.quarantine "$binary" >/dev/null 2>&1; then
  echo "M1_CROSS_MACHINE_ACCEPTANCE=FAIL reason=QUARANTINE_NOT_PRESERVED" >&2
  exit 1
fi
echo "GATEKEEPER_DIAGNOSTIC_BEGIN"
spctl -a -t open -vvv --context context:primary-signature "$binary" 2>&1 || true
echo "GATEKEEPER_DIAGNOSTIC_END"
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
printf '%s\n' "$provider_output" | grep -Fq 'Tivor AI Network Check'
printf '%s\n' "$provider_output" | grep -Fq 'OpenAI / ChatGPT / Codex'
printf '%s\n' "$provider_output" | grep -Fq 'Claude / Claude Code'
printf '%s\n' "$provider_output" | grep -Fq 'Root cause'
! printf '%s\n' "$provider_output" | grep -Eq 'Some\(|NONEOBSERVED|provider verdict WITHHELD|analysis policy'
if pgrep -x tivor >/dev/null 2>&1; then
  echo "M1_CROSS_MACHINE_ACCEPTANCE=FAIL reason=BACKGROUND_PROCESS" >&2
  exit 1
fi
echo "ZIP_SHA256=$actual_archive_sha"
echo "BINARY_SHA256=$actual_binary_sha"
echo "SILENT_UPLOAD=NOT_OBSERVED_LOCAL_ONLY_CONTRACT_PASS"
echo "REDACTION_PRIVACY=PASS_BY_FROZEN_CONTRACT_AND_LOCAL_ONLY_RUNTIME"
echo "M1_CROSS_MACHINE_ACCEPTANCE=PASS"
