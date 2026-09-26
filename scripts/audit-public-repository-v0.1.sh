#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"

test -f release/public-repository-manifest.v0.1.json
jq -e '.contract == "PUBLIC_REPOSITORY_MANIFEST_V0.1"' release/public-repository-manifest.v0.1.json >/dev/null

if find . -path ./target -prune -o -path ./dist -prune -o -name .DS_Store -print | grep -q .; then
  echo "PUBLIC_REPO_AUDIT=FAIL reason=DS_STORE" >&2
  exit 1
fi

scan_files=$(mktemp "${TMPDIR:-/tmp}/tivor-public-files.XXXXXX")
trap 'rm -f "$scan_files"' EXIT HUP INT TERM
find . -type f \
  ! -path './.git/*' \
  ! -path './target/*' ! -path './dist/*' \
  ! -path './docs/OPEN-PROBE-V0.1-ARCHITECTURE-GATE-REPORT.md' \
  ! -path './docs/OPEN-PROBE-V0.1-SLICE-*' \
  ! -path './fixtures/*' \
  ! -path './scripts/audit-public-repository-v0.1.sh' -print > "$scan_files"

if xargs grep -nE '/Users/|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|xox[baprs]-' < "$scan_files"; then
  echo "PUBLIC_REPO_AUDIT=FAIL reason=SENSITIVE_PATTERN" >&2
  exit 1
fi

if xargs grep -niE 'TonyOS|Growth Console|Recovery Guard|Stable AI Route' < "$scan_files"; then
  echo "PUBLIC_REPO_AUDIT=FAIL reason=PRIVATE_PRODUCT_REFERENCE" >&2
  exit 1
fi

echo "PUBLIC_REPO_AUDIT=PASS"
