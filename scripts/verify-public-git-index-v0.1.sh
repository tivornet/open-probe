#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
manifest="$repo_dir/release/public-git-index.v0.1.txt"
actual=$(mktemp "${TMPDIR:-/tmp}/tivor-public-index.XXXXXX")
trap 'rm -f "$actual"' EXIT HUP INT TERM

cd "$repo_dir"
find . -type f \
  ! -path './.git/*' \
  ! -path './target/*' ! -path './dist/*' \
  ! -path './docs/OPEN-PROBE-V0.1-ARCHITECTURE-GATE-REPORT.md' \
  ! -path './docs/OPEN-PROBE-V0.1-SLICE-*' \
  ! -name '.DS_Store' -print | sed 's#^./##' | LC_ALL=C sort > "$actual"

diff -u "$manifest" "$actual"
echo "PUBLIC_GIT_INDEX=EXACT"
