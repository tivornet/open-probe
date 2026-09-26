#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
archive="$repo_dir/dist/tivor-open-probe-v0.1.0-beta.1-darwin-arm64.tar.gz"
test -s "$archive"
revision=$(git -C "$repo_dir" rev-parse HEAD 2>/dev/null || printf '%s' UNCOMMITTED_SOURCE_TREE)
digest=$(shasum -a 256 "$archive" | awk '{print $1}')
cat > "$archive.provenance.json.tmp" <<EOF
{"contract":"TIVOR_RELEASE_PROVENANCE_V0.1","artifact":"$(basename "$archive")","sha256":"$digest","source_revision":"$revision","signed":false,"notarized":false}
EOF
mv "$archive.provenance.json.tmp" "$archive.provenance.json"
echo "PROVENANCE=$archive.provenance.json"
