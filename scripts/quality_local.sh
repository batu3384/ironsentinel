#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$ROOT_DIR/scripts/go_tool_helpers.sh"
cd "$ROOT_DIR"

ensure_go_tool() {
  local tool_name="$1"
  local module_ref="$2"
  local tool_path
  tool_path="$(go_tool_bin_dir)/$tool_name"
  if [[ ! -x "$tool_path" ]]; then
    go install "$module_ref"
  fi
  printf '%s\n' "$tool_path"
}

echo "[quality] go test ./..."
go test ./...

echo "[quality] coverage gate"
bash scripts/coverage_gate.sh

echo "[quality] go vet ./..."
go vet ./...

echo "[quality] staticcheck ./..."
STATICCHECK_BIN="$(ensure_go_tool staticcheck honnef.co/go/tools/cmd/staticcheck@v0.7.0)"
GOFLAGS="${GOFLAGS:+$GOFLAGS }-buildvcs=false" GOMAXPROCS="${STATICCHECK_GOMAXPROCS:-2}" "$STATICCHECK_BIN" ./...

echo "[quality] golangci-lint run ./..."
GOLANGCI_LINT_BIN="$(ensure_go_tool golangci-lint github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.3)"
"$GOLANGCI_LINT_BIN" run --config .golangci.yml --concurrency 2 ./...

echo "[quality] self-scan"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
mkdir -p "$tmp_dir/repo"
rsync -a \
  --exclude '.git' \
	  --exclude 'runtime' \
	  --exclude 'dist' \
	  --exclude 'coverage' \
	  --exclude 'internal/core/testdata' \
	  --exclude 'internal/cli/testdata' \
	  --exclude '.DS_Store' \
	  "$ROOT_DIR"/ "$tmp_dir/repo/"
go run ./cmd/ironsentinel --lang en scan "$tmp_dir/repo" --coverage core --fail-on-new high
