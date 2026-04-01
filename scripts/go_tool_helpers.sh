#!/usr/bin/env bash
set -euo pipefail

go_tool_bin_dir() {
  local gobin
  gobin="$(go env GOBIN)"
  if [[ -n "$gobin" ]]; then
    printf '%s\n' "$gobin"
    return 0
  fi
  printf '%s/bin\n' "$(go env GOPATH)"
}

require_go_tool() {
  local tool_name="$1"
  local tool_path
  tool_path="$(go_tool_bin_dir)/$tool_name"
  if [[ ! -x "$tool_path" ]]; then
    echo "[quality] expected Go tool was not installed at $tool_path" >&2
    exit 1
  fi
  printf '%s\n' "$tool_path"
}
