#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
scaffold_script="$script_dir/scaffold_cli_ui_template.sh"

expected_templates=(
  "go-cobra-bubbletea-onboarding"
  "go-cobra-help-discovery"
  "node-oclif-ink-dashboard"
  "python-textual-console"
  "python-typer-rich-onboarding"
  "python-typer-repair-flow"
  "rust-clap-ratatui-dashboard"
  "shell-progress-ledger"
)

assert_contains() {
  local haystack="$1"
  local needle="$2"
  if ! grep -Fq "$needle" <<<"$haystack"; then
    echo "Expected to find '$needle'" >&2
    exit 1
  fi
}

assert_no_placeholders() {
  local path="$1"
  if rg -n "__APP_" "$path" >/dev/null 2>&1; then
    echo "Placeholder leak detected in $path" >&2
    exit 1
  fi
}

list_output="$(bash "$scaffold_script" --list)"
for template_id in "${expected_templates[@]}"; do
  assert_contains "$list_output" "$template_id"
done

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

for template_id in "${expected_templates[@]}"; do
  dest="$tmpdir/$template_id"
  app_name="Template Check ${template_id}"
  bash "$scaffold_script" --template "$template_id" --dest "$dest" --app-name "$app_name" >/dev/null
  assert_no_placeholders "$dest"
  if [[ ! -f "$dest/README.md" ]]; then
    echo "Missing README for $template_id" >&2
    exit 1
  fi
done

echo "CLI UI template smoke checks passed."
