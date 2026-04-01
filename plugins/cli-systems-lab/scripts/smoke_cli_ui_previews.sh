#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
preview_script="$script_dir/preview_cli_ui_templates.sh"
catalog_path="$script_dir/../assets/template-catalog.json"

assert_contains() {
  local haystack="$1"
  local needle="$2"
  if ! grep -Fq "$needle" <<<"$haystack"; then
    echo "Expected to find '$needle'" >&2
    echo "$haystack" >&2
    exit 1
  fi
}

ids="$(node -e 'const fs=require("fs"); const data=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); for (const item of data) console.log(item.id);' "$catalog_path")"

for id in $ids; do
  output="$(bash "$preview_script" --template "$id" --sample)"
  assert_contains "$output" "## $id"
  assert_contains "$output" '```text'
done

echo "CLI UI preview smoke checks passed."
