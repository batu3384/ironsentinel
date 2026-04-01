#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
plugin_root="$(cd "$script_dir/.." && pwd)"
scaffold_script="$script_dir/scaffold_cli_ui_template.sh"
catalog_path="$plugin_root/assets/template-catalog.json"

slugify() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-' | sed 's/^-//; s/-$//'
}

app_name_for_template() {
  case "$1" in
    go-cobra-bubbletea-onboarding) printf '%s\n' "Signal Forge" ;;
    go-cobra-help-discovery) printf '%s\n' "Signal Forge" ;;
    node-oclif-ink-dashboard) printf '%s\n' "Radar Port" ;;
    python-textual-console) printf '%s\n' "Signal Deck" ;;
    python-typer-rich-onboarding) printf '%s\n' "Orbit Desk" ;;
    python-typer-repair-flow) printf '%s\n' "Repair Pilot" ;;
    rust-clap-ratatui-dashboard) printf '%s\n' "Watch Tower" ;;
    shell-progress-ledger) printf '%s\n' "Release Ledger" ;;
    *) printf '%s\n' "Terminal Operator" ;;
  esac
}

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

ids="$(node -e 'const fs=require("fs"); const data=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); for (const item of data) console.log(item.id);' "$catalog_path")"

for id in $ids; do
  app_name="$(app_name_for_template "$id")"
  app_slug="$(slugify "$app_name")"
  dest="$tmpdir/$id"
  bash "$scaffold_script" --template "$id" --dest "$dest" --app-name "$app_name" >/dev/null

  if [[ ! -f "$dest/preview.sh" ]]; then
    echo "Missing preview.sh for $id" >&2
    exit 1
  fi

  actual="$(bash "$dest/preview.sh")"
  expected="$(node - "$catalog_path" "$id" "$app_name" "$app_slug" <<'EOF'
const fs = require('fs');
const path = require('path');

const [, , catalogPath, templateId, appTitle, appSlug] = process.argv;
const catalog = JSON.parse(fs.readFileSync(catalogPath, 'utf8'));
const entry = catalog.find(item => item.id === templateId);
if (!entry) {
  console.error(`Unknown template: ${templateId}`);
  process.exit(1);
}

const samplePath = path.join(path.dirname(catalogPath), '..', entry.previewAsset);
let text = fs.readFileSync(samplePath, 'utf8').trimEnd();
text = text.replaceAll('Signal Forge', appTitle);
text = text.replaceAll('signal-forge', appSlug);
text = text.replaceAll('Radar Port', appTitle);
text = text.replaceAll('radar-port', appSlug);
text = text.replaceAll('Signal Deck', appTitle);
text = text.replaceAll('signal-deck', appSlug);
text = text.replaceAll('Orbit Desk', appTitle);
text = text.replaceAll('orbit-desk', appSlug);
text = text.replaceAll('Watch Tower', appTitle);
text = text.replaceAll('watch-tower', appSlug);
text = text.replaceAll('release-ledger', appSlug);
console.log(text);
EOF
)"

  if [[ "$actual" != "$expected" ]]; then
    echo "Snapshot mismatch for $id" >&2
    diff -u <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") || true
    exit 1
  fi
done

echo "CLI UI snapshot smoke checks passed."
