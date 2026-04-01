#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
plugin_root="$(cd "$script_dir/.." && pwd)"

echo "[1/7] Shell syntax checks"
find "$script_dir" -type f -name '*.sh' -print0 | xargs -0 -n1 bash -n

echo "[2/7] Template scaffold smoke"
bash "$script_dir/smoke_cli_ui_templates.sh"

echo "[3/7] Pattern selection smoke"
bash "$script_dir/smoke_cli_ui_patterns.sh"

echo "[4/7] Preview smoke"
bash "$script_dir/smoke_cli_ui_previews.sh"

echo "[5/7] Snapshot smoke"
bash "$script_dir/smoke_cli_ui_snapshots.sh"

echo "[6/7] Preview rendering sanity"
bash "$script_dir/preview_cli_ui_templates.sh" --all --sample >/dev/null

echo "[7/7] Manifest parse"
node -e 'JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")); console.log("ok")' "$plugin_root/.codex-plugin/plugin.json" >/dev/null

echo "CLI Systems Lab self-check passed."
