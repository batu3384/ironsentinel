#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  preview_cli_ui_templates.sh --list
  preview_cli_ui_templates.sh --template <id> [--sample]
  preview_cli_ui_templates.sh --all [--sample]

Preview CLI UI starter templates from the local catalog.
USAGE
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
plugin_root="$(cd "$script_dir/.." && pwd)"
catalog_path="$plugin_root/assets/template-catalog.json"
templates_root="$plugin_root/templates"
assets_root="$plugin_root/assets"

mode=""
template_id=""
show_sample="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --list)
      mode="list"
      shift
      ;;
    --template)
      if [[ $# -lt 2 || "$2" == --* ]]; then
        echo "Missing value for --template" >&2
        exit 1
      fi
      mode="template"
      template_id="$2"
      shift 2
      ;;
    --all)
      mode="all"
      shift
      ;;
    --sample)
      show_sample="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$mode" ]]; then
  usage >&2
  exit 1
fi

node - "$catalog_path" "$templates_root" "$assets_root" "$mode" "$template_id" "$show_sample" <<'EOF'
const fs = require('fs');
const path = require('path');

const [, , catalogPath, templatesRoot, assetsRoot, mode, templateId, showSample] = process.argv;
const catalog = JSON.parse(fs.readFileSync(catalogPath, 'utf8'));

function readIntro(id) {
  const readmePath = path.join(templatesRoot, id, 'README.md');
  if (!fs.existsSync(readmePath)) return 'No README found.';
  const lines = fs.readFileSync(readmePath, 'utf8').split('\n').map(line => line.trim()).filter(Boolean);
  return lines.find(line => !line.startsWith('#') && !line.startsWith('##') && !line.startsWith('```')) || 'No summary available.';
}

function render(entry) {
  const intro = readIntro(entry.id);
  console.log(`## ${entry.id}`);
  console.log(`- Stack: \`${entry.stack}\``);
  console.log(`- Pattern: \`${entry.pattern}\``);
  console.log(`- Surface: ${entry.surface}`);
  console.log(`- Use cases: ${entry.useCases.join(', ')}`);
  console.log(`- Summary: ${intro}`);
  console.log(`- Scaffold: \`bash ${path.join(path.dirname(catalogPath), '..', 'scripts', 'scaffold_cli_ui_template.sh')} --template ${entry.id} --dest ./starter --app-name "Terminal Operator"\``);
  if (entry.previewCommand) {
    console.log(`- Preview command: \`${entry.previewCommand}\``);
  }
  if (showSample === 'true') {
    const samplePath = path.join(path.dirname(catalogPath), '..', entry.previewAsset);
    if (fs.existsSync(samplePath)) {
      console.log('- Sample:');
      console.log('```text');
      console.log(fs.readFileSync(samplePath, 'utf8').trimEnd());
      console.log('```');
    }
  }
  console.log('');
}

if (mode === 'list') {
  for (const entry of catalog) console.log(entry.id);
  process.exit(0);
}

if (mode === 'template') {
  const entry = catalog.find(item => item.id === templateId);
  if (!entry) {
    console.error(`Unknown template: ${templateId}`);
    process.exit(1);
  }
  render(entry);
  process.exit(0);
}

for (const entry of catalog) render(entry);
EOF
