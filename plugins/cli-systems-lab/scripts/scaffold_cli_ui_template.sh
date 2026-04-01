#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scaffold_cli_ui_template.sh --list
  scaffold_cli_ui_template.sh --template <id> --dest <path> [--app-name <name>] [--force]

Templates:
  go-cobra-bubbletea-onboarding
  go-cobra-help-discovery
  node-oclif-ink-dashboard
  python-textual-console
  python-typer-rich-onboarding
  python-typer-repair-flow
  rust-clap-ratatui-dashboard
  shell-progress-ledger
USAGE
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
plugin_root="$(cd "$script_dir/.." && pwd)"
templates_root="$plugin_root/templates"

template_id=""
dest=""
app_name="Terminal Operator"
force="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --list)
      find "$templates_root" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sort
      exit 0
      ;;
    --template)
      if [[ $# -lt 2 || "$2" == --* ]]; then
        echo "Missing value for --template" >&2
        exit 1
      fi
      template_id="$2"
      shift 2
      ;;
    --dest)
      if [[ $# -lt 2 || "$2" == --* ]]; then
        echo "Missing value for --dest" >&2
        exit 1
      fi
      dest="$2"
      shift 2
      ;;
    --app-name)
      if [[ $# -lt 2 || "$2" == --* ]]; then
        echo "Missing value for --app-name" >&2
        exit 1
      fi
      app_name="$2"
      shift 2
      ;;
    --force)
      force="true"
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

if [[ -z "$template_id" || -z "$dest" ]]; then
  usage >&2
  exit 1
fi

template_dir="$templates_root/$template_id"
if [[ ! -d "$template_dir" ]]; then
  echo "Unknown template: $template_id" >&2
  exit 1
fi

dest_parent="$(dirname "$dest")"
mkdir -p "$dest_parent"
dest="$(cd "$dest_parent" && pwd)/$(basename "$dest")"

if [[ -e "$dest" ]]; then
  if [[ "$force" != "true" ]]; then
    echo "Destination already exists: $dest" >&2
    exit 1
  fi
  rm -rf "$dest"
fi

mkdir -p "$dest"
cp -R "$template_dir"/. "$dest"/

app_title="$app_name"
app_slug="$(printf '%s' "$app_name" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-' | sed 's/^-//; s/-$//')"
if [[ -z "$app_slug" ]]; then
  app_slug="terminal-operator"
fi

while IFS= read -r file; do
  APP_NAME="$app_name" APP_TITLE="$app_title" APP_SLUG="$app_slug" \
    perl -0pi -e 'my $name = $ENV{APP_NAME}; my $title = $ENV{APP_TITLE}; my $slug = $ENV{APP_SLUG}; s/__APP_NAME__/$name/g; s/__APP_TITLE__/$title/g; s/__APP_SLUG__/$slug/g;' "$file"
done < <(find "$dest" -type f)

echo "Scaffolded $template_id to $dest"
echo "App title: $app_title"
echo "App slug: $app_slug"
