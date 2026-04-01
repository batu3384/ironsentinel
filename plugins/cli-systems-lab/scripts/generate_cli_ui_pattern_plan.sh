#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: generate_cli_ui_pattern_plan.sh [repo-root]

Generate a narrower pattern-level CLI UI plan with a recommended scaffold.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="${1:-.}"
repo_root="$(cd "$repo_root" && pwd)"

inspect_output="$(bash "$script_dir/inspect_cli_repo.sh" "$repo_root")"

has_marker() {
  local marker="$1"
  grep -Fq "$marker" <<<"$inspect_output"
}

pattern_name="Onboarding Runway"
template_id="python-typer-rich-onboarding"
why="The repo appears command-oriented and benefits from a guided first-run surface."

if has_marker "Bubble Tea"; then
  pattern_name="Operator Cockpit"
  template_id="go-cobra-bubbletea-onboarding"
  why="Bubble Tea points to a long-running operator loop where quit, resize, and fallback behavior matter."
elif has_marker "Textual"; then
  pattern_name="Operator Cockpit"
  template_id="python-textual-console"
  why="Textual points to a full-screen Python console rather than a linear onboarding flow."
elif has_marker "ratatui"; then
  pattern_name="Operator Cockpit"
  template_id="rust-clap-ratatui-dashboard"
  why="ratatui indicates a multi-pane terminal workbench."
elif has_marker "oclif" || has_marker "Ink"; then
  pattern_name="Operator Cockpit"
  template_id="node-oclif-ink-dashboard"
  why="The Node stack fits an interactive dashboard boundary with a plain fallback path."
elif has_marker "Shell scripts" && ! has_marker "Go" && ! has_marker "Typer" && ! has_marker "oclif" && ! has_marker "clap"; then
  pattern_name="Progress Ledger"
  template_id="shell-progress-ledger"
  why="Pure shell surfaces benefit most from stable, line-oriented step output."
elif has_marker "Typer"; then
  pattern_name="Guided Repair Flow"
  template_id="python-typer-repair-flow"
  why="Typer suits short repair and recovery flows without forcing a full-screen TUI."
elif has_marker "Cobra"; then
  pattern_name="Command Discovery Board"
  template_id="go-cobra-help-discovery"
  why="Cobra command trees often need help-output cleanup before any richer UI work."
fi

cat <<EOF
# CLI UI Pattern Plan

- Repository: \`$repo_root\`
- Recommended pattern: \`$pattern_name\`
- Recommended template: \`$template_id\`

Why:
$why

Scaffold:
\`bash $script_dir/scaffold_cli_ui_template.sh --template $template_id --dest $repo_root/.codex-ui-pattern --app-name "Terminal Operator"\`
EOF
