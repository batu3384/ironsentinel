#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: generate_cli_ui_brief.sh [repo-root]

Generate a stack-aware CLI/TUI interface brief from repository markers.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="${1:-.}"
repo_root="$(cd "$repo_root" && pwd)"

inspect_output="$("$script_dir/inspect_cli_repo.sh" "$repo_root")"

has_marker() {
  local marker="$1"
  grep -Fq "$marker" <<<"$inspect_output"
}

surface_model="Styled command output with selective prompt flows"
visual_thesis="Build a crisp, low-noise terminal interface that makes the next operator action obvious."
priority_one="Help output, command discovery, and first-run guidance"
priority_two="stdout/stderr contracts, no-color mode, and non-interactive safety"
priority_three="Narrow-width readability and error-state recovery"
lead_mascot="Scout"

if has_marker "Bubble Tea" || has_marker "Textual"; then
  surface_model="Full-screen TUI with a plain-text fallback path"
  visual_thesis="Build a focused operator cockpit that stays readable under pressure and degrades cleanly outside an interactive terminal."
  priority_one="Primary pane hierarchy, keymap visibility, and live-state clarity"
  priority_two="Quit, cancel, resize, and non-TTY fallback behavior"
  priority_three="Reduced motion, alternate-screen cleanup, and narrow-width collapse rules"
  lead_mascot="Pulse"
elif has_marker "Cobra" || has_marker "Typer" || has_marker "oclif" || has_marker "clap"; then
  surface_model="Structured command UX with guided prompts for setup and bootstrap flows"
  visual_thesis="Make command discovery fast, friendly, and deterministic without hiding machine-safe behavior."
  priority_one="Command journey, help ergonomics, and onboarding prompts"
  priority_two="Pipe safety, JSON/plain fallback, and error text quality"
  priority_three="Completion states, empty states, and progressive disclosure"
  lead_mascot="Scout"
fi

cat <<EOF
# CLI UI Brief

## Target

- Repository: \`$repo_root\`
- Lead mascot: \`$lead_mascot\`

## Visual Thesis

$visual_thesis

## Recommended Surface

- Surface model: $surface_model

## Detected Stack

\`\`\`text
$inspect_output
\`\`\`

## Priority States

1. $priority_one
2. $priority_two
3. $priority_three

## Fallback Strategy

- No TTY: plain output, no prompts, no alternate screen
- No color: preserve hierarchy with spacing and labels only
- Narrow width: compress columns before dropping core actions
- Reduced motion: remove decorative loops before status transitions

## Validation Checklist

- interactive happy path
- help output and first-run guidance
- narrow-width behavior
- redirected output behavior
- no-color behavior
- cancellation and exit cleanup
EOF
