#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: generate_cli_ui_patch_plan.sh [repo-root]

Generate a stack-aware UI implementation plan for CLI or TUI improvements.
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
brief_output="$(bash "$script_dir/generate_cli_ui_brief.sh" "$repo_root")"

has_marker() {
  local marker="$1"
  grep -Fq "$marker" <<<"$inspect_output"
}

pick_candidates() {
  local patterns=("$@")
  local found=""
  local pattern
  for pattern in "${patterns[@]}"; do
    found="$(rg --files "$repo_root" -g "$pattern" 2>/dev/null | sed "s#^$repo_root/##" | sort -u | head -n 5 || true)"
    if [[ -n "$found" ]]; then
      printf '%s\n' "$found"
      return 0
    fi
  done
  return 1
}

surface_model="styled-output"
lead_mascot="Scout"
starter_template="python-typer-rich-onboarding"
patch_one="Rework help output, command grouping, and first-run guidance."
patch_two="Separate interactive prompts from machine-safe stdout behavior."
patch_three="Add empty, loading, error, and success surfaces with no-color fallbacks."
patch_four="Add smoke checks for help output, non-interactive mode, and narrow-width behavior."
validation_hint="Run the interactive happy path plus redirected-output and NO_COLOR checks."
candidate_files="$(pick_candidates 'cmd/**' 'internal/cli/**' 'pkg/**' 'src/**' '*.go' '*.py' '*.ts' '*.rs' '*.sh' || true)"

if has_marker "Bubble Tea" || has_marker "Textual" || has_marker "ratatui"; then
  surface_model="full-screen-tui"
  lead_mascot="Pulse"
  patch_one="Stabilize the main viewport layout and keep the primary action visible at narrow widths."
  patch_two="Define loading, empty, success, error, and canceled states with explicit quit and cancel affordances."
  patch_three="Move no-TTY, NO_COLOR, and reduced-motion users onto a plain-text fallback path."
  patch_four="Add cleanup tests or smoke checks for resize, cancel, and alternate-screen exit behavior."
  validation_hint="Run a full-screen happy path, resize the terminal, cancel mid-flow, and confirm clean exit."
  candidate_files="$(pick_candidates 'internal/cli/**' 'pkg/**/tui*.go' '*tui*.go' '*dashboard*.go' 'src/**' '*.rs' '*.py' '*.ts' || true)"

  if has_marker "Textual"; then
    starter_template="python-textual-console"
    candidate_files="$(pick_candidates 'src/**' '*textual*.py' '*app*.py' '*.py' || true)"
  elif has_marker "ratatui"; then
    starter_template="rust-clap-ratatui-dashboard"
    candidate_files="$(pick_candidates 'src/**' '*.rs' || true)"
  else
    starter_template="go-cobra-bubbletea-onboarding"
  fi
fi

if [[ "$surface_model" != "full-screen-tui" ]] && has_marker "Cobra"; then
  starter_template="go-cobra-bubbletea-onboarding"
  candidate_files="$(pick_candidates 'cmd/**' 'internal/cli/**' 'internal/**/help*.go' '*.go' || true)"
elif [[ "$surface_model" != "full-screen-tui" ]] && has_marker "Textual"; then
  starter_template="python-textual-console"
  candidate_files="$(pick_candidates 'src/**' '*textual*.py' '*app*.py' '*.py' || true)"
elif [[ "$surface_model" != "full-screen-tui" ]] && has_marker "Typer"; then
  starter_template="python-typer-rich-onboarding"
  candidate_files="$(pick_candidates 'src/**' '*cli*.py' '*app*.py' '*.py' || true)"
elif [[ "$surface_model" != "full-screen-tui" ]] && { has_marker "oclif" || has_marker "Ink"; }; then
  starter_template="node-oclif-ink-dashboard"
  candidate_files="$(pick_candidates 'src/**' 'bin/**' 'packages/**' '*.ts' '*.js' || true)"
elif [[ "$surface_model" != "full-screen-tui" ]] && { has_marker "clap" || has_marker "ratatui"; }; then
  starter_template="rust-clap-ratatui-dashboard"
  candidate_files="$(pick_candidates 'src/**' '*.rs' || true)"
fi

if [[ -z "$candidate_files" ]]; then
  candidate_files="No obvious UI target files detected. Inspect the repo entrypoint and help surface manually."
fi

cat <<EOF
# CLI UI Patch Plan

## Visual Summary

- Repository: \`$repo_root\`
- Surface model: \`$surface_model\`
- Lead mascot: \`$lead_mascot\`

## Brief

\`\`\`markdown
$brief_output
\`\`\`

## Candidate Write Targets

\`\`\`text
$candidate_files
\`\`\`

## Starter Template

- Template id: \`$starter_template\`
- Scaffold command: \`bash $script_dir/scaffold_cli_ui_template.sh --template $starter_template --dest $repo_root/.codex-ui-starter --app-name "Terminal Operator"\`

## Patch Sequence

1. $patch_one
2. $patch_two
3. $patch_three
4. $patch_four

## State Contract

- Idle: show the operator's next action without hiding the plain command path.
- Loading: expose progress and keep cancel or escape behavior visible.
- Empty: explain what is missing and show the first recovery action.
- Error: lead with the actionable repair step and keep raw diagnostics available.
- Success: finish with the next command, output path, or artifact summary.
- Interrupted: exit cleanly with stable terminal and exit-code behavior.

## Fallback Contract

- No TTY: disable prompts, alternate screen, and animation.
- NO_COLOR: keep hierarchy with spacing, labels, and ordering only.
- Narrow width: drop chrome before dropping the primary action area.
- Reduced motion: keep status changes, remove decorative pulses.
- Pipe mode: reserve stdout for data, push UX guidance to stderr when needed.

## Validation

- $validation_hint
- Verify help output or entry screen scans in under ten seconds.
- Verify redirected output does not contain prompt or TUI artifacts.
- Verify the quit path leaves the terminal usable.
EOF
