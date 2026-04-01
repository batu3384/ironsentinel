#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' 'Usage: generate_cli_fix_plan.sh <audit-report.md> [output-file]'
}

join_list() {
  awk 'BEGIN { first = 1 } NF { if (!first) printf ", "; printf "%s", $0; first = 0 } END { printf "" }'
}

if [[ $# -lt 1 || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  [[ $# -lt 1 ]] && exit 1 || exit 0
fi

audit_report="$1"
output_file="${2:-$(cd "$(dirname "$audit_report")" && pwd)/cli-fix-plan.md}"

if [[ ! -f "$audit_report" ]]; then
  printf 'Audit report not found: %s\n' "$audit_report" >&2
  exit 1
fi

audit_report="$(cd "$(dirname "$audit_report")" && pwd)/$(basename "$audit_report")"

target="$(awk -F': ' '/^- Target:/ {print $2; exit}' "$audit_report")"
languages="$(awk -F': ' '/^- Languages:/ {print $2; exit}' "$audit_report")"
frameworks="$(awk -F': ' '/^- Frameworks:/ {print $2; exit}' "$audit_report")"
quick_audit_status="$(awk -F': ' '/^- Quick audit status:/ {print $2; exit}' "$audit_report")"

priority_areas="$(awk '
  /^## Priority Review Areas/ {capture=1; next}
  /^## / && capture==1 {capture=0}
  capture==1 && NF {print}
' "$audit_report")"

missing_tools="$(awk '
  /^### Missing Tools/ {capture=1; next}
  /^## / && capture==1 {capture=0}
  /^### / && capture==1 {capture=0}
  capture==1 && NF {print}
' "$audit_report")"

recommended_commands="$(awk '
  /^### Recommended Commands/ {capture=1; next}
  /^## / && capture==1 {capture=0}
  /^### / && capture==1 {capture=0}
  capture==1 && NF {print}
' "$audit_report")"

high_value_files="$(awk '
  /^High-value files:/ {capture=1; next}
  /^Recommended commands:/ && capture==1 {capture=0}
  capture==1 && NF {print}
' "$audit_report" | head -n 12)"

if [[ -z "$target" ]]; then
  target="unknown"
fi
if [[ -z "$languages" ]]; then
  languages="unknown"
fi
if [[ -z "$frameworks" ]]; then
  frameworks="none detected"
fi
if [[ -z "$quick_audit_status" ]]; then
  quick_audit_status="unknown"
fi
if [[ -z "$priority_areas" ]]; then
  priority_areas="- none detected"
fi
if [[ -z "$missing_tools" ]]; then
  missing_tools="- none"
fi
if [[ -z "$recommended_commands" ]]; then
  recommended_commands="- none suggested"
fi
if [[ -z "$high_value_files" ]]; then
  high_value_files="- none extracted"
fi

p0_items=()
p1_items=()
p2_items=()
verification_items=()

if [[ "$frameworks" == *"Cobra"* ]]; then
  p0_items+=("Validate root command execution, exit codes, and stderr/stdout behavior in the main Cobra entrypoints.")
  p1_items+=("Audit context propagation from root commands into long-running operations and network or filesystem work.")
  p2_items+=("Review help text, command discoverability, and completion-related UX after correctness work lands.")
  verification_items+=("Run targeted command tests around flag parsing, output, and error paths before broad go test ./...")
fi

if [[ "$frameworks" == *"Bubble Tea"* ]]; then
  p0_items+=("Inspect Update paths for stuck states, quit handling, and key-driven transitions that can desync behavior from visible state.")
  p1_items+=("Add or tighten focused model or snapshot tests around the most volatile TUI screens.")
  p2_items+=("Review non-TTY degradation and styling assumptions after state correctness is locked down.")
  verification_items+=("Re-run targeted TUI tests first, then broader package tests for CLI surfaces.")
fi

if [[ "$languages" == *"Shell scripts"* ]]; then
  p0_items+=("Review wrapper scripts for quoting bugs, argument forwarding mistakes, and swallowed exit codes.")
  p1_items+=("Back wrapper fixes with smoke tests or at least reproducible command samples.")
  verification_items+=("Run shellcheck once available and compare wrapper exit behavior before and after the patch.")
fi

if [[ "$languages" == *"Go"* ]]; then
  p1_items+=("Tighten package-level tests for the command and TUI paths named in the audit before structural refactors.")
  verification_items+=("Run go test ./... and go vet ./...; add golangci-lint run when the tool is installed.")
fi

if [[ ${#p0_items[@]} -eq 0 ]]; then
  p0_items+=("Start with the highest-priority review area from the audit and convert it into a concrete failing test or reproduction path.")
fi
if [[ ${#p1_items[@]} -eq 0 ]]; then
  p1_items+=("Add regression coverage around the most user-visible command path before refactoring.")
fi
if [[ ${#p2_items[@]} -eq 0 ]]; then
  p2_items+=("Clean up help text, docs, and non-interactive behavior after correctness issues are addressed.")
fi
if [[ ${#verification_items[@]} -eq 0 ]]; then
  verification_items+=("Use the narrowest available test or lint command first, then re-run the broader audit commands.")
fi

{
  printf '# CLI Fix Plan\n\n'
  printf '## Scope\n\n'
  printf -- '- Audit report: %s\n' "$audit_report"
  printf -- '- Target: %s\n' "$target"
  printf -- '- Languages: %s\n' "$languages"
  printf -- '- Frameworks: %s\n' "$frameworks"
  printf -- '- Quick audit status: %s\n\n' "$quick_audit_status"

  printf '## Missing Tools\n\n%s\n\n' "$missing_tools"
  printf '## Priority Review Areas\n\n%s\n\n' "$priority_areas"
  printf '## Likely Touch Points\n\n'
  while IFS= read -r line; do
    [[ -n "$line" ]] && printf -- '- %s\n' "$line"
  done <<< "$high_value_files"
  printf '\n'

  printf '## P0 Remediation\n\n'
  for item in "${p0_items[@]}"; do
    printf -- '- %s\n' "$item"
  done
  printf '\n'

  printf '## P1 Remediation\n\n'
  for item in "${p1_items[@]}"; do
    printf -- '- %s\n' "$item"
  done
  printf '\n'

  printf '## P2 Remediation\n\n'
  for item in "${p2_items[@]}"; do
    printf -- '- %s\n' "$item"
  done
  printf '\n'

  printf '## Verification Sequence\n\n'
  for item in "${verification_items[@]}"; do
    printf -- '- %s\n' "$item"
  done
  printf '\n'

  printf '## Recommended Commands From Audit\n\n%s\n\n' "$recommended_commands"
  printf '## Patch Workflow\n\n'
  printf -- '- Pick one P0 item and identify the narrowest affected files above.\n'
  printf -- '- Add or run a targeted test or reproducible command.\n'
  printf -- '- Patch the smallest safe surface.\n'
  printf -- '- Re-run the targeted checks, then the broader commands from the audit.\n'
  printf -- '- Update the audit report or findings summary with confirmed results.\n'
} > "$output_file"

printf 'Wrote %s\n' "$output_file"
