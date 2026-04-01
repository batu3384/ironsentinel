#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' 'Usage: generate_cli_audit_report.sh [repo-root] [output-file]'
}

join_list() {
  awk 'BEGIN { first = 1 } { if (!first) printf ", "; printf "%s", $0; first = 0 } END { printf "" }'
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="${1:-.}"
repo_root="$(cd "$repo_root" && pwd)"
output_file="${2:-$repo_root/cli-audit-report.md}"

tmp_inventory="$(mktemp)"
tmp_audit="$(mktemp)"
trap 'rm -f "$tmp_inventory" "$tmp_audit"' EXIT

"$script_dir/inspect_cli_repo.sh" "$repo_root" > "$tmp_inventory"
if "$script_dir/run_cli_quick_audit.sh" "$repo_root" > "$tmp_audit" 2>&1; then
  audit_status="passed"
else
  audit_status="failed"
fi

detected_languages="$({
  awk '
    /^Detected languages and wrappers:/ {capture=1; next}
    /^$/ && capture==1 {capture=0}
    capture==1 && /^  - / {sub(/^  - /, ""); print}
  ' "$tmp_inventory"
} | join_list)"

detected_frameworks="$({
  awk '
    /^Detected frameworks and libraries:/ {capture=1; next}
    /^$/ && capture==1 {capture=0}
    capture==1 && /^  - / {sub(/^  - /, ""); print}
  ' "$tmp_inventory"
} | join_list)"

priority_areas="$(awk '
  /^Priority review areas:/ {capture=1; next}
  /^$/ && capture==1 {capture=0}
  capture==1 {print}
' "$tmp_inventory")"

recommended_commands="$(awk '
  /^Recommended commands:/ {capture=1; next}
  capture==1 && /^  - / {sub(/^  - /, "- "); print}
' "$tmp_inventory")"

missing_tools="$(awk '/^SKIP: / {sub(/^SKIP: /, "- "); print}' "$tmp_audit")"

if [[ -z "$detected_languages" ]]; then
  detected_languages="unknown"
fi
if [[ -z "$detected_frameworks" ]]; then
  detected_frameworks="none detected"
fi
if [[ -z "$recommended_commands" ]]; then
  recommended_commands="- none suggested"
fi
if [[ -z "$missing_tools" ]]; then
  missing_tools="- none"
fi
if [[ -z "$priority_areas" ]]; then
  priority_areas="- none detected"
fi

report_date="$(date '+%Y-%m-%d %H:%M:%S %z')"

{
  printf '# CLI Audit Report\n\n'
  printf '## Scope\n\n'
  printf -- '- Target: %s\n' "$repo_root"
  printf -- '- Date: %s\n' "$report_date"
  printf -- '- Reviewer: CLI Systems Lab\n\n'

  printf '## Stack Detection\n\n'
  printf -- '- Languages: %s\n' "$detected_languages"
  printf -- '- Frameworks: %s\n\n' "$detected_frameworks"

  printf '## Evidence Run\n\n'
  printf -- '- Inventory status: captured\n'
  printf -- '- Quick audit status: %s\n\n' "$audit_status"

  printf '### Recommended Commands\n\n%s\n\n' "$recommended_commands"
  printf '### Missing Tools\n\n%s\n\n' "$missing_tools"

  printf '## Priority Review Areas\n\n%s\n\n' "$priority_areas"

  printf '## Inventory Output\n\n```text\n'
  cat "$tmp_inventory"
  printf '\n```\n\n'

  printf '## Quick Audit Output\n\n```text\n'
  cat "$tmp_audit"
  printf '\n```\n\n'

  printf '## Findings\n\n'
  printf '### High Risk\n\n- [Fill after review]\n\n'
  printf '### Medium Risk\n\n- [Fill after review]\n\n'
  printf '### Low Risk\n\n- [Fill after review]\n\n'
  printf '## Quick Wins\n\n- [Fill after review]\n\n'
  printf '## Modernization Opportunities\n\n- [Fill after review]\n\n'
  printf '## Recommended Next Step\n\n- Start with the highest-risk review area above, then turn findings into tests before refactoring.\n'
} > "$output_file"

printf 'Wrote %s\n' "$output_file"
