---
name: cli-systems-orchestrator
description: Triage a CLI or TUI repo, choose the right CLI Systems Lab workflow, and drive modernization, bug hunting, and quality scanning in the right order.
metadata:
  author: local
  version: "0.13.0"
  argument-hint: <repo-or-entrypoint>
---

# CLI Systems Orchestrator

Use this as the default entrypoint when the user wants a complete CLI or TUI improvement pass.

Start here:

1. Read `../../docs/research-notes.md`.
2. Read `../../docs/stack-playbooks.md`.
3. Run `../../scripts/inspect_cli_repo.sh <target>`.
4. If safe, run `../../scripts/run_cli_quick_audit.sh <target>`.
5. If the user wants a written deliverable, run `../../scripts/generate_cli_audit_report.sh <target>`.
6. If the user wants implementation guidance or direct fixes, route through `cli-remediation-engine` and `../../scripts/generate_cli_fix_plan.sh`.
7. If the user wants interface or TUI work, route through `cli-ui-composer`, `../../scripts/generate_cli_ui_brief.sh`, `../../scripts/generate_cli_ui_patch_plan.sh`, and `../../scripts/generate_cli_ui_pattern_plan.sh`.

## Routing Rules

- If the user asks to redesign, modernize, simplify, or improve the command UX, route to `cli-modernization` first.
- If the user asks to improve onboarding, prompt flows, help UX, dashboards, theming, or terminal interface quality, route to `cli-ui-composer` first.
- If the user asks to find bugs, regressions, logic errors, or failing behavior, route to `cli-bug-hunter` first.
- If the user asks for a review, audit, analysis, or full health check, route to `cli-quality-scan` first.
- If the user asks to turn findings into patches, route to `cli-remediation-engine` after the audit step.
- On broad requests, do all four in this order:
  1. `cli-quality-scan`
  2. `cli-bug-hunter`
  3. `cli-remediation-engine`
  4. `cli-modernization`
  5. `cli-ui-composer`

## Required Output

Always produce these artifacts in your response:

- Detected stack and likely framework surface
- Highest-risk behavior issues
- Quick wins
- Evidence run or missing tooling
- Next implementation step

If you changed code, include tests or explain why you could not.
