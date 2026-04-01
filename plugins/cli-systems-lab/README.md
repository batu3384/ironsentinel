# CLI Systems Lab

CLI Systems Lab is a local Codex plugin for building, reviewing, modernizing, and debugging CLI and TUI applications.

## Included Skills

- `cli-systems-orchestrator`: Default router for full-pass CLI and TUI analysis.
- `cli-ui-composer`: Design CLI onboarding, prompt flows, dashboards, theming, and fallback-safe TUI improvements.
- `cli-modernization`: Refactor command architecture, terminal UX, help output, config flow, and observability.
- `cli-bug-hunter`: Find logic bugs, regressions, exit code problems, TTY assumptions, and state-flow issues.
- `cli-quality-scan`: Run a stack-aware audit across tests, linters, help UX, packaging, and non-interactive behavior.
- `cli-remediation-engine`: Turn audit outputs into prioritized findings, patch plans, and implementation steps.

## Included Scripts

- `scripts/inspect_cli_repo.sh`: Detect stack markers and print a prioritized audit plan.
- `scripts/run_cli_quick_audit.sh`: Run safe, high-value checks for Go, Rust, Python, and shell repos when tools are installed.
- `scripts/generate_cli_audit_report.sh`: Generate a Markdown audit report with detected stack, evidence, and placeholders for findings.
- `scripts/generate_cli_fix_plan.sh`: Generate a prioritized remediation plan from an audit report.
- `scripts/generate_cli_ui_brief.sh`: Generate a stack-aware CLI/TUI interface brief with fallback and validation guidance.
- `scripts/generate_cli_ui_patch_plan.sh`: Generate a stack-aware UI implementation plan with candidate write targets and validation steps.
- `scripts/generate_cli_ui_pattern_plan.sh`: Generate a narrower pattern-level scaffold recommendation.
- `scripts/preview_cli_ui_templates.sh`: Preview starter templates from the local catalog before scaffolding.
- `scripts/scaffold_cli_ui_template.sh`: Copy a ready CLI/TUI starter template into a destination path.
- `scripts/ci_self_check.sh`: Run the plugin-local CI self-check suite from one entrypoint.
- `scripts/smoke_cli_ui_templates.sh`: Validate that template scaffolding and placeholder replacement stay correct.
- `scripts/smoke_cli_ui_patterns.sh`: Validate pattern-level starter selection across stack fixtures.
- `scripts/smoke_cli_ui_previews.sh`: Validate that template previews and golden samples stay in sync.
- `scripts/smoke_cli_ui_snapshots.sh`: Validate scaffolded template preview commands against golden sample outputs.

## Included Docs

- `docs/research-notes.md`: Official-source research summary.
- `docs/stack-playbooks.md`: Framework-specific review checklists.
- `docs/ui-playbook.md`: CLI and TUI surface-selection, fallback, and visual-system rules.
- `docs/ui-pattern-catalog.md`: Concrete CLI/TUI interaction patterns for onboarding, help, dashboards, and progress flows.
- `docs/ui-surface-matrix.md`: Map operator task types to the narrowest matching starter template per stack.
- `docs/ui-quality-gate.md`: Mandatory evidence checklist for terminal UX work.
- `docs/remediation-playbook.md`: Fix-first workflow after an audit.
- `docs/audit-template.md`: Reusable report structure.

## Included Templates

- `templates/go-cobra-bubbletea-onboarding`: Go starter for setup and onboarding flows with a Bubble Tea fallback boundary.
- `templates/go-cobra-help-discovery`: Go starter for help output, top-task grouping, and command discovery cleanup.
- `templates/node-oclif-ink-dashboard`: Node starter for operator dashboards with oclif, Ink, and plain pipe-safe fallback behavior.
- `templates/python-textual-console`: Python Textual starter for full-screen operator consoles with a plain fallback path.
- `templates/python-typer-rich-onboarding`: Python starter for onboarding and doctor flows with Rich and Typer.
- `templates/python-typer-repair-flow`: Python starter for repair-first error and recovery flows.
- `templates/rust-clap-ratatui-dashboard`: Rust starter for operator dashboards with a plain fallback path.
- `templates/shell-progress-ledger`: Shell starter for stable step-by-step progress output.

## Catalog

- `assets/template-catalog.json`: Local metadata catalog for previewing starter templates by stack, pattern, and use case.
- `assets/template-previews/*.txt`: Golden sample terminal outputs for each starter template.

## CI

- `.github/workflows/cli-systems-lab-self-check.yml`: Path-filtered GitHub Actions workflow that runs the plugin self-check suite.

## Research Basis

See `docs/research-notes.md` for the March 28, 2026 research summary built from official project documentation and repositories only.
