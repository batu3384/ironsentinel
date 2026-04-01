# CLI UI Surface Matrix

Use this matrix when the stack is clear but the exact UI surface is not. It separates stack choice from operator task choice so the plugin can recommend a smaller, more targeted scaffold.

## Command Discovery Board

Use when the main problem is command naming, help output, or entrypoint sprawl.

- Go plus Cobra: `go-cobra-help-discovery`
- Python plus Typer: `python-typer-rich-onboarding`
- Node plus oclif: `node-oclif-ink-dashboard` only if the flow truly needs an interactive help shell; otherwise stay plain
- Rust plus clap: `rust-clap-ratatui-dashboard` only if discovery is tied to a live workbench; otherwise keep clap help plain

## Onboarding Runway

Use when the first-run path is weak and the operator needs guided setup.

- Go plus Cobra plus Bubble Tea: `go-cobra-bubbletea-onboarding`
- Python plus Typer plus Rich: `python-typer-rich-onboarding`
- Node plus oclif: `node-oclif-ink-dashboard` only for interactive setup consoles

## Guided Repair Flow

Use when the product mostly works but prerequisite or config failures need a faster recovery path.

- Python plus Typer plus Rich: `python-typer-repair-flow`
- Go plus Cobra: adapt `go-cobra-help-discovery` and keep repair text on stderr
- Shell: adapt `shell-progress-ledger` and keep stable exit codes

## Operator Cockpit

Use for monitoring, scan consoles, queue control, and any long-running multi-pane loop.

- Go plus Bubble Tea: `go-cobra-bubbletea-onboarding` as a cockpit boundary starter
- Python plus Textual: `python-textual-console`
- Node plus Ink: `node-oclif-ink-dashboard`
- Rust plus ratatui: `rust-clap-ratatui-dashboard`

## Progress Ledger

Use for build, release, install, migration, or sync workflows where users need a stable sense of step progression.

- Shell: `shell-progress-ledger`
- Go: adapt `go-cobra-help-discovery` or add a plain progress view before any TUI
- Python: adapt `python-typer-repair-flow`

## Rule

Pick the narrowest scaffold that matches the operator job. Do not force a dashboard starter into a problem that only needs clearer help text or a better repair path.
