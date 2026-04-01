# CLI UI Pattern Catalog

Use this catalog after choosing the surface model. The goal is to turn abstract "make it more modern" requests into a small number of operator-facing flows that can actually be implemented.

## Pattern 1: Onboarding Runway

Use for first-run setup, auth bootstrap, environment validation, and project initialization.

- Start with a short status header that says what will be configured.
- Show one primary action per step.
- Expose a skip or non-interactive flag path before adding prompts.
- End with a next-command handoff instead of a decorative success screen.

Good fit:

- Cobra plus prompt flow
- Typer plus Rich prompt flow
- oclif plus interactive setup command
- clap plus explicit wizard subcommand

## Pattern 2: Guided Repair Flow

Use when the tool detects broken prerequisites, missing config, or recoverable validation errors.

- Explain the failure in one sentence.
- Show the shortest repair action first.
- Keep the original raw error available under a details toggle or verbose path.
- Preserve stable exit codes for scripts.

Good fit:

- Installers
- Login and credential repair
- Missing dependency repair
- Release or packaging preflight failures

## Pattern 3: Operator Cockpit

Use for long-running scans, queue work, monitoring, incident response, and any workflow where the user needs to watch changing state.

- Put the live status in the top-left or first visible zone.
- Keep key actions visible at all times.
- Make cancel and quit paths obvious.
- Collapse panels before truncating the primary action area.

Good fit:

- Bubble Tea dashboards
- Textual consoles
- Ink or blessed operations panels
- ratatui workbenches

## Pattern 4: Command Discovery Board

Use when the main problem is poor help UX, weak subcommand naming, or confusing entrypoints.

- Group commands by operator job, not by implementation layer.
- Highlight the top three tasks in help output.
- Keep advanced flags out of the first scan line.
- Add one short example per high-value command.

Good fit:

- Cobra root help redesign
- Typer command grouping
- oclif topic help cleanup
- clap help templates

## Pattern 5: Progress Ledger

Use for build, release, migration, backup, and any multi-step job where users want a stable sense of advancement.

- Keep step labels static.
- Update state markers rather than repainting the entire screen.
- Surface warnings inline with the affected step.
- Finish with artifact paths, checksums, or next actions.

Good fit:

- Release tooling
- Migration runners
- Scanners and package installers
- Sync or import pipelines

## Pattern 6: Empty State with Direction

Use when the interface opens before any projects, runs, findings, dashboards, or accounts exist.

- Say what is missing.
- Show the first command or key action to fix it.
- Avoid motivational filler.
- If possible, include one realistic example target.

Good fit:

- New repo state
- No findings or no runs yet
- No projects configured
- Fresh local install

## Stack Translation Notes

### Go: Cobra, Bubble Tea, Lip Gloss

- Put discovery and examples in Cobra help first.
- Keep Bubble Tea responsible only for interactive loops.
- Route no-TTY and `NO_COLOR` paths back to plain Cobra output.
- Treat `cmd.Context()` propagation and quit cleanup as part of UI quality.

### Python: Typer, Rich, Textual

- Keep typed CLI entrypoints stable and move styling into presentation helpers.
- Use Rich for linear views and Textual only for real focus-driven loops.
- Make async teardown explicit in Textual apps.

### Node.js: oclif, Ink

- Preserve machine-readable output modes.
- Keep onboarding prompts isolated from command execution mode.
- Ensure Ink render loops do not own stderr or stdout in pipe mode.

### Rust: clap, ratatui

- Keep clap help templates sharp and example-driven.
- Use ratatui for multi-pane stateful work only.
- Treat panic recovery and alternate-screen restoration as required behavior.

## Validation Anchors

Every chosen pattern should still prove:

- interactive happy path
- narrow-width readability
- `NO_COLOR` fallback
- redirected output behavior
- reduced-motion or low-animation behavior
- clean cancellation and terminal restore
