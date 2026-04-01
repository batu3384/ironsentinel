---
name: cli-modernization
description: Modernize CLI and TUI architecture, help UX, output behavior, and observability without breaking user-facing contracts unless explicitly approved.
metadata:
  author: local
  version: "0.4.0"
  argument-hint: <repo-or-entrypoint>
---

# CLI Modernization

Use this skill when a user asks to redesign, refactor, modernize, or improve a CLI or TUI end to end.

Start by reading `../../docs/research-notes.md`, then inspect the target repo with `../../scripts/inspect_cli_repo.sh`.

If the request is strongly UI- or TUI-focused, pair this with `cli-ui-composer` and `../../scripts/generate_cli_ui_brief.sh`.

## Workflow

1. Inventory the command surface.
   - Read entrypoints, command registration, help text, shell completion support, config loading, env var parsing, signal handling, and tests.
   - Capture current behavior before making structural changes.
2. Map the stack and apply the matching framework rules.
   - Go and Cobra: preserve command hierarchy, improve help ergonomics, and push context through `ExecuteContext(...)` and `cmd.Context()`.
   - Bubble Tea and Lip Gloss: keep state transitions explicit, preserve `Update` and `View` separation, and verify non-TTY rendering paths.
   - Python and Typer: preserve type-hint-driven command signatures and strengthen `CliRunner` coverage.
   - Textual: respect async flows and back changes with `pytest` plus `pytest-asyncio` and snapshot coverage when visuals matter.
   - Node.js and oclif: keep UX decisions explicit, tighten JSON mode, and use hooks only where lifecycle behavior is intentional.
   - Rust and clap: prefer typed parsers, polished help, completions, and command-output tests.
3. Modernize the high-value seams first.
   - Help output and error text
   - Exit codes
   - stdout versus stderr separation
   - Config precedence and default values
   - Cancellation, timeouts, and signal handling
   - Non-interactive and CI-safe output behavior
4. Ship evidence, not only opinions.
   - Add or update tests for every changed branch with user-visible impact.
   - Run stack-native checks where available.
   - Summarize any breaking-change risk before finalizing.

## Guardrails

- Do not rename commands, flags, or env vars unless the user approves the break.
- Do not add animation, color, or alternate-screen behavior that degrades logs, pipes, or CI output.
- Prefer real edits and tests over abstract advice.
