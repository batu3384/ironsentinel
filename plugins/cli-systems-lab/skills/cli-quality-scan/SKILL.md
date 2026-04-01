---
name: cli-quality-scan
description: Run a stack-aware CLI quality scan across tests, linters, help UX, output behavior, and modernization gaps.
metadata:
  author: local
  version: "0.1.0"
  argument-hint: <repo-or-entrypoint>
---

# CLI Quality Scan

Use this skill when the user asks to analyze, examine, audit, review, or harden a CLI or TUI repository.

Read `../../docs/research-notes.md` first, then use both plugin scripts:

- `../../scripts/inspect_cli_repo.sh`
- `../../scripts/run_cli_quick_audit.sh`

## Scan Dimensions

1. Command architecture
   - Subcommands, aliases, help output, completions, docs generation
2. Runtime correctness
   - Exit codes, cancellation, retries, timeout handling, signal behavior
3. Output contracts
   - stdout versus stderr, JSON mode, pipe safety, non-TTY rendering
4. Config model
   - Flags, env vars, config files, and default precedence
5. Test quality
   - Command tests, prompt tests, snapshots, async coverage for TUIs
6. Static analysis
   - Language-specific lint, type, and shell checks
7. Packaging and release ergonomics
   - Install paths, wrappers, docs, release scripts, and generated artifacts

## Reporting

- If checks pass, state what evidence was run and what residual risks remain.
- If checks fail, separate hard failures from missing tooling and from improvement opportunities.
- Prefer precise next actions over generic recommendations.
