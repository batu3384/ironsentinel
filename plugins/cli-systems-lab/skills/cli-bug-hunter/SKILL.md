---
name: cli-bug-hunter
description: Find logic bugs, regressions, state bugs, exit-code mistakes, and unsafe terminal assumptions in CLI and TUI applications.
metadata:
  author: local
  version: "0.1.0"
  argument-hint: <repo-or-entrypoint>
---

# CLI Bug Hunter

Use this skill when the user asks to find bugs, investigate failures, review regressions, or harden a CLI or terminal UI.

Start with `../../scripts/inspect_cli_repo.sh` and then use `../../scripts/run_cli_quick_audit.sh` when the toolchain is available.

## Failure Classes To Prioritize

- Incorrect exit codes or swallowed errors
- Ambiguous stdout and stderr usage
- Broken flag parsing, validation, or defaulting
- TTY-only assumptions that fail in CI, pipes, or logs
- Bubble Tea or Textual state transitions that drift from the rendered state
- Cancellation, timeout, and signal-handling bugs
- Config, env, and file precedence mistakes
- Shell wrappers that mask or rewrite failures

## Workflow

1. Reproduce or infer the failure path.
   - Identify the command, input mode, config source, and environment assumptions.
2. Audit the narrowest relevant code surface first.
   - Entrypoints
   - Command handlers
   - Parsing and validation
   - Renderer or view state
   - Config loading
   - Tests
3. Use stack-aware checks.
   - Go: `go test`, `go vet`, `golangci-lint`
   - Python: `pytest`, Ruff, mypy, `CliRunner`
   - Rust: `cargo test`, Clippy, `assert_cmd` or snapshots
   - Node.js: framework-native command tests plus explicit stdout and stderr assertions
   - Shell: ShellCheck for wrappers and install scripts
4. Fix with a regression test whenever feasible.

## Review Mode

If the user asks for a review, findings come first. Prioritize behavior regressions, correctness, and missing tests over stylistic commentary.
