# CLI Remediation Playbook

Use this after an audit when the next goal is to turn analysis into concrete fixes.

## Order Of Operations

1. Confirm the stack and framework surface from the audit report.
2. Pull the top priority review areas.
3. Open the most relevant command entrypoints, handlers, wrappers, and tests.
4. Write or identify the narrowest test that proves the issue.
5. Patch the smallest possible surface.
6. Re-run targeted checks.
7. Re-run broad checks only after the targeted loop passes.

## What To Fix First

### P0

- Broken exit codes
- Wrong stdout versus stderr usage
- Crashes, hangs, or unrecoverable state loops
- Config precedence bugs
- Shell wrappers that swallow failures

### P1

- Missing context cancellation or timeout handling
- Inconsistent JSON or machine-readable output
- Bubble Tea or Textual state/render drift
- Missing regression tests around important commands

### P2

- Help text drift
- Command discoverability and completion gaps
- Styling that breaks in non-TTY mode
- Documentation and release ergonomics

## Stack-Specific Remediation Hints

### Cobra

- Trace the root command execution path before changing subcommands.
- Prefer `ExecuteContext(...)` and explicit propagation of `cmd.Context()`.
- Add tests around command output and flag handling before refactors.

### Bubble Tea

- Keep state mutation in `Update` and formatting in `View`.
- Add targeted model tests or snapshot tests before changing rendering behavior.
- Verify graceful quit paths and keyboard handling.

### Python CLIs

- Preserve typed signatures and prompt behavior.
- Use `CliRunner` to lock command contracts before changes.
- For Textual, cover async interactions and screen transitions.

### oclif and Node CLIs

- Protect `--json` mode and stderr/stdout contracts with tests.
- Keep hooks explicit and narrow.
- Treat docs generation and command taxonomy as part of the UX contract.

### Rust CLIs

- Use command-output tests around clap-driven parsing and help text.
- Run Clippy after behavior fixes to catch adjacent correctness issues.

### Shell

- Fix quoting, argument forwarding, tempfiles, and preserved exit codes first.
- Add smoke tests for wrappers that invoke the real binary.

## Verification Pattern

- targeted test
- narrow lint or vet pass
- broader package or repo test pass
- regenerate audit artifacts if they are part of the workflow
