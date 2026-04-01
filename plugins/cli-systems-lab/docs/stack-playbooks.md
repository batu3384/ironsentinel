# CLI Stack Playbooks

Use these as fast checklists after running `scripts/inspect_cli_repo.sh`.

## Go: Cobra and Bubble Tea

### Architecture

- Verify `ExecuteContext(...)` or equivalent root context wiring exists.
- Check whether `cmd.Context()` is passed through network, filesystem, and long-running work.
- Inspect command registration for deep nesting, duplicated flags, and hidden alias drift.
- Confirm help text is specific and action-oriented.

### TUI Behavior

- Keep Bubble Tea `Init`, `Update`, and `View` responsibilities separate.
- Check quit paths, escape hatches, and keyboard discoverability.
- Confirm alternate-screen behavior is intentional.
- Validate non-TTY and redirected output behavior for any Lip Gloss styling.

### Quality Gates

- `go test ./...`
- `go vet ./...`
- `golangci-lint run`
- Snapshot or state-machine tests where TUI rendering drives behavior

## Python: Click, Typer, Textual

### Architecture

- Keep type-hint-driven command signatures stable.
- Check prompt defaults, env var resolution, and config precedence.
- Inspect lazy command loading and command grouping for help discoverability.

### TUI Behavior

- For Textual, inspect async workers, message flow, and screen transitions.
- Check whether visual state changes are covered by snapshot tests.
- Verify app behavior under different terminal sizes.

### Quality Gates

- `pytest`
- `ruff check .`
- `mypy .`
- `CliRunner` tests for command flows and prompts
- `pytest-asyncio` and `pytest-textual-snapshot` where relevant

## Node.js and TypeScript: oclif and Similar CLIs

### Architecture

- Verify `--json` mode is consistent and script-friendly.
- Inspect hooks and lifecycle logic for hidden side effects.
- Ensure help text and command taxonomy match actual user tasks.

### Behavior

- Check stdout and stderr separation.
- Validate structured output and non-interactive mode.
- Inspect installer, autocomplete, and docs generation workflows.

### Quality Gates

- Package-manager-native test and lint scripts
- Command tests that assert exit codes, stdout, stderr, and JSON output

## Rust: clap and Terminal Apps

### Architecture

- Inspect derive-based parsers and hand-written parsing branches for drift.
- Check generated help, suggestions, and completion generation.
- Keep state and rendering isolated when TUIs are layered on top of clap.

### Quality Gates

- `cargo test`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `assert_cmd`, `trycmd`, or snapshot-style output tests

## Shell Entry Points and Wrappers

### Architecture

- Verify wrapper scripts preserve exit codes.
- Check argument quoting, tempfile handling, and portability assumptions.
- Inspect install and release scripts, not only runtime entrypoints.

### Quality Gates

- `shellcheck <files>`
- Smoke tests for wrappers that forward flags and exit codes correctly

## Cross-Cutting Checks

- Help output must be readable in narrow terminals.
- Machine-friendly output must not contain decoration by default.
- Errors belong on stderr unless there is a deliberate contract otherwise.
- Color, animation, and cursor control must degrade safely outside a TTY.
- Config precedence should be documented and testable.
