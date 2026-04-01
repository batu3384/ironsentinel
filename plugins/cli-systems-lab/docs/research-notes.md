# CLI Systems Lab Research Notes

Updated: 2026-03-28

Method: official documentation and official project repositories only.

## Executive Summary

- Current CLI frameworks converge on a few durable expectations: generated help, typed arguments, completion support, test helpers, and clear behavior in non-interactive environments.
- TUI frameworks are increasingly state-driven and need deterministic tests. Bubble Tea emphasizes Elm-style state updates, while Textual documents async-aware testing and snapshot tooling.
- Fast static analysis is part of the modern baseline. Official docs currently position `golangci-lint`, Ruff, mypy, Clippy, and ShellCheck as mainstream quality gates.
- Observability has moved into the CLI layer. Cobra's current documentation explicitly covers context propagation and OpenTelemetry-based tracing for command-line applications.

## Official Findings By Ecosystem

### Go CLI and TUI

- Cobra's documentation currently treats tutorials, complete real-world examples, shell completion, LLM-ready CLI docs, and context/tracing as first-class how-to topics.
- Cobra's context guide recommends `cmd.Context()` propagation, cancellation-aware operations, and `ExecuteContext(ctx)` so commands can honor deadlines, cancellation, and trace metadata.
- Bubble Tea describes itself as a functional, stateful terminal framework built on the Elm Architecture and highlights built-in renderer and input features for production TUIs.
- Lip Gloss automatically downsamples color and removes ANSI styling when output is not a TTY, which matters for pipes, logs, and CI output.
- Design implication: modernization work should inspect command hierarchy, help text, completion, context cancellation, renderer assumptions, and keyboard shortcuts together rather than as separate tasks.

### Python CLI and TUI

- Click positions itself as a composable CLI toolkit with sensible defaults, automatic help generation, nested commands, and lazy subcommand loading.
- Typer's official tutorial is built around Python type hints and encourages hands-on execution of examples, which is a strong signal to preserve typed interfaces when refactoring.
- Typer's testing guide standardizes `CliRunner`, `runner.invoke(...)`, and explicit assertions on exit codes and output streams. It also documents prompt testing through `input=...`.
- Textual's testing guide recommends async-capable test frameworks, specifically `pytest` with `pytest-asyncio`, and exposes snapshot testing through the official `pytest-textual-snapshot` plugin.
- Design implication: Python CLI reviews should treat type hints, `CliRunner` coverage, async test support, and visual snapshot tests as part of the same quality story.

### Node.js and TypeScript CLI

- oclif's feature set emphasizes test helpers, auto-documentation, hooks, JSON output, autocomplete, and plugin extensibility.
- oclif's UX philosophy is explicit: the framework avoids forcing UX decisions, and instead exposes hooks and a `ux` module so teams can implement the exact interaction model they want.
- oclif's testing docs show `runCommand(...)`, `@oclif/test`, mocked HTTP interactions, and direct verification of exit codes and captured stdout/stderr.
- Design implication: Node CLI modernization should preserve command contracts while tightening JSON mode, help output, hooks, and test coverage for stderr/stdout behavior.

### Rust CLI

- clap presents itself as a full-featured command-line argument parser with polished help, suggested fixes, colored output, and shell completions out of the box.
- clap's docs also point directly to testing tools like `trycmd`, `snapbox`, and `assert_cmd`, which makes snapshot or command-output testing a first-class practice instead of an afterthought.
- Clippy currently documents more than 800 lints across correctness, suspicious, style, complexity, and performance categories.
- Design implication: Rust CLI work should combine clap ergonomics with Clippy gating and output-level tests to catch both UX and logic regressions early.

### Shell-Based CLI

- ShellCheck presents itself directly as a tool that finds bugs in shell scripts and is positioned as both a local install and editor-integrated linter.
- Design implication: any plugin that claims to debug CLI systems should treat shell entrypoints, wrappers, release scripts, and install scripts as part of the quality surface, not just the main binary.

## Plugin Design Choices Derived From Research

### Why Three Skills

- `cli-modernization` exists because the official framework docs all combine architecture and UX, not just styling.
- `cli-bug-hunter` exists because official testing docs across Typer, Textual, oclif, and clap all push behavior verification, exit codes, and output assertions.
- `cli-quality-scan` exists because the modern baseline is a combined pass across static analysis, tests, help UX, completions, non-interactive behavior, and packaging ergonomics.

### Why Two Scripts

- `inspect_cli_repo.sh` turns official framework guidance into a quick repo inventory so the agent can avoid stack-blind suggestions.
- `run_cli_quick_audit.sh` turns the documented quality tools into a practical first-pass evidence collector.

## Audit Priorities For CLI Systems

1. Command contract stability: subcommands, flags, aliases, help text, and completions.
2. Output discipline: correct use of stdout versus stderr, JSON mode, and pipe-friendly formatting.
3. Runtime resilience: context cancellation, signal handling, retries, and timeouts.
4. TUI safety: no hard dependency on color or TTY-only rendering when output is redirected.
5. Config correctness: precedence of flags, env vars, config files, and defaults.
6. Testability: framework-native command tests, snapshots where visual state matters, and regression coverage for exit codes.
7. Static analysis: fast lint and type gates before deeper refactors.

## Official Sources

- Cobra docs: https://cobra.dev/docs/
- Cobra context and tracing guide: https://cobra.dev/docs/how-to-guides/context-and-tracing/
- Bubble Tea repository README: https://github.com/charmbracelet/bubbletea
- Lip Gloss repository README: https://github.com/charmbracelet/lipgloss
- Click docs: https://click.palletsprojects.com/en/stable/
- Typer tutorial: https://typer.tiangolo.com/tutorial/
- Typer testing guide: https://typer.tiangolo.com/tutorial/testing/
- Textual testing guide: https://textual.textualize.io/guide/testing/
- oclif features: https://oclif.io/docs/features/
- oclif user experience guide: https://oclif.io/docs/user_experience/
- oclif testing guide: https://oclif.io/docs/testing/
- clap docs: https://docs.rs/clap/latest/clap/
- Clippy docs: https://doc.rust-lang.org/clippy/
- golangci-lint docs: https://golangci-lint.run/
- Ruff docs: https://docs.astral.sh/ruff/
- mypy docs: https://mypy.readthedocs.io/en/stable/
- ShellCheck: https://www.shellcheck.net/
