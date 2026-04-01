# CLI UI Playbook

Use this when a CLI repo needs interface work rather than only bug fixing or architecture cleanup.

## Surface Selection

- Styled command output: short tasks, health checks, reports, release summaries
- Guided prompt flow: first-run setup, auth bootstrap, profile selection, project creation
- Full-screen TUI: monitoring, queue control, multi-pane inspection, live scan loops

Choose the simplest surface that makes the operator faster.

## Visual System

- One neutral ramp, one accent family, one alert family
- Prefer hierarchy, spacing, and grouping before borders and badges
- Keep labels short and operational
- Make empty, loading, success, and error states first-class

## Motion

- Animate only state changes, focus shifts, progress, and live updates
- Keep non-essential loops light and removable
- Always support a reduced-motion mode when the stack allows it

## Stack Patterns

### Go: Cobra, Bubble Tea, Lip Gloss

- Use Cobra for command discovery and plain fallback output
- Use Bubble Tea for operator loops and focus-driven workflows
- Keep `Update` and `View` separate and pass `cmd.Context()` all the way through
- Validate non-TTY paths and width handling explicitly

### Python: Typer, Rich, Textual

- Keep typed command signatures stable
- Separate Rich-styled output from plain log-safe output
- For Textual, treat async tasks and teardown as UI correctness issues, not polish

### Node.js: oclif, Ink

- Keep JSON mode and machine-readable output free of styling noise
- Use prompt flows only when stdin is interactive
- Make render loops and cleanup behavior explicit

### Rust: clap, ratatui

- Keep parser help crisp and typed
- Treat alternate-screen cleanup and panic exit recovery as must-have behavior
- Maintain a readable plain mode outside the TUI

## UI States

Every CLI/TUI feature should define:

- default or idle state
- loading state
- empty state
- error state
- success or completion state
- interrupted or canceled state

## Fallback Strategy

- `NO_COLOR`: no semantic loss, only style loss
- redirected stdout: no prompts, no alternate screen, no animation
- narrow width: compress columns, drop chrome, preserve the primary action
- reduced motion: remove non-essential loops first
- `TERM=dumb`: plain text and stable exit codes

## High-Value CLI UI Findings

- help output hides primary commands
- prompts appear in non-interactive mode
- stdout/stderr are mixed
- loading states block cancellation
- TUI exit leaves the terminal dirty
- color carries meaning with no plain fallback
- narrow width breaks action visibility
