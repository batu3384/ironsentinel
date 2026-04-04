# Interface Review

> Historical snapshot: this review predates the current command-center architecture. Refer to [`docs/architecture.md`](/Users/batuhanyuksel/Documents/security/docs/architecture.md) for the live interface model.

## Executive Summary

The interface layer is credible as a power-user local AppSec CLI, but it is not yet a cohesive premium terminal product. The strongest parts are breadth of command coverage, scriptability, bilingual runtime output, and a clean split between explicit command usage and interactive fallbacks. The weakest parts are fragmentation across three user-facing surfaces (`overview`, `console`, `tui`), partial localization, weak large-result ergonomics, and a very large orchestration file that will slow down consistent evolution.

The main conclusion is straightforward: the product already has enough features, but the interface system is not yet unified into one opinionated operator workflow.

## Current Interface Architecture

- Entry point: [cmd/ironsentinel/main.go](/Users/batuhanyuksel/Documents/security/cmd/ironsentinel/main.go)
- Main command graph: [internal/cli/app.go:146](/Users/batuhanyuksel/Documents/security/internal/cli/app.go:146)
- Overview/dashboard surface: [internal/cli/dashboard.go:45](/Users/batuhanyuksel/Documents/security/internal/cli/dashboard.go:45)
- Fullscreen command center: [internal/cli/app_shell.go:1](/Users/batuhanyuksel/Documents/security/internal/cli/app_shell.go:1)
- Localization catalog: [internal/i18n/catalog.go:19](/Users/batuhanyuksel/Documents/security/internal/i18n/catalog.go:19)

The interface currently exposes three separate interaction models:

1. `overview`: static operational summary
2. `console`: prompt-driven guided loop
3. `tui`: historical compatibility entry into the fullscreen command center

## Strengths

- Command coverage is broad and already maps well to an AppSec workflow.
- Scriptability is preserved because explicit arguments work without interactivity.
- The guided scan flow is conceptually strong and captures mode, coverage, isolation, gate, and DAST options well.
- Runtime/setup guidance is visible and useful.
- Localization is centrally modeled instead of being scattered ad hoc.
- The TUI already uses a modern stack (`Bubble Tea`, `Lip Gloss`) and is a credible foundation.

## Weaknesses and Risks

- Interface fragmentation is the main product-level problem. The same concepts are rendered differently in `overview`, `console`, and `tui`.
- The TUI is still secondary. It is browse-oriented, not the operational center.
- Large-result ergonomics are weak: no viewport-based scrolling, saved filters, inline search, or grouped finding exploration.
- [internal/cli/app.go](/Users/batuhanyuksel/Documents/security/internal/cli/app.go) is too large and mixes command registration, prompting, rendering, setup, and scan composition.
- Localization is partial. Some help text and labels remain English-only or mixed even when the runtime language changes.
- The TUI uses fixed styling values and simple width heuristics instead of adaptive terminal rendering patterns.
- Interface-level tests are thin and mostly cover simple helpers rather than end-to-end workflows.

## Gaps vs a Premium Security Terminal Product

- No single dominant operator surface
- No TUI-native triage/suppression/export actions
- No scan progress view in the TUI
- No saved views or investigation context
- No shell completion guidance or Active Help workflow
- No plain/high-contrast/compact presentation mode
- No strong artifact/evidence navigation affordances

## Prioritized Recommendations

1. Choose one primary interface surface and demote the others to supporting roles.
2. Split `internal/cli/app.go` into focused packages such as `commands`, `prompts`, `views`, and `actions`.
3. Make localization complete, including help text and flag descriptions.
4. Turn the TUI into an operational console, not just a viewer.
5. Add result ergonomics: filtering, searching, grouping, paging, and row expansion.
6. Add interface regression tests, including localization and workflow snapshots.
7. Add terminal accessibility modes and adaptive styling.

## Reference Technologies

- [Cobra](https://github.com/spf13/cobra)
- [Bubble Tea](https://github.com/charmbracelet/bubbletea)
- [Lip Gloss](https://github.com/charmbracelet/lipgloss)
- [PTerm](https://pterm.sh)
