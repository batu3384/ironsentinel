---
name: cli-ui-composer
description: Design and refine CLI and TUI interface systems with strong fallback behavior, purposeful motion, and stack-aware terminal UX rules.
metadata:
  author: local
  version: "0.13.0"
  argument-hint: <repo-or-entrypoint>
---

# CLI UI Composer

Use this skill when the user asks to improve CLI onboarding, command UX, prompt flows, dashboards, terminal visuals, help ergonomics, or full-screen TUI behavior.

Start here:

1. Read `../../docs/ui-playbook.md`.
2. Read `../../docs/ui-pattern-catalog.md`.
3. Read `../../docs/ui-quality-gate.md`.
4. Run `../../scripts/inspect_cli_repo.sh <target>`.
5. Run `../../scripts/generate_cli_ui_brief.sh <target>`.
6. Run `../../scripts/generate_cli_ui_patch_plan.sh <target>`.
7. Run `../../scripts/generate_cli_ui_pattern_plan.sh <target>` when the user wants a narrower pattern-level split.
8. Run `../../scripts/preview_cli_ui_templates.sh --template <id> --sample` when you want a compact starter preview with a golden sample before scaffolding.
9. If the user wants starter code, run `../../scripts/scaffold_cli_ui_template.sh --list` and scaffold the closest template.

## Workflow

1. Choose the right surface first.
   - Styled linear output for short command journeys and report screens.
   - Guided prompt flows for setup, login, bootstrap, and configuration.
   - Full-screen TUI for monitoring, queue work, incident response, or long-running operator loops.
2. Preserve stack-native patterns.
   - Cobra/Bubble Tea/Lip Gloss: keep `Model/Update/View` separation, explicit context propagation, and non-TTY fallbacks.
   - Typer/Textual/Rich: keep typed command signatures, async UI discipline, and snapshot-friendly rendering.
   - oclif/Ink/blessed: keep JSON mode safe, stdout/stderr explicit, and prompt flows isolated from pipe mode.
   - clap/ratatui: keep parser ergonomics, alternate-screen cleanup, and plain-text fallback paths.
3. Improve the operator loop before decoration.
   - Primary action visibility
   - Empty/loading/error/success states
   - Width and no-color behavior
   - Reduced-motion and redirected-output fallbacks
4. Ship proof.
   - Add UI-facing tests or smoke commands when possible.
   - Record what was verified in a real terminal.

## Guardrails

- Do not add color, animation, or alternate-screen behavior that breaks logs, CI, or redirected output.
- Do not introduce a full-screen TUI if the task fits a simpler prompt or report flow.
- Always define the plain, narrow-width, and no-color fallback before polishing visuals.

## Required Output

- Visual thesis in one sentence
- Recommended surface model
- Candidate write targets
- Suggested starter template
- Suggested pattern-level template
- UI state plan
- Fallback strategy for no-TTY, no-color, narrow width, and reduced motion
- Concrete implementation or patch path
- Validation evidence
