# IronSentinel Terminal Single-Console Redesign Design

## Summary

Rebuild the current TUI into a single-console terminal application that makes one thing obvious at all times:

- what the product is doing
- whether a scan is running
- what is being scanned
- which tools or modules are active
- what the result means

The redesign keeps the current backend, store, scan orchestration, export pipeline, GitHub integrations, and policy logic, but replaces the current multi-surface TUI mental model with one stable operator console.

Approved design direction:

- terminal application remains terminal-based
- one main console instead of multiple app-like screens
- same-surface flow: `Launch -> Mission -> Debrief`
- balanced information density
- color direction: controlled cyber neon
- mascot presence: persistent but small signal

## Problem Statement

The current TUI is functionally capable but product-wise confusing.

Observed UX failures:

- operators cannot immediately tell whether the scan is actually running
- the UI feels like multiple screens or modes stitched together
- launch, review, runtime, findings, and runs compete for attention
- the main scan path is not visually dominant enough
- repeated headers, panels, and route systems create cognitive noise
- there is too much UI structure for the amount of decision-making the operator actually needs

This makes the product feel heavier and less reliable than the backend really is.

## Goals

### Primary goals

- make the default scan path unmistakable
- make scan activity visibly alive while it is running
- keep the operator on one main surface
- make the final outcome legible without requiring screen-hopping
- remove interface ambiguity without removing backend capability

### Secondary goals

- give the terminal app a more modern, higher-confidence visual identity
- keep motion purposeful rather than decorative
- preserve shell-safe and non-interactive fallbacks
- preserve the current command contracts unless the TUI-specific experience requires a soft remapping

## Non-Goals

This redesign does not change:

- the SQLite-first product model
- scan orchestration semantics
- the canonical `RunReport` pipeline
- GitHub integrations
- campaign/remediation domain behavior
- policy and runtime-doctor core logic

This redesign is also not a web UI migration and not a backend rewrite.

## Chosen Product Model

The TUI becomes one console with three states:

1. `Launch`
2. `Mission`
3. `Debrief`

The operator should feel that the application stays in one place while its state evolves, rather than navigating through several separate mini-apps.

## Surface Model

### Launch

`Launch` is the only starting surface.

It must answer:

- what target is selected
- whether the system is ready enough to start
- what pressing `Enter` will do

It should not feel like a setup wizard or a review form.

Required information:

- selected project or target
- concise readiness state
- one-line next action
- one compact last-run summary block when prior run data exists

Allowed actions:

- `Enter`: start quick scan
- `a`: open advanced scan configuration
- `p`: change project or target
- `/`: open command palette

Everything else is secondary.

### Mission

`Mission` replaces the current feeling of "one more screen". It is still the same console, now in an active operating state.

It must answer:

- is the scan running right now
- which phase is active
- which module is active
- which tools are involved
- what the current risk or attention level is
- whether anything needs operator attention

Required visual sections:

- top live status rail
- primary operation body
- compact event or phase history
- right-side detail drawer that appears only when explicitly opened

### Debrief

`Debrief` appears below the mission state on the same surface after or during completion.

It must answer:

- did the run pass, partially pass, or fail
- how many modules completed vs did not complete
- what the most important findings are
- what the next recommended action is

The operator should not be kicked into another route to understand the result.

## Drawer Model

`Runs`, `Findings`, and `Runtime` stop being primary TUI destinations.

In the redesign they become contextual drawers or detail panels.

Rules:

- a drawer opens from the right
- only one drawer is open at a time
- the main console remains visible behind it
- drawers are decision support, not navigation hubs

Initial drawer set:

- `Findings`
- `Runtime`
- `Run details`

Future drawers are allowed, but the main console must remain the product center of gravity.

## Information Density

Chosen density: balanced.

The console should carry enough information to feel professional and trustworthy without turning into a dashboard wall.

Balanced density means:

- one strong primary block at a time
- one concise status rail
- one small secondary summary block
- details only when expanded or drawer-opened

It explicitly rejects both:

- overly sparse toy interfaces
- dense enterprise dashboards full of low-value telemetry

## Motion And Animation Rules

Motion is used only to confirm state and progress.

### Allowed motion

- live status pulse while scan is active
- active module or phase transition highlight
- progress rail movement
- drawer open and close motion
- subtle mascot signal animation

### Disallowed motion

- animated backgrounds
- constant decorative shimmer
- multi-region pulsing at once
- motion that does not communicate state change

### Fallback rules

- reduced motion disables decorative pulse and keeps only status changes
- narrow terminals reduce motion and visual layering
- no-color or plain mode keeps the same information hierarchy with plain text markers

## Visual Direction

Chosen visual direction: controlled cyber neon.

Principles:

- dark but readable base
- bright cyan or neon accents used sparingly
- strong contrast for live state and warnings
- no rainbow palette
- no arcade aesthetic
- typography and box rhythm should feel operational, not playful

Mascot mode: persistent but small signal.

This means:

- mascot supports brand identity and current system mood
- mascot is not the focal point of the layout
- mascot does not dominate reports or debrief sections

## Mission Behavior

The `Mission` state should make scan execution unmistakable.

### Top live rail

This rail always exposes:

- status label such as `SCAN RUNNING`, `CANCELLING`, `COMPLETE`
- active phase
- active module
- target identity

The top live rail is the strongest proof that the system is alive.

### Core mission body

The main body should include:

- progress state
- currently active tool or module
- current phase list with active highlight
- elapsed time
- high-signal recent event

The body should not read like raw logs. Raw events are secondary.

### Tool and module visibility

The operator explicitly asked to see what is being scanned and what is being used to scan it.

Therefore the active mission body should reveal:

- current scan domain or area
- current module
- current tool when applicable
- queued or next phases in compact form

## Debrief Behavior

`Debrief` must be readable in one downward pass.

### Layer 1: executive result

- run status
- total findings
- modules passed
- modules failed or skipped
- recommended next action

### Layer 2: technical result summary

- passed modules
- blocked or unavailable modules
- runtime issues that affected confidence
- policy or gate outcome

### Layer 3: detail

- expandable module details
- findings drawer entry point
- export or evidence actions

Default behavior should favor short summary first, deeper detail on demand.

## What Will Be Removed From The Main TUI Experience

The redesign removes these ideas from the primary operator experience:

- route-tab mental model
- numbered top-level route hopping
- separate app-like `Home`, `Runs`, `Findings`, `Runtime` destinations
- repeated hero or primer stacks
- duplicate summaries across multiple panels
- review-first scan start behavior as the default path

Some of these may remain internally or in secondary CLI commands, but not as the primary TUI UX.

## What Will Be Preserved

The following product capabilities remain authoritative and should be reused:

- scan planning and orchestration
- runtime doctor
- canonical report generation
- findings and runs model
- GitHub publishing and campaign features
- evidence policy and export flows
- non-interactive CLI behavior

The redesign is a presentation and interaction rewrite over the same core product model.

## Architecture Direction

The new TUI should be implemented as a new single-console state model rather than a gradual mutation of the existing route-first shell.

Recommended internal state groups:

- launch state
- mission state
- debrief state
- drawer state
- palette or command dispatch state

This is a stronger boundary than the current shell, and it reduces the chance that old route logic leaks back into the new experience.

## Validation Expectations

The redesign is only successful if these behaviors are true:

- opening the TUI immediately makes the next action obvious
- pressing `Enter` on the launch surface begins a scan with no ambiguity
- the user can always tell whether a scan is actively running
- the current target, module, and scan phase are visible during execution
- the final result appears on the same surface without route changes
- findings and runtime context can be inspected without leaving the main console
- narrow terminals remain usable
- `NO_COLOR=1` remains readable
- reduced motion remains informative
- non-interactive CLI output remains shell-safe and concise

## Implementation Boundary

This work is not "more polishing on the old shell".

It is a deliberate rebuild of the TUI presentation model using the current backend and product domain as stable foundations.

The expected shape is:

- keep backend truth
- replace main TUI interaction model
- preserve CLI and automation contracts where reasonable
- remove the old multi-surface mental model from the primary operator path

## Recommended Next Step

Write and execute an implementation plan that:

1. creates the new single-console shell scaffold
2. builds `Launch`
3. builds `Mission`
4. builds `Debrief`
5. reintroduces `Findings`, `Runtime`, and `Run details` as drawers
6. retires the current route-first TUI from the primary path
7. verifies TTY, plain, narrow, and reduced-motion behavior
