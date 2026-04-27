# IronSentinel Trust Console Implementation Spec

## Visual Thesis

IronSentinel should feel like a calm local AppSec command console: dark, low-glare, cyan/green trust accents, sparse warning color, and motion used only to prove live scan state.

## Approved Flow

One operator surface owns the default experience:

1. Launch: can I safely start this scan?
2. Mission: is the scan really running, where is it, and what is affected?
3. Debrief: what happened, what did not run, and what should I fix first?

`Runs`, `Findings`, and `Runtime` remain available as drawers/details, not competing primary routes.

## First Implementation Slice

This pass focuses on trust and actionability, not new scanner coverage.

### TUI

- Add a visible outcome axis row to Mission and Debrief:
  - Execution
  - Coverage
  - Policy
  - Runtime
- Replace vague progress copy with an honest progress summary:
  - percent
  - confidence: exact, estimated, or indeterminate
  - completed/total modules
  - skipped/failed modules surfaced as coverage impact
- Keep module progress integrated into Mission, never as a detached block.
- Keep mascot/brand motion small and disabled in plain or reduced-motion contexts.

### Debrief

- Debrief must produce a remediation-oriented report:
  - Status
  - What happened
  - Scope blockers
  - P0/P1/P2 fix plan
  - First step
  - Validation command
- A completed scan with skipped/failed modules is not "safe"; it is at best partial coverage.

### HTML Export

- HTML should mirror terminal Debrief:
  - executive outcome axes
  - module coverage blockers
  - prioritized remediation plan
  - validation commands
- Export remains generated from `domain.RunReport`.

### Localization

- Turkish copy must use correct Turkish characters for user-facing labels.
- Technical acronyms can stay English: SCA, DAST, SARIF, SBOM, VEX.
- Raw scanner strings must not become primary Turkish UI labels.

## Quality Gate

- Add failing tests before production changes.
- Update snapshot tests for Mission and Debrief.
- Add report export assertions for outcome axes and remediation plan.
- Run focused CLI/report tests first, then `go test ./... -count=1`.
- Run `go vet ./...` and `bash scripts/quality_local.sh` before final completion if time permits.
