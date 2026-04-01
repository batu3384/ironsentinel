# CLI UI Quality Gate

Do not call CLI interface work complete until these checks pass.

## Mandatory Evidence

- interactive happy path
- narrow-width pass at roughly 80 columns or less
- `NO_COLOR=1` or equivalent fallback
- redirected or piped output behavior
- reduced-motion behavior when animation exists
- exit cleanup for alternate-screen or full-screen TUIs

## Review Questions

- Is the main action obvious inside one screen?
- Can the operator recover from error and retry without confusion?
- Does help output explain the next action quickly?
- Are prompt flows skipped when stdin is not interactive?
- Does success output summarize what changed and where artifacts live?
- Are cancellation and quit paths visible and reliable?

## Fail Conditions

- styling leaks into JSON or machine-readable mode
- prompts block CI or redirected output
- TUI leaves the cursor, screen, or terminal state corrupted
- color alone communicates warnings or failures
- motion hides status or delays input
- width collapse makes the main action disappear
