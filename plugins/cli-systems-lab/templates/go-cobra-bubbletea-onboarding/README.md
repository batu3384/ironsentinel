# __APP_TITLE__ Starter

This template is a small Cobra plus Bubble Tea onboarding surface with a plain fallback path.

## Why it exists

- first-run setup flow
- no-TTY safe fallback
- narrow and no-color friendly screen structure
- explicit quit path

## Run

```bash
go run . setup
```

## Fallback

If stdout or stdin is not interactive, the command prints a plain setup checklist instead of opening the TUI.
