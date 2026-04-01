# __APP_TITLE__ Starter

This template is a clap plus ratatui dashboard starter with a plain fallback path.

## Run

```bash
cargo run -- dashboard
```

## Keys

- `q`: quit
- `j` or `Down`: move focus
- `k` or `Up`: move focus

## Fallback

If the terminal is not interactive or `NO_COLOR` is set, the command prints a plain status summary.
