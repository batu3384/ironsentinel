# Comprehensive System Audit

- Target: `/Users/batuhanyuksel/Documents/security`
- Date: `2026-04-01`
- Scope: CLI/TUI UX, non-interactive output contracts, runtime doctor, scan orchestration, self-scan, export/reporting, release scripts
- Method: two parallel subagent audits plus local integration, smoke, PTY, and quality-gate verification

## Overall Status

The project is broadly operational.

- `go test ./...` passed
- `go vet ./...` passed
- `bash scripts/quality_local.sh` passed
- `bash scripts/smoke_shell_guards.sh` passed
- plugin quick audit passed
- fullscreen PTY open/quit smoke passed
- `NO_COLOR` and `IRONSENTINEL_REDUCED_MOTION=1` sanity checks passed

The system is usable and the previously confirmed correctness and UX-contract issues from this audit have now been remediated in the current repo state.

## Remediation Status

Status update: `2026-04-01`

All 8 confirmed findings from this audit are fixed in the current codebase:

1. `export` stdout now emits raw structured payloads without branded prelude.
2. UTF-8 truncation now uses rune-safe slicing.
3. Release publish preflight now fails on untracked files as well as tracked diffs.
4. Runtime doctor networking now treats auth/proxy failures as non-pass.
5. Target resolution now respects caller cancellation.
6. Queue terminal persistence no longer swallows `UpdateRun` failures.
7. Non-interactive `overview` and `runtime` surfaces now use shell-safe summary output.
8. HTML report exports now tighten permissions to owner-readable.

## Historical Findings (Resolved)

### High

1. Machine-readable export is not stdout-safe.
   - `ironsentinel export <run> --format sarif` writes branded output before the SARIF payload when stdout is used directly.
   - This breaks piping and invalidates JSON/SARIF consumers.
   - Evidence:
     - `/Users/batuhanyuksel/Documents/security/internal/cli/app.go#L1933`
     - `/Users/batuhanyuksel/Documents/security/internal/cli/app.go#L1939`

2. UTF-8 truncation is byte-based and can corrupt Turkish text.
   - `trimForSelect` uses raw byte length and slicing, which can split multi-byte runes and produce replacement characters.
   - Evidence observed in plain output during audit and rooted here:
     - `/Users/batuhanyuksel/Documents/security/internal/cli/app.go#L3588`
   - Impact surface includes dashboard, brand, shell rows, and other TUI/static views.

3. Release publish preflight can report a dirty tree as clean.
   - The script checks tracked diffs but ignores untracked files.
   - In audit reproduction, a temp git repo with `?? untracked.txt` still exited success and printed a clean-tree result.
   - Evidence:
     - `/Users/batuhanyuksel/Documents/security/scripts/release_publish_preflight.sh#L92`

### Medium

4. Runtime doctor networking check is too permissive.
   - `401`, `403`, or `407` would still be treated as healthy because anything `<500` is effectively a pass.
   - That can hide real mirror/auth/proxy failures.
   - Evidence:
     - `/Users/batuhanyuksel/Documents/security/internal/core/runtime_doctor.go#L157`

5. Target resolution ignores cancellation.
   - The target resolver explicitly discards the incoming context before picker and stack-resolution work.
   - Interactive resolution therefore is not properly abortable through caller cancellation.
   - Evidence:
     - `/Users/batuhanyuksel/Documents/security/internal/agent/service.go#L39`

6. Queue failure persistence can drift from emitted state.
   - Failure/cancel code paths swallow `UpdateRun` errors.
   - That means event stream and persisted run state can diverge if the store write fails.
   - Evidence:
     - `/Users/batuhanyuksel/Documents/security/internal/core/service.go#L309`
     - `/Users/batuhanyuksel/Documents/security/internal/core/service.go#L480`

7. Non-interactive surfaces are still too TUI-like.
   - `overview`, `runtime`, and export-to-stdout paths still emit large decorated headers and wide panel layouts even in shell/log/pipe contexts.
   - Not a hard runtime failure, but it weakens automation ergonomics and output readability.
   - Evidence:
     - `/Users/batuhanyuksel/Documents/security/internal/cli/brand.go#L50`
     - `/Users/batuhanyuksel/Documents/security/internal/cli/dashboard.go#L84`
     - `/Users/batuhanyuksel/Documents/security/internal/cli/dashboard.go#L282`
     - `/Users/batuhanyuksel/Documents/security/internal/cli/app.go#L1949`

### Low

8. HTML export files are world-readable by default.
   - Reports can contain secrets, repo paths, and remediation details.
   - Current mode was reproduced as `0644`.
   - Evidence:
     - `/Users/batuhanyuksel/Documents/security/internal/cli/app.go#L1984`
     - `/Users/batuhanyuksel/Documents/security/internal/cli/app.go#L1987`

## Verified Clean Areas

- Static analysis and local quality gate are green in the current repo state.
- Trusted bundle assets verify successfully after lock refresh.
- Self-scan pipeline completes successfully.
- Shell guard/preflight scripts passed their smoke flow.
- Plain/no-color and reduced-motion modes execute without crashing.
- Fullscreen TUI opens and exits correctly in a PTY.

## Residual Risks

1. Narrow-width visual QA is only partially covered.
   - PTY smoke succeeded, but true `80x24` visual verification still needs a real terminal resize pass.

2. Self-scan findings are noisy by design.
   - This repo intentionally contains security test fixtures, tokens, and EICAR signatures.
   - Findings in self-scan are expected and should not be interpreted as platform breakage.

3. External scanner depth was not exhaustively executed for every supported tool on this machine.
   - Core orchestration and smoke paths were exercised, but not every optional scanner binary was run end to end.

## Evidence Summary

### Local Commands

- `go test ./...`
- `go vet ./...`
- `bash scripts/quality_local.sh`
- `bash scripts/smoke_shell_guards.sh`
- `bash plugins/cli-systems-lab/scripts/inspect_cli_repo.sh .`
- `bash plugins/cli-systems-lab/scripts/run_cli_quick_audit.sh .`
- `/opt/homebrew/bin/ironsentinel --lang tr --help`
- `NO_COLOR=1 /opt/homebrew/bin/ironsentinel overview --lang en`
- `IRONSENTINEL_REDUCED_MOTION=1 /opt/homebrew/bin/ironsentinel runtime --lang en`
- PTY smoke: `/opt/homebrew/bin/ironsentinel --lang tr`

### Subagent Coverage

- UI/TUI audit:
  - fullscreen behavior
  - route transitions
  - help UX
  - stdout/pipe/no-color/reduced-motion behavior
  - export stdout contract
- Backend/runtime audit:
  - runtime doctor
  - queue/orchestration
  - release preflight scripts
  - self-scan/export flow
  - report permissions

## Recommended Remediation Order

1. Fix `export --format sarif/json` stdout contract.
2. Replace byte-slicing truncation with rune-safe truncation everywhere `trimForSelect` is used.
3. Fix release preflight to fail on untracked files.
4. Tighten runtime doctor network pass/fail criteria.
5. Propagate cancellation correctly through target resolution.
6. Stop swallowing `UpdateRun` failures in queue terminal paths.
7. Rework non-interactive overview/runtime/export surfaces into simpler shell-safe output.
8. Restrict HTML report permissions to owner-readable by default.
