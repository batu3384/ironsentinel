# IronSentinel

`IronSentinel` is a Go-based local-first AppSec CLI and terminal interface with bilingual output support (`English` and `Turkish`).

The primary binary is `ironsentinel`.

When you run `ironsentinel` without a subcommand in an interactive terminal, it opens the fullscreen TUI by default. Use `ironsentinel overview` if you want the static dashboard surface.

## What it does

- registers local project folders
- scans them directly from the CLI
- provides an interactive operator console with guided flows
- normalizes findings into one model
- stores project and run history under `runtime/data/state.db`
- exports reports as `SARIF`, `CSV`, or `HTML`
- supports a saved default language with `ironsentinel config language en|tr`

The current implementation includes:

- always-on heuristic modules:
  - stack detection
  - secret pattern checks
  - malware signature checks including EICAR validation
- external scanner adapters when the binaries exist on `PATH`:
  - `semgrep`
  - `gitleaks`
  - `trivy`
  - `syft`
  - `osv-scanner`
  - `checkov`
  - `govulncheck`
  - `staticcheck`
  - `knip`
  - `vulture`
  - `clamscan`
  - `nuclei` with signed-template enforcement
  - `codeql` orchestration for `javascript/typescript`, `python`, and `go`
  - `zaproxy` via Automation Framework plans with SARIF report generation

Default scans now use `premium` coverage and fail fast when required scanners are not ready.
If you want a portable built-in-only pass on a fresh machine, use `--coverage core`.

Each scan now also persists:

- module execution manifests with command, working directory, environment allowlist, and exit code
- per-module execution journals with retry, timeout, and failure taxonomy
- local evidence files for heuristic detections
- raw scanner output copies when external tools emit structured results
- live scan output now reports per-attempt retry and timeout events for external modules
- modules now enter a queued state first and run through a bounded worker pool instead of strict serial execution

## Build

```bash
go mod tidy
go build ./cmd/ironsentinel
```

The project now targets Go `1.25.x`.

## Local Quality Gate

Run the same local quality gate used by release validation:

```bash
bash scripts/quality_local.sh
```

This executes:

- `go test ./...`
- `bash scripts/coverage_gate.sh`
- `go vet ./...`
- `staticcheck ./...`
- `golangci-lint run --config .golangci.yml --concurrency 2 ./...`
- a core self-scan with `ironsentinel`

The coverage gate writes:

- `coverage/internal.out`
- `coverage/internal-summary.txt`
- `coverage/internal-packages.txt`

Default minimum internal coverage is `45.0%` and can be overridden with `COVERAGE_MIN`.

## Run

```bash
go run ./cmd/ironsentinel
go run ./cmd/ironsentinel overview
go run ./cmd/ironsentinel tui
go run ./cmd/ironsentinel console
go run ./cmd/ironsentinel daemon
go run ./cmd/ironsentinel daemon --once
go run ./cmd/ironsentinel setup --target auto --coverage premium
go run ./cmd/ironsentinel init
go run ./cmd/ironsentinel open
go run ./cmd/ironsentinel pick
go run ./cmd/ironsentinel runtime
go run ./cmd/ironsentinel runtime lock coverage --missing-only
go run ./cmd/ironsentinel runtime release
go run ./cmd/ironsentinel runtime release verify --require-signature --require-attestation --require-external-attestation
go run ./cmd/ironsentinel runtime doctor --mode safe --require-integrity
go run ./cmd/ironsentinel runtime support --coverage premium
go run ./cmd/ironsentinel runtime doctor --mode deep --strict-versions
go run ./cmd/releasectl verify --dir dist/<version> --lock scanner-bundle.lock.json --require-signature --require-attestation --require-external-attestation
go run ./cmd/releasectl lock hydrate --lock scanner-bundle.lock.json --write
go run ./cmd/releasectl lock trust-assets --lock scanner-bundle.lock.json --generate-key --signer ironsentinel-release-root --write
go run ./cmd/releasectl keygen --lock-out /tmp/ironsentinel.lock.json --private-out /tmp/ironsentinel.key
go run ./cmd/ironsentinel runtime mirror refresh --tool trivy
go run ./cmd/ironsentinel runtime mirror refresh --tool osv-scanner
go run ./cmd/ironsentinel runtime image build --engine auto
go run ./cmd/ironsentinel projects add
go run ./cmd/ironsentinel projects add /absolute/path
go run ./cmd/ironsentinel scan --lang tr
go run ./cmd/ironsentinel scan /absolute/path --lang tr
go run ./cmd/ironsentinel scan /absolute/path --coverage core
go run ./cmd/ironsentinel scan --wizard
go run ./cmd/ironsentinel scan /absolute/path --coverage core --enqueue
go run ./cmd/ironsentinel scan /absolute/path --fail-on-new high
go run ./cmd/ironsentinel scan /absolute/path --fail-on-new critical --baseline <baseline-run-id>
go run ./cmd/ironsentinel scan /absolute/path --policy premium-default
go run ./cmd/ironsentinel scan /absolute/path --isolation container
go run ./cmd/ironsentinel scan /absolute/path --require-bundle --strict-versions
go run ./cmd/ironsentinel findings --severity high --limit 20
go run ./cmd/ironsentinel findings --run <run-id> --change new
go run ./cmd/ironsentinel findings show <fingerprint> --run <run-id>
go run ./cmd/ironsentinel review <fingerprint> --run <run-id>
go run ./cmd/ironsentinel triage set <fingerprint> --run <run-id> --status investigating --tag secrets --note "needs review"
go run ./cmd/ironsentinel triage list --status investigating
go run ./cmd/ironsentinel triage clear <fingerprint>
go run ./cmd/ironsentinel suppress <fingerprint> --run <run-id> --reason "accepted risk" --owner security --days 14
go run ./cmd/ironsentinel suppress list
go run ./cmd/ironsentinel suppress remove <fingerprint>
go run ./cmd/ironsentinel suppress renew <fingerprint> --days 30 --reason "still accepted"
go run ./cmd/ironsentinel dast plan <project-id> --target staging=https://staging.example.test
go run ./cmd/ironsentinel runs list
go run ./cmd/ironsentinel runs show <run-id>
go run ./cmd/ironsentinel runs watch <run-id>
go run ./cmd/ironsentinel runs artifacts <run-id>
go run ./cmd/ironsentinel runs cancel <run-id>
go run ./cmd/ironsentinel runs retry-failed <run-id>
go run ./cmd/ironsentinel runs diff <run-id>
go run ./cmd/ironsentinel runs diff <run-id> --baseline <baseline-run-id>
go run ./cmd/ironsentinel runs gate <run-id>
go run ./cmd/ironsentinel runs gate <run-id> --severity critical --baseline <baseline-run-id>
go run ./cmd/ironsentinel runs policy <run-id> --policy premium-default
go run ./cmd/ironsentinel export <run-id> --format html --output runtime/output/report.html
go run ./cmd/ironsentinel export <run-id> --format sarif --baseline <baseline-run-id>
go run ./cmd/ironsentinel config language tr
```

## Interactive CLI

- `ironsentinel console`
  - opens a guided operator console for scanning, findings review, runtime inspection, and language switching
  - this is now a supporting guided workflow on top of the primary TUI surface
- `ironsentinel overview`
  - opens the modern operations overview with portfolio, risk posture, recent runs, and recent findings
  - now shows queued, running, and canceled run counts in the portfolio pane
  - now also shows daemon health and PID in the runtime posture area
- `ironsentinel tui`
  - opens the fullscreen terminal UI with tabbed views for overview, runs, findings, and runtime health
  - this is now the primary interactive operator surface; plain `ironsentinel` opens it automatically when a TTY is available
  - supports `--ui-mode standard|plain|compact`; inside the TUI, `m` cycles the current session mode and `pgup/pgdown`, `home/end` handle large result sets faster
  - run details include delta and module execution counters for failed, skipped, and retried modules
  - run details now also show live queued/running module state and daemon health is visible from overview/runtime panes
  - in runs tab, `Enter` opens a focused run review with longer execution timeline, attempt details, findings, and artifact sections; `a` cycles artifact filters, `f` cycles finding severity, `s` cycles finding status, and `Esc` returns to split view
  - overview tab also shows queued, running, and canceled run counts
  - refreshes automatically every 2 seconds while keeping manual `r` refresh
  - overview and runs tabs now support `d` to drain the queued run backlog once without leaving the TUI
  - runs tab now supports `c` to cancel a queued or running run and `Shift+R` to re-enqueue a failed or canceled run
- `ironsentinel daemon`
  - runs the local queue worker that claims queued scans from `state.db` and executes them in the background
  - use `--once` to drain the current queue and exit
  - persists daemon heartbeat metadata so runtime and TUI views can show daemon status, PID, mode, and last heartbeat
- `ironsentinel scan`
  - when run without a path, scans the current working directory by default
  - use `--wizard` to open the guided scan workflow explicitly
  - defaults to `premium` coverage and fails before scan start if required runtime is missing
  - supports `--coverage core|premium|full`
  - supports `--enqueue` to register a queued run for daemon execution
  - can enforce a CI-friendly post-scan regression gate with `--fail-on-new <severity>`
  - can evaluate a built-in policy pack with `--policy premium-default`
  - can require the pinned scanner bundle with `--require-bundle` and optionally enforce exact versions with `--strict-versions`
- `ironsentinel init`
  - registers the current working directory as a project
  - accepts an optional path and `--picker` for native folder selection
- `ironsentinel open`
  - chooses one of the saved projects and starts a default quick scan
  - if only one project is registered, it opens that project directly
- `ironsentinel pick`
  - opens the native folder picker, registers the selected folder, then starts a default quick scan
- `ironsentinel runtime doctor`
  - validates the pinned scanner bundle for `safe`, `deep`, or `active` mode and exits non-zero when required tools are missing
  - use `--require-integrity` to fail when required tools are only version-pinned and still missing checksum/signature metadata in the bundle lock
  - runtime views now also show the default isolation trust contract, including network policy, mount modes, tmpfs scratch paths, and resource limits
  - runtime views also show sensitive artifact protection settings such as retention, redaction, and whether encryption-at-rest is enabled
  - runtime and doctor views now also show checksum/signature verification state for trusted bundle assets plus verification status for discovered scanner binaries
- `ironsentinel runtime lock coverage`
  - shows which pinned scanners in `scanner-bundle.lock.json` have checksum, signature, or source-digest metadata
  - use `--missing-only` to focus on tools that still lack all integrity coverage; with the current hydrated lock this filter now returns zero rows
- `releasectl lock hydrate`
  - fetches official upstream checksum manifests, GitHub asset digests, PyPI distribution digests, and source archives for supported tools and writes the results back into `scanner-bundle.lock.json`
  - built-in hydrators now cover `gitleaks`, `syft`, `nuclei`, `codeql`, `osv-scanner`, `semgrep`, `staticcheck`, `zap`, `clamav`, and `trivy`
  - on March 18, 2026 the official `trivy v0.69.1` checksum URL returned `404`; IronSentinel now falls back to the official GitHub source archive digest for that pin, so integrity coverage still remains complete
  - the lock file also supports platform-specific version overrides, so strict bundle checks can stay exact on platforms where managed local installers intentionally land on a different pinned version
- `releasectl lock trust-assets`
  - refreshes checksum + signature metadata for trusted installer, builder, and container assets in the bundle lock
  - supports `--generate-key` to rotate the trust anchor and re-sign all trusted local assets in one pass
- `ironsentinel runtime release`
  - shows discovered release bundles from `dist/`, including provenance, manifest/checksum/signature/attestation paths, and packaged artifacts
- `ironsentinel runtime release verify`
  - verifies discovered release bundles and exits non-zero on failed verification
  - use `--require-signature`, `--require-attestation`, `--require-external-attestation`, and `--require-clean-source` to enforce stricter publication policy
- `ironsentinel runtime support`
  - shows the current OS/arch support matrix for `core`, `premium`, and `full`
  - with `--coverage`, validates a requested tier against the current platform before packaging or setup
- `ironsentinel runtime mirror refresh`
  - refreshes the local vulnerability mirrors for supported tools such as `trivy` and `osv-scanner`
  - `osv-scanner` mirror seeding now uses the official offline vulnerability bucket layout under `runtime/mirrors/osv-cache/osv-scanner/<ecosystem>/all.zip`
- `ironsentinel runtime image build`
  - builds the pinned scanner bundle container image from the repo Containerfile using `docker` or `podman`
- `ironsentinel setup`
  - prepares the runtime automatically by preferring the rootless container image path and falling back to local bundle installation
  - the POSIX local installer now writes managed wrappers and downloaded binaries under `runtime/tools/bin` instead of relying only on global PATH mutation
  - the macOS/Linux safe installer now pins `setuptools<81` for Semgrep compatibility on Python 3.13 and downloads exact managed binaries for `gitleaks`, `syft`, `osv-scanner`, and `staticcheck`
  - the macOS full installer now bootstraps exact local `codeql 2.23.3`, `nuclei 3.4.10`, and `OWASP ZAP 2.16.1` wrappers in the managed tools directory
  - `--coverage full` now installs and validates the full bundle target instead of stopping at deep-only bootstrap
  - when `--mirror` is enabled, setup now attempts to seed both the `trivy` and `osv-scanner` vulnerability mirrors
  - supports `--coverage core|premium|full`
- `ironsentinel runs artifacts`
  - lists the persisted raw outputs, evidence files, and module manifests for a run
  - now also shows whether each artifact was redacted, encrypted, and when it expires under retention policy
- `ironsentinel runs watch`
  - polls either a specific run or the whole queue and refreshes the terminal view on a fixed interval
- `ironsentinel runs cancel`
  - cancels a queued run immediately or requests cancellation for a running run
- `ironsentinel runs retry-failed`
  - creates a new queued run from a failed or canceled run profile
- `ironsentinel runs show`
  - includes an execution timeline built from module journals and synthetic traces for built-in modules
  - now also prints the effective isolation trust contract for the run profile
- `ironsentinel config language`
  - when run without `en|tr` in an interactive terminal, opens a language picker
- `ironsentinel config ui-mode`
  - stores the preferred TUI accessibility mode as `standard`, `plain`, or `compact`
- `ironsentinel export`
  - when run without a run id in an interactive terminal, lets you choose a saved run first

## Release Discipline

- support matrix and capability tiers: [`docs/release-discipline.md`](docs/release-discipline.md)
- repeatable setup/doctor smoke-check: `bash scripts/smoke_setup_doctor.sh`
- shell guard smoke-check: `bash scripts/smoke_shell_guards.sh`
- Windows shell guard smoke-check: `pwsh scripts/smoke_shell_guards.ps1`
- host or matrix packaging validation: `bash scripts/validate_release_matrix.sh --host-only`
- release publish preflight: `bash scripts/release_publish_preflight.sh --version vX.Y.Z --require-signing --require-tag`
- release artifact preflight: `bash scripts/release_artifact_preflight.sh --dir dist/vX.Y.Z --require-signing --require-external-attestation`
- release notes from packaged dist: `go run ./cmd/releasectl notes --dir dist/vX.Y.Z --lock scanner-bundle.lock.json`
- CI wiring: [`release-validation.yml`](.github/workflows/release-validation.yml)
- signed packaging flow: `bash scripts/package_release.sh --version vX.Y.Z --sign`
- signed release smoke flow without a long-lived secret: `bash scripts/smoke_signed_release.sh`
  - covers manifest signature, internal attestation, and external provenance attestation verification together
- release publish workflow: [`release-publish.yml`](.github/workflows/release-publish.yml)
  - `HTML` and `SARIF` exports include module execution summaries, attempts, timeout state, and failure kinds
- `ironsentinel suppress`
  - suppresses a finding with reason, owner, expiry and optional ticket reference
- `ironsentinel suppress list`
  - lists active suppressions with owner, reason and expiry
- `ironsentinel suppress remove`
  - removes a saved suppression by fingerprint
- `ironsentinel findings show`
  - opens a detailed finding view with remediation, confidence and reachability
- `ironsentinel review`
  - opens a detailed finding review flow and can suppress directly from the terminal
- `ironsentinel triage set/list/clear`
  - manages persistent finding status, tags, note and owner metadata
- `ironsentinel dast plan`
  - produces a baseline, authenticated or active DAST execution plan for a selected project
- `ironsentinel findings --change`
  - filters a run to only `new`, `existing`, or `resolved` findings relative to the previous completed baseline
- `ironsentinel runs diff`
  - compares a run against the previous completed run for the same project, or against an explicit `--baseline` run
- `ironsentinel runs gate`
  - fails with a non-zero exit code when new findings at or above the requested severity threshold are detected
- `ironsentinel runs policy`
  - evaluates the selected run against the built-in policy pack and exits non-zero on a fail outcome

Exported `CSV`, `HTML`, and `SARIF` reports now include triage metadata where applicable:
- finding status
- baseline change classification
- tags
- owner
- note

The CLI is still scriptable: explicit command arguments always work for automation and CI.

## Language support

- One-off language switch:

  ```bash
  go run ./cmd/ironsentinel --lang tr
  ```

- Persist default language:

  ```bash
  go run ./cmd/ironsentinel config language tr
  ```

Supported values:

- `en`
- `tr`

## Data layout

- preferences: `runtime/data/preferences.json`
- project + run history: `runtime/data/state.db`
- generated report artifacts: `runtime/output/`
- managed local scanner wrappers/binaries: `runtime/tools/bin/`
- module execution manifests and evidence: `runtime/output/<run-id>/<module>/`
- fixture acceptance matrix: `go test ./internal/core ./internal/agent`
- scanner bundle container image recipe: `deploy/scanner-bundle.Containerfile`
- scanner image build script: `scripts/build_scanner_image.sh`

## Notes

- The CLI can use the native folder picker with `--picker`.
- On macOS, the native folder picker now uses `osascript` instead of the deprecated Cocoa dialog dependency, so normal builds and runs stay clean.
- The pinned scanner bootstrap script supports `--mode safe|deep|active|full` and `--apply`.
- On Windows, local bootstrap uses the PowerShell equivalents `scripts/install_scanners.ps1` and `scripts/build_scanner_image.ps1`.
- Windows local bootstrap writes managed wrappers and binaries into `runtime/tools/bin/`, and IronSentinel resolves that directory even if it is not on the global `PATH`.
- Isolation mode supports `auto`, `local`, and `container`. `auto` prefers a rootless container engine plus the configured scanner image, then falls back to the hardened local sandbox.
- Sensitive artifacts are redacted before storage by default. Set `APPSEC_ARTIFACT_ENCRYPTION_KEY` to enable optional encryption-at-rest for evidence, reports, raw outputs, and SBOM artifacts.
- Artifact retention is controlled with `APPSEC_ARTIFACT_RETENTION_DAYS` and defaults to 30 days. Set `APPSEC_ARTIFACT_REDACTION=false` only if you explicitly want unredacted local evidence files.
- Build the scanner image first if you want container isolation to become available:

  ```bash
  go run ./cmd/ironsentinel runtime image build --engine auto
  ```

- External scanners run with a narrowed environment allowlist; common secret variables are not forwarded into scanner subprocesses.
- Runtime view now reports container engine readiness, rootless state, image presence, and vulnerability mirror freshness.
- The bundle lock now carries an Ed25519 trust anchor and signed checksums for the local installer/build scripts plus the scanner Containerfile; `runtime` and `runtime doctor` verify these assets on every run.
- `premium` is the default coverage profile. `core` runs only built-in modules and is intended for fresh machines where the full scanner runtime is not prepared yet.
- The scanner bundle reference remains in [`scanner-bundle.lock.json`](/Users/batuhanyuksel/Documents/security/scanner-bundle.lock.json).
