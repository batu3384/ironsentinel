# Master Remediation Roadmap

## Objective

Turn IronSentinel from a strong local AppSec foundation into a premium-grade terminal-first security platform.

## Priority 1

### 1. Durable Storage

- Keep SQLite-backed state storage as the single persistence path.
- Prepare for future artifact indexing and append-only event capture.

### 2. Real Job Orchestration

- Move scanner execution from direct inline orchestration to a structured job model.
- Add module-level timeout, retry, exit taxonomy, and raw execution journaling.
- Preserve today’s normalized finding model while improving execution accountability.

### 3. Isolation Hardening

- Strengthen container execution with clearer runtime capability checks.
- Add resource limits, stronger file-system isolation, and clearer network policy controls.
- Make the isolation mode part of the user-visible trust contract.

## Priority 2

### 4. Scanner Depth

- Finish CodeQL orchestration.
- Move ZAP to Automation Framework flows.
- Enforce signed Nuclei templates in execution, not just planning.

### 5. Sensitive Evidence Protection

- Add masking and redaction for secrets in artifacts.
- Add retention controls and optional encryption-at-rest for stored evidence.

### 6. Supply-Chain Verification

- Add checksum and signature verification for bundle and installer assets.
- Expose verification status in `runtime doctor`.

## Priority 3

### 7. Interface Unification

- Make TUI the primary operator surface or demote it clearly.
- Break `internal/cli/app.go` into modular packages.
- Add stronger large-result ergonomics and accessibility modes.

### 8. Release Discipline

- Define supported OS/arch matrices.
- Add smoke tests for setup and doctor flows.
- Document capability tiers for `core`, `premium`, and `full`.

## Started in This Iteration

- Storage now runs on SQLite-backed persistence.
- Execution/job orchestration now includes queueing, retries, timeout taxonomy, and execution journaling.
- Isolation hardening now exposes a trust contract with network policy, read-only mounts, tmpfs scratch space, and container resource limits.
- Scanner depth now includes CodeQL orchestration, ZAP Automation Framework plans, and signed-template enforcement for Nuclei.
- Sensitive evidence protection now includes secret redaction, retention metadata, runtime visibility, and optional encryption-at-rest for stored evidence/report artifacts.
- Supply-chain verification now covers signed checksums for trusted bundle assets, trust-anchor rotation and re-signing for local installers/builders, lock coverage reporting for pinned scanners, upstream checksum hydration for supported tools, and optional integrity-enforced runtime doctor checks.
- Interface unification now includes the default fullscreen TUI surface, modularized view/label/theme layers, large-result paging, and `standard|plain|compact` accessibility modes.
- Release discipline now includes support matrix and capability tier docs, runtime-exposed platform support tiers, setup-time support enforcement, repeatable host smoke and matrix build scripts, CI wiring for release validation, automated archive packaging, and signed release publication workflows.
- Release trust visibility now includes discovered `dist/` bundles, provenance surfacing, explicit `runtime release verify` policy checks, structured release attestations, and optional external provenance attestation sidecars.
- The next active implementation target is managed-tool bootstrap enforcement and mirror seeding so fresh supported machines can move from `MISSING` runtime state to ready-to-scan premium state with one audited setup path.
