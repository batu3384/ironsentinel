# Release Discipline

## Supported Runtime Matrix

| Platform | `core` | `premium` | `full` | Notes |
| --- | --- | --- | --- | --- |
| macOS `arm64` | Supported | Supported | Supported | Best local operator experience; full local bootstrap now installs pinned `CodeQL`, `Nuclei`, and `OWASP ZAP`; container isolation still requires rootless `docker` or `podman`. |
| macOS `amd64` | Supported | Supported | Supported | Same feature tier as Apple Silicon, with slower local scanner bootstrap. |
| Linux `amd64` | Supported | Supported | Supported | Best target for CI and hardened container isolation. |
| Linux `arm64` | Supported | Supported | Supported | Container-first preferred for deeper scanner coverage. |
| Windows `amd64` | Supported | Supported | Partial | Core and premium local flows are supported; active DAST and some deep scanners remain container-first. |
| Windows `arm64` | Supported | Partial | Partial | Use `core` by default; prefer container bundle when available. |

## Capability Tiers

### `core`

- Uses only embedded modules such as stack detection, secret heuristics, and malware signature checks.
- Does not require the external pinned scanner bundle.
- Intended for fresh machines, offline-first smoke checks, and low-friction portability.
- Should not emit `skipped` modules because it avoids host binary dependencies.

### `premium`

- Default operator tier.
- Requires the pinned scanner runtime and fails fast when required tools are not ready.
- Covers the professional day-to-day AppSec path: SAST, SCA, SBOM, secrets, IaC, container, policy, diff, gate, triage, evidence, and TUI review.
- Best fit for normal desktop use and CI enforcement.
- Use `ironsentinel runtime lock coverage --missing-only` and `ironsentinel runtime doctor --require-integrity` to track which pinned scanners still lack checksum, signature, or source-digest metadata in the bundle lock.
- Use `go run ./cmd/releasectl lock hydrate --lock scanner-bundle.lock.json --write` to ingest official upstream checksum manifests, GitHub asset digests, PyPI wheel digests, and source archive digests into the lock before tightening integrity policy.
- Use `go run ./cmd/releasectl lock trust-assets --lock scanner-bundle.lock.json --generate-key --signer ironsentinel-release-root --write` when trusted installer or builder assets change and the local trust anchor needs to be rotated and re-signed.

### `full`

- Extends `premium` with the deepest scanner set and the most demanding runtime expectations.
- Intended for deep analysis, stronger authenticated DAST workflows, and the broadest scanner surface.
- Prefer rootless container isolation and prepared mirrors for repeatable results.

## Smoke Checks

Use the bundled smoke script before releases or packaging changes:

```bash
bash scripts/smoke_setup_doctor.sh
bash scripts/smoke_shell_guards.sh
bash scripts/validate_release_matrix.sh --host-only
bash scripts/smoke_signed_release.sh
bash scripts/release_publish_preflight.sh --version vX.Y.Z --require-signing --require-tag
bash scripts/release_artifact_preflight.sh --dir dist/vX.Y.Z --require-signing --require-external-attestation
go run ./cmd/releasectl notes --dir dist/vX.Y.Z --lock scanner-bundle.lock.json
pwsh scripts/smoke_setup_doctor.ps1
pwsh scripts/smoke_shell_guards.ps1
bash scripts/package_release.sh --version vX.Y.Z --sign
go run ./cmd/releasectl verify --dir dist/vX.Y.Z --lock scanner-bundle.lock.json --require-signature --require-attestation --require-clean-source
go run ./cmd/releasectl verify --dir dist/vX.Y.Z --lock scanner-bundle.lock.json --require-signature --require-attestation --require-external-attestation --require-clean-source
go run ./cmd/ironsentinel runtime release verify --version vX.Y.Z --require-signature --require-attestation --require-external-attestation
```

What it verifies:

- isolated temp runtime directories can be initialized
- `setup --coverage core` completes on a clean workspace
- `runtime doctor --mode safe` either passes or fails with the expected diagnostic surface
- shell wrapper guardrails reject missing flag values with explicit diagnostics and `package_release.sh` cleans its stage directory on build failure
- Windows PowerShell wrappers reject missing flag values before execution and keep installer temp work directories on a bounded lifecycle
- release publication now has a dedicated preflight gate for version format, local tag presence, tag alignment, signing secret presence, GitHub provenance metadata, bundle lock presence, and a clean source tree
- release artifact upload now has a dedicated preflight gate for required sidecar files, signatures, external provenance, and the presence of packaged archives
- GitHub release notes are now rendered deterministically from the packaged manifest, artifacts, and provenance instead of being handwritten in the workflow
- `runtime support` renders the current host support matrix and the requested coverage tier
- the release validator can cross-build the supported matrix targets
- the package builder emits per-platform archives, `SHA256SUMS`, `release-manifest.json`, `release-attestation.json`, `release-external-attestation.json`, and optional signatures
- the operator runtime can surface discovered release bundles and explicitly verify them from `dist/`
- the signed release path can be smoke-tested locally and in CI with an ephemeral Ed25519 key pair, including external provenance sidecar verification
- lock hydration can enrich supported pinned scanners from official upstream checksum manifests, GitHub asset digests, PyPI distribution digests, and source archives; as of March 18, 2026 the pinned `trivy v0.69.1` checksum URL still returned `404`, so IronSentinel falls back to the official source archive digest for that tool
- `scanner-bundle.lock.json` now also supports platform-specific version overrides so strict doctors can remain exact when a supported platform intentionally uses a different managed pin
- setup-time mirror seeding now covers both `trivy` and `osv-scanner`, with OSV offline databases stored in the official `osv-scanner/<ecosystem>/all.zip` layout under the runtime mirror root
- the POSIX safe installer now pins `setuptools<81` for Python-based scanner compatibility and installs exact managed binaries for `gitleaks`, `syft`, `osv-scanner`, and `staticcheck`

CI wiring lives in [`.github/workflows/release-validation.yml`](/Users/batuhanyuksel/Documents/security/.github/workflows/release-validation.yml) and runs:

- the full Go test suite
- the internal coverage gate via [scripts/coverage_gate.sh](/Users/batuhanyuksel/Documents/security/scripts/coverage_gate.sh)
  - emits `coverage/internal-summary.txt`
  - currently enforces a `45.0%` minimum across test-bearing `internal/...` packages; ratchet upward as coverage grows
- `go vet`, `staticcheck`, and `golangci-lint` with the repo policy in [`.golangci.yml`](/Users/batuhanyuksel/Documents/security/.golangci.yml)
  - the current lint policy uses `golangci-lint v2` and targets Go `1.25`, matching the repo toolchain
- host runtime support rendering on macOS, Linux, and Windows
- host smoke checks on each supported runner
- a release matrix cross-build validation job

For local parity, use [scripts/quality_local.sh](/Users/batuhanyuksel/Documents/security/scripts/quality_local.sh).

Signed publication lives in [`.github/workflows/release-publish.yml`](/Users/batuhanyuksel/Documents/security/.github/workflows/release-publish.yml). It requires the `AEGIS_RELEASE_PRIVATE_KEY_B64` secret and publishes the signed release bundle to GitHub Releases.

## Packaging Rule

- `core` must remain portable on every supported platform without external scanner installation.
- `premium` and `full` must never degrade to silent `skipped` behavior for required modules; they either run or fail with explicit runtime guidance.
- POSIX local bootstrap should prefer managed wrappers and managed binary roots under `runtime/tools/bin`; unavoidable system package-manager dependencies must stay explicit and minimal.
