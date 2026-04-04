# Backend Review

> Historical snapshot: this review predates the current architecture contract in [`docs/architecture.md`](/Users/batuhanyuksel/Documents/security/docs/architecture.md) and should be treated as archive material.

## Executive Summary

The backend/runtime layer is already a real local AppSec platform foundation. It has a usable domain model, normalized finding flow, policy evaluation, diff/gate logic, artifacts, mirrors, runtime doctor checks, and scanner bootstrap concepts. The main problem is not missing architecture; it is missing hardening. The product still behaves like an embedded monolith with a lightweight persistence layer and partially complete scanner orchestration.

## Current Backend Architecture

- Main service orchestration: [internal/core/service.go:18](/Users/batuhanyuksel/Documents/security/internal/core/service.go:18)
- Local scan/runtime agent: [internal/agent/service.go:14](/Users/batuhanyuksel/Documents/security/internal/agent/service.go:14)
- Domain model: [internal/domain/types.go:11](/Users/batuhanyuksel/Documents/security/internal/domain/types.go:11)
- Module pipeline: [internal/agent/modules.go:24](/Users/batuhanyuksel/Documents/security/internal/agent/modules.go:24)
- Isolation wrapper: [internal/agent/execution.go:26](/Users/batuhanyuksel/Documents/security/internal/agent/execution.go:26)
- Runtime doctor and bundle health: [internal/agent/bundle.go:50](/Users/batuhanyuksel/Documents/security/internal/agent/bundle.go:50)
- Persistence: [internal/store/state.go](/Users/batuhanyuksel/Documents/security/internal/store/state.go)
- Reporting/export: [internal/reports/export.go:12](/Users/batuhanyuksel/Documents/security/internal/reports/export.go:12)
- Policy packs: [internal/policy/builtin.go:5](/Users/batuhanyuksel/Documents/security/internal/policy/builtin.go:5)

## Strengths

- The domain model is appropriately broad for a local AppSec product.
- Findings, triage, suppressions, deltas, and policy decisions are unified coherently.
- Setup/runtime doctor/mirror visibility is product-grade and not an afterthought.
- Evidence/artifact persistence is a strong product choice.
- The pipeline already distinguishes built-in heuristics from external tool adapters.

## Weaknesses and Risks

- Isolation is stronger now, but local mode is still environment-hardening rather than a true OS sandbox.
- Container mode now exposes a visible trust contract with resource limits, read-only mounts, tmpfs scratch space, and explicit network policy, but it still needs deeper kernel-level hardening.
- Some integrations are still shallower than a final premium target:
  - CodeQL currently selects one supported language per run rather than a full multi-language cluster.
  - ZAP now uses Automation Framework plans, but authenticated contexts and richer API-specific flows are still limited.
  - Nuclei now enforces signed templates in execution, but template provenance/reporting could go deeper.
- Evidence protection is improved with redaction, retention metadata, and optional encryption-at-rest, but decryption/export ergonomics and key management are still basic.
- Supply-chain verification is now present for trusted bundle assets via signed checksums, but external scanner binaries still rely mostly on version pinning unless per-platform checksums are populated in the lock.
- Reporting is practical but still minimal in SARIF richness and HTML depth.
- Test coverage is good for unit and fixture behavior, but weaker for real third-party tool execution, isolation, Windows bootstrap, and failure recovery.

## Gaps vs a Premium Local AppSec Platform

- Stronger isolation model
- Deeper scanner orchestration
- Better artifact security controls
- Richer export fidelity
- More complete release discipline and supported-runtime validation

## Prioritized Recommendations

1. Finish the storage transition and make it durable, queryable, and migration-aware.
2. Introduce a real job engine with retries, timeouts, raw execution metadata, and structured failure taxonomy.
3. Harden container isolation and clearly define runtime capability tiers.
4. Complete the placeholder scanner integrations.
5. Add masking/redaction and optional encryption for sensitive evidence.
6. Expand checksum coverage from trusted local assets to more third-party scanner binaries in the lock.
7. Expand cross-platform and failure-mode tests.

## Reference Technologies

- [Semgrep CLI docs](https://semgrep.dev/docs/cli-reference)
- [Trivy filesystem scanning](https://trivy.dev/latest/docs/target/filesystem/)
- [Syft](https://github.com/anchore/syft)
- [OSV-Scanner](https://google.github.io/osv-scanner/)
- [Checkov CLI reference](https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html)
- [CodeQL CLI](https://docs.github.com/en/code-security/codeql-cli)
- [OWASP ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/)
- [Nuclei template signing](https://docs.projectdiscovery.io/templates/reference/template-signing)
- [ClamAV scanning](https://docs.clamav.net/manual/Usage/Scanning.html)
- [CycloneDX](https://cyclonedx.org/specification/overview/)
- [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
