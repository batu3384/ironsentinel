# CLI Audit Report

## Scope

- Target: /Users/batuhanyuksel/Documents/security/plugins/cli-systems-lab
- Date: 2026-03-28 12:45:51 +0300
- Reviewer: CLI Systems Lab

## Stack Detection

- Languages: Shell scripts
- Frameworks: none detected

## Evidence Run

- Inventory status: captured
- Quick audit status: passed

### Recommended Commands

- shellcheck <shell-files>

### Missing Tools

- shellcheck not installed

## Priority Review Areas

  - Shell: inspect wrappers, release scripts, install scripts, and pipe-friendly behavior.

## Inventory Output

```text
Repository: /Users/batuhanyuksel/Documents/security/plugins/cli-systems-lab

Detected languages and wrappers:
  - Shell scripts

Detected frameworks and libraries:

Priority review areas:
  - Shell: inspect wrappers, release scripts, install scripts, and pipe-friendly behavior.

High-value files:
./scripts/generate_cli_audit_report.sh
./scripts/run_cli_quick_audit.sh
./scripts/inspect_cli_repo.sh

Recommended commands:
  - shellcheck <shell-files>

```

## Quick Audit Output

```text

SKIP: shellcheck not installed

Audit completed without failing steps.

```

## Findings

### High Risk

- [Fill after review]

### Medium Risk

- [Fill after review]

### Low Risk

- [Fill after review]

## Quick Wins

- [Fill after review]

## Modernization Opportunities

- [Fill after review]

## Recommended Next Step

- Start with the highest-risk review area above, then turn findings into tests before refactoring.
