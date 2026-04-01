---
name: cli-remediation-engine
description: Turn a CLI audit report into prioritized findings, a concrete patch plan, and implementation-ready remediation steps.
metadata:
  author: local
  version: "0.3.0"
  argument-hint: <audit-report-or-repo>
---

# CLI Remediation Engine

Use this after `cli-quality-scan` or after a generated audit report exists.

Start here:

1. Read `../../docs/remediation-playbook.md`.
2. If an audit report exists, run `../../scripts/generate_cli_fix_plan.sh <audit-report>`.
3. Re-open the repo sections named in the generated plan.
4. Convert the top remediation item into a failing or targeted test when feasible.
5. Patch the code.
6. Re-run the narrowest relevant checks first, then the broader audit commands.

## Required Behavior

- Work in descending risk order.
- Prefer fixes that tighten behavior and tests together.
- Preserve public command contracts unless the user explicitly approves a break.
- Separate three things in your output:
  - confirmed findings
  - proposed patches
  - verification evidence

## Finding Quality Bar

A finding is not complete unless it includes:

- a concrete failure mode or regression risk
- likely affected files or command surface
- a verification path
- a smallest-safe next patch

## Patch Rules

- Start with command correctness, exit codes, stderr/stdout contracts, and state bugs.
- Then address UX and modernization improvements.
- If tooling is missing, note the gap and continue with what can still be verified locally.
