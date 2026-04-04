# GitHub Integration Design

## Goal

Add a first-class `ironsentinel github` command family that can publish scan results directly to GitHub without changing the existing `scan`, `runs`, `export`, or TUI contracts.

The first delivery covers:

- SARIF upload to GitHub code scanning
- dependency submission to GitHub dependency graph

## Scope

In scope:

- direct local operator upload using `GITHUB_TOKEN`, `GH_TOKEN`, or `gh auth token`
- explicit repo/ref/sha overrides
- shell-safe, non-interactive CLI behavior
- reuse of canonical `RunReport`, shared planner metadata, and existing project/run models
- tests for auth resolution, repo resolution, payload generation, and CLI command contracts

Out of scope for this delivery:

- issue creation
- PR review comments
- campaign/remediation workflows
- GitHub App auth
- server-side sync daemons

## User-Facing Contract

New command family:

```bash
ironsentinel github upload-sarif <run-id> [--repo owner/name] [--ref <git-ref>] [--sha <commit-sha>]
ironsentinel github submit-deps <project-id|run-id> [--repo owner/name] [--ref <git-ref>] [--sha <commit-sha>]
```

Behavior rules:

- existing commands keep current behavior
- `export` remains file/stdout oriented and does not publish remotely
- `github` commands print concise human summaries in normal mode
- machine-oriented output, if added later, must be opt-in rather than implicit
- errors go to stderr and return non-zero

## Approach Options

### Option A: Separate `github` command family

Pros:

- keeps publishing concerns separate from reporting concerns
- scales cleanly for future `issues`, `annotations`, `campaigns`, `repo sync`
- avoids overloading `export`

Cons:

- adds a new first-class command group

### Option B: Add GitHub publishing flags to `export`

Pros:

- shorter command surface

Cons:

- mixes file generation and remote publishing
- gets messy once dependency submission and other GitHub actions are added

### Option C: Add publishing under `runs`

Pros:

- run-centric mental model

Cons:

- poor fit for dependency graph workflows
- will not age well as GitHub integration grows

Recommended option: Option A.

## Architecture

### New package

Create `internal/integrations/github` as the only GitHub API boundary.

Responsibilities:

- resolve auth token
- resolve owner/repo, ref, and commit sha
- build and send SARIF upload requests
- build and send dependency submission requests
- normalize GitHub API errors into stable CLI-facing errors

This package should not know about Cobra, Bubble Tea, or pterm.

### CLI wiring

Add a new `github` root command in `internal/cli`.

Subcommands:

- `upload-sarif`
- `submit-deps`

CLI responsibilities:

- parse flags
- resolve run/project references through existing services
- call the integration client
- render concise results

### Data sources

#### SARIF upload

Input source:

- `service.BuildRunReport(runID, baselineID)`
- `reports.Export("sarif", report)`

This guarantees GitHub receives the same canonical finding model already used by HTML/CSV/SARIF export.

#### Dependency submission

Input source:

- project metadata from `PortfolioData` / project lookup
- module plan metadata from `internal/domain/planner.go`
- run/project dependency signals already emitted by supply-chain tools

First version should submit a minimal but valid dependency snapshot rather than attempt full dependency graph enrichment for every ecosystem on day one.

## Auth And Repository Resolution

Resolution order:

1. `GITHUB_TOKEN`
2. `GH_TOKEN`
3. `gh auth token`

Repository resolution order:

1. explicit `--repo owner/name`
2. `git remote get-url origin`

Ref resolution order:

1. explicit `--ref`
2. current branch ref if available
3. `HEAD`

SHA resolution order:

1. explicit `--sha`
2. `git rev-parse HEAD`

Failure behavior:

- if token cannot be resolved, return an actionable auth error
- if repo cannot be resolved, ask for `--repo`
- if sha cannot be resolved, fail explicitly; do not upload ambiguous payloads

## Dependency Submission Shape

The first version should generate one dependency snapshot per submission with:

- detector metadata: `ironsentinel`
- job metadata: command + version
- manifest identity derived from project path and detected stacks
- resolved dependency set from current project/run evidence

If dependency evidence is absent, the command should fail with a clear “no dependency inventory available” message rather than submit an empty snapshot pretending success.

## Error Handling

GitHub API failures should be mapped to stable categories:

- auth failure
- repo access failure
- validation failure
- rate limit / secondary limit
- transport failure

CLI should print:

- the action that failed
- the resolved repo
- the GitHub response summary
- one concrete next step

## Testing

### Unit tests

- auth token precedence
- repo/ref/sha resolution
- SARIF upload request construction
- dependency submission payload construction
- GitHub error mapping

### CLI tests

- `github --help`
- `upload-sarif --help`
- `submit-deps --help`
- missing token failure
- missing repo failure

### Integration-style tests

Use `httptest` against the GitHub client package:

- successful SARIF upload
- successful dependency submission
- 401 auth failure
- 403 access failure
- 422 validation failure

## Files To Add Or Modify

New:

- `internal/integrations/github/client.go`
- `internal/integrations/github/auth.go`
- `internal/integrations/github/repository.go`
- `internal/integrations/github/sarif.go`
- `internal/integrations/github/deps.go`
- `internal/integrations/github/client_test.go`
- `internal/integrations/github/sarif_test.go`
- `internal/integrations/github/deps_test.go`
- `docs/superpowers/specs/2026-04-03-github-integration-design.md`

Modify:

- `internal/cli/root_command.go`
- `internal/cli/app.go`
- `internal/cli/app_test.go`
- `README.md`
- `docs/architecture.md`

## Risks

- GitHub dependency submission can become ecosystem-specific very quickly. First delivery should prefer a minimal valid snapshot over over-modeling.
- Upload commands must not leak tokens in logs, errors, or artifacts.
- Repo/ref/sha auto-resolution must stay overrideable because local worktrees and detached HEAD states are common.

## Success Criteria

- an operator can upload SARIF for a run directly from a local machine
- an operator can submit a dependency snapshot for a project/run directly from a local machine
- auth and repo resolution are deterministic and well tested
- existing `export`, `runs`, and TUI surfaces remain behaviorally unchanged
- the implementation fits the current architecture by reusing canonical report and planner models
