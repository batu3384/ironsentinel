# IronSentinel Campaign And GitHub Remediation Design

## Summary

Add a local-first remediation campaign system that groups findings into actionable work units, then publishes or syncs those campaigns to GitHub Issues and pull-request workflows without changing the existing scan, finding, run, or export contracts.

The design goal is to keep IronSentinel authoritative for security state while using GitHub as a downstream execution surface.

## Project Context

Current GitHub integration already supports:

- SARIF upload
- dependency submission
- local push protection
- GitHub custom secret pattern export

Current command and data model already centers on:

- local SQLite-backed projects, runs, findings, triage, suppressions
- canonical `RunReport`
- fullscreen TUI plus shell-safe CLI

This makes remediation work a natural next step, but the current product has no durable object for "this set of findings belongs to one remediation effort".

## Approaches

### Approach 1: Local-first campaigns with GitHub publish/sync

IronSentinel stores campaigns locally and can publish them to GitHub Issues later.

Pros:

- preserves local-first architecture
- works even when GitHub is unavailable
- cleanly supports TUI, CLI, and future non-GitHub backends
- keeps findings/campaign state authoritative inside IronSentinel

Cons:

- adds a new local domain model
- requires explicit sync/publish commands

### Approach 2: GitHub-native issues only

IronSentinel creates GitHub Issues directly from selected findings and treats GitHub as the campaign system.

Pros:

- simpler first integration
- no new local campaign model

Cons:

- breaks local-first product direction
- weak offline behavior
- TUI would have to read remote state for core remediation workflows
- harder to support future Jira/Linear providers

### Approach 3: Campaign files in repo

Store remediation campaign documents as JSON or YAML files under the workspace and optionally publish them to GitHub.

Pros:

- visible in git
- auditable in repo history

Cons:

- fragile across multiple projects and mutable finding state
- poor fit for the existing SQLite portfolio model
- creates repo noise and merge friction

## Recommendation

Choose Approach 1.

It fits the current product architecture best: IronSentinel remains the system of record for campaigns and uses GitHub as a publication target. This preserves current code quality boundaries and avoids turning remote API state into core product truth.

## Design

### 1. Domain model

Add a new campaign aggregate in `internal/domain`.

Core fields:

- `ID`
- `ProjectID`
- `Title`
- `Summary`
- `Status`
- `Owner`
- `DueAt`
- `CreatedAt`
- `UpdatedAt`
- `FindingFingerprints []string`
- `BaselineRunID`
- `SourceRunID`
- `PublishedIssues []CampaignIssueRef`

Supporting types:

- `CampaignStatus`: `open`, `in_progress`, `completed`, `archived`
- `CampaignIssueRef`: provider, repo, issue number, url, state

Rules:

- campaigns reference findings by fingerprint, not by copying whole findings
- campaign state is local-first
- publication metadata is additive, not authoritative

### 2. Store and service layer

Add SQLite persistence in `internal/store/state.go` and service methods in `internal/core/service.go`.

Required service methods:

- `CreateCampaign`
- `UpdateCampaign`
- `GetCampaign`
- `ListCampaigns`
- `AddFindingsToCampaign`
- `RemoveFindingsFromCampaign`
- `PublishCampaignToGitHub`

Service behavior:

- resolve campaign findings from the current local finding model
- keep derived summaries deterministic
- gracefully handle missing/resolved findings without corrupting the campaign

### 3. GitHub integration boundary

Extend `internal/integrations/github` with issue publishing helpers.

Required capabilities:

- create issue
- optionally update issue body/labels for resync
- build issue body from campaign + live findings

Do not add issue state as a required source of truth. GitHub issue state is mirrored metadata only.

### 4. CLI surface

Add a new top-level `campaigns` command family.

Initial commands:

- `campaigns list`
- `campaigns show <campaign-id>`
- `campaigns create --project <id> --title <text> --run <id> --finding <fingerprint>...`
- `campaigns add-findings <campaign-id> --run <id> --finding <fingerprint>...`
- `campaigns publish-github <campaign-id> --repo owner/name`

Add one convenience command under `github`:

- `github create-issues-from-campaign <campaign-id> --repo owner/name`

This is a thin wrapper over the same campaign publish service, kept only for consistency with existing GitHub subcommands.

### 5. TUI behavior

Do not add a full new route yet.

Phase 1 TUI scope:

- show campaign count and publish hint in `Findings` and `Runs` detail surfaces when a selection is present
- add command-palette action to create a campaign from the current finding scope

This keeps scope controlled and avoids another large UI branch before the domain model is proven.

### 6. GitHub issue shape

Each published issue should include:

- campaign title
- campaign summary
- project
- source run
- severity distribution
- top findings table
- remediation guidance snippets
- links/commands for local follow-up

Labels should be deterministic:

- `ironsentinel`
- `security`
- severity label for highest finding
- category labels for included finding groups

### 7. Error handling

- local campaign creation must succeed without network
- GitHub publish failures must not corrupt local campaigns
- partial publish should return exact created issue refs
- repeated publish should support idempotent detection where possible

### 8. Testing

Required tests:

- domain and store round-trip for campaigns
- service-level create/add/remove flows
- GitHub issue body builder tests
- CLI command contract tests
- TUI summary visibility tests

### 9. Non-goals for this slice

Not in this delivery:

- Jira or Linear backends
- PR comment automation
- bidirectional sync from GitHub Issues back into core campaign truth
- campaign analytics dashboards

## Public Contract Impact

Preserved:

- existing `github` commands
- existing `findings`, `runs`, `review`, `triage`, `export` commands

Added:

- `campaigns` command family
- GitHub issue publishing helper command

No breaking contract changes are required.

## File Impact

Expected primary files:

- `internal/domain/types.go` or a new `internal/domain/campaign.go`
- `internal/store/state.go`
- `internal/core/service.go`
- `internal/integrations/github/issues.go`
- `internal/cli/app.go`
- `internal/cli/app_shell_*`
- `README.md`
- `docs/architecture.md`

## Success Criteria

- operators can create a campaign from selected findings without network
- a campaign can be published to GitHub as one or more issues
- publication metadata is visible locally
- current scan/report/finding workflows remain unchanged
- `go test ./...`, `go vet ./...`, and `bash scripts/quality_local.sh` stay green
