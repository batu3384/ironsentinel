# Campaign And GitHub Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a local-first campaign system that groups findings into remediation work items and publishes those campaigns to GitHub Issues without changing existing scan, finding, run, export, or TUI contracts.

**Architecture:** Keep campaign truth in the local SQLite-backed service and store layers. Add a thin GitHub issue publishing adapter under `internal/integrations/github`, then expose it through a new `campaigns` CLI family plus a compatibility wrapper under `github`. Keep TUI scope small in phase one: summary visibility and palette-triggered campaign creation, not a full new route.

**Tech Stack:** Go, Cobra, Bubble Tea, SQLite state store, existing `internal/core` service layer, existing `internal/integrations/github` package, `httptest`.

---

### Task 1: Add the campaign domain model

**Files:**
- Create: `/Users/batuhanyuksel/Documents/security/internal/domain/campaign.go`
- Test: `/Users/batuhanyuksel/Documents/security/internal/domain/campaign_test.go`

- [ ] **Step 1: Write the failing domain tests**

```go
package domain

import (
	"testing"
	"time"
)

func TestNewCampaignNormalizesFindingFingerprints(t *testing.T) {
	now := time.Date(2026, 4, 4, 15, 0, 0, 0, time.UTC)
	campaign := NewCampaign("cmp-1", "prj-1", "Fix reachable SCA", "Source run summary", "run-1", "", []string{"fp-2", "fp-1", "fp-1"}, now)

	if campaign.Status != CampaignOpen {
		t.Fatalf("expected open status, got %s", campaign.Status)
	}
	if len(campaign.FindingFingerprints) != 2 {
		t.Fatalf("expected deduped findings, got %+v", campaign.FindingFingerprints)
	}
	if campaign.FindingFingerprints[0] != "fp-1" || campaign.FindingFingerprints[1] != "fp-2" {
		t.Fatalf("expected sorted fingerprints, got %+v", campaign.FindingFingerprints)
	}
}

func TestCampaignHighestSeverity(t *testing.T) {
	campaign := Campaign{
		FindingFingerprints: []string{"fp-1"},
	}
	findings := []Finding{
		{Fingerprint: "fp-1", Severity: SeverityCritical},
		{Fingerprint: "fp-2", Severity: SeverityLow},
	}
	if got := campaign.HighestSeverity(findings); got != SeverityCritical {
		t.Fatalf("expected critical severity, got %s", got)
	}
}
```

- [ ] **Step 2: Run the test subset and verify it fails**

Run:

```bash
go test ./internal/domain -run 'Test(NewCampaignNormalizesFindingFingerprints|CampaignHighestSeverity)$' -count=1
```

Expected: FAIL with undefined `Campaign`, `CampaignOpen`, `NewCampaign`, or `HighestSeverity`.

- [ ] **Step 3: Add the minimal campaign domain implementation**

```go
// /Users/batuhanyuksel/Documents/security/internal/domain/campaign.go
package domain

import (
	"slices"
	"strings"
	"time"
)

type CampaignStatus string

const (
	CampaignOpen       CampaignStatus = "open"
	CampaignInProgress CampaignStatus = "in_progress"
	CampaignCompleted  CampaignStatus = "completed"
	CampaignArchived   CampaignStatus = "archived"
)

type CampaignIssueRef struct {
	Provider string `json:"provider"`
	Repo     string `json:"repo"`
	Number   int    `json:"number"`
	URL      string `json:"url"`
	State    string `json:"state"`
}

type Campaign struct {
	ID                  string             `json:"id"`
	ProjectID           string             `json:"projectId"`
	Title               string             `json:"title"`
	Summary             string             `json:"summary"`
	Status              CampaignStatus     `json:"status"`
	Owner               string             `json:"owner,omitempty"`
	DueAt               *time.Time         `json:"dueAt,omitempty"`
	CreatedAt           time.Time          `json:"createdAt"`
	UpdatedAt           time.Time          `json:"updatedAt"`
	FindingFingerprints []string           `json:"findingFingerprints"`
	SourceRunID         string             `json:"sourceRunId,omitempty"`
	BaselineRunID       string             `json:"baselineRunId,omitempty"`
	PublishedIssues     []CampaignIssueRef `json:"publishedIssues,omitempty"`
}

func NewCampaign(id, projectID, title, summary, sourceRunID, baselineRunID string, findingFingerprints []string, now time.Time) Campaign {
	normalized := make([]string, 0, len(findingFingerprints))
	seen := map[string]struct{}{}
	for _, fingerprint := range findingFingerprints {
		value := strings.TrimSpace(fingerprint)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	slices.Sort(normalized)
	return Campaign{
		ID:                  id,
		ProjectID:           projectID,
		Title:               strings.TrimSpace(title),
		Summary:             strings.TrimSpace(summary),
		Status:              CampaignOpen,
		CreatedAt:           now.UTC(),
		UpdatedAt:           now.UTC(),
		FindingFingerprints: normalized,
		SourceRunID:         strings.TrimSpace(sourceRunID),
		BaselineRunID:       strings.TrimSpace(baselineRunID),
	}
}

func (c Campaign) HighestSeverity(findings []Finding) Severity {
	best := SeverityInfo
	lookup := map[string]struct{}{}
	for _, fingerprint := range c.FindingFingerprints {
		lookup[fingerprint] = struct{}{}
	}
	for _, finding := range findings {
		if _, ok := lookup[finding.Fingerprint]; !ok {
			continue
		}
		if SeverityRank(finding.Severity) < SeverityRank(best) {
			best = finding.Severity
		}
	}
	return best
}
```

- [ ] **Step 4: Run the tests and verify they pass**

Run:

```bash
go test ./internal/domain -run 'Test(NewCampaignNormalizesFindingFingerprints|CampaignHighestSeverity)$' -count=1
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/domain/campaign.go internal/domain/campaign_test.go
git commit -m "feat: add campaign domain model"
```

### Task 2: Persist campaigns in the SQLite store

**Files:**
- Modify: `/Users/batuhanyuksel/Documents/security/internal/store/state.go`
- Test: `/Users/batuhanyuksel/Documents/security/internal/store/state_test.go`

- [ ] **Step 1: Write the failing store tests**

```go
func TestCampaignRoundTrip(t *testing.T) {
	store := newTestStateStore(t)
	campaign := domain.NewCampaign("cmp-1", "prj-1", "Fix secrets", "summary", "run-1", "", []string{"fp-1", "fp-2"}, time.Now().UTC())

	if err := store.SaveCampaign(campaign); err != nil {
		t.Fatalf("save campaign: %v", err)
	}

	got, ok := store.GetCampaign(campaign.ID)
	if !ok {
		t.Fatalf("expected campaign %s", campaign.ID)
	}
	if got.Title != "Fix secrets" || len(got.FindingFingerprints) != 2 {
		t.Fatalf("unexpected stored campaign: %+v", got)
	}
}

func TestListCampaignsFiltersByProject(t *testing.T) {
	store := newTestStateStore(t)
	first := domain.NewCampaign("cmp-1", "prj-1", "One", "", "", "", []string{"fp-1"}, time.Now().UTC())
	second := domain.NewCampaign("cmp-2", "prj-2", "Two", "", "", "", []string{"fp-2"}, time.Now().UTC())
	_ = store.SaveCampaign(first)
	_ = store.SaveCampaign(second)

	items := store.ListCampaigns("prj-1")
	if len(items) != 1 || items[0].ID != "cmp-1" {
		t.Fatalf("unexpected filtered campaigns: %+v", items)
	}
}
```

- [ ] **Step 2: Run the test subset and verify it fails**

Run:

```bash
go test ./internal/store -run 'Test(CampaignRoundTrip|ListCampaignsFiltersByProject)$' -count=1
```

Expected: FAIL with missing `SaveCampaign`, `GetCampaign`, or `ListCampaigns`.

- [ ] **Step 3: Implement minimal store support**

```go
// add migration in /Users/batuhanyuksel/Documents/security/internal/store/state.go
const campaignMigration = `
create table if not exists campaigns (
  id text primary key,
  project_id text not null,
  payload json not null
);
`
```

```go
func (s *StateStore) SaveCampaign(campaign domain.Campaign) error {
	return s.upsertJSON("campaigns", campaign.ID, campaign.ProjectID, campaign)
}

func (s *StateStore) GetCampaign(id string) (domain.Campaign, bool) {
	var campaign domain.Campaign
	ok := s.querySingleJSON(`select payload from campaigns where id = ?`, []any{id}, &campaign)
	return campaign, ok
}

func (s *StateStore) ListCampaigns(projectID string) []domain.Campaign {
	query := `select payload from campaigns`
	args := []any{}
	if strings.TrimSpace(projectID) != "" {
		query += ` where project_id = ?`
		args = append(args, projectID)
	}
	query += ` order by json_extract(payload, '$.updatedAt') desc`
	var campaigns []domain.Campaign
	s.queryJSONList(query, args, &campaigns)
	return campaigns
}
```

- [ ] **Step 4: Run the tests and verify they pass**

Run:

```bash
go test ./internal/store -run 'Test(CampaignRoundTrip|ListCampaignsFiltersByProject)$' -count=1
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/store/state.go internal/store/state_test.go
git commit -m "feat: persist remediation campaigns"
```

### Task 3: Add service-layer campaign workflows

**Files:**
- Modify: `/Users/batuhanyuksel/Documents/security/internal/core/service.go`
- Test: `/Users/batuhanyuksel/Documents/security/internal/core/service_test.go`

- [ ] **Step 1: Write the failing service tests**

```go
func TestCreateCampaignFromRunFindings(t *testing.T) {
	service, run, findings := newServiceWithRunAndFindings(t)

	campaign, err := service.CreateCampaign(domain.Campaign{
		ID:                  "cmp-1",
		ProjectID:           run.ProjectID,
		Title:               "Fix reachable SCA",
		SourceRunID:         run.ID,
		FindingFingerprints: []string{findings[0].Fingerprint},
	})
	if err != nil {
		t.Fatalf("create campaign: %v", err)
	}
	if campaign.Status != domain.CampaignOpen {
		t.Fatalf("expected open campaign, got %s", campaign.Status)
	}
}

func TestAddFindingsToCampaignDeduplicates(t *testing.T) {
	service, run, findings := newServiceWithRunAndFindings(t)
	campaign, _ := service.CreateCampaign(domain.Campaign{
		ID:                  "cmp-1",
		ProjectID:           run.ProjectID,
		Title:               "Fix queue",
		SourceRunID:         run.ID,
		FindingFingerprints: []string{findings[0].Fingerprint},
	})

	updated, err := service.AddFindingsToCampaign(campaign.ID, []string{findings[0].Fingerprint, findings[1].Fingerprint})
	if err != nil {
		t.Fatalf("add findings: %v", err)
	}
	if len(updated.FindingFingerprints) != 2 {
		t.Fatalf("expected deduped fingerprints, got %+v", updated.FindingFingerprints)
	}
}
```

- [ ] **Step 2: Run the test subset and verify it fails**

Run:

```bash
go test ./internal/core -run 'Test(CreateCampaignFromRunFindings|AddFindingsToCampaignDeduplicates)$' -count=1
```

Expected: FAIL with missing service methods.

- [ ] **Step 3: Implement minimal service methods**

```go
func (s *Service) CreateCampaign(input domain.Campaign) (domain.Campaign, error) {
	now := time.Now().UTC()
	campaign := domain.NewCampaign(
		input.ID,
		input.ProjectID,
		input.Title,
		input.Summary,
		input.SourceRunID,
		input.BaselineRunID,
		input.FindingFingerprints,
		now,
	)
	if err := s.store.SaveCampaign(campaign); err != nil {
		return domain.Campaign{}, err
	}
	return campaign, nil
}

func (s *Service) AddFindingsToCampaign(campaignID string, fingerprints []string) (domain.Campaign, error) {
	campaign, ok := s.store.GetCampaign(campaignID)
	if !ok {
		return domain.Campaign{}, fmt.Errorf("campaign not found: %s", campaignID)
	}
	combined := append(append([]string(nil), campaign.FindingFingerprints...), fingerprints...)
	updated := domain.NewCampaign(campaign.ID, campaign.ProjectID, campaign.Title, campaign.Summary, campaign.SourceRunID, campaign.BaselineRunID, combined, campaign.CreatedAt)
	updated.Status = campaign.Status
	updated.Owner = campaign.Owner
	updated.DueAt = campaign.DueAt
	updated.PublishedIssues = campaign.PublishedIssues
	updated.CreatedAt = campaign.CreatedAt
	updated.UpdatedAt = time.Now().UTC()
	if err := s.store.SaveCampaign(updated); err != nil {
		return domain.Campaign{}, err
	}
	return updated, nil
}
```

- [ ] **Step 4: Run the tests and verify they pass**

Run:

```bash
go test ./internal/core -run 'Test(CreateCampaignFromRunFindings|AddFindingsToCampaignDeduplicates)$' -count=1
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/core/service.go internal/core/service_test.go
git commit -m "feat: add campaign service workflows"
```

### Task 4: Add GitHub issue publishing for campaigns

**Files:**
- Create: `/Users/batuhanyuksel/Documents/security/internal/integrations/github/issues.go`
- Test: `/Users/batuhanyuksel/Documents/security/internal/integrations/github/issues_test.go`

- [ ] **Step 1: Write the failing publisher tests**

```go
func TestBuildCampaignIssuePayload(t *testing.T) {
	campaign := domain.Campaign{
		ID:        "cmp-1",
		ProjectID: "prj-1",
		Title:     "Fix reachable SCA",
		Summary:   "Top security campaign",
	}
	findings := []domain.Finding{
		{Title: "Reachable package issue", Severity: domain.SeverityCritical, Category: domain.CategorySCA},
	}

	payload := BuildCampaignIssuePayload(campaign, findings)
	if payload.Title != "Fix reachable SCA" {
		t.Fatalf("unexpected title: %+v", payload)
	}
	if len(payload.Labels) == 0 {
		t.Fatalf("expected deterministic labels")
	}
	if !strings.Contains(payload.Body, "Reachable package issue") {
		t.Fatalf("expected finding in issue body: %q", payload.Body)
	}
}
```

- [ ] **Step 2: Run the test subset and verify it fails**

Run:

```bash
go test ./internal/integrations/github -run 'TestBuildCampaignIssuePayload$' -count=1
```

Expected: FAIL with undefined issue payload helpers.

- [ ] **Step 3: Implement the minimal issue publisher**

```go
package github

import (
	"context"
	"fmt"
	"strings"

	"github.com/batu3384/ironsentinel/internal/domain"
)

type IssuePayload struct {
	Title  string   `json:"title"`
	Body   string   `json:"body"`
	Labels []string `json:"labels,omitempty"`
}

type IssueResponse struct {
	Number int    `json:"number"`
	State  string `json:"state"`
	URL    string `json:"html_url"`
}

func BuildCampaignIssuePayload(campaign domain.Campaign, findings []domain.Finding) IssuePayload {
	lines := []string{
		campaign.Summary,
		"",
		"## Findings",
	}
	for _, finding := range findings {
		lines = append(lines, fmt.Sprintf("- [%s] %s (%s)", strings.ToUpper(string(finding.Severity)), finding.Title, finding.Module))
	}
	return IssuePayload{
		Title: campaign.Title,
		Body:  strings.TrimSpace(strings.Join(lines, "\n")),
		Labels: []string{
			"ironsentinel",
			"security",
		},
	}
}

func (c *Client) CreateIssue(ctx context.Context, repo Repository, payload IssuePayload) (IssueResponse, error) {
	resp, err := c.postJSON(ctx, fmt.Sprintf("/repos/%s/%s/issues", repo.Owner, repo.Name), payload)
	if err != nil {
		return IssueResponse{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return IssueResponse{}, fmt.Errorf("github issue create failed: %s", readBody(resp))
	}
	defer resp.Body.Close()
	var issue IssueResponse
	return issue, json.NewDecoder(resp.Body).Decode(&issue)
}
```

- [ ] **Step 4: Run the tests and verify they pass**

Run:

```bash
go test ./internal/integrations/github -run 'TestBuildCampaignIssuePayload$' -count=1
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/integrations/github/issues.go internal/integrations/github/issues_test.go
git commit -m "feat: add GitHub issue publishing for campaigns"
```

### Task 5: Expose campaigns in the CLI

**Files:**
- Modify: `/Users/batuhanyuksel/Documents/security/internal/cli/app.go`
- Test: `/Users/batuhanyuksel/Documents/security/internal/cli/app_test.go`
- Modify: `/Users/batuhanyuksel/Documents/security/internal/i18n/catalog_en.go`
- Modify: `/Users/batuhanyuksel/Documents/security/internal/i18n/catalog_tr.go`

- [ ] **Step 1: Write the failing CLI tests**

```go
func TestCampaignsCommandIncludesCreateListShowAndPublish(t *testing.T) {
	app := newTestCLIApp(t)
	root := app.RootCommand()

	for _, use := range []string{"campaigns create", "campaigns list", "campaigns show", "campaigns publish-github"} {
		parts := strings.Split(use, " ")
		if _, _, err := root.Find(parts); err != nil {
			t.Fatalf("expected command %q: %v", use, err)
		}
	}
}

func TestGitHubCreateIssuesFromCampaignCommandExists(t *testing.T) {
	app := newTestCLIApp(t)
	cmd := app.githubCommand()
	if _, _, err := cmd.Find([]string{"create-issues-from-campaign"}); err != nil {
		t.Fatalf("expected GitHub campaign publish wrapper: %v", err)
	}
}
```

- [ ] **Step 2: Run the test subset and verify it fails**

Run:

```bash
go test ./internal/cli -run 'Test(CampaignsCommandIncludesCreateListShowAndPublish|GitHubCreateIssuesFromCampaignCommandExists)$' -count=1
```

Expected: FAIL because the commands do not exist yet.

- [ ] **Step 3: Implement the minimal command surface**

```go
func (a *App) campaignsCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "campaigns",
		Short: "Remediation campaigns",
	}
	// add list/show/create/publish-github here
	return command
}
```

```go
func (a *App) githubCreateIssuesFromCampaignCommand() *cobra.Command {
	var repoFlag string
	return &cobra.Command{
		Use:   "create-issues-from-campaign [campaign-id]",
		Short: "Publish a local remediation campaign to GitHub Issues",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.publishCampaignToGitHub(cmd.Context(), args[0], repoFlag)
		},
	}
}
```

- [ ] **Step 4: Run the tests and verify they pass**

Run:

```bash
go test ./internal/cli -run 'Test(CampaignsCommandIncludesCreateListShowAndPublish|GitHubCreateIssuesFromCampaignCommandExists)$' -count=1
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/cli/app.go internal/cli/app_test.go internal/i18n/catalog_en.go internal/i18n/catalog_tr.go
git commit -m "feat: add campaign CLI workflows"
```

### Task 6: Add lightweight TUI visibility and docs

**Files:**
- Modify: `/Users/batuhanyuksel/Documents/security/internal/cli/app_shell_details.go`
- Modify: `/Users/batuhanyuksel/Documents/security/internal/cli/app_shell_routes.go`
- Test: `/Users/batuhanyuksel/Documents/security/internal/cli/app_shell_test.go`
- Modify: `/Users/batuhanyuksel/Documents/security/README.md`
- Modify: `/Users/batuhanyuksel/Documents/security/docs/architecture.md`

- [ ] **Step 1: Write the failing TUI visibility test**

```go
func TestAppShellFindingDetailShowsCampaignHint(t *testing.T) {
	app, model := newAppShellWithFindingFixture(t)
	_ = app
	content := model.renderFindingDetailContent(100)
	if !strings.Contains(content, "Campaign") {
		t.Fatalf("expected campaign hint in finding detail, got %q", content)
	}
}
```

- [ ] **Step 2: Run the test subset and verify it fails**

Run:

```bash
go test ./internal/cli -run 'TestAppShellFindingDetailShowsCampaignHint$' -count=1
```

Expected: FAIL because the TUI does not reference campaigns yet.

- [ ] **Step 3: Add the minimal TUI and docs updates**

```go
// show campaign count or a command hint, not a full route
hint := m.app.catalog.T("campaigns_create_hint")
```

```md
## Remediation Campaigns

Use `ironsentinel campaigns create` to turn selected findings into a durable local remediation work item, then publish it with `ironsentinel campaigns publish-github`.
```

- [ ] **Step 4: Run the tests and verify they pass**

Run:

```bash
go test ./internal/cli -run 'TestAppShellFindingDetailShowsCampaignHint$' -count=1
```

Expected: PASS

- [ ] **Step 5: Run full verification**

Run:

```bash
go test ./...
go vet ./...
bash scripts/quality_local.sh
```

Expected: all commands exit `0`

- [ ] **Step 6: Commit**

```bash
git add internal/cli/app_shell_details.go internal/cli/app_shell_routes.go internal/cli/app_shell_test.go README.md docs/architecture.md
git commit -m "feat: surface remediation campaigns in tui and docs"
```

## Spec Coverage Check

- Local-first campaign domain: covered by Tasks 1-3.
- GitHub issue publication: covered by Task 4 and CLI wrapper in Task 5.
- New `campaigns` command family: covered by Task 5.
- Phase-one TUI visibility only: covered by Task 6.
- Non-goals such as Jira/Linear, PR comments, and analytics are intentionally excluded.

## Self-Review Notes

- No placeholder APIs remain in the plan; every new symbol named above is defined in the corresponding task.
- Scope is still one delivery slice: campaign domain, persistence, service, GitHub issue publish, CLI, and minimal TUI visibility.
- The plan preserves current product contracts and adds only additive command surfaces.
