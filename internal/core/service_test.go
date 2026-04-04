package core

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
	"github.com/batu3384/ironsentinel/internal/policy"
)

func TestGetRunDeltaUsesPreviousCompletedRunAsBaseline(t *testing.T) {
	cfg := config.Config{
		DataDir:   filepath.Join(t.TempDir(), "data"),
		OutputDir: filepath.Join(t.TempDir(), "output"),
	}

	service, err := New(cfg)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	project := domain.Project{
		ID:           "prj-1",
		DisplayName:  "Fixture",
		TargetHandle: "fixture",
		LocationHint: "/tmp/fixture",
		CreatedAt:    time.Now().UTC().Add(-2 * time.Hour),
	}
	if err := service.store.CreateProject(project); err != nil {
		t.Fatalf("create project: %v", err)
	}

	baseline := domain.ScanRun{
		ID:        "run-1",
		ProjectID: project.ID,
		Status:    domain.ScanCompleted,
		StartedAt: time.Now().UTC().Add(-90 * time.Minute),
		Profile: domain.ScanProfile{
			SeverityGate: domain.SeverityHigh,
		},
		Summary: domain.NewScanSummary(),
	}
	if err := service.store.CreateRun(baseline); err != nil {
		t.Fatalf("create baseline run: %v", err)
	}

	current := domain.ScanRun{
		ID:        "run-2",
		ProjectID: project.ID,
		Status:    domain.ScanCompleted,
		StartedAt: time.Now().UTC().Add(-30 * time.Minute),
		Profile: domain.ScanProfile{
			SeverityGate: domain.SeverityHigh,
		},
		Summary: domain.NewScanSummary(),
	}
	if err := service.store.CreateRun(current); err != nil {
		t.Fatalf("create current run: %v", err)
	}

	for _, finding := range []domain.Finding{
		{ScanID: baseline.ID, ProjectID: project.ID, Fingerprint: "fp-existing", Severity: domain.SeverityHigh, Title: "Existing"},
		{ScanID: baseline.ID, ProjectID: project.ID, Fingerprint: "fp-resolved", Severity: domain.SeverityMedium, Title: "Resolved"},
		{ScanID: current.ID, ProjectID: project.ID, Fingerprint: "fp-existing", Severity: domain.SeverityHigh, Title: "Existing"},
		{ScanID: current.ID, ProjectID: project.ID, Fingerprint: "fp-new", Severity: domain.SeverityCritical, Title: "New"},
	} {
		if err := service.store.AddFinding(finding); err != nil {
			t.Fatalf("add finding %s: %v", finding.Fingerprint, err)
		}
	}

	delta, run, baselineRun, err := service.GetRunDelta(current.ID, "")
	if err != nil {
		t.Fatalf("get run delta: %v", err)
	}

	if run.ID != current.ID {
		t.Fatalf("expected current run %s, got %s", current.ID, run.ID)
	}
	if baselineRun == nil || baselineRun.ID != baseline.ID {
		t.Fatalf("expected baseline run %s", baseline.ID)
	}
	if delta.CountsByChange[domain.FindingNew] != 1 {
		t.Fatalf("expected 1 new finding, got %d", delta.CountsByChange[domain.FindingNew])
	}
	if delta.CountsByChange[domain.FindingExisting] != 1 {
		t.Fatalf("expected 1 existing finding, got %d", delta.CountsByChange[domain.FindingExisting])
	}
	if delta.CountsByChange[domain.FindingResolved] != 1 {
		t.Fatalf("expected 1 resolved finding, got %d", delta.CountsByChange[domain.FindingResolved])
	}
}

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
	if campaign.Title != "Fix reachable SCA" {
		t.Fatalf("expected trimmed title to be preserved, got %q", campaign.Title)
	}
	if len(campaign.FindingFingerprints) != 1 || campaign.FindingFingerprints[0] != findings[0].Fingerprint {
		t.Fatalf("unexpected campaign findings: %+v", campaign.FindingFingerprints)
	}
	if got, ok := service.store.GetCampaign(campaign.ID); !ok || got.ID != campaign.ID {
		t.Fatalf("expected campaign to be persisted, got %+v ok=%v", got, ok)
	}
}

func TestAddFindingsToCampaignDeduplicates(t *testing.T) {
	service, run, findings := newServiceWithRunAndFindings(t)

	campaign, err := service.CreateCampaign(domain.Campaign{
		ID:                  "cmp-1",
		ProjectID:           run.ProjectID,
		Title:               "Fix queue",
		SourceRunID:         run.ID,
		FindingFingerprints: []string{findings[0].Fingerprint},
	})
	if err != nil {
		t.Fatalf("create campaign: %v", err)
	}

	updated, err := service.AddFindingsToCampaign(campaign.ID, []string{findings[0].Fingerprint, findings[1].Fingerprint})
	if err != nil {
		t.Fatalf("add findings: %v", err)
	}
	if len(updated.FindingFingerprints) != 2 {
		t.Fatalf("expected deduped fingerprints, got %+v", updated.FindingFingerprints)
	}
	if updated.FindingFingerprints[0] != findings[0].Fingerprint || updated.FindingFingerprints[1] != findings[1].Fingerprint {
		t.Fatalf("expected sorted fingerprints, got %+v", updated.FindingFingerprints)
	}
	if got, ok := service.store.GetCampaign(campaign.ID); !ok || len(got.FindingFingerprints) != 2 {
		t.Fatalf("expected updated campaign to be persisted, got %+v ok=%v", got, ok)
	}
}

func TestCreateCampaignRejectsInvalidAggregate(t *testing.T) {
	service, run, findings := newServiceWithRunAndFindings(t)

	if _, err := service.CreateCampaign(domain.Campaign{
		ID:                  "cmp-empty-title",
		ProjectID:           run.ProjectID,
		Title:               "   ",
		SourceRunID:         run.ID,
		FindingFingerprints: []string{findings[0].Fingerprint},
	}); err == nil {
		t.Fatalf("expected blank-title campaign to fail")
	}

	if _, err := service.CreateCampaign(domain.Campaign{
		ID:                  "cmp-missing-finding",
		ProjectID:           run.ProjectID,
		Title:               "Fix queue",
		SourceRunID:         run.ID,
		FindingFingerprints: []string{"fp-missing"},
	}); err == nil {
		t.Fatalf("expected missing finding campaign to fail")
	}
}

func TestAddFindingsToCampaignRejectsForeignFingerprint(t *testing.T) {
	service, run, findings := newServiceWithRunAndFindings(t)

	campaign, err := service.CreateCampaign(domain.Campaign{
		ID:                  "cmp-1",
		ProjectID:           run.ProjectID,
		Title:               "Fix queue",
		SourceRunID:         run.ID,
		FindingFingerprints: []string{findings[0].Fingerprint},
	})
	if err != nil {
		t.Fatalf("create campaign: %v", err)
	}

	otherProject := domain.Project{
		ID:           "prj-2",
		DisplayName:  "Other",
		TargetHandle: "other",
		LocationHint: "/tmp/other",
		CreatedAt:    time.Now().UTC(),
	}
	if err := service.store.CreateProject(otherProject); err != nil {
		t.Fatalf("create other project: %v", err)
	}
	otherRun := domain.ScanRun{
		ID:        "run-2",
		ProjectID: otherProject.ID,
		Status:    domain.ScanCompleted,
		StartedAt: time.Now().UTC(),
		Profile:   domain.ScanProfile{SeverityGate: domain.SeverityHigh},
		Summary:   domain.NewScanSummary(),
	}
	if err := service.store.CreateRun(otherRun); err != nil {
		t.Fatalf("create other run: %v", err)
	}
	if err := service.store.AddFinding(domain.Finding{
		ScanID:      otherRun.ID,
		ProjectID:   otherProject.ID,
		Category:    domain.CategorySCA,
		Title:       "Foreign finding",
		Severity:    domain.SeverityCritical,
		Fingerprint: "fp-foreign",
	}); err != nil {
		t.Fatalf("add foreign finding: %v", err)
	}

	if _, err := service.AddFindingsToCampaign(campaign.ID, []string{"fp-foreign"}); err == nil {
		t.Fatalf("expected foreign fingerprint to be rejected")
	}
}

func TestBuildRunReportProducesCanonicalChangeAndModuleMetadata(t *testing.T) {
	cfg := config.Config{
		DataDir:   filepath.Join(t.TempDir(), "data"),
		OutputDir: filepath.Join(t.TempDir(), "output"),
	}

	service, err := New(cfg)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	project := domain.Project{
		ID:             "prj-1",
		DisplayName:    "Fixture",
		TargetHandle:   "fixture",
		LocationHint:   "/tmp/fixture",
		DetectedStacks: []string{"go"},
		CreatedAt:      time.Now().UTC().Add(-2 * time.Hour),
	}
	if err := service.store.CreateProject(project); err != nil {
		t.Fatalf("create project: %v", err)
	}

	baseline := domain.ScanRun{
		ID:        "run-1",
		ProjectID: project.ID,
		Status:    domain.ScanCompleted,
		StartedAt: time.Now().UTC().Add(-90 * time.Minute),
		Profile:   domain.ScanProfile{SeverityGate: domain.SeverityHigh},
		Summary:   domain.NewScanSummary(),
		ModuleResults: []domain.ModuleResult{
			{Name: "semgrep", Status: domain.ModuleCompleted, Attempts: 1, DurationMs: 1000, FindingCount: 1, Summary: "baseline"},
		},
	}
	current := domain.ScanRun{
		ID:        "run-2",
		ProjectID: project.ID,
		Status:    domain.ScanCompleted,
		StartedAt: time.Now().UTC().Add(-30 * time.Minute),
		Profile:   domain.ScanProfile{SeverityGate: domain.SeverityHigh},
		Summary:   domain.NewScanSummary(),
		ModuleResults: []domain.ModuleResult{
			{Name: "semgrep", Status: domain.ModuleFailed, Attempts: 2, DurationMs: 1250, TimedOut: true, FailureKind: domain.ModuleFailureTimeout, FindingCount: 1, Summary: "current"},
			{Name: "codeql", Status: domain.ModuleSkipped, Attempts: 0, DurationMs: 0, FailureKind: domain.ModuleFailureSkipped, Summary: "tool unavailable"},
		},
	}
	if err := service.store.CreateRun(baseline); err != nil {
		t.Fatalf("create baseline run: %v", err)
	}
	if err := service.store.CreateRun(current); err != nil {
		t.Fatalf("create current run: %v", err)
	}

	for _, finding := range []domain.Finding{
		{ScanID: baseline.ID, ProjectID: project.ID, Fingerprint: "fp-existing", Severity: domain.SeverityHigh, Title: "Existing"},
		{ScanID: current.ID, ProjectID: project.ID, Fingerprint: "fp-existing", Severity: domain.SeverityHigh, Title: "Existing"},
		{ScanID: current.ID, ProjectID: project.ID, Fingerprint: "fp-new", Severity: domain.SeverityCritical, Title: "New", Module: "semgrep"},
	} {
		if err := service.store.AddFinding(finding); err != nil {
			t.Fatalf("add finding %s: %v", finding.Fingerprint, err)
		}
	}

	report, err := service.BuildRunReport(current.ID, "")
	if err != nil {
		t.Fatalf("build run report: %v", err)
	}

	if report.Run.ID != current.ID {
		t.Fatalf("expected current run in report, got %s", report.Run.ID)
	}
	if report.Baseline == nil || report.Baseline.ID != baseline.ID {
		t.Fatalf("expected baseline run %s in report", baseline.ID)
	}
	if report.ModuleStats["failed"] != 1 || report.ModuleStats["skipped"] != 1 || report.ModuleStats["retried"] != 1 {
		t.Fatalf("unexpected module stats: %+v", report.ModuleStats)
	}
	if len(report.ModuleSummaries) != 2 {
		t.Fatalf("expected 2 module summaries, got %d", len(report.ModuleSummaries))
	}
	if len(report.Findings) != 2 {
		t.Fatalf("expected 2 report findings, got %d", len(report.Findings))
	}
	changes := make(map[string]domain.FindingChange, len(report.Findings))
	for _, finding := range report.Findings {
		changes[finding.Finding.Fingerprint] = finding.Change
	}
	if changes["fp-new"] != domain.FindingNew {
		t.Fatalf("expected fp-new to be marked new, got %s", changes["fp-new"])
	}
	if changes["fp-existing"] != domain.FindingExisting {
		t.Fatalf("expected fp-existing to be marked existing, got %s", changes["fp-existing"])
	}
}

func newServiceWithRunAndFindings(t *testing.T) (*Service, domain.ScanRun, []domain.Finding) {
	t.Helper()

	cfg := config.Config{
		DataDir:   filepath.Join(t.TempDir(), "data"),
		OutputDir: filepath.Join(t.TempDir(), "output"),
	}

	service, err := New(cfg)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	project := domain.Project{
		ID:           "prj-1",
		DisplayName:  "Fixture",
		TargetHandle: "fixture",
		LocationHint: "/tmp/fixture",
		CreatedAt:    time.Now().UTC().Add(-2 * time.Hour),
	}
	if err := service.store.CreateProject(project); err != nil {
		t.Fatalf("create project: %v", err)
	}

	run := domain.ScanRun{
		ID:        "run-1",
		ProjectID: project.ID,
		Status:    domain.ScanCompleted,
		StartedAt: time.Now().UTC().Add(-30 * time.Minute),
		Profile:   domain.ScanProfile{SeverityGate: domain.SeverityHigh},
		Summary:   domain.NewScanSummary(),
	}
	if err := service.store.CreateRun(run); err != nil {
		t.Fatalf("create run: %v", err)
	}

	findings := []domain.Finding{
		{
			ScanID:      run.ID,
			ProjectID:   project.ID,
			Category:    domain.CategorySCA,
			Title:       "First finding",
			Severity:    domain.SeverityHigh,
			Fingerprint: "fp-1",
		},
		{
			ScanID:      run.ID,
			ProjectID:   project.ID,
			Category:    domain.CategorySCA,
			Title:       "Second finding",
			Severity:    domain.SeverityCritical,
			Fingerprint: "fp-2",
		},
	}
	for _, finding := range findings {
		if err := service.store.AddFinding(finding); err != nil {
			t.Fatalf("add finding %s: %v", finding.Fingerprint, err)
		}
	}

	return service, run, findings
}

func TestServiceReadPathsReEnrichStoredFindingsAndPreserveTriageTags(t *testing.T) {
	cfg := config.Config{
		DataDir:   filepath.Join(t.TempDir(), "data"),
		OutputDir: filepath.Join(t.TempDir(), "output"),
	}

	service, err := New(cfg)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	project := domain.Project{
		ID:             "prj-1",
		DisplayName:    "Fixture",
		TargetHandle:   "fixture",
		LocationHint:   "/tmp/fixture",
		DetectedStacks: []string{"go"},
		CreatedAt:      time.Now().UTC().Add(-2 * time.Hour),
	}
	if err := service.store.CreateProject(project); err != nil {
		t.Fatalf("create project: %v", err)
	}

	run := domain.ScanRun{
		ID:        "run-1",
		ProjectID: project.ID,
		Status:    domain.ScanCompleted,
		StartedAt: time.Now().UTC().Add(-30 * time.Minute),
		Profile:   domain.ScanProfile{SeverityGate: domain.SeverityHigh},
		Summary:   domain.NewScanSummary(),
	}
	if err := service.store.CreateRun(run); err != nil {
		t.Fatalf("create run: %v", err)
	}

	rawFinding := domain.Finding{
		ScanID:       run.ID,
		ProjectID:    project.ID,
		Category:     domain.CategorySCA,
		RuleID:       "dependency_confusion.unpinned_npm_scope",
		Title:        "Potential dependency confusion risk for npm package \"@acme/internal-ui\"",
		Severity:     domain.SeverityHigh,
		Confidence:   0.68,
		Reachability: domain.Reachability(" Reachable "),
		Fingerprint:  "fp-dep-confusion",
		Remediation:  "Pin the scope.",
		Location:     "package.json",
		Module:       "dependency-confusion",
	}
	if err := service.store.AddFinding(rawFinding); err != nil {
		t.Fatalf("add finding: %v", err)
	}
	if err := service.store.SaveFindingTriage(domain.FindingTriage{
		Fingerprint: rawFinding.Fingerprint,
		Status:      domain.FindingInvestigating,
		Tags:        []string{"owner:platform"},
		Owner:       "platform",
		Note:        "triage note",
		UpdatedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("save triage: %v", err)
	}

	findings := service.ListFindings(run.ID)
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].Priority <= 0 {
		t.Fatalf("expected read-path finding to be enriched with priority, got %.2f", findings[0].Priority)
	}
	if findings[0].Reachability != domain.ReachabilityReachable {
		t.Fatalf("expected read-path reachability to normalize, got %q", findings[0].Reachability)
	}
	if !containsFindingTag(findings[0].Tags, "owner:platform") {
		t.Fatalf("expected triage tag to be preserved, got %v", findings[0].Tags)
	}
	if !containsFindingTag(findings[0].Tags, "sca:reachable") {
		t.Fatalf("expected derived sca reachability tag, got %v", findings[0].Tags)
	}
	if !containsFindingTag(findings[0].Tags, "supply-chain:dependency-confusion") {
		t.Fatalf("expected derived dependency-confusion tag, got %v", findings[0].Tags)
	}

	finding, ok := service.GetFinding(run.ID, rawFinding.Fingerprint)
	if !ok {
		t.Fatalf("expected finding lookup to succeed")
	}
	if !containsFindingTag(finding.Tags, "owner:platform") || !containsFindingTag(finding.Tags, "sca:reachable") {
		t.Fatalf("expected GetFinding to return merged tags, got %v", finding.Tags)
	}

	portfolio := service.PortfolioData()
	if len(portfolio.Findings) != 1 {
		t.Fatalf("expected one portfolio finding, got %d", len(portfolio.Findings))
	}
	if !containsFindingTag(portfolio.Findings[0].Tags, "supply-chain:malicious") {
		t.Fatalf("expected portfolio finding to include malicious supply-chain tag, got %v", portfolio.Findings[0].Tags)
	}
}

func TestEvaluatePolicyUsesEnrichedSupplyChainSignals(t *testing.T) {
	cfg := config.Config{
		DataDir:   filepath.Join(t.TempDir(), "data"),
		OutputDir: filepath.Join(t.TempDir(), "output"),
	}

	service, err := New(cfg)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	project := domain.Project{
		ID:             "prj-1",
		DisplayName:    "Fixture",
		TargetHandle:   "fixture",
		LocationHint:   "/tmp/fixture",
		DetectedStacks: []string{"node"},
		CreatedAt:      time.Now().UTC().Add(-2 * time.Hour),
	}
	if err := service.store.CreateProject(project); err != nil {
		t.Fatalf("create project: %v", err)
	}

	run := domain.ScanRun{
		ID:        "run-1",
		ProjectID: project.ID,
		Status:    domain.ScanCompleted,
		StartedAt: time.Now().UTC().Add(-30 * time.Minute),
		Profile:   domain.ScanProfile{SeverityGate: domain.SeverityHigh},
		Summary:   domain.NewScanSummary(),
	}
	if err := service.store.CreateRun(run); err != nil {
		t.Fatalf("create run: %v", err)
	}

	if err := service.store.AddFinding(domain.Finding{
		ScanID:       run.ID,
		ProjectID:    project.ID,
		Category:     domain.CategorySCA,
		RuleID:       "dependency_confusion.unpinned_npm_scope",
		Title:        "Potential dependency confusion risk for npm package \"@acme/internal-ui\"",
		Severity:     domain.SeverityHigh,
		Confidence:   0.68,
		Reachability: domain.ReachabilityReachable,
		Fingerprint:  "fp-dep-confusion",
		Remediation:  "Pin the scope.",
		Location:     "package.json",
		Module:       "dependency-confusion",
	}); err != nil {
		t.Fatalf("add finding: %v", err)
	}

	evaluation, current, baseline, err := service.EvaluatePolicy(run.ID, "", policy.PremiumDefaultPolicy)
	if err != nil {
		t.Fatalf("evaluate policy: %v", err)
	}
	if current.ID != run.ID {
		t.Fatalf("expected current run %s, got %s", run.ID, current.ID)
	}
	if baseline != nil {
		t.Fatalf("expected no baseline run")
	}
	if evaluation.Passed {
		t.Fatalf("expected premium policy to fail on enriched supply-chain signal")
	}

	resultsByRule := make(map[string]domain.PolicyRuleResult, len(evaluation.Results))
	for _, result := range evaluation.Results {
		resultsByRule[result.Rule.ID] = result
	}
	if resultsByRule["malicious-supply-chain"].MatchedCount != 1 {
		t.Fatalf("expected malicious-supply-chain rule to match 1 finding, got %d", resultsByRule["malicious-supply-chain"].MatchedCount)
	}
	if resultsByRule["reachable-sca-regression"].MatchedCount != 1 {
		t.Fatalf("expected reachable-sca-regression rule to match 1 finding, got %d", resultsByRule["reachable-sca-regression"].MatchedCount)
	}
}

func TestEvaluatePolicyWithVEXIgnoresNotAffectedSCASignal(t *testing.T) {
	cfg := config.Config{
		DataDir:   filepath.Join(t.TempDir(), "data"),
		OutputDir: filepath.Join(t.TempDir(), "output"),
	}

	service, err := New(cfg)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	project := domain.Project{
		ID:           "prj-1",
		DisplayName:  "Fixture",
		TargetHandle: "fixture",
		LocationHint: "/tmp/fixture",
		CreatedAt:    time.Now().UTC(),
	}
	if err := service.store.CreateProject(project); err != nil {
		t.Fatalf("create project: %v", err)
	}

	sbomPath := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(sbomPath, []byte(`{"components":[{"name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21"}]}`), 0o644); err != nil {
		t.Fatalf("write sbom: %v", err)
	}

	run := domain.ScanRun{
		ID:        "run-vex-policy",
		ProjectID: project.ID,
		Status:    domain.ScanCompleted,
		StartedAt: time.Now().UTC(),
		Profile:   domain.ScanProfile{SeverityGate: domain.SeverityHigh},
		Summary:   domain.NewScanSummary(),
		ArtifactRefs: []domain.ArtifactRef{
			{Kind: "sbom", Label: "CycloneDX", URI: sbomPath},
		},
	}
	if err := service.store.CreateRun(run); err != nil {
		t.Fatalf("create run: %v", err)
	}
	if err := service.store.AddFinding(domain.Finding{
		ScanID:       run.ID,
		ProjectID:    project.ID,
		Category:     domain.CategorySCA,
		RuleID:       "CVE-2026-0001",
		Title:        "lodash vulnerability",
		Severity:     domain.SeverityHigh,
		Reachability: domain.ReachabilityReachable,
		Fingerprint:  "fp-lodash",
		Location:     "lodash",
		Module:       "osv-scanner",
	}); err != nil {
		t.Fatalf("add finding: %v", err)
	}

	vexPath := filepath.Join(t.TempDir(), "doc.openvex.json")
	if err := os.WriteFile(vexPath, []byte(`{
  "@context":"https://openvex.dev/ns/v0.2.0",
  "@id":"https://example.test/vex",
  "author":"Security Team",
  "role":"VEX Author",
  "timestamp":"2026-04-04T12:00:00Z",
  "version":1,
  "statements":[
    {
      "vulnerability":{"name":"CVE-2026-0001"},
      "products":[{"@id":"pkg:npm/lodash@4.17.21"}],
      "status":"not_affected",
      "justification":"vulnerable_code_not_present"
    }
  ]
}`), 0o644); err != nil {
		t.Fatalf("write vex: %v", err)
	}

	evaluation, _, _, err := service.EvaluatePolicyWithVEX(run.ID, "", policy.PremiumDefaultPolicy, vexPath)
	if err != nil {
		t.Fatalf("evaluate policy with vex: %v", err)
	}
	if !evaluation.Passed {
		t.Fatalf("expected VEX-suppressed policy evaluation to pass")
	}
}

func TestEvaluateGateWithVEXIgnoresNotAffectedNewFinding(t *testing.T) {
	cfg := config.Config{
		DataDir:   filepath.Join(t.TempDir(), "data"),
		OutputDir: filepath.Join(t.TempDir(), "output"),
	}

	service, err := New(cfg)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	project := domain.Project{
		ID:           "prj-gate",
		DisplayName:  "Fixture",
		TargetHandle: "fixture",
		LocationHint: "/tmp/fixture",
		CreatedAt:    time.Now().UTC(),
	}
	if err := service.store.CreateProject(project); err != nil {
		t.Fatalf("create project: %v", err)
	}

	sbomPath := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(sbomPath, []byte(`{"components":[{"name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21"}]}`), 0o644); err != nil {
		t.Fatalf("write sbom: %v", err)
	}

	baseline := domain.ScanRun{
		ID:        "run-baseline",
		ProjectID: project.ID,
		Status:    domain.ScanCompleted,
		StartedAt: time.Now().UTC().Add(-1 * time.Hour),
		Profile:   domain.ScanProfile{SeverityGate: domain.SeverityHigh},
		Summary:   domain.NewScanSummary(),
	}
	if err := service.store.CreateRun(baseline); err != nil {
		t.Fatalf("create baseline: %v", err)
	}

	current := domain.ScanRun{
		ID:        "run-current",
		ProjectID: project.ID,
		Status:    domain.ScanCompleted,
		StartedAt: time.Now().UTC(),
		Profile:   domain.ScanProfile{SeverityGate: domain.SeverityHigh},
		Summary:   domain.NewScanSummary(),
		ArtifactRefs: []domain.ArtifactRef{
			{Kind: "sbom", Label: "CycloneDX", URI: sbomPath},
		},
	}
	if err := service.store.CreateRun(current); err != nil {
		t.Fatalf("create current: %v", err)
	}

	if err := service.store.AddFinding(domain.Finding{
		ScanID:       current.ID,
		ProjectID:    project.ID,
		Category:     domain.CategorySCA,
		RuleID:       "CVE-2026-0001",
		Title:        "lodash vulnerability",
		Severity:     domain.SeverityHigh,
		Reachability: domain.ReachabilityReachable,
		Fingerprint:  "fp-lodash",
		Location:     "lodash",
		Module:       "osv-scanner",
	}); err != nil {
		t.Fatalf("add finding: %v", err)
	}

	vexPath := filepath.Join(t.TempDir(), "doc.openvex.json")
	if err := os.WriteFile(vexPath, []byte(`{
  "@context":"https://openvex.dev/ns/v0.2.0",
  "@id":"https://example.test/vex",
  "author":"Security Team",
  "role":"VEX Author",
  "timestamp":"2026-04-04T12:00:00Z",
  "version":1,
  "statements":[
    {
      "vulnerability":{"name":"CVE-2026-0001"},
      "products":[{"@id":"pkg:npm/lodash@4.17.21"}],
      "status":"not_affected"
    }
  ]
}`), 0o644); err != nil {
		t.Fatalf("write vex: %v", err)
	}

	_, _, _, blocking, err := service.EvaluateGateWithVEX(current.ID, baseline.ID, domain.SeverityHigh, vexPath)
	if err != nil {
		t.Fatalf("evaluate gate with vex: %v", err)
	}
	if len(blocking) != 0 {
		t.Fatalf("expected no blocking findings after VEX, got %d", len(blocking))
	}
}

func containsFindingTag(tags []string, target string) bool {
	for _, tag := range tags {
		if tag == target {
			return true
		}
	}
	return false
}

func TestEvaluateGateReturnsOnlyNewFindingsAtOrAboveThreshold(t *testing.T) {
	cfg := config.Config{
		DataDir:   filepath.Join(t.TempDir(), "data"),
		OutputDir: filepath.Join(t.TempDir(), "output"),
	}

	service, err := New(cfg)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	project := domain.Project{
		ID:           "prj-1",
		DisplayName:  "Fixture",
		TargetHandle: "fixture",
		LocationHint: "/tmp/fixture",
		CreatedAt:    time.Now().UTC().Add(-2 * time.Hour),
	}
	if err := service.store.CreateProject(project); err != nil {
		t.Fatalf("create project: %v", err)
	}

	baseline := domain.ScanRun{
		ID:        "run-1",
		ProjectID: project.ID,
		Status:    domain.ScanCompleted,
		StartedAt: time.Now().UTC().Add(-90 * time.Minute),
		Profile:   domain.ScanProfile{SeverityGate: domain.SeverityHigh},
		Summary:   domain.NewScanSummary(),
	}
	current := domain.ScanRun{
		ID:        "run-2",
		ProjectID: project.ID,
		Status:    domain.ScanCompleted,
		StartedAt: time.Now().UTC().Add(-30 * time.Minute),
		Profile:   domain.ScanProfile{SeverityGate: domain.SeverityHigh},
		Summary:   domain.NewScanSummary(),
	}
	if err := service.store.CreateRun(baseline); err != nil {
		t.Fatalf("create baseline run: %v", err)
	}
	if err := service.store.CreateRun(current); err != nil {
		t.Fatalf("create current run: %v", err)
	}

	for _, finding := range []domain.Finding{
		{ScanID: baseline.ID, ProjectID: project.ID, Fingerprint: "fp-existing", Severity: domain.SeverityHigh, Title: "Existing"},
		{ScanID: current.ID, ProjectID: project.ID, Fingerprint: "fp-existing", Severity: domain.SeverityHigh, Title: "Existing"},
		{ScanID: current.ID, ProjectID: project.ID, Fingerprint: "fp-critical", Severity: domain.SeverityCritical, Title: "Critical New"},
		{ScanID: current.ID, ProjectID: project.ID, Fingerprint: "fp-medium", Severity: domain.SeverityMedium, Title: "Medium New"},
	} {
		if err := service.store.AddFinding(finding); err != nil {
			t.Fatalf("add finding %s: %v", finding.Fingerprint, err)
		}
	}

	_, _, _, blocking, err := service.EvaluateGate(current.ID, "", domain.SeverityHigh)
	if err != nil {
		t.Fatalf("evaluate gate: %v", err)
	}

	if len(blocking) != 1 {
		t.Fatalf("expected 1 blocking finding, got %d", len(blocking))
	}
	if blocking[0].Fingerprint != "fp-critical" {
		t.Fatalf("expected fp-critical to block gate, got %s", blocking[0].Fingerprint)
	}
}

func TestAppendArtifactRefsUniqueDeduplicates(t *testing.T) {
	base := []domain.ArtifactRef{
		{Kind: "report", Label: "HTML", URI: "/tmp/report.html"},
	}
	out := appendArtifactRefsUnique(base,
		domain.ArtifactRef{Kind: "report", Label: "HTML", URI: "/tmp/report.html"},
		domain.ArtifactRef{Kind: "manifest", Label: "Module manifest", URI: "/tmp/manifest.json"},
	)
	if len(out) != 2 {
		t.Fatalf("expected 2 unique artifacts, got %d", len(out))
	}
}

func TestPortfolioDataUsesFilteredFindingsForRunSummaries(t *testing.T) {
	cfg := config.Config{
		DataDir:   filepath.Join(t.TempDir(), "data"),
		OutputDir: filepath.Join(t.TempDir(), "output"),
	}

	service, err := New(cfg)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	project := domain.Project{
		ID:           "prj-1",
		DisplayName:  "Fixture",
		TargetHandle: "fixture",
		LocationHint: "/tmp/fixture",
		CreatedAt:    time.Now().UTC().Add(-2 * time.Hour),
	}
	if err := service.store.CreateProject(project); err != nil {
		t.Fatalf("create project: %v", err)
	}

	runOne := domain.ScanRun{
		ID:        "run-1",
		ProjectID: project.ID,
		Status:    domain.ScanCompleted,
		StartedAt: time.Now().UTC().Add(-90 * time.Minute),
		Profile:   domain.ScanProfile{SeverityGate: domain.SeverityHigh},
		Summary:   domain.NewScanSummary(),
	}
	runTwo := domain.ScanRun{
		ID:        "run-2",
		ProjectID: project.ID,
		Status:    domain.ScanCompleted,
		StartedAt: time.Now().UTC().Add(-30 * time.Minute),
		Profile:   domain.ScanProfile{SeverityGate: domain.SeverityHigh},
		Summary:   domain.NewScanSummary(),
	}
	if err := service.store.CreateRun(runOne); err != nil {
		t.Fatalf("create first run: %v", err)
	}
	if err := service.store.CreateRun(runTwo); err != nil {
		t.Fatalf("create second run: %v", err)
	}

	for _, finding := range []domain.Finding{
		{ScanID: runOne.ID, ProjectID: project.ID, Fingerprint: "fp-suppressed", Severity: domain.SeverityCritical, Title: "Suppressed", Category: domain.CategorySecret},
		{ScanID: runOne.ID, ProjectID: project.ID, Fingerprint: "fp-medium", Severity: domain.SeverityMedium, Title: "Visible", Category: domain.CategorySAST},
		{ScanID: runTwo.ID, ProjectID: project.ID, Fingerprint: "fp-high", Severity: domain.SeverityHigh, Title: "Investigating", Category: domain.CategorySCA},
	} {
		if err := service.store.AddFinding(finding); err != nil {
			t.Fatalf("add finding %s: %v", finding.Fingerprint, err)
		}
	}

	if err := service.store.SaveSuppression(domain.Suppression{
		Fingerprint: "fp-suppressed",
		Reason:      "test",
		Owner:       "qa",
		ExpiresAt:   time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatalf("save suppression: %v", err)
	}
	if err := service.store.SaveFindingTriage(domain.FindingTriage{
		Fingerprint: "fp-high",
		Status:      domain.FindingInvestigating,
		UpdatedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("save triage: %v", err)
	}

	portfolio := service.PortfolioData()
	if len(portfolio.Findings) != 2 {
		t.Fatalf("expected suppressed findings to be filtered, got %d findings", len(portfolio.Findings))
	}

	runSummaries := make(map[string]domain.ScanSummary, len(portfolio.Runs))
	for _, run := range portfolio.Runs {
		runSummaries[run.ID] = run.Summary
	}

	if runSummaries[runOne.ID].TotalFindings != 1 {
		t.Fatalf("expected run-1 to keep 1 visible finding, got %d", runSummaries[runOne.ID].TotalFindings)
	}
	if runSummaries[runOne.ID].Blocked {
		t.Fatalf("expected run-1 summary to stay below gate")
	}
	if runSummaries[runTwo.ID].CountsByStatus[domain.FindingInvestigating] != 1 {
		t.Fatalf("expected run-2 summary to count investigating finding, got %+v", runSummaries[runTwo.ID].CountsByStatus)
	}
	if !runSummaries[runTwo.ID].Blocked {
		t.Fatalf("expected run-2 summary to block on high severity finding")
	}
}

func TestRuntimeDoctorAddsSystemChecks(t *testing.T) {
	cfg := config.Config{
		DataDir:   filepath.Join(t.TempDir(), "data"),
		OutputDir: filepath.Join(t.TempDir(), "output"),
		ToolsDir:  filepath.Join(t.TempDir(), "tools"),
	}

	service, err := New(cfg)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	originalProbes := runtimeDoctorProbeURLs
	runtimeDoctorProbeURLs = []string{server.URL}
	t.Cleanup(func() { runtimeDoctorProbeURLs = originalProbes })

	doctor := service.RuntimeDoctor(domain.ScanProfile{Mode: domain.ModeSafe}, false, false)
	if len(doctor.Checks) < 4 {
		t.Fatalf("expected system checks to be attached, got %+v", doctor.Checks)
	}

	index := make(map[string]domain.RuntimeDoctorCheck, len(doctor.Checks))
	for _, check := range doctor.Checks {
		index[check.Name] = check
	}

	for _, key := range []string{"sqlite_integrity", "permissions_data_dir", "permissions_output_dir", "disk_space", "network_probe"} {
		if _, ok := index[key]; !ok {
			t.Fatalf("expected doctor check %s to be present", key)
		}
	}
	if index["sqlite_integrity"].Status != domain.RuntimeCheckPass {
		t.Fatalf("expected sqlite integrity check to pass, got %+v", index["sqlite_integrity"])
	}
	if index["sqlite_integrity"].Class != domain.RuntimeCheckClassIntegrity {
		t.Fatalf("expected sqlite integrity check class to be integrity, got %+v", index["sqlite_integrity"])
	}
	if index["permissions_data_dir"].Class != domain.RuntimeCheckClassFilesystem {
		t.Fatalf("expected permissions_data_dir class to be filesystem, got %+v", index["permissions_data_dir"])
	}
	if index["network_probe"].Status != domain.RuntimeCheckPass {
		t.Fatalf("expected network probe to pass, got %+v", index["network_probe"])
	}
	if index["network_probe"].Class != domain.RuntimeCheckClassNetwork {
		t.Fatalf("expected network_probe class to be network, got %+v", index["network_probe"])
	}
}

func TestRuntimeDoctorTreatsAuthChallengesAsWarn(t *testing.T) {
	cfg := config.Config{
		DataDir:   filepath.Join(t.TempDir(), "data"),
		OutputDir: filepath.Join(t.TempDir(), "output"),
		ToolsDir:  filepath.Join(t.TempDir(), "tools"),
	}

	service, err := New(cfg)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	originalProbes := runtimeDoctorProbeURLs
	runtimeDoctorProbeURLs = []string{server.URL}
	t.Cleanup(func() { runtimeDoctorProbeURLs = originalProbes })

	doctor := service.RuntimeDoctor(domain.ScanProfile{Mode: domain.ModeSafe}, false, false)
	index := make(map[string]domain.RuntimeDoctorCheck, len(doctor.Checks))
	for _, check := range doctor.Checks {
		index[check.Name] = check
	}
	if index["network_probe"].Status != domain.RuntimeCheckWarn {
		t.Fatalf("expected auth challenge probe to warn, got %+v", index["network_probe"])
	}
}

func TestPersistRunUpdateWrapsUpdaterErrors(t *testing.T) {
	err := persistRunUpdate(domain.ScanRun{ID: "run-1"}, func(domain.ScanRun) error {
		return errors.New("write failed")
	}, "terminal run state")
	if err == nil || !strings.Contains(err.Error(), "persist terminal run state") {
		t.Fatalf("expected wrapped persistence error, got %v", err)
	}
}

func TestGetRunExecutionTracesLoadsJournalArtifactsAndSynthesizesMissingModules(t *testing.T) {
	cfg := config.Config{
		DataDir:   filepath.Join(t.TempDir(), "data"),
		OutputDir: filepath.Join(t.TempDir(), "output"),
	}

	service, err := New(cfg)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	project := domain.Project{
		ID:           "prj-1",
		DisplayName:  "Fixture",
		TargetHandle: "fixture",
		LocationHint: "/tmp/fixture",
		CreatedAt:    time.Now().UTC().Add(-2 * time.Hour),
	}
	if err := service.store.CreateProject(project); err != nil {
		t.Fatalf("create project: %v", err)
	}

	finishedAt := time.Now().UTC()
	run := domain.ScanRun{
		ID:         "run-1",
		ProjectID:  project.ID,
		Status:     domain.ScanCompleted,
		StartedAt:  finishedAt.Add(-2 * time.Minute),
		FinishedAt: &finishedAt,
		Profile: domain.ScanProfile{
			SeverityGate: domain.SeverityHigh,
		},
		Summary: domain.NewScanSummary(),
		ModuleResults: []domain.ModuleResult{
			{Name: "semgrep", Status: domain.ModuleCompleted, Attempts: 2, DurationMs: 1500},
			{Name: "stack-detector", Status: domain.ModuleCompleted, DurationMs: 1},
		},
	}

	journalPath := filepath.Join(cfg.OutputDir, "run-1", "semgrep", "execution-journal.json")
	if err := os.MkdirAll(filepath.Dir(journalPath), 0o755); err != nil {
		t.Fatalf("mkdir journal dir: %v", err)
	}
	journal := domain.ModuleExecutionTrace{
		Module:       "semgrep",
		Status:       domain.ModuleCompleted,
		MaxAttempts:  2,
		AttemptsUsed: 2,
		DurationMs:   1500,
		AttemptJournal: []domain.ModuleAttemptTrace{
			{Attempt: 1, FailureKind: domain.ModuleFailureTimeout, TimedOut: true},
			{Attempt: 2},
		},
	}
	body, err := json.Marshal(journal)
	if err != nil {
		t.Fatalf("marshal journal: %v", err)
	}
	if err := os.WriteFile(journalPath, body, 0o644); err != nil {
		t.Fatalf("write journal: %v", err)
	}
	run.ArtifactRefs = []domain.ArtifactRef{
		{Kind: "execution-journal", Label: "Module execution journal", URI: journalPath},
	}

	if err := service.store.CreateRun(run); err != nil {
		t.Fatalf("create run: %v", err)
	}

	traces, err := service.GetRunExecutionTraces(run.ID)
	if err != nil {
		t.Fatalf("get execution traces: %v", err)
	}
	if len(traces) != 2 {
		t.Fatalf("expected 2 traces, got %d", len(traces))
	}
	if traces[0].Module != "semgrep" || traces[0].AttemptsUsed != 2 {
		t.Fatalf("expected journal-backed semgrep trace first, got %+v", traces[0])
	}
	if traces[1].Module != "stack-detector" || traces[1].AttemptsUsed != 1 {
		t.Fatalf("expected synthesized stack-detector trace second, got %+v", traces[1])
	}
}

func TestEnqueueCancelAndRetryFailedRun(t *testing.T) {
	cfg := config.Config{
		DataDir:   filepath.Join(t.TempDir(), "data"),
		OutputDir: filepath.Join(t.TempDir(), "output"),
	}

	service, err := New(cfg)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	project := domain.Project{
		ID:           "prj-1",
		DisplayName:  "Fixture",
		TargetHandle: "fixture",
		LocationHint: t.TempDir(),
		CreatedAt:    time.Now().UTC(),
	}
	if err := service.store.CreateProject(project); err != nil {
		t.Fatalf("create project: %v", err)
	}

	queuedRun, err := service.EnqueueScan(project.ID, domain.ScanProfile{
		Mode:         domain.ModeSafe,
		Coverage:     domain.CoverageCore,
		Modules:      []string{"stack-detector"},
		SeverityGate: domain.SeverityHigh,
	})
	if err != nil {
		t.Fatalf("enqueue scan: %v", err)
	}
	if queuedRun.Status != domain.ScanQueued {
		t.Fatalf("expected queued run, got %s", queuedRun.Status)
	}

	canceledRun, err := service.CancelRun(queuedRun.ID)
	if err != nil {
		t.Fatalf("cancel run: %v", err)
	}
	if canceledRun.Status != domain.ScanCanceled {
		t.Fatalf("expected queued run to become canceled, got %s", canceledRun.Status)
	}

	failedRun := domain.ScanRun{
		ID:        "run-failed",
		ProjectID: project.ID,
		Status:    domain.ScanFailed,
		StartedAt: time.Now().UTC(),
		Profile: domain.ScanProfile{
			Mode:         domain.ModeSafe,
			Coverage:     domain.CoverageCore,
			SeverityGate: domain.SeverityHigh,
		},
		Summary: domain.NewScanSummary(),
	}
	if err := service.store.CreateRun(failedRun); err != nil {
		t.Fatalf("create failed run: %v", err)
	}

	retryRun, err := service.RetryFailedRun(failedRun.ID)
	if err != nil {
		t.Fatalf("retry failed run: %v", err)
	}
	if retryRun.Status != domain.ScanQueued {
		t.Fatalf("expected retry run to be queued, got %s", retryRun.Status)
	}
	if retryRun.RetriedFromRunID != failedRun.ID {
		t.Fatalf("expected retry run to point to source run, got %s", retryRun.RetriedFromRunID)
	}
}

func TestRunQueueWorkerProcessesQueuedRun(t *testing.T) {
	cfg := config.Config{
		DataDir:   filepath.Join(t.TempDir(), "data"),
		OutputDir: filepath.Join(t.TempDir(), "output"),
	}

	service, err := New(cfg)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("GITHUB_TOKEN="+testGitHubPAT()+"\n"), 0o644); err != nil {
		t.Fatalf("write fixture file: %v", err)
	}

	project := domain.Project{
		ID:           "prj-queue",
		DisplayName:  "Queue Fixture",
		TargetHandle: "fixture-queue",
		LocationHint: root,
		CreatedAt:    time.Now().UTC(),
	}
	if err := service.store.CreateProject(project); err != nil {
		t.Fatalf("create project: %v", err)
	}

	queuedRun, err := service.EnqueueScan(project.ID, domain.ScanProfile{
		Mode:         domain.ModeSafe,
		Coverage:     domain.CoverageCore,
		Modules:      []string{"stack-detector", "secret-heuristics"},
		SeverityGate: domain.SeverityHigh,
	})
	if err != nil {
		t.Fatalf("enqueue scan: %v", err)
	}

	if err := service.RunQueueWorker(context.Background(), true, nil); err != nil {
		t.Fatalf("run queue worker: %v", err)
	}

	finalRun, ok := service.GetRun(queuedRun.ID)
	if !ok {
		t.Fatalf("expected queued run to still exist")
	}
	if finalRun.Status != domain.ScanCompleted {
		t.Fatalf("expected queued run to complete, got %s", finalRun.Status)
	}
	if len(service.ListFindings(finalRun.ID)) == 0 {
		t.Fatalf("expected queued run to persist findings")
	}
}

func testGitHubPAT() string {
	return strings.Join([]string{"gh", "p_", strings.Repeat("1", 36)}, "")
}

func TestDASTPlanIncludesAuthenticatedProfileSteps(t *testing.T) {
	cfg := config.Config{
		DataDir:   filepath.Join(t.TempDir(), "data"),
		OutputDir: filepath.Join(t.TempDir(), "output"),
	}

	service, err := New(cfg)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	targets := []domain.DastTarget{{
		Name:        "api",
		URL:         "https://api.example.test",
		AuthType:    domain.DastAuthBearer,
		AuthProfile: "staging-bearer",
	}}
	authProfiles := []domain.DastAuthProfile{{
		Name:                "staging-bearer",
		Type:                domain.DastAuthBearer,
		SecretEnv:           "STAGING_API_TOKEN",
		SessionCheckURL:     "https://api.example.test/me",
		SessionCheckPattern: "200 OK",
	}}

	plan := service.DASTPlan("prj-auth", targets, authProfiles, false)
	if plan.Policy != "authenticated" {
		t.Fatalf("expected authenticated policy, got %s", plan.Policy)
	}
	joined := strings.Join(plan.Steps, "\n")
	for _, fragment := range []string{"staging-bearer", "bearer", "https://api.example.test/me"} {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("expected dast plan steps to contain %q, got %s", fragment, joined)
		}
	}
}
