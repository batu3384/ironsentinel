package cli

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
	"github.com/batu3384/ironsentinel/internal/i18n"
	"github.com/batu3384/ironsentinel/internal/store"
)

func TestFilterFindingsAppliesSeverityCategoryAndLimit(t *testing.T) {
	findings := []domain.Finding{
		{Fingerprint: "fp-secret", Severity: domain.SeverityHigh, Category: domain.CategorySecret, Title: "Secret exposed"},
		{Fingerprint: "fp-xss", Severity: domain.SeverityHigh, Category: domain.CategorySAST, Title: "Potential XSS"},
		{Fingerprint: "fp-entropy", Severity: domain.SeverityLow, Category: domain.CategorySecret, Title: "Weak entropy"},
	}

	filtered := filterFindings(findings, "high", "secret", "", 10)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 filtered finding, got %d", len(filtered))
	}
	if filtered[0].Title != "Secret exposed" {
		t.Fatalf("unexpected finding selected: %s", filtered[0].Title)
	}

	limited := filterFindings(findings, "", "", "", 2)
	if len(limited) != 2 {
		t.Fatalf("expected limit to truncate to 2, got %d", len(limited))
	}
}

func TestFilterFindingsByChangeUsesDeltaFingerprintSets(t *testing.T) {
	current := []domain.Finding{
		{Fingerprint: "fp-existing", Severity: domain.SeverityHigh, Title: "Existing"},
		{Fingerprint: "fp-new", Severity: domain.SeverityCritical, Title: "New"},
	}
	baseline := []domain.Finding{
		{Fingerprint: "fp-existing", Severity: domain.SeverityHigh, Title: "Existing"},
		{Fingerprint: "fp-resolved", Severity: domain.SeverityMedium, Title: "Resolved"},
	}

	delta := domain.CalculateRunDelta(current, baseline, "run-2", "run-1", "prj-1")

	newOnly := filterFindingsByChange(current, delta, "new")
	if len(newOnly) != 1 || newOnly[0].Fingerprint != "fp-new" {
		t.Fatalf("expected only fp-new in new change filter")
	}

	existingOnly := filterFindingsByChange(current, delta, "existing")
	if len(existingOnly) != 1 || existingOnly[0].Fingerprint != "fp-existing" {
		t.Fatalf("expected only fp-existing in existing change filter")
	}

	resolvedOnly := filterFindingsByChange(baseline, delta, "resolved")
	if len(resolvedOnly) != 1 || resolvedOnly[0].Fingerprint != "fp-resolved" {
		t.Fatalf("expected only fp-resolved in resolved change filter")
	}
}

func TestFilterFindingsAtOrAboveSeverityDelegatesToDomainOrdering(t *testing.T) {
	findings := []domain.Finding{
		{Fingerprint: "fp-low", Severity: domain.SeverityLow, Title: "Low"},
		{Fingerprint: "fp-critical", Severity: domain.SeverityCritical, Title: "Critical"},
		{Fingerprint: "fp-high", Severity: domain.SeverityHigh, Title: "High"},
	}

	filtered := domain.FilterFindingsAtOrAboveSeverity(findings, domain.SeverityHigh)
	if len(filtered) != 2 {
		t.Fatalf("expected 2 findings at or above high, got %d", len(filtered))
	}
	if filtered[0].Fingerprint != "fp-critical" || filtered[1].Fingerprint != "fp-high" {
		t.Fatalf("expected findings ordered critical then high")
	}
}

func TestModuleExecutionCountsAndLabel(t *testing.T) {
	app := &App{
		lang:    i18n.EN,
		catalog: i18n.New(i18n.EN),
	}

	modules := []domain.ModuleResult{
		{Name: "semgrep", Status: domain.ModuleCompleted, Attempts: 1, DurationMs: 850},
		{Name: "codeql", Status: domain.ModuleFailed, Attempts: 2, TimedOut: true, FailureKind: domain.ModuleFailureTimeout},
		{Name: "zaproxy", Status: domain.ModuleSkipped, FailureKind: domain.ModuleFailureSkipped},
	}

	failed, skipped, retried := app.moduleExecutionCounts(modules)
	if failed != 1 || skipped != 1 || retried != 1 {
		t.Fatalf("unexpected execution counts: failed=%d skipped=%d retried=%d", failed, skipped, retried)
	}

	label := app.moduleEventLabel(modules[1])
	if label == "" {
		t.Fatalf("expected non-empty module event label")
	}
	if got, want := app.moduleFailureLabel(domain.ModuleFailureToolMiss), "tool missing"; got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
	if got := app.maxModuleAttempts(modules[2]); got != 0 {
		t.Fatalf("expected skipped module to report 0 attempts, got %d", got)
	}

	trace := domain.ModuleExecutionTrace{
		Module: "codeql",
		AttemptJournal: []domain.ModuleAttemptTrace{
			{Attempt: 2, FailureKind: domain.ModuleFailureTimeout, TimedOut: true},
		},
	}
	if label := app.traceLastAttemptLabel(trace); label == "" || label == "-" {
		t.Fatalf("expected populated trace label, got %q", label)
	}
}

func TestCountRunStatusesAndActiveQueueRuns(t *testing.T) {
	app := &App{
		lang:    i18n.EN,
		catalog: i18n.New(i18n.EN),
	}
	runs := []domain.ScanRun{
		{ID: "run-1", Status: domain.ScanQueued},
		{ID: "run-2", Status: domain.ScanRunning},
		{ID: "run-3", Status: domain.ScanCanceled},
		{ID: "run-4", Status: domain.ScanCompleted},
	}

	counts := app.countRunStatuses(runs)
	if counts.Queued != 1 || counts.Running != 1 || counts.Canceled != 1 || counts.Completed != 1 {
		t.Fatalf("unexpected run counts: %+v", counts)
	}

	active := app.activeQueueRuns(runs, 10)
	if len(active) != 2 || active[0].ID != "run-1" || active[1].ID != "run-2" {
		t.Fatalf("unexpected active queue runs: %+v", active)
	}
}

func TestScanLaneDescriptorsForProjectUsesHistoricalDurations(t *testing.T) {
	app := &App{
		lang:    i18n.EN,
		catalog: i18n.New(i18n.EN),
	}
	runs := []domain.ScanRun{
		{
			ID:        "run-1",
			ProjectID: "prj-1",
			Status:    domain.ScanCompleted,
			ModuleResults: []domain.ModuleResult{
				{Name: "stack-detector", Status: domain.ModuleCompleted, DurationMs: 1000},
				{Name: "surface-inventory", Status: domain.ModuleCompleted, DurationMs: 3000},
				{Name: "trivy", Status: domain.ModuleCompleted, DurationMs: 90000},
				{Name: "syft", Status: domain.ModuleCompleted, DurationMs: 30000},
			},
		},
		{
			ID:        "run-2",
			ProjectID: "prj-1",
			Status:    domain.ScanCompleted,
			ModuleResults: []domain.ModuleResult{
				{Name: "stack-detector", Status: domain.ModuleCompleted, DurationMs: 2000},
				{Name: "surface-inventory", Status: domain.ModuleCompleted, DurationMs: 2000},
				{Name: "trivy", Status: domain.ModuleCompleted, DurationMs: 60000},
				{Name: "syft", Status: domain.ModuleCompleted, DurationMs: 60000},
			},
		},
	}

	project := domain.Project{ID: "prj-1", DetectedStacks: []string{"go"}}
	lanes := app.scanLaneDescriptorsForProject(project, []string{"stack-detector", "surface-inventory", "trivy", "syft"}, runs)
	if len(lanes) < 2 {
		t.Fatalf("expected multiple lane descriptors, got %d", len(lanes))
	}
	if lanes[0].ETA != "~4s" {
		t.Fatalf("expected surface lane ETA to use historical duration, got %q", lanes[0].ETA)
	}
	if lanes[1].ETA != "~2m0s" {
		t.Fatalf("expected supply lane ETA to use historical duration, got %q", lanes[1].ETA)
	}
}

func TestScanLaneDescriptorsForProjectUsesHeuristicWhenHistoryMissing(t *testing.T) {
	app := &App{
		lang:    i18n.EN,
		catalog: i18n.New(i18n.EN),
	}
	project := domain.Project{ID: "prj-new", DetectedStacks: []string{"go", "swift"}}
	lanes := app.scanLaneDescriptorsForProject(project, []string{"semgrep", "codeql", "trivy", "syft"}, nil)
	if len(lanes) < 2 {
		t.Fatalf("expected multiple lane descriptors, got %d", len(lanes))
	}
	if lanes[0].ETA != "~17s" {
		t.Fatalf("expected heuristic code lane ETA, got %q", lanes[0].ETA)
	}
	if lanes[1].ETA != "~2m22s" {
		t.Fatalf("expected heuristic supply lane ETA, got %q", lanes[1].ETA)
	}
}

func TestBuildPortfolioSnapshotIndexesProjectsAndFindings(t *testing.T) {
	app, run, _, _ := newFocusedRunFilterFixture(t)
	project, ok := app.service.GetProject(run.ProjectID)
	if !ok {
		t.Fatalf("expected run project %s to exist", run.ProjectID)
	}

	snapshot := app.buildPortfolioSnapshot()
	if got := snapshot.projectLabel(run.ProjectID); got != project.DisplayName {
		t.Fatalf("expected snapshot project label %q, got %q", project.DisplayName, got)
	}
	if findings := snapshot.findingsForRun(run.ID); len(findings) == 0 {
		t.Fatalf("expected snapshot findings index to include run %s", run.ID)
	}
}

func TestLoadDASTAuthProfilesAndBindTargets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dast-auth.json")
	body := []byte(`{
  "profiles": [
    {
      "name": " staging-bearer ",
      "type": "Bearer",
      "secretEnv": " STAGING_API_TOKEN ",
      "sessionCheckUrl": " https://api.example.test/me ",
      "sessionCheckPattern": " 200 OK "
    }
  ]
}`)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write auth file: %v", err)
	}

	profiles, err := loadDASTAuthProfiles(path)
	if err != nil {
		t.Fatalf("load dast auth profiles: %v", err)
	}
	if len(profiles) != 1 {
		t.Fatalf("expected 1 auth profile, got %d", len(profiles))
	}
	if profiles[0].Type != domain.DastAuthBearer {
		t.Fatalf("expected bearer auth type, got %s", profiles[0].Type)
	}
	if profiles[0].Name != "staging-bearer" {
		t.Fatalf("expected normalized auth profile name, got %q", profiles[0].Name)
	}
	if profiles[0].SecretEnv != "STAGING_API_TOKEN" {
		t.Fatalf("expected normalized secret env, got %q", profiles[0].SecretEnv)
	}

	targets, err := bindDASTTargetAuthProfiles(
		parseTargets([]string{"api=https://api.example.test", "admin=https://admin.example.test"}),
		[]string{"api=staging-bearer"},
		profiles,
	)
	if err != nil {
		t.Fatalf("bind dast target auth profiles: %v", err)
	}
	if got := targets[0].AuthProfile; got != "staging-bearer" {
		t.Fatalf("expected api target to reference auth profile, got %q", got)
	}
	if got := targets[0].AuthType; got != domain.DastAuthBearer {
		t.Fatalf("expected api target auth type bearer, got %s", got)
	}
	if got := targets[1].AuthType; got != domain.DastAuthNone {
		t.Fatalf("expected unmatched target auth type none, got %s", got)
	}
}

func TestLoadDASTAuthProfilesRejectsInvalidFormProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dast-auth.json")
	body := []byte(`[
  {
    "name": "staging-form",
    "type": "form",
    "loginPageUrl": "https://app.example.test/login",
    "loginRequestUrl": "https://app.example.test/sessions",
    "loginRequestBody": "username={%username%}&password={%password%}",
    "usernameEnv": "STAGING_WEB_USER",
    "passwordEnv": "STAGING_WEB_PASS"
  }
]`)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write auth file: %v", err)
	}

	_, err := loadDASTAuthProfiles(path)
	if err == nil {
		t.Fatalf("expected invalid form auth profile error")
	}
	if got, want := err.Error(), `dast auth profile "staging-form" requires sessionCheckUrl or loggedInRegex/loggedOutRegex for form auth verification`; got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}

func TestDASTAuthTemplateCommandPrintsAllProfiles(t *testing.T) {
	app := &App{
		lang:    i18n.EN,
		catalog: i18n.New(i18n.EN),
	}

	cmd := app.dastCommand()
	buffer := &bytes.Buffer{}
	cmd.SetOut(buffer)
	cmd.SetErr(buffer)
	cmd.SetArgs([]string{"auth-template"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute dast auth-template: %v", err)
	}

	var payload struct {
		Profiles []domain.DastAuthProfile `json:"profiles"`
	}
	if err := json.Unmarshal(buffer.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal template output: %v", err)
	}
	if len(payload.Profiles) != 5 {
		t.Fatalf("expected 5 auth templates, got %d", len(payload.Profiles))
	}
	if payload.Profiles[3].Type != domain.DastAuthBrowser {
		t.Fatalf("expected browser template in output, got %s", payload.Profiles[3].Type)
	}
	if payload.Profiles[4].Type != domain.DastAuthForm {
		t.Fatalf("expected form template in output, got %s", payload.Profiles[4].Type)
	}
}

func TestDASTAuthTemplateCommandPrintsSingleTemplate(t *testing.T) {
	app := &App{
		lang:    i18n.EN,
		catalog: i18n.New(i18n.EN),
	}

	cmd := app.dastCommand()
	buffer := &bytes.Buffer{}
	cmd.SetOut(buffer)
	cmd.SetErr(buffer)
	cmd.SetArgs([]string{"auth-template", "form"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute dast auth-template form: %v", err)
	}

	var payload struct {
		Profiles []domain.DastAuthProfile `json:"profiles"`
	}
	if err := json.Unmarshal(buffer.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal template output: %v", err)
	}
	if len(payload.Profiles) != 1 {
		t.Fatalf("expected 1 auth template, got %d", len(payload.Profiles))
	}
	profile := payload.Profiles[0]
	if profile.Type != domain.DastAuthForm {
		t.Fatalf("expected form template, got %s", profile.Type)
	}
	if profile.LoginRequestBody == "" || profile.LoggedInRegex == "" {
		t.Fatalf("expected form template to include login and verification fields, got %+v", profile)
	}
}

func TestTrimForSelectPreservesUTF8(t *testing.T) {
	if got := trimForSelect("İnceleme akışı", 5); got != "İn..." {
		t.Fatalf("expected rune-safe truncation, got %q", got)
	}
	if got := trimForSelect("çalışma", 2); got != "ça" {
		t.Fatalf("expected short rune-safe truncation, got %q", got)
	}
}

func TestWriteRunExportUsesOwnerOnlyPermissions(t *testing.T) {
	app, run, _, _ := newFocusedRunFilterFixture(t)
	output := filepath.Join(t.TempDir(), "report.html")

	written, err := app.writeRunExport(run.ID, "html", output, "")
	if err != nil {
		t.Fatalf("write run export: %v", err)
	}

	info, err := os.Stat(written)
	if err != nil {
		t.Fatalf("stat export: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected owner-only report permissions, got %#o", info.Mode().Perm())
	}
}

func TestWriteRunExportAppliesEvidencePolicyToReportArtifacts(t *testing.T) {
	app, run, _, _ := newFocusedRunFilterFixture(t)
	app.cfg.ArtifactRedaction = true
	app.cfg.ArtifactEncryptionKey = "test-secret"
	app.cfg.ArtifactRetentionDays = 7

	written, err := app.writeRunExport(run.ID, "html", filepath.Join(t.TempDir(), "report.html"), "")
	if err != nil {
		t.Fatalf("write run export: %v", err)
	}
	if !strings.HasSuffix(written, ".enc") {
		t.Fatalf("expected encrypted report path, got %q", written)
	}
	body, err := os.ReadFile(written)
	if err != nil {
		t.Fatalf("read report export: %v", err)
	}
	if !strings.Contains(string(body), `"algorithm": "AES-256-GCM"`) {
		t.Fatalf("expected encrypted report envelope, got %q", string(body))
	}
}

func TestExportRunStdoutWritesRawStructuredContentOnly(t *testing.T) {
	app, run, _, _ := newFocusedRunFilterFixture(t)
	output := captureCLIStdout(t, func() error {
		return app.exportRun(run.ID, "sarif", "", "")
	})

	trimmed := strings.TrimSpace(output)
	if strings.Contains(trimmed, "IRONSENTINEL") {
		t.Fatalf("expected raw SARIF without branded header, got %q", trimmed)
	}
	if !json.Valid([]byte(trimmed)) {
		t.Fatalf("expected valid JSON SARIF payload, got %q", trimmed)
	}
}

func TestVerifySBOMAttestationPassesForMatchingRun(t *testing.T) {
	app, run, _, _ := newFocusedRunFilterFixture(t)
	attestationPath := filepath.Join(t.TempDir(), "sbom-attestation.json")
	content, err := app.service.Export(run.ID, "sbom-attestation", "")
	if err != nil {
		t.Fatalf("export attestation: %v", err)
	}
	if err := os.WriteFile(attestationPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write attestation: %v", err)
	}

	if err := app.verifySBOMAttestation(run.ID, attestationPath); err != nil {
		t.Fatalf("verify sbom attestation: %v", err)
	}
}

func TestRenderFindingDetailsShowsVEXFields(t *testing.T) {
	app, _, _, _ := newFocusedRunFilterFixture(t)
	finding := domain.Finding{
		Category:           domain.CategorySCA,
		Severity:           domain.SeverityHigh,
		Title:              "Reachable package vulnerability",
		Location:           "lodash",
		Module:             "osv-scanner",
		RuleID:             "CVE-2026-0001",
		Reachability:       domain.ReachabilityReachable,
		VEXStatus:          domain.VEXStatusNotAffected,
		VEXJustification:   "vulnerable_code_not_present",
		VEXStatementSource: "https://example.test/vex",
		Fingerprint:        "fp-vex",
	}

	output := captureCLIStdout(t, func() error {
		return app.renderFindingDetails(finding)
	})

	for _, want := range []string{"not affected", "vulnerable code not present", "https://example.test/vex"} {
		if !strings.Contains(strings.ToLower(output), want) {
			t.Fatalf("expected finding details output to contain %q, got %q", want, output)
		}
	}
}

func TestOverviewPlainReportUsesShellSafeSummary(t *testing.T) {
	app, run, _, _ := newFocusedRunFilterFixture(t)
	snapshot := app.buildPortfolioSnapshot()
	report := app.overviewPlainReport(snapshot)

	if !strings.Contains(report, strings.ToUpper(brandProductName)+" overview") {
		t.Fatalf("expected plain overview header, got %q", report)
	}
	if !strings.Contains(report, app.catalog.T("overview_operator_focus")) {
		t.Fatalf("expected overview focus summary, got %q", report)
	}
	if strings.Contains(report, "██") || strings.Contains(report, "[cyan]") || strings.Contains(report, "╭") {
		t.Fatalf("expected shell-safe summary without TUI art, got %q", report)
	}
	if !strings.Contains(report, run.ID) {
		t.Fatalf("expected recent run context in plain summary, got %q", report)
	}
}

func TestRuntimePlainReportUsesShellSafeSummary(t *testing.T) {
	app, _ := newTestTUIApp(t)
	report := app.runtimePlainReport(app.runtimeStatus(false))

	if !strings.Contains(report, strings.ToUpper(brandProductName)+" runtime") {
		t.Fatalf("expected plain runtime header, got %q", report)
	}
	if !strings.Contains(report, app.catalog.T("runtime_trust_signal_title")) {
		t.Fatalf("expected runtime trust section, got %q", report)
	}
	if strings.Contains(report, "██") || strings.Contains(report, "[cyan]") || strings.Contains(report, "╭") {
		t.Fatalf("expected shell-safe runtime summary without TUI art, got %q", report)
	}
}

func TestRenderQueueHeadlineFromSnapshotUsesSnapshotProjectLabels(t *testing.T) {
	app, project := newTestTUIApp(t)
	run, err := app.service.EnqueueScan(project.ID, domain.ScanProfile{
		Mode:         domain.ModeSafe,
		Coverage:     domain.CoverageCore,
		Modules:      []string{"stack-detector"},
		SeverityGate: domain.SeverityHigh,
	})
	if err != nil {
		t.Fatalf("enqueue scan: %v", err)
	}

	snapshot := app.buildPortfolioSnapshot()
	headline := app.renderQueueHeadlineFromSnapshot(snapshot, []domain.ScanRun{run})
	if !strings.Contains(headline, project.DisplayName) {
		t.Fatalf("expected queue headline to use snapshot project label %q, got %q", project.DisplayName, headline)
	}
}

func TestOverviewPlainReportTurkishLocalizesHeadlineAndDeduplicatesHotFindings(t *testing.T) {
	app, project := newTestTUIApp(t)
	app.lang = i18n.TR
	app.catalog = i18n.New(i18n.TR)

	snapshot := portfolioSnapshot{
		Projects:     []domain.Project{project},
		ProjectsByID: map[string]domain.Project{project.ID: project},
		Runs: []domain.ScanRun{
			{ID: "run-1", ProjectID: project.ID, Status: domain.ScanRunning, StartedAt: time.Unix(1_763_000_000, 0).UTC()},
		},
		Findings: []domain.Finding{
			{Fingerprint: "fp-1", Severity: domain.SeverityCritical, Priority: 5.5, Title: "Potential GitHub personal access token"},
			{Fingerprint: "fp-2", Severity: domain.SeverityCritical, Priority: 5.4, Title: "Potential GitHub personal access token"},
			{Fingerprint: "fp-3", Severity: domain.SeverityHigh, Priority: 4.8, Title: "Reachable supply-chain issue"},
		},
	}

	report := app.overviewPlainReport(snapshot)
	if strings.Contains(report, "RUNNING") {
		t.Fatalf("expected Turkish overview to avoid raw RUNNING token\n%s", report)
	}
	if !strings.Contains(report, "ÇALIŞIYOR") {
		t.Fatalf("expected Turkish overview to localize recent run status\n%s", report)
	}
	if count := strings.Count(report, "Potential GitHub personal access token"); count != 1 {
		t.Fatalf("expected duplicated hot findings to be compacted, saw %d copies\n%s", count, report)
	}
}

func TestRuntimePlainReportTurkishAvoidsRawTokensAndPluralStatusLeaks(t *testing.T) {
	app, _ := newTestTUIApp(t)
	app.lang = i18n.TR
	app.catalog = i18n.New(i18n.TR)

	runtime := app.runtimeStatus(false)
	runtime.Daemon = domain.RuntimeDaemon{}
	runtime.Isolation.EffectiveMode = domain.IsolationLocal
	runtime.Isolation.Rootless = false
	runtime.ScannerBundle = []domain.RuntimeTool{
		{Name: "trivy", Available: true, Healthy: true, ActualVersion: "0.69.4", Path: "/opt/homebrew/bin/trivy"},
		{Name: "syft", Available: true, Healthy: false, ActualVersion: "1.42.2", Path: "/opt/homebrew/bin/syft"},
		{Name: "semgrep", Available: false, ExpectedVersion: "1.119.0"},
	}

	report := app.runtimePlainReport(runtime)
	for _, forbidden := range []string{"Bosta", "LOCAL", ": false", "semgrep | Eksik tarayıcılar |", "trivy | Mevcut tarayıcılar |"} {
		if strings.Contains(report, forbidden) {
			t.Fatalf("expected Turkish runtime report to avoid raw token %q\n%s", forbidden, report)
		}
	}
	for _, expected := range []string{"Boşta", "YEREL", "Hayır", "semgrep | EKSİK |", "trivy | HAZIR |"} {
		if !strings.Contains(report, expected) {
			t.Fatalf("expected Turkish runtime report to include %q\n%s", expected, report)
		}
	}
}

func TestFindingsViewSourceUsesSnapshotForRunAndPortfolio(t *testing.T) {
	app, run, _, _ := newFocusedRunFilterFixture(t)
	snapshot := app.buildPortfolioSnapshot()

	scoped := findingsViewSource(snapshot, run.ID)
	if len(scoped) == 0 {
		t.Fatalf("expected scoped findings from snapshot for run %s", run.ID)
	}
	if len(findingsViewSource(snapshot, "")) != len(snapshot.Findings) {
		t.Fatalf("expected empty run scope to return full snapshot findings")
	}
}

func TestWatchRunsReturnsImmediatelyWhenContextCanceled(t *testing.T) {
	app := &App{
		lang:    i18n.EN,
		catalog: i18n.New(i18n.EN),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := app.watchRuns(ctx, "", time.Second); err != nil {
		t.Fatalf("watchRuns returned error for canceled context: %v", err)
	}
}

func captureCLIStdout(t *testing.T, fn func() error) string {
	t.Helper()

	originalStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	os.Stdout = writer
	pterm.SetDefaultOutput(writer)
	t.Cleanup(func() {
		os.Stdout = originalStdout
		pterm.SetDefaultOutput(originalStdout)
	})

	runErr := fn()
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	if runErr != nil {
		t.Fatalf("captured command returned error: %v", runErr)
	}
	return string(body)
}

func TestRootCommandIncludesSimpleProjectSelectionCommands(t *testing.T) {
	app := &App{
		lang:    i18n.EN,
		catalog: i18n.New(i18n.EN),
	}

	root := app.RootCommand()
	for _, use := range []string{"init", "open", "pick"} {
		if _, _, err := root.Find([]string{use}); err != nil {
			t.Fatalf("expected root command to include %s: %v", use, err)
		}
	}
}

func TestRootCommandNoArgsInteractiveUsesPrimaryConsoleShell(t *testing.T) {
	app, _ := newTestTUIApp(t)
	app.languageConfigured = true

	originalTerminalIsTerminal := terminalIsTerminal
	originalRunTeaProgram := runTeaProgram
	t.Cleanup(func() {
		terminalIsTerminal = originalTerminalIsTerminal
		runTeaProgram = originalRunTeaProgram
	})
	terminalIsTerminal = func(int) bool { return true }

	var calls []tea.Model
	runTeaProgram = func(model tea.Model, opts ...tea.ProgramOption) (tea.Model, error) {
		calls = append(calls, model)
		return model, nil
	}

	root := app.RootCommand()
	root.SetArgs([]string{})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute root command: %v", err)
	}
	if got := app.primaryTUIModelName(); got != "console_shell" {
		t.Fatalf("expected primary TUI model name console_shell, got %q", got)
	}
	if len(calls) != 1 {
		t.Fatalf("expected root command to boot a single primary model, got %d call(s)", len(calls))
	}
	if _, ok := calls[0].(consoleShellModel); !ok {
		t.Fatalf("expected root command to boot console shell, got %T", calls[0])
	}
}

func TestRootCommandNoArgsNonInteractiveFallsBackToPlainOverview(t *testing.T) {
	app, _ := newTestTUIApp(t)
	app.languageConfigured = true

	originalTerminalIsTerminal := terminalIsTerminal
	originalRunTeaProgram := runTeaProgram
	t.Cleanup(func() {
		terminalIsTerminal = originalTerminalIsTerminal
		runTeaProgram = originalRunTeaProgram
	})
	terminalIsTerminal = func(int) bool { return false }

	runTeaProgram = func(model tea.Model, opts ...tea.ProgramOption) (tea.Model, error) {
		t.Fatalf("expected non-interactive root path to avoid TUI launch, got %T", model)
		return model, nil
	}

	root := app.RootCommand()
	root.SetArgs([]string{})
	output := captureCLIStdout(t, func() error {
		return root.Execute()
	})
	if !strings.Contains(output, strings.ToUpper(brandProductName)+" overview") {
		t.Fatalf("expected plain overview output, got %q", output)
	}
}

func TestGitHubUploadSARIFCommandRequiresToken(t *testing.T) {
	app, run, _, _ := newFocusedRunFilterFixture(t)
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	t.Setenv("PATH", t.TempDir())

	cmd := app.githubCommand()
	cmd.SetArgs([]string{"upload-sarif", run.ID, "--repo", "batu3384/ironsentinel"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "github auth token not found") {
		t.Fatalf("expected auth error, got %v", err)
	}
}

func TestGitHubUploadSARIFCommandPrefersProjectWorkspaceRoot(t *testing.T) {
	app, run, _, _ := newFocusedRunFilterFixture(t)
	project, ok := app.service.GetProject(run.ProjectID)
	if !ok {
		t.Fatalf("expected run project %s to exist", run.ProjectID)
	}
	if strings.TrimSpace(project.LocationHint) == "" {
		t.Fatalf("expected project location hint for run %s", run.ID)
	}
	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("get wd: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(originalWD)
	})

	workdir := t.TempDir()
	otherDir := t.TempDir()
	if err := os.Chdir(otherDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	app.cwd = workdir

	binDir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "git-cwd.txt")
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s' "$(pwd)" > %q
case "$*" in
  "remote get-url origin") printf '%%s\n' 'git@github.com:batu3384/ironsentinel.git' ;;
  "rev-parse HEAD") printf '%%s\n' 'abc123def456' ;;
  "symbolic-ref --quiet --short HEAD") printf '%%s\n' 'main' ;;
  *) exit 1 ;;
esac
`, marker)
	gitPath := filepath.Join(binDir, "git")
	if err := os.WriteFile(gitPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake git: %v", err)
	}
	t.Setenv("PATH", binDir)
	t.Setenv("GITHUB_TOKEN", "ghs-test")
	t.Setenv("GH_TOKEN", "")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")

	cmd := app.githubCommand()
	cmd.SetArgs([]string{"upload-sarif", run.ID})
	err = cmd.Execute()
	if err == nil {
		t.Fatalf("expected upload to fail after exercising cwd resolution")
	}
	recorded, readErr := os.ReadFile(marker)
	if readErr != nil {
		t.Fatalf("read git cwd marker: %v", readErr)
	}
	if got, want := filepath.Clean(strings.TrimSpace(string(recorded))), filepath.Clean(project.LocationHint); got != want {
		t.Fatalf("expected github upload to prefer project workspace root %s, got %s", want, got)
	}
}

func TestGitHubSubmitDepsCommandFailsWithoutDependencyInventory(t *testing.T) {
	app, run, _, _ := newFocusedRunFilterFixture(t)
	t.Setenv("GITHUB_TOKEN", "ghs-test")
	t.Setenv("GH_TOKEN", "")

	cmd := app.githubCommand()
	cmd.SetArgs([]string{"submit-deps", run.ProjectID, "--repo", "batu3384/ironsentinel"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "no dependency inventory available") {
		t.Fatalf("expected dependency inventory error, got %v", err)
	}
}

func TestGitHubSubmitDepsMetadataRootPrefersProjectWorkspaceRoot(t *testing.T) {
	app, run, _, _ := newFocusedRunFilterFixture(t)
	project, ok := app.service.GetProject(run.ProjectID)
	if !ok {
		t.Fatalf("expected run project %s to exist", run.ProjectID)
	}

	app.cwd = t.TempDir()
	if got, want := app.githubDependencyMetadataRoot(project), strings.TrimSpace(project.LocationHint); got != want {
		t.Fatalf("expected submit-deps metadata root %q, got %q", want, got)
	}
}

func TestGitHubDependencyPackagesPreferCanonicalPURLAndSkipInvalidVersions(t *testing.T) {
	app := &App{}
	sbomPath := filepath.Join(t.TempDir(), "sbom.json")
	sbom := `{"components":[{"name":"github.com/spf13/cobra","version":"1.9.1","type":"library","purl":"pkg:go/github.com/spf13/cobra@1.9.1"},{"name":"github.com/spf13/pflag","version":"5.0.0","type":"library"},{"name":"github.com/spf13/skip","version":"","type":"library"}]}`
	if err := os.WriteFile(sbomPath, []byte(sbom), 0o644); err != nil {
		t.Fatalf("write sbom: %v", err)
	}

	packages, err := app.githubDependencyPackages(domain.ScanRun{
		ArtifactRefs: []domain.ArtifactRef{{Kind: "sbom", URI: sbomPath}},
	})
	if err != nil {
		t.Fatalf("github dependency packages: %v", err)
	}
	if len(packages) != 2 {
		t.Fatalf("expected invalid package to be skipped while keeping canonical and fallback packages, got %+v", packages)
	}
	if got, want := packages[0].PackageURL, "pkg:go/github.com/spf13/cobra@1.9.1"; got != want {
		t.Fatalf("expected canonical purl %q, got %q", want, got)
	}
	if got, want := packages[0].Ecosystem, "go"; got != want {
		t.Fatalf("expected ecosystem from canonical purl %q, got %q", want, got)
	}
	if got, want := packages[0].Relationship, "indirect"; got != want {
		t.Fatalf("expected indirect relationship fallback, got %q", got)
	}
	if got, want := packages[1].Relationship, "indirect"; got != want {
		t.Fatalf("expected indirect relationship fallback for generic package, got %q", got)
	}
	if got, want := packages[1].Ecosystem, "generic"; got != want {
		t.Fatalf("expected neutral fallback ecosystem %q, got %q", want, got)
	}
	if got := strings.TrimSpace(packages[1].PackageURL); got != "" {
		t.Fatalf("expected no canonical package url for fallback package, got %q", got)
	}
}

func TestGitHubDependencyRunPrefersNewestUsableInventory(t *testing.T) {
	app, project := newTestTUIApp(t)

	olderRun, err := app.service.EnqueueScan(project.ID, domain.ScanProfile{Mode: domain.ModeSafe, Coverage: domain.CoverageCore, Modules: []string{"syft"}})
	if err != nil {
		t.Fatalf("enqueue older run: %v", err)
	}
	newerRun, err := app.service.EnqueueScan(project.ID, domain.ScanProfile{Mode: domain.ModeSafe, Coverage: domain.CoverageCore, Modules: []string{"secret-heuristics"}})
	if err != nil {
		t.Fatalf("enqueue newer run: %v", err)
	}

	sbomPath := filepath.Join(t.TempDir(), "sbom.json")
	sbom := `{"components":[{"name":"github.com/spf13/cobra","version":"1.9.1","type":"library","purl":"pkg:go/github.com/spf13/cobra@1.9.1"}]}`
	if err := os.WriteFile(sbomPath, []byte(sbom), 0o644); err != nil {
		t.Fatalf("write sbom: %v", err)
	}

	olderRun.StartedAt = time.Now().Add(-2 * time.Hour)
	olderRun.Status = domain.ScanCompleted
	finishedOlder := time.Now().Add(-90 * time.Minute)
	olderRun.FinishedAt = &finishedOlder
	olderRun.ArtifactRefs = []domain.ArtifactRef{{Kind: "sbom", URI: sbomPath}}
	newerRun.StartedAt = time.Now()
	newerRun.Status = domain.ScanRunning
	newerRun.ArtifactRefs = []domain.ArtifactRef{{Kind: "sbom", URI: sbomPath}}
	updateRunRecord(t, app, olderRun)
	updateRunRecord(t, app, newerRun)

	got, err := app.githubDependencyRun(project, "")
	if err != nil {
		t.Fatalf("github dependency run: %v", err)
	}
	if got == nil || got.ID != olderRun.ID {
		t.Fatalf("expected older usable run %s, got %+v", olderRun.ID, got)
	}
}

func TestCampaignsCommandIncludesCreateListShowAndPublish(t *testing.T) {
	app, _ := newTestTUIApp(t)
	root := app.RootCommand()

	for _, use := range []string{"campaigns create", "campaigns list", "campaigns show", "campaigns add-findings", "campaigns publish-github"} {
		parts := strings.Split(use, " ")
		if _, _, err := root.Find(parts); err != nil {
			t.Fatalf("expected command %q: %v", use, err)
		}
	}
}

func TestGitHubCreateIssuesFromCampaignCommandExists(t *testing.T) {
	app, _ := newTestTUIApp(t)
	cmd := app.githubCommand()
	if _, _, err := cmd.Find([]string{"create-issues-from-campaign"}); err != nil {
		t.Fatalf("expected GitHub campaign publish wrapper: %v", err)
	}
}

func TestCampaignsCreateCommandPersistsCampaign(t *testing.T) {
	app, run, _, _ := newFocusedRunFilterFixture(t)
	root := app.RootCommand()
	findings := app.service.ListFindings(run.ID)
	if len(findings) == 0 {
		t.Fatalf("expected run findings for campaign creation")
	}
	selectedFingerprint := findings[0].Fingerprint

	buffer := &bytes.Buffer{}
	root.SetOut(buffer)
	root.SetErr(buffer)
	root.SetArgs([]string{
		"campaigns", "create",
		"--project", run.ProjectID,
		"--run", run.ID,
		"--id", "cmp-cli-1",
		"--title", "Fix reachable secrets",
		"--summary", "Turn the finding set into one remediation issue",
		"--finding", selectedFingerprint,
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute campaigns create: %v", err)
	}

	campaignStore, err := store.NewStateStore(filepath.Join(app.cfg.DataDir, "state.db"))
	if err != nil {
		t.Fatalf("open campaign store: %v", err)
	}
	t.Cleanup(func() { _ = campaignStore.Close() })
	got, ok := campaignStore.GetCampaign("cmp-cli-1")
	if !ok {
		t.Fatalf("expected campaign cmp-cli-1 to be persisted")
	}
	if got.ProjectID != run.ProjectID || got.SourceRunID != run.ID {
		t.Fatalf("unexpected campaign payload: %+v", got)
	}
	if len(got.FindingFingerprints) == 0 {
		t.Fatalf("expected campaign fingerprints to be populated")
	}
	if got.Title != "Fix reachable secrets" {
		t.Fatalf("unexpected campaign title: %q", got.Title)
	}
	if len(got.FindingFingerprints) != 1 || got.FindingFingerprints[0] != selectedFingerprint {
		t.Fatalf("expected explicit campaign membership to be preserved, got %+v", got.FindingFingerprints)
	}
}

func TestCampaignScopedFindingsFiltersToCampaignMembership(t *testing.T) {
	findings := []domain.Finding{
		{Fingerprint: "fp-1", Title: "One"},
		{Fingerprint: "fp-2", Title: "Two"},
	}

	scoped := campaignScopedFindings(findings, []string{"fp-2"})
	if len(scoped) != 1 || scoped[0].Fingerprint != "fp-2" {
		t.Fatalf("expected only campaign finding membership, got %+v", scoped)
	}
}

func TestCampaignPublishCommandsRequireRepoFlag(t *testing.T) {
	app, _ := newTestTUIApp(t)

	campaigns := app.campaignsPublishGitHubCommand()
	if flag := campaigns.Flags().Lookup("repo"); flag == nil || flag.Annotations == nil || len(flag.Annotations[cobra.BashCompOneRequiredFlag]) == 0 {
		t.Fatalf("expected campaigns publish-github repo flag to be required")
	}

	github := app.githubCreateIssuesFromCampaignCommand()
	if flag := github.Flags().Lookup("repo"); flag == nil || flag.Annotations == nil || len(flag.Annotations[cobra.BashCompOneRequiredFlag]) == 0 {
		t.Fatalf("expected github create-issues-from-campaign repo flag to be required")
	}
}

func TestGitHubPublishingDocsAndHelpSurface(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	architecture, err := os.ReadFile(filepath.Join("..", "..", "docs", "architecture.md"))
	if err != nil {
		t.Fatalf("read architecture doc: %v", err)
	}

	readmeText := string(readme)
	for _, want := range []string{
		"## GitHub Publishing",
		"ironsentinel github export-custom-patterns",
		"ironsentinel github upload-sarif <run-id>",
		"ironsentinel github submit-deps <project-id>",
		"ironsentinel setup install-pre-push",
	} {
		if !strings.Contains(readmeText, want) {
			t.Fatalf("expected README to mention %q", want)
		}
	}

	architectureText := string(architecture)
	for _, want := range []string{
		"### GitHub integration",
		"internal/integrations/github",
		"code scanning",
		"dependency graph",
		"custom pattern",
		"pre-push",
	} {
		if !strings.Contains(architectureText, want) {
			t.Fatalf("expected architecture doc to mention %q", want)
		}
	}

	app := &App{
		lang:    i18n.EN,
		catalog: i18n.New(i18n.EN),
	}
	root := app.RootCommand()

	buffer := &bytes.Buffer{}
	root.SetOut(buffer)
	root.SetErr(buffer)
	root.SetArgs([]string{"github", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute github help: %v", err)
	}

	help := buffer.String()
	for _, want := range []string{
		"GitHub publishing",
		"export-custom-patterns",
		"upload-sarif",
		"submit-deps",
		"push-protect",
		"Export IronSentinel secret patterns in GitHub custom pattern form",
		"Upload SARIF to GitHub code scanning",
		"Submit dependencies to the GitHub dependency graph",
		"Block pushes that contain high-confidence secrets",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("expected github help to mention %q, got %q", want, help)
		}
	}

	buffer.Reset()
	root.SetArgs([]string{"setup", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute setup help: %v", err)
	}
	setupHelp := buffer.String()
	for _, want := range []string{
		"install-pre-push",
		"Install the IronSentinel pre-push guard into the current repository",
	} {
		if !strings.Contains(setupHelp, want) {
			t.Fatalf("expected setup help to mention %q, got %q", want, setupHelp)
		}
	}
}

func TestDASTDocsAndHelpSurface(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	architecture, err := os.ReadFile(filepath.Join("..", "..", "docs", "architecture.md"))
	if err != nil {
		t.Fatalf("read architecture doc: %v", err)
	}

	readmeText := string(readme)
	for _, want := range []string{
		"## Authenticated DAST Profiles",
		"ironsentinel dast auth-template",
		"ironsentinel dast auth-template form",
		"--target-auth api=staging-bearer",
	} {
		if !strings.Contains(readmeText, want) {
			t.Fatalf("expected README to mention %q", want)
		}
	}

	architectureText := string(architecture)
	for _, want := range []string{
		"`dast auth-template [type]`",
		"reusable auth profile definitions",
		"target intent, auth material, and execution policy separate",
	} {
		if !strings.Contains(architectureText, want) {
			t.Fatalf("expected architecture doc to mention %q", want)
		}
	}

	app := &App{
		lang:    i18n.EN,
		catalog: i18n.New(i18n.EN),
	}
	root := app.RootCommand()

	buffer := &bytes.Buffer{}
	root.SetOut(buffer)
	root.SetErr(buffer)
	root.SetArgs([]string{"dast", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute dast help: %v", err)
	}

	help := buffer.String()
	for _, want := range []string{
		"plan",
		"auth-template",
		"Print reusable DAST auth profile JSON templates",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("expected dast help to mention %q, got %q", want, help)
		}
	}
}

func TestSetupInstallPrePushCommandWritesManagedHook(t *testing.T) {
	repo := t.TempDir()
	runGitForTest(t, repo, "init", "-b", "main")

	app, err := New(config.Load())
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	app.cwd = repo

	cmd := app.setupCommand()
	cmd.SetArgs([]string{"install-pre-push", "--binary", "/usr/local/bin/ironsentinel"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute install-pre-push: %v", err)
	}

	body, err := os.ReadFile(filepath.Join(repo, ".git", "hooks", "pre-push"))
	if err != nil {
		t.Fatalf("read pre-push hook: %v", err)
	}
	text := string(body)
	for _, want := range []string{"Managed by IronSentinel", "/usr/local/bin/ironsentinel", "github push-protect"} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected installed hook to contain %q, got %q", want, text)
		}
	}
}

func TestGitHubExportCustomPatternsCommandPrintsJSONManifest(t *testing.T) {
	app, err := New(config.Load())
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	app.lang = i18n.EN
	app.catalog = i18n.New(i18n.EN)

	cmd := app.githubCommand()
	buffer := &bytes.Buffer{}
	cmd.SetOut(buffer)
	cmd.SetErr(buffer)
	cmd.SetArgs([]string{"export-custom-patterns"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute export-custom-patterns: %v", err)
	}

	text := buffer.String()
	for _, want := range []string{
		`"version": "1"`,
		`IronSentinel / secret.github_pat`,
		`IronSentinel / secret.aws_access_key`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected command output to contain %q, got %q", want, text)
		}
	}
}

func runGitForTest(t *testing.T, dir string, args ...string) string {
	t.Helper()

	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, string(out))
	}
	return string(out)
}

func TestRootCommandCompatibilityCommandsAreHiddenButCallable(t *testing.T) {
	app := &App{
		lang:    i18n.EN,
		catalog: i18n.New(i18n.EN),
	}

	root := app.RootCommand()
	for _, use := range []string{"console", "open", "pick", "tui"} {
		command, _, err := root.Find([]string{use})
		if err != nil {
			t.Fatalf("expected compatibility command %s to remain callable: %v", use, err)
		}
		if !command.Hidden {
			t.Fatalf("expected compatibility command %s to be hidden from primary help", use)
		}
		if strings.TrimSpace(command.Deprecated) == "" {
			t.Fatalf("expected compatibility command %s to advertise a migration hint", use)
		}
	}
}

func TestCompatibilityCommandsRequireInteractiveSurface(t *testing.T) {
	app := &App{
		lang:               i18n.EN,
		catalog:            i18n.New(i18n.EN),
		languageConfigured: true,
	}

	originalTerminalIsTerminal := terminalIsTerminal
	t.Cleanup(func() {
		terminalIsTerminal = originalTerminalIsTerminal
	})
	terminalIsTerminal = func(int) bool { return false }

	for _, command := range []*cobra.Command{app.tuiCommand(), app.consoleCommand()} {
		command.SetOut(io.Discard)
		command.SetErr(io.Discard)
		command.SetArgs([]string{})
		if err := command.Execute(); err == nil || !strings.Contains(err.Error(), app.catalog.T("interactive_required")) {
			t.Fatalf("expected %s to require an interactive surface, got %v", command.Use, err)
		}
	}
}

func TestCompatibilityCommandsUsePrimaryConsoleShellWhenInteractive(t *testing.T) {
	app, _ := newTestTUIApp(t)
	app.languageConfigured = true

	originalTerminalIsTerminal := terminalIsTerminal
	originalRunTeaProgram := runTeaProgram
	t.Cleanup(func() {
		terminalIsTerminal = originalTerminalIsTerminal
		runTeaProgram = originalRunTeaProgram
	})
	terminalIsTerminal = func(int) bool { return true }

	for _, command := range []*cobra.Command{app.tuiCommand(), app.consoleCommand()} {
		var calls []tea.Model
		runTeaProgram = func(model tea.Model, opts ...tea.ProgramOption) (tea.Model, error) {
			calls = append(calls, model)
			return model, nil
		}

		command.SetOut(io.Discard)
		command.SetErr(io.Discard)
		command.SetArgs([]string{})
		if err := command.Execute(); err != nil {
			t.Fatalf("execute %s: %v", command.Use, err)
		}
		if len(calls) != 1 {
			t.Fatalf("expected %s to boot a single primary model, got %d call(s)", command.Use, len(calls))
		}
		if _, ok := calls[0].(consoleShellModel); !ok {
			t.Fatalf("expected %s to boot console shell, got %T", command.Use, calls[0])
		}
		if _, ok := calls[0].(appShellModel); ok {
			t.Fatalf("expected %s to avoid legacy route shell", command.Use)
		}
	}
}

func TestScanCommandExposesStrictAlias(t *testing.T) {
	app, _ := newTestTUIApp(t)
	cmd := app.scanCommand()

	if cmd.Flags().Lookup("strict") == nil {
		t.Fatal("expected scan command to expose --strict as a strict profile alias")
	}
}

func TestInteractiveScanCommandUsesLegacyCompatibilityShellState(t *testing.T) {
	app, project := newTestTUIApp(t)
	app.languageConfigured = true

	originalTerminalIsTerminal := terminalIsTerminal
	originalRunTeaProgram := runTeaProgram
	t.Cleanup(func() {
		terminalIsTerminal = originalTerminalIsTerminal
		runTeaProgram = originalRunTeaProgram
	})
	terminalIsTerminal = func(int) bool { return true }

	var calls []tea.Model
	runTeaProgram = func(model tea.Model, opts ...tea.ProgramOption) (tea.Model, error) {
		calls = append(calls, model)
		return model, nil
	}

	cmd := app.scanCommand()
	cmd.SetArgs([]string{
		project.LocationHint,
		"--mode", "active",
		"--dast-target", "staging=https://example.test",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute scan command: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected interactive scan to boot a single legacy compatibility shell, got %d call(s)", len(calls))
	}
	legacy, ok := calls[0].(appShellModel)
	if !ok {
		t.Fatalf("expected interactive scan to route through launchTUIWithState legacy shell, got %T", calls[0])
	}
	if legacy.route != appRouteScanReview {
		t.Fatalf("expected interactive scan to seed scan review route, got %v", legacy.route)
	}
	if legacy.selectedProjectID != project.ID {
		t.Fatalf("expected interactive scan to seed selected project %s, got %s", project.ID, legacy.selectedProjectID)
	}
	if !legacy.review.ActiveValidation {
		t.Fatalf("expected interactive scan to seed active validation review state")
	}
	if len(legacy.reviewDASTTargets) != 1 || legacy.reviewDASTTargets[0].Name != "staging" || legacy.reviewDASTTargets[0].URL != "https://example.test" {
		t.Fatalf("expected interactive scan to seed DAST target list, got %+v", legacy.reviewDASTTargets)
	}
}

func updateRunRecord(t *testing.T, app *App, run domain.ScanRun) {
	t.Helper()

	db, err := sql.Open("sqlite", filepath.Join(app.cfg.DataDir, "state.db"))
	if err != nil {
		t.Fatalf("open state db: %v", err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Fatalf("close state db: %v", closeErr)
		}
	}()

	payload, err := json.Marshal(run)
	if err != nil {
		t.Fatalf("marshal run: %v", err)
	}

	if _, err := db.Exec(`UPDATE runs SET started_at = ?, payload = ? WHERE id = ?`, run.StartedAt.UTC().Format(time.RFC3339Nano), string(payload), run.ID); err != nil {
		t.Fatalf("update run record: %v", err)
	}
}

func TestRootHelpOmitsCompatibilityCommands(t *testing.T) {
	app := &App{
		lang:    i18n.EN,
		catalog: i18n.New(i18n.EN),
	}

	root := app.RootCommand()
	buffer := &bytes.Buffer{}
	root.SetOut(buffer)
	root.SetErr(buffer)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute help: %v", err)
	}

	help := buffer.String()
	for _, hidden := range []string{"console", "open", "pick", "tui"} {
		if strings.Contains(help, hidden) {
			t.Fatalf("expected help output to omit hidden compatibility command %q, got %q", hidden, help)
		}
	}
	for _, visible := range []string{"overview", "scan", "findings", "runtime"} {
		if !strings.Contains(help, visible) {
			t.Fatalf("expected help output to include %q, got %q", visible, help)
		}
	}
}

func TestAppRuntimeDoctorUsesInjectedOverride(t *testing.T) {
	calls := 0
	app := &App{
		runtimeDoctorFn: func(profile domain.ScanProfile, strictVersions, requireIntegrity bool) domain.RuntimeDoctor {
			calls++
			return domain.RuntimeDoctor{
				Mode:             profile.Mode,
				StrictVersions:   strictVersions,
				RequireIntegrity: requireIntegrity,
				Ready:            true,
			}
		},
	}

	doctor := app.runtimeDoctor(domain.ScanProfile{Mode: domain.ModeActive}, true, true)

	if !doctor.Ready {
		t.Fatalf("expected injected runtime doctor to be returned")
	}
	if doctor.Mode != domain.ModeActive || !doctor.StrictVersions || !doctor.RequireIntegrity {
		t.Fatalf("expected injected runtime doctor to preserve inputs, got %+v", doctor)
	}
	if calls != 1 {
		t.Fatalf("expected injected runtime doctor to be called once, got %d", calls)
	}
}

func TestAppRuntimeDoctorCachesByProfile(t *testing.T) {
	calls := 0
	app := &App{
		runtimeDoctorFn: func(profile domain.ScanProfile, strictVersions, requireIntegrity bool) domain.RuntimeDoctor {
			calls++
			return domain.RuntimeDoctor{
				Mode:  profile.Mode,
				Ready: true,
			}
		},
	}
	profile := domain.ScanProfile{
		Mode:    domain.ModeDeep,
		Modules: []string{"semgrep", "gitleaks"},
	}

	first := app.runtimeDoctor(profile, false, false)
	second := app.runtimeDoctor(profile, false, false)

	if !first.Ready || !second.Ready {
		t.Fatalf("expected cached runtime doctor results to stay ready")
	}
	if calls != 1 {
		t.Fatalf("expected runtime doctor result to be cached, got %d calls", calls)
	}
}

func TestPreviewPersistentFlagValuesParsesLangAndUIMode(t *testing.T) {
	lang, mode, _ := previewPersistentFlagValues([]string{"scan", "--lang", "tr", "--ui-mode=compact"})
	if lang != "tr" || mode != "compact" {
		t.Fatalf("previewPersistentFlagValues() = (%q, %q), want (tr, compact)", lang, mode)
	}
}

func TestRootCommandLocalizesHelpFlagsFromPreviewArgs(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{brandPrimaryBinary, "--lang", "tr", "--help"}

	app := &App{
		lang:    i18n.EN,
		catalog: i18n.New(i18n.EN),
	}

	root := app.RootCommand()
	flag := root.PersistentFlags().Lookup("lang")
	if flag == nil {
		t.Fatalf("expected lang flag to exist")
	}
	if got := flag.Usage; got != "Dil: en veya tr" {
		t.Fatalf("lang flag usage = %q, want Turkish localized usage", got)
	}
}

func TestShouldPromptForInitialLanguageForCommand(t *testing.T) {
	app := &App{
		lang:    i18n.EN,
		catalog: i18n.New(i18n.EN),
	}

	if !app.shouldPromptForInitialLanguageForCommand(brandPrimaryBinary+" scan", "", true, []string{"scan"}) {
		t.Fatalf("expected first interactive scan to prompt for language")
	}
	if app.shouldPromptForInitialLanguageForCommand(brandPrimaryBinary+" scan", "tr", true, []string{"scan", "--lang", "tr"}) {
		t.Fatalf("expected explicit --lang to skip first-run prompt")
	}
	if app.shouldPromptForInitialLanguageForCommand(brandPrimaryBinary+" config language", "", true, []string{"config", "language"}) {
		t.Fatalf("expected config language command to skip first-run prompt")
	}
	if app.shouldPromptForInitialLanguageForCommand(brandPrimaryBinary+" scan", "", false, []string{"scan"}) {
		t.Fatalf("expected non-interactive command to skip first-run prompt")
	}
	if app.shouldPromptForInitialLanguageForCommand(brandPrimaryBinary, "", true, []string{"--help"}) {
		t.Fatalf("expected help flow to skip first-run prompt")
	}

	app.languageConfigured = true
	if app.shouldPromptForInitialLanguageForCommand(brandPrimaryBinary+" scan", "", true, []string{"scan"}) {
		t.Fatalf("expected saved language to skip first-run prompt")
	}
}

func TestLanguageSelectionOptionsMarksRecommendedLocale(t *testing.T) {
	app := &App{
		cfg:     config.Config{DefaultLanguage: "tr"},
		lang:    i18n.TR,
		catalog: i18n.New(i18n.TR),
	}

	options := app.languageSelectionOptions(true)
	if len(options) != 2 {
		t.Fatalf("expected 2 language options, got %d", len(options))
	}
	if !strings.Contains(options[1].Label, "önerilen") {
		t.Fatalf("expected Turkish option to be marked recommended, got %q", options[1].Label)
	}
	if strings.Contains(options[0].Label, "önerilen") {
		t.Fatalf("did not expect English option to be marked recommended, got %q", options[0].Label)
	}
}

func TestQuickScanProfileUsesSimpleSafeDefaults(t *testing.T) {
	app := &App{
		cfg:     config.Config{SandboxMode: string(domain.IsolationAuto)},
		lang:    i18n.EN,
		catalog: i18n.New(i18n.EN),
	}

	project := domain.Project{
		ID:             "prj-1",
		DisplayName:    "demo",
		DetectedStacks: []string{"javascript", "docker", "terraform"},
	}

	profile := app.quickScanProfile(project)
	if profile.Mode != domain.ModeSafe {
		t.Fatalf("expected safe mode, got %s", profile.Mode)
	}
	if profile.Coverage != domain.CoveragePremium {
		t.Fatalf("expected premium coverage, got %s", profile.Coverage)
	}
	if profile.Isolation != domain.IsolationAuto {
		t.Fatalf("expected auto isolation, got %s", profile.Isolation)
	}
	if !profile.BestEffort {
		t.Fatalf("expected quick scan profile to run in best-effort mode")
	}
	if len(profile.Modules) == 0 {
		t.Fatalf("expected quick scan to resolve modules")
	}
	for _, required := range []string{"surface-inventory", "script-audit", "secret-heuristics"} {
		found := false
		for _, module := range profile.Modules {
			if module == required {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected quick scan profile to include %s", required)
		}
	}
}

func TestEnforceRequiredRuntimeAllowsBestEffortProfiles(t *testing.T) {
	app, project := newTestTUIApp(t)
	app.runtimeDoctorFn = func(profile domain.ScanProfile, strictVersions, requireIntegrity bool) domain.RuntimeDoctor {
		return domain.RuntimeDoctor{
			Mode:             profile.Mode,
			StrictVersions:   strictVersions,
			RequireIntegrity: requireIntegrity,
			Ready:            false,
			Missing:          []domain.RuntimeTool{{Name: "semgrep"}},
		}
	}

	profile := domain.ScanProfile{
		Mode:       domain.ModeSafe,
		Coverage:   domain.CoveragePremium,
		Isolation:  domain.IsolationLocal,
		Modules:    []string{"semgrep"},
		BestEffort: true,
	}
	if err := app.enforceRequiredRuntime(project, profile, false, false); err != nil {
		t.Fatalf("expected best-effort profile to skip runtime blocking, got %v", err)
	}

	profile.BestEffort = false
	if err := app.enforceRequiredRuntime(project, profile, false, false); err == nil {
		t.Fatalf("expected strict profile to block on missing runtime support")
	}
}

func TestRequiredScanErrorIsSoftenedForBestEffortProfiles(t *testing.T) {
	app, _ := newTestTUIApp(t)
	requiredErr := fmt.Errorf("partial")

	if err := app.requiredScanError(domain.ScanProfile{BestEffort: true}, requiredErr); err != nil {
		t.Fatalf("expected best-effort required error to stay non-fatal, got %v", err)
	}
	if err := app.requiredScanError(domain.ScanProfile{}, requiredErr); err == nil {
		t.Fatalf("expected strict profile to keep required error fatal")
	}
	if err := app.requiredScanError(domain.ScanProfile{BestEffort: true}, nil); err != nil {
		t.Fatalf("expected nil required error to stay nil, got %v", err)
	}
}

func TestApplyCompliancePresetOverridesProfileDefaults(t *testing.T) {
	app := &App{
		cfg:     config.Config{SandboxMode: string(domain.IsolationAuto)},
		lang:    i18n.EN,
		catalog: i18n.New(i18n.EN),
	}

	project := domain.Project{
		ID:             "prj-1",
		DisplayName:    "demo",
		DetectedStacks: []string{"javascript", "terraform", "docker"},
	}

	profile := app.applyCompliancePreset(project, domain.ScanProfile{
		Mode:         domain.ModeSafe,
		Coverage:     domain.CoveragePremium,
		SeverityGate: domain.SeverityHigh,
		PresetID:     domain.CompliancePresetPCIDSS,
	}, false, false, false, false, false, false, false)

	if profile.Mode != domain.ModeDeep {
		t.Fatalf("expected pci preset to switch mode to deep, got %s", profile.Mode)
	}
	if profile.Coverage != domain.CoverageFull {
		t.Fatalf("expected pci preset to switch coverage to full, got %s", profile.Coverage)
	}
	if profile.PolicyID != "pci-dss" {
		t.Fatalf("expected pci preset to set policy, got %s", profile.PolicyID)
	}
	if !slices.Contains(profile.Modules, "tfsec") || !slices.Contains(profile.Modules, "trivy-image") {
		t.Fatalf("expected pci preset to include infrastructure and image scanners, got %+v", profile.Modules)
	}
}

func TestBuildScheduledProfileAppliesPreset(t *testing.T) {
	app := &App{
		cfg:     config.Config{SandboxMode: string(domain.IsolationAuto)},
		lang:    i18n.EN,
		catalog: i18n.New(i18n.EN),
	}
	project := domain.Project{
		ID:             "prj-1",
		DisplayName:    "demo",
		DetectedStacks: []string{"javascript", "docker"},
	}

	profile := app.buildScheduledProfile(project, daemonOptions{
		PresetID: domain.CompliancePresetOWASPTop10,
	})
	if profile.PresetID != domain.CompliancePresetOWASPTop10 {
		t.Fatalf("expected scheduled profile to carry preset")
	}
	if profile.Mode != domain.ModeActive {
		t.Fatalf("expected OWASP preset to force active mode, got %s", profile.Mode)
	}
	if !slices.Contains(profile.Modules, "zaproxy") || !slices.Contains(profile.Modules, "nuclei") {
		t.Fatalf("expected OWASP scheduled profile to include DAST modules, got %+v", profile.Modules)
	}
}

func TestModuleStatusCounts(t *testing.T) {
	app := &App{
		lang:    i18n.EN,
		catalog: i18n.New(i18n.EN),
	}
	modules := []domain.ModuleResult{
		{Name: "semgrep", Status: domain.ModuleQueued, Summary: "Queued in scan worker pool."},
		{Name: "trivy", Status: domain.ModuleRunning, Summary: "Running in hardened sandbox."},
		{Name: "syft", Status: domain.ModuleCompleted},
		{Name: "gitleaks", Status: domain.ModuleFailed},
		{Name: "knip", Status: domain.ModuleSkipped},
	}

	queued, running, completed, failed, skipped := app.moduleStatusCounts(modules)
	if queued != 1 || running != 1 || completed != 1 || failed != 1 || skipped != 1 {
		t.Fatalf("unexpected module status counts: %d %d %d %d %d", queued, running, completed, failed, skipped)
	}
}

func TestModuleNarrativeCoversEnhancedBuiltins(t *testing.T) {
	app := &App{
		lang:    i18n.EN,
		catalog: i18n.New(i18n.EN),
	}

	for _, module := range []string{"surface-inventory", "script-audit"} {
		if got := app.moduleNarrative(module); got == "" || got == module {
			t.Fatalf("expected module narrative for %s, got %q", module, got)
		}
		if got := app.modulePhaseLabel(module); got == "" {
			t.Fatalf("expected module phase label for %s", module)
		}
	}
}

func TestMissionConsoleHelpersProduceSchematicAndCodeStream(t *testing.T) {
	app := &App{
		lang:    i18n.TR,
		catalog: i18n.New(i18n.TR),
	}

	summary := domain.NewScanSummary()
	summary.TotalFindings = 1
	summary.CountsBySeverity[domain.SeverityHigh] = 1

	console := &liveScanConsole{
		project: domain.Project{DisplayName: "demo"},
		profile: domain.ScanProfile{
			Mode:     domain.ModeSafe,
			Coverage: domain.CoverageCore,
			Modules:  []string{"surface-inventory", "script-audit", "secret-heuristics"},
		},
		run: domain.ScanRun{
			Summary: summary,
			ModuleResults: []domain.ModuleResult{
				{Name: "surface-inventory", Status: domain.ModuleCompleted, Summary: "Surface mapped."},
				{Name: "script-audit", Status: domain.ModuleRunning, Summary: "Auditing scripts."},
				{Name: "secret-heuristics", Status: domain.ModuleQueued, Summary: "Queued."},
			},
		},
		lastPhase:   app.catalog.T("scan_phase_attack_surface"),
		lastModule:  "script-audit",
		lastFinding: "Risky bootstrap command",
		telemetry:   []string{"[exec ] script-audit -> auditing scripts"},
	}

	if lines := app.missionLaneSchematicLines(console); len(lines) == 0 {
		t.Fatalf("expected lane schematic lines")
	}
	if lines := app.missionCoverageMatrixLines(console); len(lines) == 0 {
		t.Fatalf("expected coverage matrix lines")
	}
	if lines := app.missionCodeStreamLines(console); len(lines) == 0 {
		t.Fatalf("expected mission code stream lines")
	}
	if got := app.missionAgentThought(console); got == "" {
		t.Fatalf("expected mission agent thought")
	}
}

func TestNextReviewFindingPicksHighestSeverity(t *testing.T) {
	app := &App{}
	findings := []domain.Finding{
		{Fingerprint: "low", Severity: domain.SeverityLow, Title: "Low"},
		{Fingerprint: "critical", Severity: domain.SeverityCritical, Title: "Critical"},
		{Fingerprint: "high", Severity: domain.SeverityHigh, Title: "High"},
	}

	finding, ok := app.nextReviewFinding(findings)
	if !ok {
		t.Fatalf("expected next review finding")
	}
	if finding.Fingerprint != "critical" {
		t.Fatalf("expected critical finding, got %s", finding.Fingerprint)
	}
}

func TestNextReviewFindingUsesPriorityWhenAvailable(t *testing.T) {
	app := &App{}
	findings := []domain.Finding{
		{Fingerprint: "critical-low-priority", Severity: domain.SeverityCritical, Title: "EICAR test signature detected", Priority: 3.8},
		{Fingerprint: "high-top-priority", Severity: domain.SeverityHigh, Title: "Potential GitHub personal access token", Priority: 9.7},
	}

	finding, ok := app.nextReviewFinding(findings)
	if !ok {
		t.Fatalf("expected next review finding")
	}
	if finding.Fingerprint != "high-top-priority" {
		t.Fatalf("expected priority resolver to select high-top-priority, got %s", finding.Fingerprint)
	}
}

func TestScanDebriefActionLinesReflectOutcome(t *testing.T) {
	app := &App{
		lang:    i18n.EN,
		catalog: i18n.New(i18n.EN),
	}
	run := domain.ScanRun{ID: "run-1"}
	findings := []domain.Finding{{Fingerprint: "critical", Severity: domain.SeverityCritical, Title: "Critical"}}

	lines := app.scanDebriefActionLines(run, findings, nil)
	if len(lines) == 0 || !strings.Contains(strings.Join(lines, "\n"), "guided review") {
		t.Fatalf("expected review-oriented debrief actions, got %v", lines)
	}

	lines = app.scanDebriefActionLines(run, nil, fmt.Errorf("partial"))
	if len(lines) == 0 || !strings.Contains(strings.Join(lines, "\n"), "runtime doctor") {
		t.Fatalf("expected runtime-doctor debrief actions, got %v", lines)
	}
}

func TestConsoleDebriefReportLinesBuildActionableFixPlan(t *testing.T) {
	app := &App{
		lang:    i18n.EN,
		catalog: i18n.New(i18n.EN),
	}
	run := domain.ScanRun{
		ID:     "run-22",
		Status: domain.ScanCompleted,
		Summary: domain.ScanSummary{
			TotalFindings: 2,
			CountsBySeverity: map[domain.Severity]int{
				domain.SeverityCritical: 1,
				domain.SeverityHigh:     1,
			},
		},
		ModuleResults: []domain.ModuleResult{
			{Name: "semgrep", Status: domain.ModuleCompleted, Summary: "Semantic rules completed.", FindingCount: 1},
			{Name: "gitleaks", Status: domain.ModuleFailed, Summary: "Binary is missing from the runtime path."},
			{Name: "trivy", Status: domain.ModuleSkipped, Summary: "Supply-chain lane deferred."},
		},
	}
	findings := []domain.Finding{
		{Fingerprint: "fp-critical", Severity: domain.SeverityCritical, Title: "Deploy token is committed", Module: "gitleaks"},
		{Fingerprint: "fp-high", Severity: domain.SeverityHigh, Title: "Unsafe eval path remains reachable", Module: "semgrep"},
	}

	lines := app.consoleDebriefReportLines(run, findings, fmt.Errorf("partial"))
	report := strings.Join(lines, "\n")
	for _, fragment := range []string{
		app.catalog.T("scan_outcome_title"),
		app.catalog.T("scan_report_blockers_title"),
		app.catalog.T("scan_report_fix_plan_title"),
		app.catalog.T("scan_report_first_step_title"),
		app.catalog.T("scan_spotlight_title"),
		"Deploy token is committed",
		"GITLEAKS",
	} {
		if !strings.Contains(report, fragment) {
			t.Fatalf("expected debrief report to contain %q, got %q", fragment, report)
		}
	}
}

func TestSelectRuntimeReleaseBundlesAndVerificationPolicy(t *testing.T) {
	bundles := []domain.RuntimeReleaseBundle{
		{
			Version: "v1.0.0",
			Signed:  false,
			Verification: domain.RuntimeVerification{
				ChecksumConfigured: true,
				ChecksumVerified:   true,
			},
			Attested: true,
			AttestationVerification: domain.RuntimeVerification{
				ChecksumConfigured: true,
				ChecksumVerified:   true,
			},
			ExternalAttested: true,
			ExternalAttestationVerification: domain.RuntimeVerification{
				ChecksumConfigured: true,
				ChecksumVerified:   true,
			},
		},
		{
			Version: "v1.0.1",
			Signed:  true,
			Verification: domain.RuntimeVerification{
				ChecksumConfigured:  true,
				ChecksumVerified:    true,
				SignatureConfigured: true,
				SignatureVerified:   true,
			},
			Attested: true,
			AttestationVerification: domain.RuntimeVerification{
				ChecksumConfigured:  true,
				ChecksumVerified:    true,
				SignatureConfigured: true,
				SignatureVerified:   true,
			},
			ExternalAttested: true,
			ExternalAttestationVerification: domain.RuntimeVerification{
				ChecksumConfigured: true,
				ChecksumVerified:   true,
			},
		},
	}

	selected, err := selectRuntimeReleaseBundles(bundles, "v1.0.1")
	if err != nil {
		t.Fatalf("expected version lookup to succeed: %v", err)
	}
	if len(selected) != 1 || selected[0].Version != "v1.0.1" {
		t.Fatalf("unexpected selected release bundles: %+v", selected)
	}
	if _, err := selectRuntimeReleaseBundles(nil, ""); err == nil || err.Error() != "runtime_release_none" {
		t.Fatalf("expected runtime_release_none error, got %v", err)
	}
	if _, err := selectRuntimeReleaseBundles(bundles, "v9.9.9"); err == nil || err.Error() != "runtime_release_not_found" {
		t.Fatalf("expected runtime_release_not_found error, got %v", err)
	}

	if issue := runtimeReleaseBundleIssue(bundles[0], true, true, false, false); issue == "" {
		t.Fatalf("expected unsigned bundle to fail when signature is required")
	}
	if issue := runtimeReleaseBundleIssue(bundles[0], false, true, false, false); issue != "" {
		t.Fatalf("expected unsigned checksum-verified bundle to pass when signature is optional, got %q", issue)
	}
	if issue := runtimeReleaseBundleIssue(bundles[1], true, true, false, false); issue != "" {
		t.Fatalf("expected signed verified bundle to pass, got %q", issue)
	}
	unsignedAttestation := bundles[0]
	unsignedAttestation.Attested = false
	if issue := runtimeReleaseBundleIssue(unsignedAttestation, false, true, false, false); issue == "" {
		t.Fatalf("expected missing attestation to fail when required")
	}
	dirtyBundle := bundles[1]
	dirtyBundle.Provenance.SourceDirty = true
	if issue := runtimeReleaseBundleIssue(dirtyBundle, true, true, false, true); issue == "" {
		t.Fatalf("expected dirty source to fail when clean source is required")
	}
	unsignedExternal := bundles[1]
	unsignedExternal.ExternalAttested = false
	if issue := runtimeReleaseBundleIssue(unsignedExternal, true, true, true, false); issue == "" {
		t.Fatalf("expected missing external attestation to fail when required")
	}
}
