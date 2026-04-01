package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pterm/pterm"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
	"github.com/batu3384/ironsentinel/internal/i18n"
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

func TestPreviewPersistentFlagValuesParsesLangAndUIMode(t *testing.T) {
	lang, mode := previewPersistentFlagValues([]string{"scan", "--lang", "tr", "--ui-mode=compact"})
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
