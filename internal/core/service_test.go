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
	if index["network_probe"].Status != domain.RuntimeCheckPass {
		t.Fatalf("expected network probe to pass, got %+v", index["network_probe"])
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
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("GITHUB_TOKEN=ghp_123456789012345678901234567890123456\n"), 0o644); err != nil {
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
