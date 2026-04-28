package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/batu3384/ironsentinel/internal/domain"
	"github.com/batu3384/ironsentinel/internal/i18n"
)

func TestPtermSprintfStripsMarkupWhenNoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	app := &App{}
	rendered := app.ptermSprintf("%s [cyan]%d[-]", "ready", 3)

	if rendered != "ready 3" {
		t.Fatalf("expected plain text without markup, got %q", rendered)
	}
}

func TestOverviewPlainReportUsesLaunchMissionDebriefHierarchy(t *testing.T) {
	app, _, _, _ := newFocusedRunFilterFixture(t)

	report := app.overviewPlainReport(app.buildPortfolioSnapshot())

	launch := app.catalog.T("console_stage_launch") + ":"
	mission := app.catalog.T("console_stage_mission") + ":"
	debrief := app.catalog.T("console_stage_debrief") + ":"
	for _, heading := range []string{launch, mission, debrief} {
		if !strings.Contains(report, heading) {
			t.Fatalf("expected plain overview report to include %q\n%s", heading, report)
		}
	}
	if strings.Index(report, launch) >= strings.Index(report, mission) || strings.Index(report, mission) >= strings.Index(report, debrief) {
		t.Fatalf("expected plain overview report to preserve launch -> mission -> debrief order\n%s", report)
	}
}

func TestRuntimePlainReportUsesLaunchMissionDebriefHierarchy(t *testing.T) {
	app, _ := newTestTUIApp(t)

	report := app.runtimePlainReport(app.runtimeStatus(false))

	launch := app.catalog.T("console_stage_launch") + ":"
	mission := app.catalog.T("console_stage_mission") + ":"
	debrief := app.catalog.T("console_stage_debrief") + ":"
	for _, heading := range []string{launch, mission, debrief} {
		if !strings.Contains(report, heading) {
			t.Fatalf("expected plain runtime report to include %q\n%s", heading, report)
		}
	}
	if strings.Index(report, launch) >= strings.Index(report, mission) || strings.Index(report, mission) >= strings.Index(report, debrief) {
		t.Fatalf("expected plain runtime report to preserve launch -> mission -> debrief order\n%s", report)
	}
}

func TestPlainRunSummaryUsesDebriefOrder(t *testing.T) {
	app, project := newTestTUIApp(t)
	run := domain.ScanRun{
		ID:        "run-1",
		ProjectID: project.ID,
		Status:    domain.ScanCompleted,
		Profile: domain.ScanProfile{
			Mode: domain.ModeSafe,
		},
		StartedAt: time.Unix(1_763_000_000, 0).UTC(),
		Summary: domain.ScanSummary{
			TotalFindings: 1,
		},
	}
	report := app.renderPlainRunSummary(run, &project, []domain.Finding{{
		Fingerprint: "fp-1",
		Severity:    domain.SeverityHigh,
		Title:       "Reachable issue",
	}})

	launch := app.catalog.T("console_stage_launch") + ":"
	mission := app.catalog.T("console_stage_mission") + ":"
	debrief := app.catalog.T("console_stage_debrief") + ":"
	for _, heading := range []string{launch, mission, debrief} {
		if !strings.Contains(report, heading) {
			t.Fatalf("expected plain run summary to include %q\n%s", heading, report)
		}
	}
	if strings.Index(report, launch) >= strings.Index(report, mission) || strings.Index(report, mission) >= strings.Index(report, debrief) {
		t.Fatalf("expected plain run summary to preserve launch -> mission -> debrief order\n%s", report)
	}
	if !strings.Contains(report, app.catalog.T("scan_report_fix_plan_title")) {
		t.Fatalf("expected plain run summary to include fix plan\n%s", report)
	}
}

func TestRenderRunSummaryPlainUsesWatchActionForRunningRun(t *testing.T) {
	app, project := newTestTUIApp(t)
	app.uiMode = uiModePlain
	run := domain.ScanRun{
		ID:        "run-watch",
		ProjectID: project.ID,
		Status:    domain.ScanRunning,
		Profile: domain.ScanProfile{
			Mode: domain.ModeSafe,
		},
		StartedAt: time.Unix(1_763_000_000, 0).UTC(),
	}

	output := captureCLIStdout(t, func() error {
		app.renderRunSummary(run, &project, nil)
		return nil
	})

	if !strings.Contains(output, app.commandHint("runs", "watch", run.ID)) {
		t.Fatalf("expected running plain summary to point to runs watch\n%s", output)
	}
}

func TestRenderRunSummaryPlainUsesDoctorActionForPartialRun(t *testing.T) {
	app, project := newTestTUIApp(t)
	app.uiMode = uiModePlain
	run := domain.ScanRun{
		ID:        "run-partial",
		ProjectID: project.ID,
		Status:    domain.ScanCompleted,
		Profile: domain.ScanProfile{
			Mode:    domain.ModeSafe,
			Modules: []string{"semgrep"},
		},
		StartedAt: time.Unix(1_763_000_000, 0).UTC(),
		ModuleResults: []domain.ModuleResult{
			{Name: "semgrep", Status: domain.ModuleFailed, Summary: "Execution failed."},
		},
	}

	output := captureCLIStdout(t, func() error {
		app.renderRunSummary(run, &project, nil)
		return nil
	})

	if !strings.Contains(output, app.catalog.T("scan_debrief_action_doctor")) {
		t.Fatalf("expected partial plain summary to point to runtime doctor\n%s", output)
	}
}

func TestPlainDebriefSurfacesDoNotLeakPtermMarkup(t *testing.T) {
	app, project := newTestTUIApp(t)
	app.uiMode = uiModePlain
	run := domain.ScanRun{
		ID:        "run-debrief",
		ProjectID: project.ID,
		Status:    domain.ScanCompleted,
		Profile: domain.ScanProfile{
			Mode:     domain.ModeSafe,
			Coverage: domain.CoverageCore,
		},
		StartedAt: time.Unix(1_763_000_000, 0).UTC(),
		Summary: domain.ScanSummary{
			TotalFindings: 1,
			CountsBySeverity: map[domain.Severity]int{
				domain.SeverityCritical: 1,
			},
		},
		ModuleResults: []domain.ModuleResult{
			{Name: "secret-heuristics", Status: domain.ModuleCompleted},
		},
	}
	findings := []domain.Finding{{
		Fingerprint: "fp-1",
		Severity:    domain.SeverityCritical,
		Category:    domain.CategorySecret,
		Module:      "secret-heuristics",
		Title:       "Potential GitHub personal access token",
		Location:    ".env",
		RuleID:      "secret.github_pat",
	}}

	output := captureCLIStdout(t, func() error {
		app.renderMissionDebrief(project, run, findings, nil)
		app.renderFindingSpotlight(findings, 1)
		app.renderAnalystHandoff(run, findings, nil)
		return nil
	})

	if strings.Contains(output, "[cyan]") || strings.Contains(output, "[-]") {
		t.Fatalf("expected plain debrief surfaces to strip pterm markup\n%s", output)
	}
}

func TestShellSafeLiveTrackerUsesPlainProgressWithoutCarriageReturns(t *testing.T) {
	app, project := newTestTUIApp(t)
	app.lang = i18n.TR
	app.catalog = i18n.New(i18n.TR)

	originalTerminalIsTerminal := terminalIsTerminal
	terminalIsTerminal = func(int) bool { return false }
	t.Cleanup(func() {
		terminalIsTerminal = originalTerminalIsTerminal
	})

	output := captureCLIStdout(t, func() error {
		tracker := app.startLiveScanTracker(project, domain.ScanProfile{
			Mode:     domain.ModeSafe,
			Coverage: domain.CoverageCore,
			Modules:  []string{"surface-inventory", "secret-heuristics"},
		})
		app.updateLiveScanTracker(tracker, domain.StreamEvent{
			Type: "module.updated",
			Module: &domain.ModuleResult{
				Name:   "surface-inventory",
				Status: domain.ModuleCompleted,
			},
		})
		return nil
	})

	if strings.Contains(output, "\r") {
		t.Fatalf("expected shell-safe tracker to avoid carriage-return spinner artifacts\n%q", output)
	}
	if !strings.Contains(output, "%") {
		t.Fatalf("expected shell-safe tracker to emit percent progress\n%s", output)
	}
}

func TestRuntimeDoctorPlainModeUsesLogSafeOutputWithoutMascotHero(t *testing.T) {
	app, _ := newTestTUIApp(t)
	app.uiMode = uiModePlain
	app.lang = i18n.TR
	app.catalog = i18n.New(i18n.TR)

	output := captureCLIStdout(t, func() error {
		app.renderRuntimeDoctor(domain.RuntimeDoctor{
			Mode:             domain.ModeSafe,
			StrictVersions:   true,
			RequireIntegrity: true,
			Ready:            false,
			Required: []domain.RuntimeTool{
				{Name: "checkov", ExpectedVersion: "3.2.0"},
				{Name: "syft", ExpectedVersion: "1.42.0", ActualVersion: "1.40.0", Available: true},
			},
			Missing: []domain.RuntimeTool{
				{Name: "checkov", ExpectedVersion: "3.2.0"},
			},
			Outdated: []domain.RuntimeTool{
				{Name: "syft", ExpectedVersion: "1.42.0", ActualVersion: "1.40.0", Available: true},
			},
			Checks: []domain.RuntimeDoctorCheck{
				{Name: "state-store", Status: "pass", Summary: "state store writable"},
			},
		})
		return nil
	})

	for _, forbidden := range []string{"SCOUT", "WARDEN", "IRONSENTINEL", "[cyan]", "╭"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("expected plain runtime doctor to avoid mascot/hero/styled chrome %q\n%s", forbidden, output)
		}
	}
	for _, want := range []string{app.catalog.T("runtime_doctor_title"), "Mod", "Eksik", "checkov", "syft", app.catalog.T("overview_next_steps")} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected plain runtime doctor to contain %q\n%s", want, output)
		}
	}
	for _, tool := range []string{"checkov", "syft"} {
		if count := strings.Count(output, "- "+tool+" |"); count != 1 {
			t.Fatalf("expected %s to be listed once, got %d\n%s", tool, count, output)
		}
	}
}

func TestRenderStreamEventLocalizesFindingTitle(t *testing.T) {
	app, _ := newTestTUIApp(t)
	app.lang = i18n.TR
	app.catalog = i18n.New(i18n.TR)

	output := captureCLIStdout(t, func() error {
		app.renderStreamEvent(domain.StreamEvent{
			Type: "finding.created",
			Finding: &domain.Finding{
				RuleID: "secret.github_pat",
				Title:  "Potential GitHub personal access token",
			},
		})
		return nil
	})

	if strings.Contains(output, "Potential GitHub personal access token") {
		t.Fatalf("expected stream event not to leak raw scanner title\n%s", output)
	}
	if !strings.Contains(output, "GitHub kişisel erişim belirteci olasılığı") {
		t.Fatalf("expected stream event to localize finding title\n%s", output)
	}
}

func TestPlainRunSummaryIncludesSeverityBreakdownAndModuleOutcomeSummary(t *testing.T) {
	app, project := newTestTUIApp(t)
	app.lang = i18n.TR
	app.catalog = i18n.New(i18n.TR)

	run := domain.ScanRun{
		ID:        "run-rich-debrief",
		ProjectID: project.ID,
		Status:    domain.ScanCompleted,
		Profile: domain.ScanProfile{
			Mode: domain.ModeSafe,
		},
		StartedAt: time.Unix(1_763_000_000, 0).UTC(),
		Summary: domain.ScanSummary{
			TotalFindings: 2,
			CountsBySeverity: map[domain.Severity]int{
				domain.SeverityCritical: 1,
				domain.SeverityHigh:     1,
			},
		},
		ModuleResults: []domain.ModuleResult{
			{Name: "semgrep", Status: domain.ModuleFailed},
			{Name: "grype", Status: domain.ModuleSkipped},
			{Name: "syft", Status: domain.ModuleCompleted},
		},
	}

	report := app.renderPlainRunSummary(run, &project, []domain.Finding{
		{Fingerprint: "fp-1", Severity: domain.SeverityCritical, Priority: 5.5, Title: "Potential GitHub personal access token"},
		{Fingerprint: "fp-2", Severity: domain.SeverityHigh, Priority: 4.5, Title: "Reachable supply-chain issue"},
	})

	for _, expected := range []string{"KRİTİK 1", "YÜKSEK 1", "SEMGREP", "GRYPE", app.catalog.T("scan_report_blockers_title")} {
		if !strings.Contains(report, expected) {
			t.Fatalf("expected plain run summary to include %q\n%s", expected, report)
		}
	}
}

func TestDebriefSeverityBreakdownUsesNoFindingsCopyWhenEmpty(t *testing.T) {
	app := &App{
		lang:    i18n.TR,
		catalog: i18n.New(i18n.TR),
	}

	label := app.debriefSeverityBreakdown(domain.ScanRun{Summary: domain.ScanSummary{CountsBySeverity: map[domain.Severity]int{}}})
	if label != "Doğrulanmış bulgu yok" {
		t.Fatalf("expected empty debrief severity summary to use no-findings copy, got %q", label)
	}
}

func TestRenderRunDetailsPlainStaysSingleSurface(t *testing.T) {
	app, run, _, _ := newFocusedRunFilterFixture(t)
	app.uiMode = uiModePlain

	output := captureCLIStdout(t, func() error {
		return app.renderRunDetails(run.ID)
	})

	for _, forbidden := range []string{
		app.catalog.T("execution_timeline_title"),
		app.catalog.T("artifacts_title"),
		app.catalog.T("findings_queue_title"),
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("expected plain run details to stay on single debrief surface, found %q\n%s", forbidden, output)
		}
	}
	if !strings.Contains(output, app.catalog.T("console_stage_debrief")+":") {
		t.Fatalf("expected plain run details to include debrief stage\n%s", output)
	}
}

func TestRenderRunWatchFramePlainStaysSingleSurface(t *testing.T) {
	app, run, _, _ := newFocusedRunFilterFixture(t)
	app.uiMode = uiModePlain

	output := captureCLIStdout(t, func() error {
		return app.renderRunWatchFrame(run.ID, 5*time.Second)
	})

	for _, forbidden := range []string{
		app.catalog.T("execution_timeline_title"),
		app.catalog.T("module_queued_count"),
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("expected plain run watch output to avoid legacy sections, found %q\n%s", forbidden, output)
		}
	}
	if !strings.Contains(output, app.catalog.T("console_stage_mission")+":") {
		t.Fatalf("expected plain run watch output to include mission stage\n%s", output)
	}
}
