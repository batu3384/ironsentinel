package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/batu3384/ironsentinel/internal/domain"
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
	if !strings.Contains(report, app.catalog.T("overview_next_steps")) {
		t.Fatalf("expected plain run summary to include next steps\n%s", report)
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
