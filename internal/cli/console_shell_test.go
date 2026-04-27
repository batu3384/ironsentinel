package cli

import (
	"context"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/core"
	"github.com/batu3384/ironsentinel/internal/domain"
	"github.com/batu3384/ironsentinel/internal/i18n"
)

func TestConsoleShellLaunchViewShowsPrimaryActionAndSelectedTarget(t *testing.T) {
	app, project := newTestTUIApp(t)

	model := newConsoleShellModel(app, consoleShellLaunchState{
		SelectedProjectID: project.ID,
	}, context.Background())

	if model.stage != consoleStageLaunch {
		t.Fatalf("expected console shell to start in launch stage, got %v", model.stage)
	}
	if model.drawer != consoleDrawerNone {
		t.Fatalf("expected console shell to start with no drawer, got %v", model.drawer)
	}

	view := model.View()
	for _, fragment := range []string{
		app.catalog.T("console_title"),
		app.catalog.T("console_launch_subtitle"),
		app.catalog.T("console_launch_hint"),
		app.catalog.T("console_launch_target_label"),
		app.catalog.T("console_launch_readiness_ready"),
		app.catalog.T("console_launch_primary_action"),
		project.DisplayName,
		app.catalog.T("console_launch_plan_title"),
		app.catalog.T("scan_mode"),
		app.modeLabel(domain.ModeSafe),
		app.catalog.T("coverage_profile"),
		app.coverageLabel(domain.CoveragePremium),
		app.catalog.T("scan_modules"),
		"stack-detector",
		app.catalog.T("console_launch_mode_impact_title"),
		app.catalog.T("console_launch_best_effort_impact"),
		app.catalog.T("console_launch_strict_impact"),
	} {
		if !strings.Contains(view, fragment) {
			t.Fatalf("expected launch view to contain %q, got %q", fragment, view)
		}
	}
	for _, fragment := range []string{
		app.catalog.T("app_route_home"),
		app.catalog.T("app_route_scan_review"),
		app.catalog.T("app_route_live_scan"),
		app.catalog.T("console_launch_advanced_hint"),
	} {
		if strings.Contains(view, fragment) {
			t.Fatalf("expected route-first copy %q to be absent, got %q", fragment, view)
		}
	}
}

func TestLaunchTUIStartsDefaultQuickPathWhenProjectSelected(t *testing.T) {
	app, project := newTestTUIApp(t)

	originalRunTeaProgram := runTeaProgram
	t.Cleanup(func() {
		runTeaProgram = originalRunTeaProgram
	})

	var calls []tea.Model
	runTeaProgram = func(model tea.Model, opts ...tea.ProgramOption) (tea.Model, error) {
		calls = append(calls, model)
		switch typed := model.(type) {
		case consoleShellModel:
			updated, _ := typed.Update(tea.KeyMsg{Type: tea.KeyEnter})
			return updated, nil
		default:
			return model, nil
		}
	}

	if err := app.launchTUI(context.Background()); err != nil {
		t.Fatalf("launch tui: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected launch tui to stay inside console shell for quick path, got %d call(s)", len(calls))
	}
	console, ok := calls[0].(consoleShellModel)
	if !ok {
		t.Fatalf("expected first program run to use console shell, got %T", calls[0])
	}
	if console.launch.SelectedProjectID != project.ID {
		t.Fatalf("expected console shell to select project %s, got %s", project.ID, console.launch.SelectedProjectID)
	}
}

func TestLaunchTUIShowsSingleConsoleNotRouteShell(t *testing.T) {
	app, project := newTestTUIApp(t)

	originalRunTeaProgram := runTeaProgram
	t.Cleanup(func() {
		runTeaProgram = originalRunTeaProgram
	})

	var calls []tea.Model
	runTeaProgram = func(model tea.Model, opts ...tea.ProgramOption) (tea.Model, error) {
		calls = append(calls, model)
		switch typed := model.(type) {
		case consoleShellModel:
			updated, _ := typed.Update(tea.KeyMsg{Type: tea.KeyEnter})
			return updated, nil
		default:
			return model, nil
		}
	}

	if err := app.launchTUI(context.Background()); err != nil {
		t.Fatalf("launch tui: %v", err)
	}
	if got := app.primaryTUIModelName(); got != "console_shell" {
		t.Fatalf("expected primary TUI model name console_shell, got %q", got)
	}
	if len(calls) != 1 {
		t.Fatalf("expected launch tui to run a single primary model, got %d call(s)", len(calls))
	}
	if _, ok := calls[0].(consoleShellModel); !ok {
		t.Fatalf("expected launch tui to boot console shell, got %T", calls[0])
	}
	if _, ok := calls[0].(appShellModel); ok {
		t.Fatalf("expected launch tui to avoid booting legacy route shell")
	}
	console := calls[0].(consoleShellModel)
	if console.launch.SelectedProjectID != project.ID {
		t.Fatalf("expected console shell to preserve selected project %s, got %s", project.ID, console.launch.SelectedProjectID)
	}
}

func TestLegacyRouteShellIsNotPrimaryPathAnymore(t *testing.T) {
	app, project := newTestTUIApp(t)

	if got := app.primaryTUIModelName(); got != "console_shell" {
		t.Fatalf("expected primary TUI model name console_shell, got %q", got)
	}

	originalRunTeaProgram := runTeaProgram
	t.Cleanup(func() {
		runTeaProgram = originalRunTeaProgram
	})

	var calls []tea.Model
	runTeaProgram = func(model tea.Model, opts ...tea.ProgramOption) (tea.Model, error) {
		calls = append(calls, model)
		return model, nil
	}

	if err := app.launchTUIWithState(context.Background(), appShellLaunchState{
		Route:             appRouteScanReview,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	}); err != nil {
		t.Fatalf("launch legacy tui with state: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected explicit compatibility path to run once, got %d call(s)", len(calls))
	}
	if _, ok := calls[0].(appShellModel); !ok {
		t.Fatalf("expected explicit compatibility path to boot legacy route shell, got %T", calls[0])
	}
}

func TestLaunchTUIDoesNotHandOffToLegacyRouteFirstPathOnAKey(t *testing.T) {
	app, project := newTestTUIApp(t)

	originalRunTeaProgram := runTeaProgram
	t.Cleanup(func() {
		runTeaProgram = originalRunTeaProgram
	})

	var calls []tea.Model
	runTeaProgram = func(model tea.Model, opts ...tea.ProgramOption) (tea.Model, error) {
		calls = append(calls, model)
		switch typed := model.(type) {
		case consoleShellModel:
			updated, _ := typed.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
			return updated, nil
		case appShellModel:
			return model, nil
		default:
			return model, nil
		}
	}

	if err := app.launchTUI(context.Background()); err != nil {
		t.Fatalf("launch tui: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected launch tui to stay in the console shell, got %d call(s)", len(calls))
	}
	console, ok := calls[0].(consoleShellModel)
	if !ok {
		t.Fatalf("expected primary program run to use console shell, got %T", calls[0])
	}
	if console.stage != consoleStageLaunch {
		t.Fatalf("expected advanced key to keep console shell on launch stage, got %v", console.stage)
	}
	if console.launch.SelectedProjectID != project.ID {
		t.Fatalf("expected advanced key to preserve selected project %s, got %s", project.ID, console.launch.SelectedProjectID)
	}
}

func TestLaunchTUIKeepsNoProjectLaunchInsideConsoleShell(t *testing.T) {
	app := newEmptyTUIApp(t)

	originalRunTeaProgram := runTeaProgram
	t.Cleanup(func() {
		runTeaProgram = originalRunTeaProgram
	})

	var calls []tea.Model
	runTeaProgram = func(model tea.Model, opts ...tea.ProgramOption) (tea.Model, error) {
		calls = append(calls, model)
		switch typed := model.(type) {
		case consoleShellModel:
			updated, _ := typed.Update(tea.KeyMsg{Type: tea.KeyEnter})
			return updated, nil
		case appShellModel:
			return model, nil
		default:
			return model, nil
		}
	}

	if err := app.launchTUI(context.Background()); err != nil {
		t.Fatalf("launch tui: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected launch tui to stay in console shell without a project, got %d call(s)", len(calls))
	}
	console, ok := calls[0].(consoleShellModel)
	if !ok {
		t.Fatalf("expected first program run to use console shell, got %T", calls[0])
	}
	if console.launch.SelectedProjectID != "" {
		t.Fatalf("expected no-project launch to stay waiting, got %s", console.launch.SelectedProjectID)
	}
	if console.stage != consoleStageLaunch {
		t.Fatalf("expected no-project Enter to stay on launch stage, got %v", console.stage)
	}
}

func TestConsoleShellLaunchViewWaitsForTargetWithoutProject(t *testing.T) {
	app := newEmptyTUIApp(t)

	model := newConsoleShellModel(app, consoleShellLaunchState{}, context.Background())
	if model.launch.SelectedProjectID != "" {
		t.Fatalf("expected no-project launch to stay waiting, got %s", model.launch.SelectedProjectID)
	}

	view := model.View()
	for _, fragment := range []string{
		app.catalog.T("console_launch_target_empty"),
		app.catalog.T("console_launch_readiness_waiting"),
		app.catalog.T("console_launch_primary_action"),
	} {
		if !strings.Contains(view, fragment) {
			t.Fatalf("expected waiting view to contain %q, got %q", fragment, view)
		}
	}
}

func TestConsoleShellMissionViewShowsRunningStatePhaseAndTool(t *testing.T) {
	app, project := newTestTUIApp(t)
	profile := domain.ScanProfile{
		Mode:         domain.ModeSafe,
		Coverage:     domain.CoverageCore,
		Modules:      []string{"surface-inventory", "semgrep"},
		SeverityGate: domain.SeverityHigh,
		Isolation:    domain.IsolationAuto,
	}

	model := newConsoleShellModel(app, consoleShellLaunchState{
		SelectedProjectID: project.ID,
	}, context.Background())
	model.stage = consoleStageMission
	model.width = 160
	model.height = 44
	model.mission = consoleShellMissionState{
		project:    project,
		profile:    profile,
		doctor:     app.runtimeDoctor(profile, false, false),
		launchedAt: time.Unix(1_763_000_000, 0).UTC(),
		running:    true,
		console: &liveScanConsole{
			project:    project,
			profile:    profile,
			frame:      4,
			lastEvent:  "Semgrep semantic rules are traversing the source graph.",
			lastStatus: string(domain.ScanRunning),
			lastPhase:  app.catalog.T("scan_phase_code"),
			lastModule: "semgrep",
			lastTool:   "semgrep",
			telemetry: []string{
				"Queued semantic analysis lane.",
				"Promoted semgrep to active execution.",
			},
			run: domain.ScanRun{
				Status: domain.ScanRunning,
				Summary: domain.ScanSummary{
					TotalFindings: 1,
					CountsBySeverity: map[domain.Severity]int{
						domain.SeverityHigh: 1,
					},
				},
				ModuleResults: []domain.ModuleResult{
					{Name: "surface-inventory", Status: domain.ModuleCompleted, Summary: "Mapped repository exposure."},
					{Name: "semgrep", Status: domain.ModuleRunning, Summary: "Correlating semantic rules."},
				},
			},
		},
		run: domain.ScanRun{
			Status: domain.ScanRunning,
			Summary: domain.ScanSummary{
				TotalFindings: 1,
				CountsBySeverity: map[domain.Severity]int{
					domain.SeverityHigh: 1,
				},
			},
			ModuleResults: []domain.ModuleResult{
				{Name: "surface-inventory", Status: domain.ModuleCompleted, Summary: "Mapped repository exposure."},
				{Name: "semgrep", Status: domain.ModuleRunning, Summary: "Correlating semantic rules."},
			},
		},
	}

	view := model.View()
	for _, fragment := range []string{
		app.catalog.T("status"),
		strings.ToUpper(string(domain.ScanRunning)),
		app.catalog.T("scan_mc_progress"),
		"50%",
		app.catalog.T("app_label_target"),
		project.LocationHint,
		app.phaseLabel(),
		app.catalog.T("scan_phase_code"),
		app.catalog.T("app_label_module"),
		"SEMGREP",
		app.toolLabel(),
		strings.ToUpper("semgrep"),
		app.catalog.T("scan_mc_activity"),
		"Semgrep semantic rules are traversing the source graph.",
	} {
		if !strings.Contains(view, fragment) {
			t.Fatalf("expected mission view to contain %q, got %q", fragment, view)
		}
	}
}

func TestConsoleShellMissionViewLocalizesTurkishLabelsAndStatuses(t *testing.T) {
	app, project := newTestTUIApp(t)
	app.lang = i18n.TR
	app.catalog = i18n.New(i18n.TR)
	profile := domain.ScanProfile{
		Mode:         domain.ModeSafe,
		Coverage:     domain.CoverageCore,
		Modules:      []string{"surface-inventory"},
		SeverityGate: domain.SeverityHigh,
		Isolation:    domain.IsolationAuto,
	}

	model := newConsoleShellModel(app, consoleShellLaunchState{
		SelectedProjectID: project.ID,
	}, context.Background())
	model.stage = consoleStageMission
	model.width = 160
	model.height = 44
	model.mission = consoleShellMissionState{
		project:    project,
		profile:    profile,
		doctor:     app.runtimeDoctor(profile, false, false),
		launchedAt: time.Unix(1_763_000_000, 0).UTC(),
		running:    true,
		console: &liveScanConsole{
			project:    project,
			profile:    profile,
			frame:      2,
			lastEvent:  "Yerleşik analiz depo yüzeyini tarıyor.",
			lastStatus: string(domain.ScanRunning),
			lastPhase:  app.catalog.T("scan_phase_attack_surface"),
			lastModule: "surface-inventory",
			lastTool:   app.moduleToolLabel("surface-inventory"),
			run: domain.ScanRun{
				Status: domain.ScanRunning,
				ModuleResults: []domain.ModuleResult{
					{Name: "surface-inventory", Status: domain.ModuleRunning, Summary: "Depo maruziyeti haritalanıyor."},
				},
			},
		},
		run: domain.ScanRun{
			Status: domain.ScanRunning,
			ModuleResults: []domain.ModuleResult{
				{Name: "surface-inventory", Status: domain.ModuleRunning, Summary: "Depo maruziyeti haritalanıyor."},
			},
		},
	}

	view := model.View()
	for _, fragment := range []string{
		"Aşama",
		"Araç",
		"Modül",
		"ÇALIŞIYOR",
		"OTOMATİK",
		"YERLEŞİK ANALİZ",
		"Görev",
	} {
		if !strings.Contains(view, fragment) {
			t.Fatalf("expected Turkish mission view to contain %q, got %q", fragment, view)
		}
	}
	for _, fragment := range []string{"RUNNING", "AUTO", "Arac", "Asama", "Gorev"} {
		if strings.Contains(view, fragment) {
			t.Fatalf("expected Turkish mission view to avoid raw token %q, got %q", fragment, view)
		}
	}
}

func TestConsoleShellMissionViewDoesNotRenderRouteRibbon(t *testing.T) {
	app, project := newTestTUIApp(t)
	profile := domain.ScanProfile{
		Mode:         domain.ModeSafe,
		Coverage:     domain.CoverageCore,
		Modules:      []string{"surface-inventory"},
		SeverityGate: domain.SeverityHigh,
		Isolation:    domain.IsolationAuto,
	}

	model := newConsoleShellModel(app, consoleShellLaunchState{
		SelectedProjectID: project.ID,
	}, context.Background())
	model.stage = consoleStageMission
	model.width = 160
	model.height = 44
	model.mission = consoleShellMissionState{
		project:    project,
		profile:    profile,
		doctor:     app.runtimeDoctor(profile, false, false),
		launchedAt: time.Unix(1_763_000_000, 0).UTC(),
		running:    true,
		console: &liveScanConsole{
			project:    project,
			profile:    profile,
			lastStatus: string(domain.ScanRunning),
			lastPhase:  app.catalog.T("scan_phase_attack_surface"),
			lastModule: "surface-inventory",
			lastTool:   app.moduleToolLabel("surface-inventory"),
			lastEvent:  "Repository surface inventory is building the target graph.",
			run: domain.ScanRun{
				Status: domain.ScanRunning,
				ModuleResults: []domain.ModuleResult{
					{Name: "surface-inventory", Status: domain.ModuleRunning},
				},
			},
		},
		run: domain.ScanRun{
			Status: domain.ScanRunning,
			ModuleResults: []domain.ModuleResult{
				{Name: "surface-inventory", Status: domain.ModuleRunning},
			},
		},
	}

	view := model.View()
	for _, fragment := range []string{
		app.catalog.T("app_route_home"),
		app.catalog.T("app_route_scan_review"),
		app.catalog.T("app_route_live_scan"),
	} {
		if strings.Contains(view, fragment) {
			t.Fatalf("expected mission view to omit route ribbon copy %q, got %q", fragment, view)
		}
	}
}

func TestConsoleShellEnterTransitionsToMissionAndStartsQuickScan(t *testing.T) {
	app, project := newTestTUIApp(t)

	originalStartConsoleShellMission := startConsoleShellMission
	t.Cleanup(func() {
		startConsoleShellMission = originalStartConsoleShellMission
	})

	var startedProject domain.Project
	var startedProfile domain.ScanProfile
	startConsoleShellMission = func(app *App, ctx context.Context, project domain.Project, profile domain.ScanProfile, seq int) consoleShellMissionSession {
		startedProject = project
		startedProfile = profile
		return consoleShellMissionSession{
			cancel:  func() {},
			eventCh: make(chan domain.StreamEvent),
			doneCh:  make(chan scanMissionDoneMsg),
		}
	}

	model := newConsoleShellModel(app, consoleShellLaunchState{
		SelectedProjectID: project.ID,
	}, context.Background())

	updated, cmd := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	next := updated.(consoleShellModel)

	if next.stage != consoleStageMission {
		t.Fatalf("expected Enter to transition to mission stage, got %v", next.stage)
	}
	if !next.mission.running {
		t.Fatalf("expected Enter to start mission state")
	}
	if next.mission.project.ID != project.ID {
		t.Fatalf("expected mission project %s, got %s", project.ID, next.mission.project.ID)
	}
	expectedProfile := app.quickScanProfile(project)
	if startedProject.ID != project.ID {
		t.Fatalf("expected mission starter to receive project %s, got %s", project.ID, startedProject.ID)
	}
	if startedProfile.Mode != expectedProfile.Mode || startedProfile.Coverage != expectedProfile.Coverage {
		t.Fatalf("expected quick scan profile %+v, got %+v", expectedProfile, startedProfile)
	}
	if len(startedProfile.Modules) != len(expectedProfile.Modules) {
		t.Fatalf("expected quick scan modules %v, got %v", expectedProfile.Modules, startedProfile.Modules)
	}
	if cmd == nil {
		t.Fatalf("expected mission start to return async command")
	}
}

func TestConsoleShellEnterSeedsMissionStatusBeforeFirstEvent(t *testing.T) {
	app, project := newTestTUIApp(t)

	originalStartConsoleShellMission := startConsoleShellMission
	t.Cleanup(func() {
		startConsoleShellMission = originalStartConsoleShellMission
	})
	startConsoleShellMission = func(app *App, ctx context.Context, project domain.Project, profile domain.ScanProfile, seq int) consoleShellMissionSession {
		return consoleShellMissionSession{
			cancel:  func() {},
			eventCh: make(chan domain.StreamEvent),
			doneCh:  make(chan scanMissionDoneMsg),
		}
	}

	model := newConsoleShellModel(app, consoleShellLaunchState{
		SelectedProjectID: project.ID,
	}, context.Background())

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	next := updated.(consoleShellModel)

	firstModule := firstModuleName(next.mission.profile.Modules)
	if firstModule == "" {
		t.Fatalf("expected quick profile to include at least one module")
	}
	if next.mission.console.lastModule != firstModule {
		t.Fatalf("expected initial mission module %q, got %q", firstModule, next.mission.console.lastModule)
	}
	if next.mission.console.lastPhase != app.modulePhaseLabel(firstModule) {
		t.Fatalf("expected initial mission phase %q, got %q", app.modulePhaseLabel(firstModule), next.mission.console.lastPhase)
	}
	if next.mission.console.lastTool != app.moduleToolLabel(firstModule) {
		t.Fatalf("expected initial mission tool %q, got %q", app.moduleToolLabel(firstModule), next.mission.console.lastTool)
	}
	if next.mission.console.lastEvent == app.catalog.T("scan_mc_boot") || strings.TrimSpace(next.mission.console.lastEvent) == "" {
		t.Fatalf("expected initial mission event to be seeded from the quick plan, got %q", next.mission.console.lastEvent)
	}
	if missionModel, ok := next.activeMissionModel(); !ok {
		t.Fatalf("expected mission model to be active after enter")
	} else if done, total := missionModel.progressCounts(); done != 0 || total != len(next.mission.profile.Modules) {
		t.Fatalf("expected seeded mission progress 0/%d, got %d/%d", len(next.mission.profile.Modules), done, total)
	}
}

func TestConsoleShellMissionDoneViewDoesNotAdvertiseFollowUpActions(t *testing.T) {
	app, project := newTestTUIApp(t)

	originalStartConsoleShellMission := startConsoleShellMission
	t.Cleanup(func() {
		startConsoleShellMission = originalStartConsoleShellMission
	})
	startConsoleShellMission = func(app *App, ctx context.Context, project domain.Project, profile domain.ScanProfile, seq int) consoleShellMissionSession {
		return consoleShellMissionSession{
			cancel:  func() {},
			eventCh: make(chan domain.StreamEvent),
			doneCh:  make(chan scanMissionDoneMsg),
		}
	}

	model := newConsoleShellModel(app, consoleShellLaunchState{
		SelectedProjectID: project.ID,
	}, context.Background())
	started, _ := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	running := started.(consoleShellModel)
	running.width = 160
	running.height = 44

	updated, _ := running.Update(scanMissionDoneMsg{
		seq: running.mission.seq,
		run: domain.ScanRun{
			Status: domain.ScanCompleted,
			Summary: domain.ScanSummary{
				TotalFindings: 1,
				CountsBySeverity: map[domain.Severity]int{
					domain.SeverityHigh: 1,
				},
			},
			ModuleResults: []domain.ModuleResult{
				{Name: firstModuleName(running.mission.profile.Modules), Status: domain.ModuleCompleted, FindingCount: 1},
			},
		},
		findings: []domain.Finding{{Fingerprint: "fp-1", Severity: domain.SeverityHigh, Title: "Leaked token"}},
	})
	done := updated.(consoleShellModel)
	view := done.View()

	for _, fragment := range []string{
		app.catalog.T("scan_mode_live_notice_doctor"),
		app.catalog.T("scan_mode_live_notice_review"),
		app.catalog.T("scan_mode_live_notice_details"),
		app.catalog.T("scan_mode_live_footer_doctor"),
		app.catalog.T("scan_mode_live_footer_review"),
		app.catalog.T("scan_mode_live_footer_clean"),
		app.catalog.T("scan_mode_live_subtitle_done"),
	} {
		if strings.Contains(view, fragment) {
			t.Fatalf("expected mission-only done view to omit follow-up affordance %q, got %q", fragment, view)
		}
	}
}

func TestConsoleShellAppendsDebriefBelowMissionWhenRunCompletes(t *testing.T) {
	model := newCompletedConsoleShellModel(t)

	if model.stage != consoleStageDebrief {
		t.Fatalf("expected completed run to move into debrief stage, got %v", model.stage)
	}

	view := model.View()
	fragments := []string{
		model.app.catalog.T("scan_debrief_title"),
		model.app.catalog.T("app_label_report"),
		model.app.catalog.T("scan_report_fix_plan_title"),
		model.app.catalog.T("scan_report_blockers_title"),
		model.app.catalog.T("scan_mc_handoff_title"),
		model.app.catalog.T("app_label_findings"),
		model.app.catalog.T("module_completed_count"),
		model.app.catalog.T("module_failed_count"),
		strings.ToUpper(string(domain.ScanCompleted)),
		model.mission.project.DisplayName,
		model.app.catalog.T("scan_report_first_step_title"),
		"GITLEAKS",
	}
	for _, fragment := range fragments {
		if !strings.Contains(view, fragment) {
			t.Fatalf("expected debrief view to contain %q\n%s", fragment, view)
		}
	}
	if missionIndex, debriefIndex := strings.Index(view, model.app.catalog.T("scan_mc_activity")), strings.Index(view, model.app.catalog.T("scan_debrief_title")); missionIndex == -1 || debriefIndex == -1 || debriefIndex <= missionIndex {
		t.Fatalf("expected debrief to be appended after mission content\n%s", view)
	}
}

func TestConsoleShellDebriefReportLocalizesTurkishAndShowsDetailedSections(t *testing.T) {
	model := newCompletedConsoleShellModel(t)
	model.app.lang = i18n.TR
	model.app.catalog = i18n.New(i18n.TR)
	model.mission.notice = model.app.consoleMissionDoneNotice(model.mission.run.Status, nil, len(model.mission.findings))

	view := model.View()
	for _, fragment := range []string{
		model.app.catalog.T("app_label_report"),
		model.app.catalog.T("scan_outcome_title"),
		model.app.catalog.T("scan_report_fix_plan_title"),
		model.app.catalog.T("scan_report_blockers_title"),
		model.app.catalog.T("scan_phase_verdicts_title"),
		model.app.catalog.T("scan_report_first_step_title"),
		"TAMAMLANDI",
	} {
		if !strings.Contains(view, fragment) {
			t.Fatalf("expected Turkish debrief to contain %q, got %q", fragment, view)
		}
	}
	for _, fragment := range []string{"Mission completed", "COMPLETED", "FAILED", "Gorev"} {
		if strings.Contains(view, fragment) {
			t.Fatalf("expected Turkish debrief to avoid raw token %q, got %q", fragment, view)
		}
	}
}

func TestConsoleShellDrawerOpensWithoutChangingStage(t *testing.T) {
	model := newCompletedConsoleShellModel(t)
	stageBefore := model.stage

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'f'}})
	findingsDrawer := updated.(consoleShellModel)
	if findingsDrawer.stage != stageBefore {
		t.Fatalf("expected findings drawer to preserve stage %v, got %v", stageBefore, findingsDrawer.stage)
	}
	if findingsDrawer.drawer != consoleDrawerFindings {
		t.Fatalf("expected findings drawer to open, got %v", findingsDrawer.drawer)
	}

	updated, _ = findingsDrawer.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	runtimeDrawer := updated.(consoleShellModel)
	if runtimeDrawer.stage != stageBefore {
		t.Fatalf("expected runtime drawer to preserve stage %v, got %v", stageBefore, runtimeDrawer.stage)
	}
	if runtimeDrawer.drawer != consoleDrawerRuntime {
		t.Fatalf("expected runtime drawer to replace findings drawer, got %v", runtimeDrawer.drawer)
	}

	updated, _ = runtimeDrawer.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	runDrawer := updated.(consoleShellModel)
	if runDrawer.stage != stageBefore {
		t.Fatalf("expected run drawer to preserve stage %v, got %v", stageBefore, runDrawer.stage)
	}
	if runDrawer.drawer != consoleDrawerRun {
		t.Fatalf("expected run drawer to replace runtime drawer, got %v", runDrawer.drawer)
	}

	updated, _ = runDrawer.Update(tea.KeyMsg{Type: tea.KeyEsc})
	closed := updated.(consoleShellModel)
	if closed.stage != stageBefore {
		t.Fatalf("expected closing drawer to preserve stage %v, got %v", stageBefore, closed.stage)
	}
	if closed.drawer != consoleDrawerNone {
		t.Fatalf("expected escape to close the drawer, got %v", closed.drawer)
	}
}

func TestConsoleShellDrawerHintUsesCatalogCopy(t *testing.T) {
	t.Run("english", func(t *testing.T) {
		model := newCompletedConsoleShellModel(t)
		if got, want := model.drawerHint(), model.app.catalog.T("console_drawer_hint"); got != want {
			t.Fatalf("expected english drawer hint %q from catalog, got %q", want, got)
		}
	})

	t.Run("turkish", func(t *testing.T) {
		model := newCompletedConsoleShellModel(t)
		model.app.lang = i18n.TR
		model.app.catalog = i18n.New(i18n.TR)
		if got, want := model.drawerHint(), model.app.catalog.T("console_drawer_hint"); got != want {
			t.Fatalf("expected turkish drawer hint %q from catalog, got %q", want, got)
		}
	})
}

func TestConsoleShellRunningMissionOpensReadOnlyDrawers(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newConsoleShellModel(app, consoleShellLaunchState{
		SelectedProjectID: project.ID,
	}, context.Background())
	profile := app.quickScanProfile(project)
	model.stage = consoleStageMission
	model.width = 150
	model.height = 42
	model.mission = consoleShellMissionState{
		project:    project,
		profile:    profile,
		doctor:     app.runtimeDoctor(profile, false, false),
		launchedAt: time.Unix(1_763_000_000, 0).UTC(),
		running:    true,
		console:    model.seededMissionConsole(project, profile),
		run:        model.seededMissionRun(profile),
	}

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	runtimeDrawer := updated.(consoleShellModel)
	if runtimeDrawer.drawer != consoleDrawerRuntime {
		t.Fatalf("expected runtime drawer to open during running mission, got %v", runtimeDrawer.drawer)
	}
	if !strings.Contains(runtimeDrawer.View(), app.catalog.T("runtime_command_title")) {
		t.Fatalf("expected running mission to render read-only runtime drawer\n%s", runtimeDrawer.View())
	}

	updated, _ = runtimeDrawer.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'f'}})
	findingsDrawer := updated.(consoleShellModel)
	if findingsDrawer.drawer != consoleDrawerFindings {
		t.Fatalf("expected findings drawer to replace runtime drawer during running mission, got %v", findingsDrawer.drawer)
	}

	updated, _ = findingsDrawer.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	runDrawer := updated.(consoleShellModel)
	if runDrawer.drawer != consoleDrawerRun {
		t.Fatalf("expected run drawer to open during running mission, got %v", runDrawer.drawer)
	}
}

func TestConsoleShellDebriefLayoutFitsShortTerminalWithDrawerOpen(t *testing.T) {
	model := newCompletedConsoleShellModel(t)
	model.width = 118
	model.height = 30
	model.drawer = consoleDrawerFindings

	view := model.View()
	if got := lipgloss.Height(view); got > model.height {
		t.Fatalf("expected completed console surface to fit within %d lines, got %d\n%s", model.height, got, view)
	}
	for _, fragment := range []string{
		model.app.catalog.T("app_label_report"),
		model.app.catalog.T("scan_debrief_title"),
		model.drawerHint(),
	} {
		if !strings.Contains(view, fragment) {
			t.Fatalf("expected short completed console view to keep %q visible\n%s", fragment, view)
		}
	}
}

func TestConsoleShellAdvancedKeyDoesNotLeaveSameSurfaceFlow(t *testing.T) {
	t.Run("mission", func(t *testing.T) {
		app, project := newTestTUIApp(t)
		model := newConsoleShellModel(app, consoleShellLaunchState{
			SelectedProjectID: project.ID,
		}, context.Background())
		model.stage = consoleStageMission
		model.mission = consoleShellMissionState{
			project: project,
			profile: domain.ScanProfile{Modules: []string{"surface-inventory"}},
			running: true,
			console: &liveScanConsole{
				project:    project,
				profile:    domain.ScanProfile{Modules: []string{"surface-inventory"}},
				lastModule: "surface-inventory",
				lastPhase:  app.modulePhaseLabel("surface-inventory"),
				lastTool:   app.moduleToolLabel("surface-inventory"),
				lastEvent:  app.moduleNarrative("surface-inventory"),
				run: domain.ScanRun{
					Status: domain.ScanRunning,
					ModuleResults: []domain.ModuleResult{
						{Name: "surface-inventory", Status: domain.ModuleRunning},
					},
				},
			},
			run: domain.ScanRun{
				Status: domain.ScanRunning,
				ModuleResults: []domain.ModuleResult{
					{Name: "surface-inventory", Status: domain.ModuleRunning},
				},
			},
		}

		updated, cmd := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
		next := updated.(consoleShellModel)

		if next.stage != consoleStageMission {
			t.Fatalf("expected mission-stage a key to preserve mission stage, got %v", next.stage)
		}
		if cmd != nil {
			t.Fatalf("expected mission-stage a key to avoid quitting to legacy shell")
		}
	})

	t.Run("debrief", func(t *testing.T) {
		model := newCompletedConsoleShellModel(t)

		updated, cmd := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
		next := updated.(consoleShellModel)

		if next.stage != consoleStageDebrief {
			t.Fatalf("expected debrief-stage a key to preserve debrief stage, got %v", next.stage)
		}
		if cmd != nil {
			t.Fatalf("expected debrief-stage a key to avoid quitting to legacy shell")
		}
	})
}

func TestConsoleShellRuntimeDrawerUsesMissionScopedRuntimeContext(t *testing.T) {
	model := newCompletedConsoleShellModel(t)
	model.drawer = consoleDrawerRuntime
	model.app.runtimeCache = domain.RuntimeStatus{
		ScannerBundle: []domain.RuntimeTool{
			{Name: "cache-only-a", Available: true, Healthy: true},
			{Name: "cache-only-b", Available: true, Healthy: false},
			{Name: "cache-only-c", Available: false},
			{Name: "cache-only-d", Available: false},
		},
		Mirrors: []domain.RuntimeMirror{
			{Tool: "mirror-a", Available: true},
			{Tool: "mirror-b", Available: true},
			{Tool: "mirror-c", Available: true},
			{Tool: "mirror-d", Available: false},
			{Tool: "mirror-e", Available: false},
			{Tool: "mirror-f", Available: false},
		},
	}
	model.app.runtimeCacheAt = time.Now()
	model.mission.doctor = domain.RuntimeDoctor{
		Mode:  model.mission.profile.Mode,
		Ready: false,
		Missing: []domain.RuntimeTool{
			{Name: "mission-only-tool"},
		},
		Checks: []domain.RuntimeDoctorCheck{
			{Name: "sqlite_integrity", Status: domain.RuntimeCheckPass},
			{Name: "network_probe", Status: domain.RuntimeCheckWarn},
		},
	}

	view := model.View()
	if !strings.Contains(view, "mission-only-tool") {
		t.Fatalf("expected runtime drawer to show mission doctor context\n%s", view)
	}
	if strings.Contains(view, "2 available • 1 outdated • 2 missing • 0 failed tools • 3/6 mirrors") {
		t.Fatalf("expected runtime drawer to avoid present-time runtime cache summary\n%s", view)
	}
}

func TestConsoleShellMissionTickDoesNotChangeViewWithoutStatusChange(t *testing.T) {
	app, project := newTestTUIApp(t)
	profile := domain.ScanProfile{
		Mode:         domain.ModeSafe,
		Coverage:     domain.CoverageCore,
		Modules:      []string{"surface-inventory", "semgrep"},
		SeverityGate: domain.SeverityHigh,
		Isolation:    domain.IsolationAuto,
	}

	model := newConsoleShellModel(app, consoleShellLaunchState{
		SelectedProjectID: project.ID,
	}, context.Background())
	model.stage = consoleStageMission
	model.width = 160
	model.height = 44
	model.mission = consoleShellMissionState{
		project:    project,
		profile:    profile,
		doctor:     app.runtimeDoctor(profile, false, false),
		launchedAt: time.Unix(1_763_000_000, 0).UTC(),
		running:    true,
		console: &liveScanConsole{
			project:    project,
			profile:    profile,
			frame:      4,
			lastEvent:  "Semgrep semantic rules are traversing the source graph.",
			lastStatus: string(domain.ScanRunning),
			lastPhase:  app.catalog.T("scan_phase_code"),
			lastModule: "semgrep",
			lastTool:   "semgrep",
			run: domain.ScanRun{
				Status: domain.ScanRunning,
				ModuleResults: []domain.ModuleResult{
					{Name: "surface-inventory", Status: domain.ModuleCompleted},
					{Name: "semgrep", Status: domain.ModuleRunning},
				},
			},
		},
		run: domain.ScanRun{
			Status: domain.ScanRunning,
			ModuleResults: []domain.ModuleResult{
				{Name: "surface-inventory", Status: domain.ModuleCompleted},
				{Name: "semgrep", Status: domain.ModuleRunning},
			},
		},
	}

	frameBefore := model.mission.console.frame
	updated, cmd := model.Update(scanMissionTickMsg(time.Unix(1_763_000_100, 0)))
	next := updated.(consoleShellModel)

	if next.mission.console.frame != frameBefore {
		t.Fatalf("expected tick without status change to leave mission frame unchanged")
	}
	if cmd != nil {
		t.Fatalf("expected mission tick to avoid scheduling decorative animation")
	}
}

func TestConsoleShellMissionDoneNoticeRespectsFailedAndCanceledOutcomes(t *testing.T) {
	app, project := newTestTUIApp(t)

	originalStartConsoleShellMission := startConsoleShellMission
	t.Cleanup(func() {
		startConsoleShellMission = originalStartConsoleShellMission
	})
	startConsoleShellMission = func(app *App, ctx context.Context, project domain.Project, profile domain.ScanProfile, seq int) consoleShellMissionSession {
		return consoleShellMissionSession{
			cancel:  func() {},
			eventCh: make(chan domain.StreamEvent),
			doneCh:  make(chan scanMissionDoneMsg),
		}
	}

	base := newConsoleShellModel(app, consoleShellLaunchState{
		SelectedProjectID: project.ID,
	}, context.Background())
	started, _ := base.Update(tea.KeyMsg{Type: tea.KeyEnter})
	running := started.(consoleShellModel)

	failedUpdated, _ := running.Update(scanMissionDoneMsg{
		seq: running.mission.seq,
		run: domain.ScanRun{
			Status: domain.ScanFailed,
			ModuleResults: []domain.ModuleResult{
				{Name: firstModuleName(running.mission.profile.Modules), Status: domain.ModuleFailed},
			},
		},
	})
	failed := failedUpdated.(consoleShellModel)
	if want := "Mission failed. Evidence summary remains on this surface."; failed.mission.notice != want {
		t.Fatalf("expected failed mission notice %q, got %q", want, failed.mission.notice)
	}

	canceledRunning := running
	canceledRunning.mission.seq++
	canceledUpdated, _ := canceledRunning.Update(scanMissionDoneMsg{
		seq: canceledRunning.mission.seq,
		run: domain.ScanRun{
			Status: domain.ScanCanceled,
			ModuleResults: []domain.ModuleResult{
				{Name: firstModuleName(canceledRunning.mission.profile.Modules), Status: domain.ModuleSkipped},
			},
		},
	})
	canceled := canceledUpdated.(consoleShellModel)
	if want := "Mission canceled. Collected evidence summary remains on this surface."; canceled.mission.notice != want {
		t.Fatalf("expected canceled mission notice %q, got %q", want, canceled.mission.notice)
	}
}

func TestConsoleShellMissionRunningFooterMatchesQBehavior(t *testing.T) {
	app, project := newTestTUIApp(t)

	model := newConsoleShellModel(app, consoleShellLaunchState{
		SelectedProjectID: project.ID,
	}, context.Background())
	model.stage = consoleStageMission
	model.mission = consoleShellMissionState{
		project: project,
		profile: domain.ScanProfile{Modules: []string{"stack-detector"}},
		running: true,
		console: &liveScanConsole{
			project:    project,
			profile:    domain.ScanProfile{Modules: []string{"stack-detector"}},
			lastModule: "stack-detector",
			lastPhase:  app.modulePhaseLabel("stack-detector"),
			lastTool:   app.moduleToolLabel("stack-detector"),
			lastEvent:  app.moduleNarrative("stack-detector"),
			run: domain.ScanRun{
				Status: domain.ScanRunning,
				ModuleResults: []domain.ModuleResult{
					{Name: "stack-detector", Status: domain.ModuleRunning},
				},
			},
		},
		run: domain.ScanRun{
			Status: domain.ScanRunning,
			ModuleResults: []domain.ModuleResult{
				{Name: "stack-detector", Status: domain.ModuleRunning},
			},
		},
	}

	footer := model.activeMissionModelMust(t).footerText()
	if strings.Contains(strings.ToLower(footer), "close mission") {
		t.Fatalf("expected running footer to avoid close wording, got %q", footer)
	}
	if !strings.Contains(strings.ToLower(footer), "cancel") {
		t.Fatalf("expected running footer to describe cancel behavior, got %q", footer)
	}
}

func (m consoleShellModel) activeMissionModelMust(t *testing.T) scanMissionModel {
	t.Helper()
	mission, ok := m.activeMissionModel()
	if !ok {
		t.Fatalf("expected active mission model")
	}
	return mission
}

func newCompletedConsoleShellModel(t *testing.T) consoleShellModel {
	t.Helper()

	app, project := newTestTUIApp(t)
	profile := domain.ScanProfile{
		Mode:         domain.ModeSafe,
		Coverage:     domain.CoverageCore,
		Modules:      []string{"surface-inventory", "semgrep", "gitleaks"},
		SeverityGate: domain.SeverityHigh,
		Isolation:    domain.IsolationAuto,
	}
	doctor := app.runtimeDoctor(profile, false, false)
	doctor.Checks = []domain.RuntimeDoctorCheck{
		{Name: "sqlite_integrity", Status: domain.RuntimeCheckPass, Summary: "Local state verified."},
		{Name: "network_probe", Status: domain.RuntimeCheckWarn, Summary: "Network egress remains constrained."},
	}

	findings := []domain.Finding{
		{
			Fingerprint: "fp-critical",
			Severity:    domain.SeverityCritical,
			Category:    domain.CategorySecret,
			Title:       "Leaked deploy token remains in .env",
			Location:    ".env:3",
			Status:      domain.FindingOpen,
			Priority:    98,
			Module:      "gitleaks",
		},
		{
			Fingerprint: "fp-high",
			Severity:    domain.SeverityHigh,
			Category:    domain.CategorySAST,
			Title:       "Command injection sink remains reachable",
			Location:    "cmd/server/router.go:44",
			Status:      domain.FindingInvestigating,
			Priority:    87,
			Module:      "semgrep",
		},
	}

	run := domain.ScanRun{
		ID:        "run-complete-1",
		ProjectID: project.ID,
		Status:    domain.ScanCompleted,
		StartedAt: time.Unix(1_763_000_000, 0).UTC(),
		Summary: domain.ScanSummary{
			TotalFindings: 2,
			CountsBySeverity: map[domain.Severity]int{
				domain.SeverityCritical: 1,
				domain.SeverityHigh:     1,
			},
		},
		Profile: profile,
		ModuleResults: []domain.ModuleResult{
			{Name: "surface-inventory", Category: domain.CategoryPlatform, Status: domain.ModuleCompleted, Summary: "Enumerated the repository attack surface.", Attempts: 1, DurationMs: 80},
			{Name: "semgrep", Category: domain.CategorySAST, Status: domain.ModuleCompleted, Summary: "Correlated semantic rules across the source graph.", Attempts: 1, FindingCount: 1, DurationMs: 2100},
			{Name: "gitleaks", Category: domain.CategorySecret, Status: domain.ModuleFailed, Summary: "Secret validation surfaced a blocking credential exposure.", Attempts: 2, FindingCount: 1, DurationMs: 1600},
		},
	}

	return consoleShellModel{
		app:    app,
		stage:  consoleStageDebrief,
		drawer: consoleDrawerNone,
		width:  176,
		height: 48,
		mission: consoleShellMissionState{
			project:     project,
			profile:     profile,
			doctor:      doctor,
			launchedAt:  run.StartedAt,
			cpuBaseline: 12.5,
			console: &liveScanConsole{
				project:        project,
				profile:        profile,
				frame:          6,
				lastEvent:      "Mission completed. Evidence cards and handoff are ready.",
				lastStatus:     string(domain.ScanCompleted),
				lastPhase:      app.catalog.T("scan_phase_code"),
				lastModule:     "gitleaks",
				lastTool:       "gitleaks",
				recentFindings: findings,
				telemetry: []string{
					"Queued semantic analysis lane.",
					"Correlated the source graph and dependency edges.",
					"Closed the mission with exportable evidence.",
				},
				run: run,
			},
			run:      run,
			findings: findings,
			done:     true,
			notice:   app.consoleMissionDoneNotice(run.Status, nil, len(findings)),
		},
	}
}

func newEmptyTUIApp(t *testing.T) *App {
	t.Helper()

	cfg := config.Config{
		DataDir:         t.TempDir(),
		OutputDir:       t.TempDir(),
		DefaultLanguage: "en",
	}
	service, err := core.New(cfg)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return &App{
		cfg:     cfg,
		service: service,
		lang:    i18n.EN,
		catalog: i18n.New(i18n.EN),
		runtimeDoctorFn: func(profile domain.ScanProfile, strictVersions, requireIntegrity bool) domain.RuntimeDoctor {
			return domain.RuntimeDoctor{
				Mode:             profile.Mode,
				StrictVersions:   strictVersions,
				RequireIntegrity: requireIntegrity,
				Ready:            true,
			}
		},
	}
}
