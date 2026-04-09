package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/batu3384/ironsentinel/internal/domain"
	"github.com/batu3384/ironsentinel/internal/i18n"
)

func TestNewLegacyAppShellModelDefaultsToHomeRoute(t *testing.T) {
	app, project := newTestTUIApp(t)

	model := newAppShellModel(app, appShellLaunchState{
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})

	if model.route != appRouteHome {
		t.Fatalf("expected default route to be home, got %v", model.route)
	}
	if model.selectedProjectID != project.ID {
		t.Fatalf("expected latest project %s to be auto-selected, got %s", project.ID, model.selectedProjectID)
	}
	if model.width <= 0 || model.height <= 0 {
		t.Fatalf("expected initial viewport dimensions to be seeded, got %dx%d", model.width, model.height)
	}
	if model.reviewContext.projectID != project.ID {
		t.Fatalf("expected initial review context project %s, got %s", project.ID, model.reviewContext.projectID)
	}
}

func TestInitialInteractiveLegacyLaunchRouteUsesHomeForPicker(t *testing.T) {
	if got := initialInteractiveLaunchRoute(true); got != appRouteHome {
		t.Fatalf("expected picker startup route to be home, got %v", got)
	}
	if got := initialInteractiveLaunchRoute(false); got != appRouteScanReview {
		t.Fatalf("expected non-picker startup route to be scan review, got %v", got)
	}
}

func TestNewAppShellModelPrefersCurrentWorkspaceProject(t *testing.T) {
	app, _ := newTestTUIApp(t)
	root := t.TempDir()
	project, _, err := app.service.EnsureProject(context.Background(), root, "Workspace Fixture", false)
	if err != nil {
		t.Fatalf("ensure project: %v", err)
	}

	previousWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(previousWD)
	})

	model := newAppShellModel(app, appShellLaunchState{
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	if model.selectedProjectID != project.ID {
		t.Fatalf("expected current workspace project %s, got %s", project.ID, model.selectedProjectID)
	}
}

func TestAppShellPaletteRoutesToRuntime(t *testing.T) {
	app, _ := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteHome,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	model = model.openPalette()
	model.paletteInput.SetValue("runtime")

	updated, _ := model.updatePalette(tea.KeyMsg{Type: tea.KeyEnter})
	next := updated.(appShellModel)
	if next.route != appRouteRuntime {
		t.Fatalf("expected palette enter to route to runtime, got %v", next.route)
	}
	if next.paletteActive {
		t.Fatalf("expected palette to close after executing a route")
	}
}

func TestAppShellPaletteStartBlockedWithoutValidationTarget(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteScanReview,
		SelectedProjectID: project.ID,
		Review: scanReviewState{
			Preset:           reviewPresetFullDeep,
			Isolation:        domain.IsolationAuto,
			ActiveValidation: true,
			StrictVersions:   false,
			RequireIntegrity: false,
		},
	})

	updated, cmd := model.executePaletteCommand(paletteCommand{
		ID:     "start",
		Label:  app.catalog.T("app_action_start_scan"),
		Hint:   app.catalog.T("app_action_start_scan_hint"),
		Action: appShellActionStartScan,
	})
	next := updated.(appShellModel)
	if cmd != nil {
		t.Fatalf("expected blocked palette start to stay in the shell")
	}
	if next.outcomeAction != appShellActionNone {
		t.Fatalf("expected no outcome action when start is blocked, got %s", next.outcomeAction)
	}
	if next.route != appRouteScanReview {
		t.Fatalf("expected to stay on scan review when start is blocked, got %v", next.route)
	}
	if !next.alert {
		t.Fatalf("expected alert state when active validation target is missing")
	}
	if !strings.Contains(next.notice, app.catalog.T("app_scan_review_requires_target_short")) &&
		!strings.Contains(next.notice, app.catalog.T("app_scan_review_requires_target")) {
		t.Fatalf("expected missing target notice, got %q", next.notice)
	}
}

func TestAppShellFindingAndRunFocusHighlightSCASignals(t *testing.T) {
	app, project := newTestTUIApp(t)
	run := domain.ScanRun{
		ID:        "run-1",
		ProjectID: project.ID,
		Status:    domain.ScanCompleted,
		Summary: domain.ScanSummary{
			TotalFindings:    1,
			CountsBySeverity: map[domain.Severity]int{domain.SeverityHigh: 1},
		},
	}
	finding := domain.Finding{
		ScanID:       run.ID,
		ProjectID:    project.ID,
		Fingerprint:  "fp-1",
		Category:     domain.CategorySCA,
		Severity:     domain.SeverityHigh,
		Title:        "Reachable dependency confusion risk",
		Location:     "package.json",
		Module:       "dependency-confusion",
		Reachability: domain.ReachabilityReachable,
		Tags:         []string{"supply-chain:dependency-confusion"},
		Priority:     8.7,
	}

	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteFindings,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.snapshot.Portfolio.Projects = []domain.Project{project}
	model.snapshot.Portfolio.Runs = []domain.ScanRun{run}
	model.snapshot.Portfolio.Findings = []domain.Finding{finding}
	model.cursor = 0

	findingLines := model.findingFocusLines(80)
	if !appShellLinesContain(findingLines, "reachable path | dependency confusion signal") {
		t.Fatalf("expected finding focus to show the supply-chain signal, got %v", findingLines)
	}

	model.route = appRouteRuns
	runLines := model.runFocusLines(80)
	if !appShellLinesContain(runLines, "dependency confusion signal") {
		t.Fatalf("expected run focus to surface the top finding signal, got %v", runLines)
	}
}

func TestAppShellFindingDetailShowsVEXState(t *testing.T) {
	app, project := newTestTUIApp(t)
	run := domain.ScanRun{
		ID:        "run-vex-ui",
		ProjectID: project.ID,
		Status:    domain.ScanCompleted,
		StartedAt: time.Now().UTC(),
		Profile:   domain.ScanProfile{SeverityGate: domain.SeverityHigh},
		Summary: domain.ScanSummary{
			TotalFindings:    1,
			CountsBySeverity: map[domain.Severity]int{domain.SeverityHigh: 1},
		},
	}
	finding := domain.Finding{
		ScanID:             run.ID,
		ProjectID:          project.ID,
		Fingerprint:        "fp-vex-1",
		Category:           domain.CategorySCA,
		Severity:           domain.SeverityHigh,
		Title:              "Reachable package vulnerability",
		Location:           "lodash",
		Module:             "osv-scanner",
		Reachability:       domain.ReachabilityReachable,
		VEXStatus:          domain.VEXStatusNotAffected,
		VEXJustification:   "vulnerable_code_not_present",
		VEXStatementSource: "https://example.test/vex",
		Priority:           8.1,
	}

	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteFindings,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.snapshot.Portfolio.Projects = []domain.Project{project}
	model.snapshot.Portfolio.Runs = []domain.ScanRun{run}
	model.snapshot.Portfolio.Findings = []domain.Finding{finding}
	model.cursor = 0

	content := model.renderFindingDetailContent(100)
	for _, want := range []string{"not affected", "vulnerable code not present", "https://example.test/vex"} {
		if !strings.Contains(content, want) {
			t.Fatalf("expected finding detail to contain %q, got %q", want, content)
		}
	}
}

func TestAppShellFindingDetailShowsCampaignHint(t *testing.T) {
	app, project := newTestTUIApp(t)
	run := domain.ScanRun{
		ID:        "run-campaign-ui",
		ProjectID: project.ID,
		Status:    domain.ScanCompleted,
		Summary: domain.ScanSummary{
			TotalFindings:    1,
			CountsBySeverity: map[domain.Severity]int{domain.SeverityHigh: 1},
		},
	}
	finding := domain.Finding{
		ScanID:      run.ID,
		ProjectID:   project.ID,
		Fingerprint: "fp-campaign-1",
		Category:    domain.CategorySCA,
		Severity:    domain.SeverityHigh,
		Title:       "Remediation candidate",
		Location:    "package.json",
		Module:      "campaign-fixture",
	}

	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteFindings,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.snapshot.Portfolio.Projects = []domain.Project{project}
	model.snapshot.Portfolio.Runs = []domain.ScanRun{run}
	model.snapshot.Portfolio.Findings = []domain.Finding{finding}
	model.cursor = 0

	content := model.renderFindingDetailContent(100)
	for _, want := range []string{app.catalog.T("campaigns_title"), "--project", "--run", "--title", "--finding"} {
		if !strings.Contains(content, want) {
			t.Fatalf("expected finding detail campaign hint to contain %q, got %q", want, content)
		}
	}
}

func TestAppShellRunDetailShowsCampaignHint(t *testing.T) {
	app, project := newTestTUIApp(t)
	run := domain.ScanRun{
		ID:        "run-campaign-ui",
		ProjectID: project.ID,
		Status:    domain.ScanCompleted,
		Summary: domain.ScanSummary{
			TotalFindings:    1,
			CountsBySeverity: map[domain.Severity]int{domain.SeverityHigh: 1},
		},
	}
	finding := domain.Finding{
		ScanID:      run.ID,
		ProjectID:   project.ID,
		Fingerprint: "fp-campaign-1",
		Category:    domain.CategorySCA,
		Severity:    domain.SeverityHigh,
		Title:       "Remediation candidate",
		Location:    "package.json",
		Module:      "campaign-fixture",
	}

	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteRuns,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.snapshot.Portfolio.Projects = []domain.Project{project}
	model.snapshot.Portfolio.Runs = []domain.ScanRun{run}
	model.snapshot.Portfolio.Findings = []domain.Finding{finding}
	model.cursor = 0

	content := model.renderRunDetailContent(100)
	for _, want := range []string{app.catalog.T("campaigns_title"), "--project", "--run", "--title"} {
		if !strings.Contains(content, want) {
			t.Fatalf("expected run detail campaign hint to contain %q, got %q", want, content)
		}
	}
}

func appShellLinesContain(lines []string, needle string) bool {
	for _, line := range lines {
		if strings.Contains(line, needle) {
			return true
		}
	}
	return false
}

func TestAppShellReviewStartRequiresProject(t *testing.T) {
	app, _ := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteScanReview,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.selectedProjectID = ""
	model.cursor = 6

	updated, _ := model.activateReviewRow()
	next := updated.(appShellModel)
	if !next.projectPickerActive {
		t.Fatalf("expected missing project to open project picker")
	}
}

func TestAppShellOpenProjectPickerShortcut(t *testing.T) {
	app, _ := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteHome,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("P")})
	next := updated.(appShellModel)
	if !next.projectPickerActive {
		t.Fatalf("expected P to open project picker")
	}
}

func TestAppShellResolvedReviewProfileDefaultsToFullDeep(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteScanReview,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})

	profile := model.resolvedReviewProfile(project)
	if profile.Mode != domain.ModeDeep {
		t.Fatalf("expected deep mode, got %s", profile.Mode)
	}
	if profile.Coverage != domain.CoverageFull {
		t.Fatalf("expected full coverage, got %s", profile.Coverage)
	}
	if profile.AllowBuild {
		t.Fatalf("expected allowBuild=false")
	}
	if profile.AllowNetwork {
		t.Fatalf("expected allowNetwork=false")
	}
	if len(profile.Modules) == 0 {
		t.Fatalf("expected resolved modules for full deep preset")
	}
}

func TestAppShellResolvedReviewProfileActiveValidationEnablesTarget(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteScanReview,
		SelectedProjectID: project.ID,
		ReviewDASTTargets: []domain.DastTarget{{
			Name:        "api",
			URL:         "https://example.internal",
			AuthType:    domain.DastAuthBearer,
			AuthProfile: "staging-bearer",
		}},
		ReviewAuthProfiles: []domain.DastAuthProfile{{
			Name:      "staging-bearer",
			Type:      domain.DastAuthBearer,
			SecretEnv: "STAGING_API_TOKEN",
		}},
		Review: scanReviewState{
			Preset:           reviewPresetFullDeep,
			Isolation:        domain.IsolationAuto,
			ActiveValidation: true,
			DASTTarget:       "https://example.internal",
		},
	})

	profile := model.resolvedReviewProfile(project)
	if profile.Mode != domain.ModeActive {
		t.Fatalf("expected active mode, got %s", profile.Mode)
	}
	if !profile.AllowNetwork {
		t.Fatalf("expected active validation to enable network")
	}
	if len(profile.DASTTargets) != 1 || profile.DASTTargets[0].URL != "https://example.internal" {
		t.Fatalf("expected preserved dast target, got %+v", profile.DASTTargets)
	}
	if len(profile.DASTAuthProfiles) != 1 || profile.DASTAuthProfiles[0].Name != "staging-bearer" {
		t.Fatalf("expected preserved dast auth profile, got %+v", profile.DASTAuthProfiles)
	}
	if profile.DASTTargets[0].AuthProfile != "staging-bearer" {
		t.Fatalf("expected target auth profile to survive review state, got %+v", profile.DASTTargets)
	}
}

func TestAppShellRefreshReviewContextReusesCachedEntryForUnchangedSnapshot(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteScanReview,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.reviewContext = reviewContextCacheEntry{
		projectID:     project.ID,
		snapshotStamp: model.snapshotUpdatedAt,
		review:        model.review,
		profile: domain.ScanProfile{
			Mode:    domain.ScanMode("cached-mode"),
			Modules: []string{"cached-module"},
		},
		doctor: domain.RuntimeDoctor{
			Ready: true,
		},
		ready:           true,
		blockers:        []string{"cached blocker"},
		includedModules: map[string]struct{}{"cached-module": {}},
		laneDescriptors: []scanLaneDescriptor{{
			Key:   "cached",
			Title: "Cached",
			Kind:  "fast",
			ETA:   "cached",
		}},
		flowCurrent:  "cached-current",
		flowNext:     "cached-next",
		flowDeferred: "cached-deferred",
	}

	model.refreshReviewContext()

	if model.reviewContext.profile.Mode != domain.ScanMode("cached-mode") {
		t.Fatalf("expected cached profile to be reused, got %q", model.reviewContext.profile.Mode)
	}
	if len(model.reviewContext.blockers) != 1 || model.reviewContext.blockers[0] != "cached blocker" {
		t.Fatalf("expected cached blockers to be reused, got %+v", model.reviewContext.blockers)
	}
	if model.reviewContext.flowCurrent != "cached-current" || model.reviewContext.flowNext != "cached-next" || model.reviewContext.flowDeferred != "cached-deferred" {
		t.Fatalf("expected cached lane flow to be reused, got current=%q next=%q deferred=%q", model.reviewContext.flowCurrent, model.reviewContext.flowNext, model.reviewContext.flowDeferred)
	}
}

func TestAppShellRefreshReviewContextRebuildsAfterSnapshotChange(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteScanReview,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.reviewContext = reviewContextCacheEntry{
		projectID:     project.ID,
		snapshotStamp: model.snapshotUpdatedAt,
		review:        model.review,
		profile: domain.ScanProfile{
			Mode:    domain.ScanMode("cached-mode"),
			Modules: []string{"cached-module"},
		},
		doctor: domain.RuntimeDoctor{
			Ready: true,
		},
		ready:           true,
		blockers:        []string{"cached blocker"},
		includedModules: map[string]struct{}{"cached-module": {}},
		laneDescriptors: []scanLaneDescriptor{{
			Key:   "cached",
			Title: "Cached",
			Kind:  "fast",
			ETA:   "cached",
		}},
		flowCurrent:  "cached-current",
		flowNext:     "cached-next",
		flowDeferred: "cached-deferred",
	}
	model.snapshotUpdatedAt = model.snapshotUpdatedAt.Add(time.Second)

	model.refreshReviewContext()

	if model.reviewContext.profile.Mode == domain.ScanMode("cached-mode") {
		t.Fatalf("expected snapshot change to rebuild review context")
	}
	if model.reviewContext.snapshotStamp != model.snapshotUpdatedAt {
		t.Fatalf("expected rebuilt review context to track current snapshot timestamp")
	}
}

func TestAppShellFilteredPaletteIncludesLiveScanAndStart(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteHome,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})

	commands := model.filteredPaletteCommands()
	ids := make(map[string]struct{}, len(commands))
	for _, command := range commands {
		ids[command.ID] = struct{}{}
	}
	for _, expected := range []string{"home", "scan-review", "live-scan", "runs", "findings", "runtime", "project-picker", "start"} {
		if _, ok := ids[expected]; !ok {
			t.Fatalf("expected palette command %q to exist", expected)
		}
	}
}

func TestAppShellFilteredPaletteRanksExactPrefixHigher(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteRuns,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.findingsScopeRun = "run-123"
	model.paletteInput.SetValue("clear")

	commands := model.filteredPaletteCommands()
	if len(commands) == 0 {
		t.Fatalf("expected filtered palette commands")
	}
	if commands[0].ID != "clear-findings-scope" {
		t.Fatalf("expected clear-findings-scope to rank first for query %q, got %q", model.paletteInput.Value(), commands[0].ID)
	}
}

func TestAppShellRenderProjectsContentIncludesProjectAndFocus(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteHome,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.route = appRouteProjects
	model.width = 160

	out := model.renderProjectsContent(120)
	for _, fragment := range []string{"Projects", project.DisplayName, app.catalog.T("projects_roster_title"), app.catalog.T("app_project_tree_title"), app.catalog.T("app_projects_brief_title"), app.catalog.T("app_route_scan_review_short")} {
		if !strings.Contains(out, fragment) {
			t.Fatalf("expected projects content to contain %q", fragment)
		}
	}
}

func TestAppShellRenderHomeContentIncludesLaunchpadSignals(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteHome,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.width = 160

	out := model.renderHomeContent(120)
	for _, fragment := range []string{
		app.catalog.T("app_label_workspace"),
		app.catalog.T("app_label_project"),
		app.catalog.T("app_home_launchpad_title"),
		app.catalog.T("app_home_focus_title"),
		project.DisplayName,
	} {
		if !strings.Contains(out, fragment) {
			t.Fatalf("expected home content to contain %q", fragment)
		}
	}
}

func TestAppShellShellContentWidthClampsLargeViewport(t *testing.T) {
	app, _ := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteHome,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.width = 240

	if got := model.shellContentWidth(); got > 152 {
		t.Fatalf("expected home shell width to clamp, got %d", got)
	}

	model.route = appRouteLiveScan
	if got := model.shellContentWidth(); got > 156 {
		t.Fatalf("expected live scan shell width to clamp, got %d", got)
	}
}

func TestAppShellRenderRouteBarUsesPrimaryRoutes(t *testing.T) {
	app, _ := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteHome,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})

	out := model.renderRouteBar(140)
	for _, fragment := range []string{
		app.catalog.T("app_route_home"),
		app.catalog.T("app_route_scan_review"),
		app.catalog.T("app_route_live_scan"),
		app.catalog.T("runs_title"),
		app.catalog.T("findings_title"),
		app.catalog.T("runtime_command_title"),
	} {
		if !strings.Contains(out, fragment) {
			t.Fatalf("expected route bar to contain %q", fragment)
		}
	}
	if strings.Contains(out, app.catalog.T("app_route_projects")) {
		t.Fatalf("expected projects route to be hidden from primary route bar")
	}
}

func TestAppShellSmallViewportViewStaysReadable(t *testing.T) {
	app, project := newTestTUIApp(t)
	app.lang = i18n.TR
	app.catalog = i18n.New(i18n.TR)
	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteHome,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.width = 80
	model.height = 24

	out := model.View()
	for _, fragment := range []string{"IRONSENTINEL", app.catalog.T("app_route_home")} {
		if !strings.Contains(out, fragment) {
			t.Fatalf("expected compact home view to contain %q", fragment)
		}
	}
}

func TestNewAppShellModelInitialViewRendersBrand(t *testing.T) {
	app, _ := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})

	out := model.View()
	for _, fragment := range []string{"IRONSENTINEL", app.catalog.T("app_route_home_subtitle")} {
		if !strings.Contains(out, fragment) {
			t.Fatalf("expected initial view to contain %q", fragment)
		}
	}
}

func TestAppShellHeaderUsesRouteMascot(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteRuntime,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.width = 140
	model.height = 32

	out := model.renderShellHeader(120)
	if !strings.Contains(out, strings.ToUpper(app.catalog.T("brand_mascot_warden"))) {
		t.Fatalf("expected runtime header to use warden mascot")
	}
}

func TestAppShellReducedMotionDisablesAnimation(t *testing.T) {
	t.Setenv("IRONSENTINEL_REDUCED_MOTION", "1")
	app, project := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteLiveScan,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.routePulse = 4
	model.scanRunning = true
	if model.shouldAnimate() {
		t.Fatalf("expected reduced motion to disable shell animation")
	}
}

func TestAppShellRenderScanReviewContentIncludesLaneSummaryAndTreePreview(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteScanReview,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.width = 180

	out := model.renderScanReviewContent(160)
	for _, fragment := range []string{
		app.catalog.T("app_scan_review_controls_title"),
		app.catalog.T("app_scan_review_plan_title"),
		app.catalog.T("app_label_current"),
		app.catalog.T("app_label_next"),
		app.catalog.T("app_project_tree_title"),
		app.catalog.T("app_scan_review_brief_title"),
	} {
		if !strings.Contains(out, fragment) {
			t.Fatalf("expected scan review content to contain %q", fragment)
		}
	}
}

func TestAppShellCompactScanReviewViewStaysReadable(t *testing.T) {
	app, project := newTestTUIApp(t)
	app.lang = i18n.TR
	app.catalog = i18n.New(i18n.TR)
	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteScanReview,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.width = 84
	model.height = 24

	out := model.View()
	for _, fragment := range []string{"IRONSENTINEL", app.catalog.T("app_route_scan_review"), app.catalog.T("app_scan_review_lane_summary")} {
		if !strings.Contains(out, fragment) {
			t.Fatalf("expected compact scan review view to contain %q", fragment)
		}
	}
}

func TestAppShellRenderLiveScanContentStates(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteLiveScan,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.width = 160

	empty := model.renderLiveScanContent(120)
	if !strings.Contains(empty, app.catalog.T("app_live_scan_empty")) {
		t.Fatalf("expected empty live scan view")
	}

	model.lastScan = &scanMissionOutcome{
		run: domain.ScanRun{
			ID:     "run-1",
			Status: domain.ScanCompleted,
			Summary: domain.ScanSummary{
				TotalFindings: 1,
			},
			ModuleResults: []domain.ModuleResult{
				{Name: "semgrep", Status: domain.ModuleCompleted, Summary: "Semantic analysis completed."},
			},
		},
		findings: []domain.Finding{
			{Fingerprint: "fp-1", Severity: domain.SeverityHigh, Title: "Leaked secret"},
		},
		requiredErr: errors.New("runtime degraded"),
	}
	blocked := model.renderLiveScanContent(120)
	for _, fragment := range []string{"Launch blockers", "runtime degraded", app.catalog.T("app_label_next")} {
		if !strings.Contains(blocked, fragment) {
			t.Fatalf("expected live scan debrief to contain %q", fragment)
		}
	}
}

func TestAppShellBeginLiveScanMovesToLiveRoute(t *testing.T) {
	app, _ := newTestTUIApp(t)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	project, _, err := app.service.EnsureProject(context.Background(), root, "Inline Scan", false)
	if err != nil {
		t.Fatalf("ensure project: %v", err)
	}

	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteScanReview,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})

	profile := domain.ScanProfile{
		Mode:         domain.ModeSafe,
		Coverage:     domain.CoverageCore,
		Modules:      []string{"stack-detector"},
		SeverityGate: domain.SeverityHigh,
		Isolation:    domain.IsolationAuto,
	}
	updated, cmd := model.beginLiveScan(project, profile, app.runtimeDoctor(profile, false, false))
	next := updated.(appShellModel)
	if next.route != appRouteLiveScan {
		t.Fatalf("expected live scan route, got %v", next.route)
	}
	if !next.scanRunning {
		t.Fatalf("expected inline scan to be marked running")
	}
	if next.scanProject.ID != project.ID {
		t.Fatalf("expected inline scan project %s, got %s", project.ID, next.scanProject.ID)
	}
	if cmd == nil {
		t.Fatalf("expected async scan commands to be returned")
	}
	if next.scanCancel != nil {
		next.scanCancel()
	}
	if next.scanDoneCh != nil {
		select {
		case <-next.scanDoneCh:
		case <-time.After(3 * time.Second):
			t.Fatalf("timed out waiting for inline scan to finish after cancel")
		}
	}
}

func TestAppShellIgnoresStaleScanMissionEvents(t *testing.T) {
	app, _ := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteLiveScan,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.scanSeq = 2
	model.scanRunning = true
	model.scanRun = domain.ScanRun{ID: "current-run"}

	updated, _ := model.Update(scanMissionEventMsg{
		seq: 1,
		event: domain.StreamEvent{
			Run: domain.ScanRun{ID: "stale-run"},
		},
	})
	next := updated.(appShellModel)
	if next.scanRun.ID != "current-run" {
		t.Fatalf("expected stale scan event to be ignored, got run %q", next.scanRun.ID)
	}
}

func TestAppShellIgnoresStaleScanMissionDone(t *testing.T) {
	app, _ := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteLiveScan,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.scanSeq = 3
	model.scanRunning = true
	model.scanRun = domain.ScanRun{ID: "current-run"}

	updated, _ := model.Update(scanMissionDoneMsg{
		seq:      2,
		run:      domain.ScanRun{ID: "stale-run"},
		findings: []domain.Finding{{Fingerprint: "stale"}},
	})
	next := updated.(appShellModel)
	if !next.scanRunning {
		t.Fatalf("expected stale scan completion to be ignored")
	}
	if next.scanRun.ID != "current-run" {
		t.Fatalf("expected current scan state to stay intact, got %q", next.scanRun.ID)
	}
}

func TestAppShellProjectPickerSelectionStartsFreshReview(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteHome,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.routeState[appRouteScanReview] = routeViewState{Cursor: 6, DetailScroll: 5}
	model = model.openProjectPicker()
	model.projectPickerCursor = 2

	updated, _ := model.updateProjectPicker(tea.KeyMsg{Type: tea.KeyEnter})
	next := updated.(appShellModel)
	if next.route != appRouteScanReview {
		t.Fatalf("expected project picker selection to enter scan review, got %v", next.route)
	}
	if next.cursor != 0 || next.detailScroll != 0 {
		t.Fatalf("expected fresh scan review state after project selection, got cursor=%d detail=%d", next.cursor, next.detailScroll)
	}
}

func TestAppShellRenderRouteNativePanels(t *testing.T) {
	app, run, _, _ := newFocusedRunFilterFixture(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteRuns,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.width = 160
	model.height = 48

	model.route = appRouteRuns
	model.cursor = 0
	runs := model.renderRunsContent(120)
	if !strings.Contains(runs, app.catalog.T("runs_ledger_title")) || !strings.Contains(runs, app.catalog.T("app_runs_brief_title")) || !strings.Contains(runs, app.catalog.T("show_details")) {
		t.Fatalf("expected route-native runs content")
	}

	model.route = appRouteFindings
	findings := model.renderFindingsContent(120)
	if !strings.Contains(findings, app.catalog.T("findings_queue_title")) || !strings.Contains(findings, app.catalog.T("app_findings_brief_title")) || !strings.Contains(findings, app.catalog.T("show_details")) {
		t.Fatalf("expected route-native findings content")
	}

	model.route = appRouteRuntime
	runtime := model.renderRuntimeContent(120)
	if !strings.Contains(runtime, app.catalog.T("runtime_scanners_title")) || !strings.Contains(runtime, app.catalog.T("app_runtime_brief_title")) {
		t.Fatalf("expected route-native runtime content")
	}

	if run.ID == "" {
		t.Fatalf("expected populated focused fixture run")
	}
}

func TestAppShellRunEnterScopesFindings(t *testing.T) {
	app, run, _, _ := newFocusedRunFilterFixture(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteRuns,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.snapshot = app.buildTUISnapshot()
	model.width = 160
	model.height = 40
	for index, candidate := range model.snapshot.Portfolio.Runs {
		if candidate.ID == run.ID {
			model.cursor = index
			break
		}
	}

	updated, _ := model.activateSelection()
	next := updated.(appShellModel)
	if next.route != appRouteFindings {
		t.Fatalf("expected run enter to route to findings, got %v", next.route)
	}
	if next.findingsScopeRun != run.ID {
		t.Fatalf("expected findings scope to be %s, got %s", run.ID, next.findingsScopeRun)
	}
	if len(next.scopedFindings()) == 0 {
		t.Fatalf("expected scoped findings for selected run")
	}
}

func TestAppShellRunQuickKeyScopesFindings(t *testing.T) {
	app, run, _, _ := newFocusedRunFilterFixture(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteRuns,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.snapshot = app.buildTUISnapshot()
	for index, candidate := range model.snapshot.Portfolio.Runs {
		if candidate.ID == run.ID {
			model.cursor = index
			break
		}
	}

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("o")})
	next := updated.(appShellModel)
	if next.route != appRouteFindings || next.findingsScopeRun != run.ID {
		t.Fatalf("expected o to open scoped findings for %s, got route=%v scope=%s", run.ID, next.route, next.findingsScopeRun)
	}
}

func TestAppShellScopedFindingsPreferSnapshotData(t *testing.T) {
	app, run, _, _ := newFocusedRunFilterFixture(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteFindings,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.snapshot = app.buildTUISnapshot()
	model.findingsScopeRun = run.ID
	model.snapshot.Portfolio.Findings = []domain.Finding{
		{
			ScanID:      run.ID,
			ProjectID:   run.ProjectID,
			Fingerprint: "snapshot-only",
			Severity:    domain.SeverityMedium,
			Title:       "Snapshot Only",
			Status:      domain.FindingOpen,
		},
	}

	findings := model.scopedFindings()
	if len(findings) != 1 || findings[0].Fingerprint != "snapshot-only" {
		t.Fatalf("expected scoped findings to come from snapshot, got %+v", findings)
	}
}

func TestAppShellRunDetailLoadsAsynchronously(t *testing.T) {
	app, run, _, _ := newFocusedRunFilterFixture(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteRuns,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.snapshot = app.buildTUISnapshot()
	for index, candidate := range model.snapshot.Portfolio.Runs {
		if candidate.ID == run.ID {
			model.cursor = index
			break
		}
	}

	initial := model.renderRunDetailContent(120)
	if !strings.Contains(initial, app.catalog.T("app_loading_short")) {
		t.Fatalf("expected initial run detail to show loading state, got %q", initial)
	}

	cmd := model.scheduleSelectedRunDetailLoad()
	if cmd == nil {
		t.Fatalf("expected run detail load command")
	}
	msg := cmd()
	updated, _ := model.Update(msg)
	next := updated.(appShellModel)
	loaded := next.renderRunDetailContent(120)
	if strings.Contains(loaded, app.catalog.T("app_loading_short")) {
		t.Fatalf("expected loaded run detail to replace loading state, got %q", loaded)
	}
}

func TestAppShellRunQuickCancelAndRetry(t *testing.T) {
	app, _ := newTestTUIApp(t)
	project, _, err := app.service.EnsureProject(context.Background(), t.TempDir(), "Run Control Fixture", false)
	if err != nil {
		t.Fatalf("ensure project: %v", err)
	}

	queuedRun, err := app.service.EnqueueScan(project.ID, domain.ScanProfile{
		Mode:         domain.ModeSafe,
		Coverage:     domain.CoverageCore,
		Modules:      []string{"stack-detector"},
		SeverityGate: domain.SeverityHigh,
	})
	if err != nil {
		t.Fatalf("enqueue scan: %v", err)
	}

	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteRuns,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.snapshot = app.buildTUISnapshot()
	for index, candidate := range model.snapshot.Portfolio.Runs {
		if candidate.ID == queuedRun.ID {
			model.cursor = index
			break
		}
	}

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("c")})
	next := updated.(appShellModel)
	canceled, ok := app.service.GetRun(queuedRun.ID)
	if !ok || canceled.Status != domain.ScanCanceled {
		t.Fatalf("expected queued run to become canceled, got %+v", canceled)
	}
	if !strings.Contains(next.notice, queuedRun.ID) {
		t.Fatalf("expected cancel notice to mention run id, got %q", next.notice)
	}

	for index, candidate := range next.snapshot.Portfolio.Runs {
		if candidate.ID == queuedRun.ID {
			next.cursor = index
			break
		}
	}
	updated, _ = next.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("R")})
	retried := updated.(appShellModel)
	if len(retried.snapshot.Portfolio.Runs) < 2 {
		t.Fatalf("expected retry to create another run")
	}
	if !strings.Contains(retried.notice, queuedRun.ID) {
		t.Fatalf("expected retry notice to mention source run id, got %q", retried.notice)
	}
}

func TestAppShellRouteSwitchPreservesCursorAndDetail(t *testing.T) {
	app, _, _, _ := newFocusedRunFilterFixture(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteRuns,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.snapshot = app.buildTUISnapshot()
	model.route = appRouteRuns
	model.cursor = min(1, max(0, len(model.snapshot.Portfolio.Runs)-1))
	model.detailScroll = 4
	runsCursor := model.cursor

	model.setRoutePreservingState(appRouteFindings)
	model.cursor = min(1, max(0, len(model.scopedFindings())-1))
	model.detailScroll = 2

	model.setRoutePreservingState(appRouteRuns)
	if model.route != appRouteRuns {
		t.Fatalf("expected to return to runs route, got %v", model.route)
	}
	if model.cursor != runsCursor {
		t.Fatalf("expected runs cursor %d to be restored, got %d", runsCursor, model.cursor)
	}
	if model.detailScroll != 4 {
		t.Fatalf("expected runs detail scroll to be restored, got %d", model.detailScroll)
	}
}

func TestAppShellFindingsFiltersCycleAndReduceQueue(t *testing.T) {
	app, _, criticalTitle, _ := newFocusedRunFilterFixture(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteFindings,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.snapshot = app.buildTUISnapshot()

	allFindings := model.filteredScopedFindings()
	if len(allFindings) < 2 {
		t.Fatalf("expected multiple findings in focused fixture")
	}

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("f")})
	next := updated.(appShellModel)
	if next.currentFindingsSeverityFilter() != "critical" {
		t.Fatalf("expected critical severity filter, got %q", next.currentFindingsSeverityFilter())
	}
	filtered := next.filteredScopedFindings()
	if len(filtered) == 0 || len(filtered) >= len(allFindings) {
		t.Fatalf("expected severity filter to reduce findings: all=%d filtered=%d", len(allFindings), len(filtered))
	}
	for _, finding := range filtered {
		if finding.Severity != domain.SeverityCritical {
			t.Fatalf("expected only critical findings, got %s", finding.Severity)
		}
	}
	if !strings.Contains(next.notice, app.catalog.T("finding_filter_notice", next.currentFindingsSeverityFilterLabel(), next.currentFindingsStatusFilterLabel())) {
		t.Fatalf("expected filter notice, got %q", next.notice)
	}
	if !strings.Contains(next.renderFindingsContent(120), criticalTitle) {
		t.Fatalf("expected filtered findings content to contain critical finding title")
	}
}

func TestAppShellFindingsRoutePreservesFiltersAcrossRouteSwitch(t *testing.T) {
	app, _, _, _ := newFocusedRunFilterFixture(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteFindings,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.snapshot = app.buildTUISnapshot()
	model.findingsSeverityIdx = 1
	model.findingsStatusIdx = 1
	model.cursor = 1
	model.detailScroll = 3

	model.setRoutePreservingState(appRouteRuns)
	model.setRoutePreservingState(appRouteFindings)

	if model.currentFindingsSeverityFilter() != "critical" {
		t.Fatalf("expected findings severity filter to persist, got %q", model.currentFindingsSeverityFilter())
	}
	if model.currentFindingsStatusFilter() != "open" {
		t.Fatalf("expected findings status filter to persist, got %q", model.currentFindingsStatusFilter())
	}
}

func TestAppShellFindingsFilterResetKeyClearsFilters(t *testing.T) {
	app, _, _, _ := newFocusedRunFilterFixture(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteFindings,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.snapshot = app.buildTUISnapshot()
	model.findingsSeverityIdx = 2
	model.findingsStatusIdx = 3
	model.cursor = 1
	model.detailScroll = 4

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("0")})
	next := updated.(appShellModel)
	if next.currentFindingsSeverityFilter() != "all" || next.currentFindingsStatusFilter() != "all" {
		t.Fatalf("expected filters reset, got severity=%q status=%q", next.currentFindingsSeverityFilter(), next.currentFindingsStatusFilter())
	}
	if next.cursor != 0 || next.detailScroll != 0 {
		t.Fatalf("expected findings cursor/detail reset, got cursor=%d detail=%d", next.cursor, next.detailScroll)
	}
}

func TestAppShellSelectCurrentResolvesProjectInApp(t *testing.T) {
	app, _ := newTestTUIApp(t)
	root := t.TempDir()
	previousWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(previousWD)
	})
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteHome,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	updated, cmd := model.activateRow(appSelectableRow{Action: appShellActionSelectCurrent})
	next := updated.(appShellModel)
	if cmd == nil {
		t.Fatalf("expected project resolution command")
	}
	msg := cmd()
	projectMsg, ok := msg.(appShellProjectResolvedMsg)
	if !ok {
		t.Fatalf("expected project resolved message, got %T", msg)
	}
	updated, _ = next.Update(projectMsg)
	final := updated.(appShellModel)
	if final.route != appRouteScanReview {
		t.Fatalf("expected in-app project resolution to route to scan review, got %v", final.route)
	}
	if final.selectedProjectID == "" {
		t.Fatalf("expected selected project to be set")
	}
	if final.reviewContext.projectID != final.selectedProjectID {
		t.Fatalf("expected review context to track selected project, got %s for %s", final.reviewContext.projectID, final.selectedProjectID)
	}
	if final.alert {
		t.Fatalf("expected successful in-app project resolution")
	}
}

func TestAppShellScopedFindingsRouteStartsFresh(t *testing.T) {
	app, run, _, _ := newFocusedRunFilterFixture(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteRuns,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.snapshot = app.buildTUISnapshot()
	model.routeState[appRouteFindings] = routeViewState{Cursor: 4, DetailScroll: 9, FindingsSeverityIdx: 1, FindingsStatusIdx: 2}
	for index, candidate := range model.snapshot.Portfolio.Runs {
		if candidate.ID == run.ID {
			model.cursor = index
			break
		}
	}

	updated, _ := model.activateSelection()
	next := updated.(appShellModel)
	if next.route != appRouteFindings {
		t.Fatalf("expected route to findings, got %v", next.route)
	}
	if next.cursor != 0 {
		t.Fatalf("expected scoped findings cursor reset, got %d", next.cursor)
	}
	if next.detailScroll != 0 {
		t.Fatalf("expected scoped findings detail scroll reset, got %d", next.detailScroll)
	}
	if next.currentFindingsSeverityFilter() != "all" || next.currentFindingsStatusFilter() != "all" {
		t.Fatalf("expected scoped findings filters reset, got severity=%q status=%q", next.currentFindingsSeverityFilter(), next.currentFindingsStatusFilter())
	}
}

func TestAppShellClearFindingsScopeCommand(t *testing.T) {
	app, run, _, _ := newFocusedRunFilterFixture(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:            appRouteFindings,
		FindingsScopeRun: run.ID,
		Review:           defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.snapshot = app.buildTUISnapshot()
	model.cursor = 2
	model.detailScroll = 5
	model.routeState[appRouteFindings] = routeViewState{Cursor: 2, DetailScroll: 5, FindingsSeverityIdx: 1, FindingsStatusIdx: 1}

	updated, cmd := model.executePaletteCommand(paletteCommand{
		ID:     "clear-findings-scope",
		Action: appShellActionClearFinds,
	})
	next := updated.(appShellModel)
	if cmd != nil {
		t.Fatalf("expected clear findings scope to stay inside shell")
	}
	if next.findingsScopeRun != "" {
		t.Fatalf("expected findings scope to clear, got %s", next.findingsScopeRun)
	}
	if next.cursor != 0 || next.detailScroll != 0 {
		t.Fatalf("expected findings state to reset after clearing scope, got cursor=%d detail=%d", next.cursor, next.detailScroll)
	}
	if next.currentFindingsSeverityFilter() != "all" || next.currentFindingsStatusFilter() != "all" {
		t.Fatalf("expected findings filters to reset after clearing scope, got severity=%q status=%q", next.currentFindingsSeverityFilter(), next.currentFindingsStatusFilter())
	}
	if !strings.Contains(next.notice, app.catalog.T("app_findings_scope_cleared")) {
		t.Fatalf("expected cleared notice, got %q", next.notice)
	}
}

func TestAppShellRenderRunsEmptyStateIsContextual(t *testing.T) {
	app, _ := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteRuns,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.snapshot.Portfolio.Runs = nil
	model.width = 140
	model.height = 40

	out := model.renderRunsContent(120)
	for _, fragment := range []string{
		app.catalog.T("runs_focus_empty"),
	} {
		if !strings.Contains(out, fragment) {
			t.Fatalf("expected runs empty state to contain %q", fragment)
		}
	}
}

func TestAppShellRenderRuntimeEmptyDetailIsContextual(t *testing.T) {
	app, _ := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteRuntime,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.snapshot.Runtime.ScannerBundle = nil

	out := model.renderRuntimeDetailContent(100)
	for _, fragment := range []string{
		app.catalog.T("runtime_doctor_title"),
		app.catalog.T("runtime_available"),
	} {
		if !strings.Contains(out, fragment) {
			t.Fatalf("expected runtime empty detail to contain %q", fragment)
		}
	}
}

func TestAppShellRenderRouteSkeletonDuringPulse(t *testing.T) {
	app, _ := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteRuns,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.width = 140
	model.height = 40
	model.refreshing = true
	model.refreshingRoute = appRouteRuns
	model.snapshot = tuiSnapshot{}
	model.snapshotUpdatedAt = time.Time{}

	out := model.renderRouteContent(120)
	for _, fragment := range []string{
		app.catalog.T("app_loading_title"),
		app.catalog.T("app_loading_short"),
	} {
		if !strings.Contains(out, fragment) {
			t.Fatalf("expected route skeleton to contain %q", fragment)
		}
	}
}

func TestAppShellRenderMetaRowIncludesUpdatedChip(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteRuntime,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.width = 140
	model.snapshotUpdatedAt = time.Now()

	out := model.renderShellMetaRow(120)
	if !strings.Contains(out, app.catalog.T("runtime_meta_ready")) {
		t.Fatalf("expected meta row to include runtime status chip")
	}
	if !strings.Contains(out, app.catalog.T("app_sync_live")) && !strings.Contains(out, model.snapshotUpdatedClock()) {
		t.Fatalf("expected meta row to include sync freshness")
	}
}

func TestAppShellRefreshStartsAsyncRefreshState(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteRuntime,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})

	updated, cmd := model.Update(appShellRefreshMsg{})
	next := updated.(appShellModel)
	if cmd == nil {
		t.Fatalf("expected refresh command")
	}
	if !next.refreshing {
		t.Fatalf("expected refreshing state to be enabled")
	}
	if next.refreshingRoute != appRouteRuntime {
		t.Fatalf("expected refreshing route to be runtime, got %v", next.refreshingRoute)
	}
	if strings.Contains(next.renderShellMetaRow(120), app.catalog.T("app_refreshing")) {
		t.Fatalf("expected auto refresh to avoid showing refreshing chip")
	}
}

func TestAppShellRefreshSkipsLiveScanWhileStreaming(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteLiveScan,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.scanRunning = true

	updated, cmd := model.Update(appShellRefreshMsg{})
	next := updated.(appShellModel)
	if cmd == nil {
		t.Fatalf("expected refresh loop command to continue")
	}
	if next.refreshing {
		t.Fatalf("expected live scan refresh tick to skip full snapshot refresh while streaming")
	}
}

func TestAppShellRoutePulseDoesNotShowSkeletonWithoutRefresh(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteRuns,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.routePulse = 4

	if model.showRouteSkeleton() {
		t.Fatalf("expected route pulse alone to avoid skeleton state")
	}
}

func TestAppShellSnapshotLoadedClearsRefreshingState(t *testing.T) {
	app, _ := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteRuns,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.refreshing = true
	model.refreshingRoute = appRouteRuns
	model.refreshSeq = 1

	updated, _ := model.Update(appShellSnapshotLoadedMsg{
		snapshot: app.buildTUISnapshot(),
		route:    appRouteRuns,
		at:       time.Now(),
		seq:      1,
	})
	next := updated.(appShellModel)
	if next.refreshing {
		t.Fatalf("expected refreshing state to clear")
	}
	if !next.snapshotUpdatedAt.After(time.Time{}) {
		t.Fatalf("expected snapshot updated timestamp to be set")
	}
}

func TestAppShellSnapshotLoadedReconcilesMissingSelectedProject(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteHome,
		SelectedProjectID: "missing-project",
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})

	updated, _ := model.Update(appShellSnapshotLoadedMsg{
		snapshot: app.buildTUISnapshot(),
		route:    appRouteHome,
		at:       time.Now(),
		seq:      0,
	})
	next := updated.(appShellModel)
	if next.selectedProjectID != project.ID {
		t.Fatalf("expected missing selected project to reconcile to %s, got %s", project.ID, next.selectedProjectID)
	}
	if next.reviewContext.projectID != project.ID {
		t.Fatalf("expected review context to reconcile to %s, got %s", project.ID, next.reviewContext.projectID)
	}
}

func TestAppShellSelectedProjectUsesSnapshotData(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteHome,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.snapshot.Portfolio.Projects = nil

	if _, ok := model.selectedProject(); ok {
		t.Fatalf("expected selected project lookup to fail when snapshot has no matching project")
	}
}

func TestAppShellReconcileSnapshotStateClearsFindingsScopeFromSnapshot(t *testing.T) {
	app, run, _, _ := newFocusedRunFilterFixture(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:            appRouteFindings,
		FindingsScopeRun: run.ID,
		Review:           defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.snapshot = app.buildTUISnapshot()
	model.snapshot.Portfolio.Runs = nil

	model.reconcileSnapshotState(appRouteFindings)

	if model.findingsScopeRun != "" {
		t.Fatalf("expected stale findings scope to clear when run is missing from snapshot, got %s", model.findingsScopeRun)
	}
}

func TestAppShellScopedFindingsDoesNotFallbackToStoreWhenScopeMissingFromSnapshot(t *testing.T) {
	app, run, _, _ := newFocusedRunFilterFixture(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:            appRouteFindings,
		FindingsScopeRun: run.ID,
		Review:           defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.snapshot = app.buildTUISnapshot()
	model.snapshot.Portfolio.Runs = nil
	model.snapshot.Portfolio.Findings = nil

	findings := model.scopedFindings()
	if len(findings) != 0 {
		t.Fatalf("expected scoped findings to stay empty when snapshot no longer contains scoped run, got %d", len(findings))
	}
}

func TestAppShellSnapshotLoadedInvalidatesCurrentRouteAfterRouteChange(t *testing.T) {
	app, _ := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteHome,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.route = appRouteRuns
	model.refreshing = true
	model.refreshingRoute = appRouteHome
	model.refreshSeq = 3
	model.projectTreeCache["tree"] = []string{"cached"}
	model.runDetailCache["run"] = runDetailCacheEntry{err: "cached"}

	updated, _ := model.Update(appShellSnapshotLoadedMsg{
		snapshot: app.buildTUISnapshot(),
		route:    appRouteHome,
		at:       time.Now(),
		seq:      3,
	})
	next := updated.(appShellModel)
	if len(next.runDetailCache) != 0 {
		t.Fatalf("expected current route cache to be invalidated after route change")
	}
}

func TestAppShellIgnoresStaleSnapshotSequence(t *testing.T) {
	app, _ := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteRuns,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.refreshing = true
	model.refreshingRoute = appRouteRuns
	model.refreshSeq = 4
	before := model.snapshotUpdatedAt

	updated, _ := model.Update(appShellSnapshotLoadedMsg{
		snapshot: tuiSnapshot{},
		route:    appRouteRuns,
		at:       time.Now().Add(time.Minute),
		seq:      3,
	})
	next := updated.(appShellModel)
	if !next.snapshotUpdatedAt.Equal(before) {
		t.Fatalf("expected stale snapshot response to be ignored")
	}
	if !next.refreshing {
		t.Fatalf("expected refreshing state to remain until current sequence completes")
	}
}

func TestAppShellSecondaryProjectsRouteUsesStableCompatibilityNavigation(t *testing.T) {
	app, _ := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteHome,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.route = appRouteProjects
	if got := model.nextCompatibilityRoute(1); got != appRouteScanReview {
		t.Fatalf("expected projects route to advance to scan review, got %v", got)
	}
	if got := model.nextCompatibilityRoute(-1); got != appRouteHome {
		t.Fatalf("expected projects route to go back to home, got %v", got)
	}
}

func TestAppShellPaletteScanReviewWithoutProjectOpensPicker(t *testing.T) {
	app, _ := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteHome,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.selectedProjectID = ""

	updated, _ := model.executePaletteCommand(paletteCommand{
		ID:    "scan-review",
		Label: app.catalog.T("app_route_scan_review"),
		Route: appRouteScanReview,
	})
	next := updated.(appShellModel)
	if next.route != appRouteScanReview {
		t.Fatalf("expected scan review route, got %v", next.route)
	}
	if !next.projectPickerActive {
		t.Fatalf("expected project picker to open when scan review has no selected project")
	}
}

func TestAppShellSelectionSummaryShowsPosition(t *testing.T) {
	app, run, _, _ := newFocusedRunFilterFixture(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteRuns,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.snapshot = app.buildTUISnapshot()
	for index, candidate := range model.snapshot.Portfolio.Runs {
		if candidate.ID == run.ID {
			model.cursor = index
			break
		}
	}
	rows := model.runRows()
	summary := model.selectionSummary(rows, model.cursor, 0)
	if summary != app.catalog.T("app_selection_position", model.cursor+1, len(rows)) {
		t.Fatalf("unexpected selection summary: %q", summary)
	}
}

func TestAppShellSelectionContextSummaryIncludesLabel(t *testing.T) {
	rows := selectableRows{
		{Label: "First item"},
		{Label: "Second item"},
	}
	app, _ := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{Review: defaultScanReviewState(app.cfg.SandboxMode)})

	summary := model.selectionContextSummary(rows, 1, 0)
	if !strings.Contains(summary, "Second item") {
		t.Fatalf("expected selection context summary to include selected label, got %q", summary)
	}
}

func TestAppShellInvalidateCachesForRouteIsTargeted(t *testing.T) {
	app, _ := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteRuns,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.projectTreeCache["tree"] = []string{"a"}
	model.runDetailCache["run"] = runDetailCacheEntry{err: "cached"}
	model.scopedFindingsMap["scope"] = []domain.Finding{{Fingerprint: "fp"}}

	model.invalidateCachesForRoute(appRouteRuns)

	if len(model.runDetailCache) != 0 {
		t.Fatalf("expected run detail cache to be cleared")
	}
	if len(model.projectTreeCache) == 0 {
		t.Fatalf("expected project tree cache to stay warm")
	}
	if len(model.scopedFindingsMap) == 0 {
		t.Fatalf("expected scoped findings cache to stay warm")
	}
}

func TestAppShellProjectTreeLoadsAsynchronously(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteProjects,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.projectTreeCache = map[string][]string{}

	preview := model.projectTreePreview(project, 2, 8)
	if len(preview) == 0 || preview[0] != app.catalog.T("app_loading_short") {
		t.Fatalf("expected uncached project tree preview to show loading, got %#v", preview)
	}

	cmd := model.scheduleSelectedProjectTreeLoad()
	if cmd == nil {
		t.Fatalf("expected async project tree load command")
	}
	msg := cmd()
	updated, _ := model.Update(msg)
	next := updated.(appShellModel)

	lines := next.projectTreePreview(project, 2, 8)
	if len(lines) == 0 || lines[0] == app.catalog.T("app_loading_short") {
		t.Fatalf("expected loaded project tree preview, got %#v", lines)
	}
}

func TestAppShellRenderRuntimeRefreshPanelVisibleWhileRefreshing(t *testing.T) {
	app, _ := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:  appRouteRuntime,
		Review: defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.refreshing = true
	model.refreshingRoute = appRouteRuntime
	model.manualRefresh = true

	out := model.renderRuntimeRefreshPanel(80)
	if !strings.Contains(out, app.catalog.T("app_refreshing")) {
		t.Fatalf("expected runtime refresh panel to render refreshing label")
	}
}

func TestAppShellRouteSubtitleAndFooter(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteLiveScan,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})

	if subtitle := model.routeSubtitle(); !strings.Contains(subtitle, "flow") && !strings.Contains(subtitle, "debrief") && !strings.Contains(subtitle, "akış") && !strings.Contains(subtitle, "debrief") {
		t.Fatalf("expected live scan subtitle, got %q", subtitle)
	}
	if footer := model.footerText(); !strings.Contains(footer, "route") && !strings.Contains(footer, "rota") && !strings.Contains(footer, "ekran") && !strings.Contains(footer, "screen") {
		t.Fatalf("expected live scan footer, got %q", footer)
	}

	model.paletteActive = true
	if footer := model.footerText(); footer != app.catalog.T("app_palette_footer") {
		t.Fatalf("expected palette footer, got %q", footer)
	}
	model.paletteActive = false
	model.projectPickerActive = true
	if footer := model.footerText(); footer != app.catalog.T("app_project_picker_footer") {
		t.Fatalf("expected project picker footer, got %q", footer)
	}
}

func TestReviewModuleStateLabels(t *testing.T) {
	app, project := newTestTUIApp(t)
	project.DetectedStacks = []string{"go"}
	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteScanReview,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})

	if got := model.reviewModuleState(project, domain.ScanProfile{}, "nuclei", map[string]struct{}{}); got != app.catalog.T("app_scan_review_requires_target_short") {
		t.Fatalf("expected nuclei to require target, got %q", got)
	}
	if got := model.reviewModuleState(project, domain.ScanProfile{}, "knip", map[string]struct{}{}); got != app.catalog.T("app_scan_review_not_applicable") {
		t.Fatalf("expected knip to be not applicable for go project, got %q", got)
	}
	if got := model.reviewModuleState(project, domain.ScanProfile{}, "govulncheck", map[string]struct{}{"govulncheck": {}}); got != app.catalog.T("app_scan_review_ready") {
		t.Fatalf("expected included module to be ready, got %q", got)
	}
}
