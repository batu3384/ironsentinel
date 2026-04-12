package cli

import (
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/batu3384/ironsentinel/internal/domain"
	"github.com/batu3384/ironsentinel/internal/i18n"
)

func TestScanMissionModelRecommendedAction(t *testing.T) {
	app, _ := newTestTUIApp(t)
	model := scanMissionModel{app: app}

	model.requiredErr = errors.New("runtime broken")
	if action := model.recommendedAction(); action != scanMissionActionDoctor {
		t.Fatalf("expected doctor action, got %s", action)
	}

	model.requiredErr = nil
	model.findings = []domain.Finding{{Fingerprint: "fp-1", Severity: domain.SeverityHigh, Title: "Leaked key"}}
	if action := model.recommendedAction(); action != scanMissionActionReview {
		t.Fatalf("expected review action, got %s", action)
	}

	model.findings = nil
	if action := model.recommendedAction(); action != scanMissionActionDetails {
		t.Fatalf("expected details action, got %s", action)
	}
}

func TestScanMissionModelEnterUsesRecommendedAction(t *testing.T) {
	app, _ := newTestTUIApp(t)
	model := scanMissionModel{
		app:  app,
		done: true,
		findings: []domain.Finding{
			{Fingerprint: "fp-1", Severity: domain.SeverityHigh, Title: "Leaked key"},
		},
	}

	updated, cmd := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	next := updated.(scanMissionModel)
	if next.action != scanMissionActionReview {
		t.Fatalf("expected enter to choose review, got %s", next.action)
	}
	if cmd == nil {
		t.Fatalf("expected quit command after enter")
	}
}

func TestScanMissionModelRunningQRequestsCancel(t *testing.T) {
	app, _ := newTestTUIApp(t)
	canceled := false
	model := scanMissionModel{
		app: app,
		cancel: func() {
			canceled = true
		},
	}

	updated, cmd := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	next := updated.(scanMissionModel)
	if cmd != nil {
		t.Fatalf("expected running q to wait for shutdown instead of quitting")
	}
	if !canceled {
		t.Fatalf("expected cancel callback to run")
	}
	if !next.aborting {
		t.Fatalf("expected model to enter aborting state")
	}
	if next.notice == "" || !next.alert {
		t.Fatalf("expected alert notice after cancel request")
	}
}

func TestScanMissionModelSharedDoneFooterStillOffersFollowUpActions(t *testing.T) {
	app, _ := newTestTUIApp(t)
	model := scanMissionModel{
		app:  app,
		done: true,
		findings: []domain.Finding{
			{Fingerprint: "fp-1", Severity: domain.SeverityHigh, Title: "Leaked key"},
		},
	}

	footer := model.footerText()
	if !strings.Contains(footer, app.catalog.T("scan_mode_live_footer_review")) {
		t.Fatalf("expected shared live-scan footer to preserve review affordance, got %q", footer)
	}
}

func TestScanMissionModelSharedTickStillAnimates(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("IRONSENTINEL_REDUCED_MOTION", "")
	t.Setenv("TERM", "xterm-256color")

	app, project := newTestTUIApp(t)
	model := scanMissionModel{
		app: app,
		console: &liveScanConsole{
			project: project,
			profile: domain.ScanProfile{Modules: []string{"semgrep"}},
			frame:   2,
			run: domain.ScanRun{
				Status: domain.ScanRunning,
				ModuleResults: []domain.ModuleResult{
					{Name: "semgrep", Status: domain.ModuleRunning},
				},
			},
		},
	}

	updated, cmd := model.Update(scanMissionTickMsg(time.Unix(1_763_000_100, 0)))
	next := updated.(scanMissionModel)
	if next.console.frame != 3 {
		t.Fatalf("expected shared live-scan tick to advance frame, got %d", next.console.frame)
	}
	if cmd == nil {
		t.Fatalf("expected shared live-scan tick to reschedule")
	}
	msg := cmd()
	if _, ok := msg.(scanMissionTickMsg); !ok {
		t.Fatalf("expected shared live-scan tick command to emit scanMissionTickMsg, got %T", msg)
	}
}

func TestScanMissionModelScrollKeysAdjustDetailViewport(t *testing.T) {
	app, _ := newTestTUIApp(t)
	model := scanMissionModel{
		app:    app,
		width:  140,
		height: 40,
	}

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyPgDown})
	next := updated.(scanMissionModel)
	if next.detailScroll <= 0 {
		t.Fatalf("expected pgdown to advance detail scroll, got %d", next.detailScroll)
	}

	updated, _ = next.Update(tea.KeyMsg{Type: tea.KeyPgUp})
	next = updated.(scanMissionModel)
	if next.detailScroll != 0 {
		t.Fatalf("expected pgup to return detail scroll to 0, got %d", next.detailScroll)
	}
}

func TestRenderBrandHeroIncludesIronSentinel(t *testing.T) {
	app, _ := newTestTUIApp(t)

	hero := app.renderBrandHero(140, 2, "subtitle")
	if !strings.Contains(hero, "IRONSENTINEL") {
		t.Fatalf("expected hero to contain IRONSENTINEL banner, got %q", hero)
	}
	if !strings.Contains(hero, strings.ToUpper(app.catalog.T("brand_mascot_scout"))) {
		t.Fatalf("expected hero to include scout mascot")
	}
}

func TestScanMissionViewIncludesAdvancedDashboardPanels(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := scanMissionModel{
		app:         app,
		project:     project,
		profile:     domain.ScanProfile{Mode: domain.ModeSafe, Coverage: domain.CoverageCore, Modules: []string{"surface-inventory", "semgrep", "gitleaks"}},
		projectTree: []string{"fixture", "  ├─ src/", "  └─ package.json"},
		launchedAt:  time.Now().Add(-30 * time.Second),
		console: &liveScanConsole{
			project:   project,
			profile:   domain.ScanProfile{Mode: domain.ModeSafe, Coverage: domain.CoverageCore},
			frame:     3,
			lastEvent: "Semgrep rule set is active.",
			run: domain.ScanRun{
				Status: domain.ScanRunning,
				Summary: domain.ScanSummary{
					TotalFindings: 2,
					CountsBySeverity: map[domain.Severity]int{
						domain.SeverityCritical: 1,
						domain.SeverityHigh:     1,
						domain.SeverityMedium:   0,
						domain.SeverityLow:      0,
						domain.SeverityInfo:     0,
					},
				},
				ModuleResults: []domain.ModuleResult{
					{Name: "surface-inventory", Status: domain.ModuleCompleted, Summary: "Done", Attempts: 1},
					{Name: "semgrep", Status: domain.ModuleRunning, Summary: "Running", Attempts: 1},
				},
			},
		},
		width:  160,
		height: 48,
	}

	view := model.View()
	for _, fragment := range []string{"Mission brief", "Module queue and lane map", "Execution stream", "Threat board", "Current", "Next", app.catalog.T("app_lane_kind_fast"), project.DisplayName} {
		if !strings.Contains(view, fragment) {
			t.Fatalf("expected view to contain %q", fragment)
		}
	}
}

func TestScanMissionViewIncludesScrollHintWhenPanelOverflows(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := scanMissionModel{
		app:         app,
		project:     project,
		profile:     domain.ScanProfile{Mode: domain.ModeSafe, Coverage: domain.CoverageCore, Modules: []string{"surface-inventory", "semgrep", "gitleaks"}},
		projectTree: []string{"fixture", "  ├─ src/", "  └─ package.json"},
		launchedAt:  time.Now().Add(-30 * time.Second),
		width:       160,
		height:      36,
		console: &liveScanConsole{
			project:    project,
			profile:    domain.ScanProfile{Mode: domain.ModeSafe, Coverage: domain.CoverageCore},
			frame:      3,
			eventCount: 32,
			lastEvent:  strings.Repeat("Semgrep telemetry stream is active. ", 6),
			run: domain.ScanRun{
				Status: domain.ScanRunning,
				Summary: domain.ScanSummary{
					TotalFindings: 4,
					CountsBySeverity: map[domain.Severity]int{
						domain.SeverityCritical: 1,
						domain.SeverityHigh:     2,
						domain.SeverityMedium:   1,
					},
				},
				ModuleResults: []domain.ModuleResult{
					{Name: "surface-inventory", Status: domain.ModuleCompleted, Summary: "Done", Attempts: 1},
					{Name: "semgrep", Status: domain.ModuleRunning, Summary: "Running", Attempts: 1},
				},
			},
			telemetry: []string{
				"telemetry-01", "telemetry-02", "telemetry-03", "telemetry-04", "telemetry-05",
				"telemetry-06", "telemetry-07", "telemetry-08", "telemetry-09", "telemetry-10",
				"telemetry-11", "telemetry-12",
			},
			recentFindings: []domain.Finding{
				{Fingerprint: "fp-1", Severity: domain.SeverityCritical, Title: "Critical leak", Module: "semgrep"},
				{Fingerprint: "fp-2", Severity: domain.SeverityHigh, Title: "High leak", Module: "gitleaks"},
				{Fingerprint: "fp-3", Severity: domain.SeverityMedium, Title: "Medium leak", Module: "trivy"},
			},
		},
	}

	view := model.View()
	if !strings.Contains(view, app.catalog.T("app_help_scroll_hint")) {
		t.Fatalf("expected mission view to contain scroll hint when a detail panel overflows")
	}
}

func TestScanMissionViewRendersTurkishDeckCopy(t *testing.T) {
	app, project := newTestTUIApp(t)
	app.lang = i18n.TR
	app.catalog = i18n.New(i18n.TR)
	model := scanMissionModel{
		app:         app,
		project:     project,
		profile:     domain.ScanProfile{Mode: domain.ModeSafe, Coverage: domain.CoverageCore, Modules: []string{"surface-inventory", "secret-heuristics"}},
		projectTree: []string{"örnek", "  ├─ src/", "  └─ package.json"},
		launchedAt:  time.Now().Add(-15 * time.Second),
		console: &liveScanConsole{
			project:    project,
			profile:    domain.ScanProfile{Mode: domain.ModeSafe, Coverage: domain.CoverageCore},
			frame:      2,
			eventCount: 7,
			lastEvent:  "Gizli bilgi taraması sürüyor.",
			run: domain.ScanRun{
				Status: domain.ScanRunning,
				Summary: domain.ScanSummary{
					TotalFindings: 1,
					CountsBySeverity: map[domain.Severity]int{
						domain.SeverityCritical: 0,
						domain.SeverityHigh:     1,
						domain.SeverityMedium:   0,
						domain.SeverityLow:      0,
						domain.SeverityInfo:     0,
					},
				},
				ModuleResults: []domain.ModuleResult{
					{Name: "surface-inventory", Status: domain.ModuleCompleted, Summary: "Tamamlandı", Attempts: 1},
					{Name: "secret-heuristics", Status: domain.ModuleRunning, Summary: "Çalışıyor", Attempts: 1},
				},
			},
		},
		width:  160,
		height: 48,
	}

	view := model.View()
	for _, fragment := range []string{"Görev özeti", "Yürütme akışı", "Tehdit panosu", "Ön kontrol"} {
		if !strings.Contains(view, fragment) {
			t.Fatalf("expected Turkish view to contain %q", fragment)
		}
	}
}

func TestScanMissionViewStaysReadableOnSmallViewport(t *testing.T) {
	app, project := newTestTUIApp(t)
	app.lang = i18n.TR
	app.catalog = i18n.New(i18n.TR)
	model := scanMissionModel{
		app:         app,
		project:     project,
		profile:     domain.ScanProfile{Mode: domain.ModeDeep, Coverage: domain.CoverageFull, Modules: []string{"surface-inventory", "semgrep", "gitleaks", "trivy"}},
		projectTree: []string{"takvim", "  ├─ Sources/", "  └─ Package.swift"},
		launchedAt:  time.Now().Add(-20 * time.Second),
		console: &liveScanConsole{
			project:    project,
			profile:    domain.ScanProfile{Mode: domain.ModeDeep, Coverage: domain.CoverageFull},
			frame:      2,
			lastEvent:  "Semgrep semantic analysis is traversing source files.",
			lastStatus: "Code lane is active.",
			lastPhase:  "Kod ve gizli bilgiler",
			lastModule: "semgrep",
			run: domain.ScanRun{
				Status: domain.ScanRunning,
				Summary: domain.ScanSummary{
					TotalFindings: 1,
					CountsBySeverity: map[domain.Severity]int{
						domain.SeverityHigh: 1,
					},
				},
				ModuleResults: []domain.ModuleResult{
					{Name: "surface-inventory", Status: domain.ModuleCompleted, Summary: "Done", Attempts: 1},
					{Name: "semgrep", Status: domain.ModuleRunning, Summary: "Running", Attempts: 1},
				},
			},
		},
		width:  84,
		height: 24,
	}

	view := model.View()
	for _, fragment := range []string{"IRONSENTINEL", "Görev özeti", "Yürütme akışı", "Sağlık duruşu"} {
		if !strings.Contains(view, fragment) {
			t.Fatalf("expected compact mission view to contain %q", fragment)
		}
	}
}

func TestMissionCPUPercentUsesBaselineDelta(t *testing.T) {
	value := missionCPUPercent(14, 10, 2*time.Second)
	if value < 199 || value > 201 {
		t.Fatalf("expected baseline-adjusted cpu percent near 200, got %.2f", value)
	}

	if value := missionCPUPercent(8, 10, 2*time.Second); value != 0 {
		t.Fatalf("expected negative delta to clamp to 0, got %.2f", value)
	}
}
