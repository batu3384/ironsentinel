package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/batu3384/ironsentinel/internal/domain"
	"github.com/batu3384/ironsentinel/internal/i18n"
)

func TestScanMissionSnapshot(t *testing.T) {
	app, project := newTestTUIApp(t)
	app.uiMode = uiModeStandard
	previousMetricsReader := missionRuntimeMetricsReader
	missionRuntimeMetricsReader = func(scanMissionModel) missionRuntimeMetrics {
		return missionRuntimeMetrics{
			CPUPercent:    0,
			MemoryMiB:     12.5,
			Goroutines:    9,
			ModulePerMin:  0,
			FindingPerMin: 0,
			HealthLabel:   "Breach",
			HealthSummary: "1 critical finding(s) are currently shaping the mission posture.",
		}
	}
	t.Cleanup(func() {
		missionRuntimeMetricsReader = previousMetricsReader
	})

	model := scanMissionModel{
		app:         app,
		project:     project,
		profile:     domain.ScanProfile{Mode: domain.ModeSafe, Coverage: domain.CoverageCore, Modules: []string{"surface-inventory", "script-audit", "semgrep", "gitleaks"}},
		projectTree: []string{"fixture", "  ├─ src/", "  ├─ .github/workflows/", "  └─ package.json"},
		launchedAt:  time.Unix(1_763_000_000, 0).UTC(),
		done:        false,
		console: &liveScanConsole{
			project:    project,
			profile:    domain.ScanProfile{Mode: domain.ModeSafe, Coverage: domain.CoverageCore},
			frame:      4,
			lastEvent:  "Semgrep semantic rules are traversing the source graph.",
			lastStatus: "Correlating static analysis and dependency signals.",
			lastPhase:  "Code analysis",
			lastModule: "semgrep",
			telemetry: []string{
				"Queued semantic analysis lane.",
				"Promoted semgrep to active execution.",
				"Correlating source graph and dependency edges.",
			},
			recentFindings: []domain.Finding{
				{
					Fingerprint: "fp-critical",
					Severity:    domain.SeverityCritical,
					Category:    domain.CategorySecret,
					Title:       "Leaked GitHub token in .env",
					Location:    ".env:3",
				},
				{
					Fingerprint: "fp-high",
					Severity:    domain.SeverityHigh,
					Category:    domain.CategorySAST,
					Title:       "Command injection sink reachable from router",
					Location:    "src/http/handler.go:41",
				},
			},
			run: domain.ScanRun{
				Status: domain.ScanRunning,
				Summary: domain.ScanSummary{
					TotalFindings: 3,
					CountsBySeverity: map[domain.Severity]int{
						domain.SeverityCritical: 1,
						domain.SeverityHigh:     1,
						domain.SeverityMedium:   1,
					},
				},
				ModuleResults: []domain.ModuleResult{
					{Name: "surface-inventory", Category: domain.CategoryPlatform, Status: domain.ModuleCompleted, Summary: "Enumerated repository attack surface.", Attempts: 1, DurationMs: 80},
					{Name: "script-audit", Category: domain.CategoryPlatform, Status: domain.ModuleCompleted, Summary: "Audited workflow and package scripts.", Attempts: 1, DurationMs: 120},
					{Name: "semgrep", Category: domain.CategorySAST, Status: domain.ModuleRunning, Summary: "Correlating semantic rules across the source graph.", Attempts: 1, FindingCount: 2, DurationMs: 2100},
					{Name: "gitleaks", Category: domain.CategorySecret, Status: domain.ModuleQueued, Summary: "Waiting in hardened execution queue.", Attempts: 0},
				},
			},
		},
		width:  160,
		height: 46,
	}

	out := []byte(model.View())
	if !containsAll(out, "Mission brief", "Module queue and lane map", "Execution stream", "Threat board", "Health posture", "SEMGREP") {
		t.Fatalf("scan mission snapshot is missing expected sections")
	}
}

func TestAppShellHomeSnapshot(t *testing.T) {
	app, project := newTestTUIApp(t)
	app.uiMode = uiModeStandard

	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteHome,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.width = 160
	model.height = 46
	model.frame = 4

	out := []byte(model.View())
	if !containsAll(out,
		"IRONSENTINEL",
		"Launchpad",
		"Mission focus",
		app.catalog.T("app_label_workspace"),
		project.DisplayName,
	) {
		t.Fatalf("app shell home snapshot is missing expected sections")
	}
}

func TestAppShellScanReviewSnapshot(t *testing.T) {
	app, project := newTestTUIApp(t)
	app.uiMode = uiModeStandard

	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteScanReview,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.width = 170
	model.height = 48
	model.frame = 5

	out := []byte(model.View())
	fragments := []string{
		app.catalog.T("app_route_scan_review"),
		project.DisplayName,
		app.catalog.T("app_scan_review_preset"),
		app.catalog.T("app_scan_review_plan_title"),
	}
	if !containsAll(out, fragments...) {
		t.Fatalf("app shell scan review snapshot is missing expected sections: %v\n%s", missingFragments(out, fragments...), string(out))
	}
}

func TestAppShellTurkishHomeSnapshot(t *testing.T) {
	app, project := newTestTUIApp(t)
	app.uiMode = uiModeStandard
	app.lang = i18n.TR
	app.catalog = i18n.New(i18n.TR)

	model := newAppShellModel(app, appShellLaunchState{
		Route:             appRouteHome,
		SelectedProjectID: project.ID,
		Review:            defaultScanReviewState(app.cfg.SandboxMode),
	})
	model.width = 160
	model.height = 46
	model.frame = 3

	out := []byte(model.View())
	if !containsAll(out,
		"IRONSENTINEL",
		"Başlatma güvertesi",
		app.catalog.T("app_home_focus_title"),
		app.catalog.T("app_label_workspace"),
		project.DisplayName,
	) {
		t.Fatalf("turkish app shell snapshot is missing expected sections")
	}
}

func containsAll(out []byte, fragments ...string) bool {
	text := string(out)
	for _, fragment := range fragments {
		if !strings.Contains(text, fragment) {
			return false
		}
	}
	return true
}

func missingFragments(out []byte, fragments ...string) []string {
	text := string(out)
	missing := make([]string, 0, len(fragments))
	for _, fragment := range fragments {
		if !strings.Contains(text, fragment) {
			missing = append(missing, fragment)
		}
	}
	return missing
}
