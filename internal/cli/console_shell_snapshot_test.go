package cli

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/batu3384/ironsentinel/internal/domain"
)

func TestConsoleShellMissionSnapshot(t *testing.T) {
	app, project := newTestTUIApp(t)
	app.uiMode = uiModeStandard

	profile := domain.ScanProfile{
		Mode:         domain.ModeSafe,
		Coverage:     domain.CoverageCore,
		Modules:      []string{"surface-inventory", "semgrep", "gitleaks"},
		SeverityGate: domain.SeverityHigh,
		Isolation:    domain.IsolationAuto,
	}

	model := newConsoleShellModel(app, consoleShellLaunchState{
		SelectedProjectID: project.ID,
	}, context.Background())
	model.stage = consoleStageMission
	model.width = 160
	model.height = 46
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
				"Correlating source graph and dependency edges.",
			},
			run: domain.ScanRun{
				Status: domain.ScanRunning,
				Summary: domain.ScanSummary{
					TotalFindings: 2,
					CountsBySeverity: map[domain.Severity]int{
						domain.SeverityHigh:   1,
						domain.SeverityMedium: 1,
					},
				},
				ModuleResults: []domain.ModuleResult{
					{Name: "surface-inventory", Status: domain.ModuleCompleted, Summary: "Mapped repository exposure."},
					{Name: "semgrep", Status: domain.ModuleRunning, Summary: "Correlating semantic rules."},
					{Name: "gitleaks", Status: domain.ModuleQueued, Summary: "Queued for secret validation."},
				},
			},
		},
		run: domain.ScanRun{
			Status: domain.ScanRunning,
			Summary: domain.ScanSummary{
				TotalFindings: 2,
				CountsBySeverity: map[domain.Severity]int{
					domain.SeverityHigh:   1,
					domain.SeverityMedium: 1,
				},
			},
			ModuleResults: []domain.ModuleResult{
				{Name: "surface-inventory", Status: domain.ModuleCompleted, Summary: "Mapped repository exposure."},
				{Name: "semgrep", Status: domain.ModuleRunning, Summary: "Correlating semantic rules."},
				{Name: "gitleaks", Status: domain.ModuleQueued, Summary: "Queued for secret validation."},
			},
		},
	}

	out := []byte(model.View())
	for _, fragment := range []string{
		app.catalog.T("status"),
		app.phaseLabel(),
		app.catalog.T("app_label_module"),
		app.toolLabel(),
		app.catalog.T("scan_mc_activity"),
		"SEMGREP",
		project.DisplayName,
	} {
		if !strings.Contains(string(out), fragment) {
			t.Fatalf("console shell mission snapshot is missing %q\n%s", fragment, string(out))
		}
	}
}

func TestConsoleShellDebriefDrawerSnapshot(t *testing.T) {
	model := newCompletedConsoleShellModel(t)
	model.drawer = consoleDrawerFindings

	out := []byte(model.View())
	fragments := []string{
		model.app.catalog.T("scan_debrief_title"),
		model.app.catalog.T("findings_title"),
		model.app.catalog.T("scan_mc_handoff_title"),
		model.app.catalog.T("scan_mc_activity"),
		model.mission.project.DisplayName,
		"Leaked deploy",
	}
	if !containsAll(out, fragments...) {
		t.Fatalf("console shell debrief drawer snapshot is missing expected sections: %v\n%s", missingFragments(out, fragments...), string(out))
	}
}

func TestConsoleShellBrandHeroMotionFreezesForPlainAndReducedContexts(t *testing.T) {
	t.Run("plain", func(t *testing.T) {
		app, _ := newTestTUIApp(t)
		app.uiMode = uiModePlain

		frameOne := app.renderBrandHeroForRoute(140, 1, "Launch control", appRouteLiveScan)
		frameTwo := app.renderBrandHeroForRoute(140, 2, "Launch control", appRouteLiveScan)

		if frameOne != frameTwo {
			t.Fatalf("expected plain mode brand hero to stay static across frames\nframe 1:\n%s\n\nframe 2:\n%s", frameOne, frameTwo)
		}
	})

	t.Run("reduced-motion", func(t *testing.T) {
		t.Setenv("IRONSENTINEL_REDUCED_MOTION", "1")

		app, _ := newTestTUIApp(t)
		app.uiMode = uiModeStandard

		frameOne := app.renderBrandHeroForRoute(140, 1, "Mission control", appRouteLiveScan)
		frameTwo := app.renderBrandHeroForRoute(140, 2, "Mission control", appRouteLiveScan)

		if frameOne != frameTwo {
			t.Fatalf("expected reduced-motion brand hero to stay static across frames\nframe 1:\n%s\n\nframe 2:\n%s", frameOne, frameTwo)
		}
	})
}

func TestMissionAvatarMotionFreezesForPlainAndReducedContexts(t *testing.T) {
	t.Run("plain", func(t *testing.T) {
		app, project := newTestTUIApp(t)
		app.uiMode = uiModePlain
		console := &liveScanConsole{
			project: project,
			profile: domain.ScanProfile{Mode: domain.ModeSafe, Coverage: domain.CoverageCore},
			run: domain.ScanRun{
				Status: domain.ScanRunning,
			},
			frame: 1,
		}

		frameOne := app.missionAgentAvatar(console)
		console.frame = 3
		frameTwo := app.missionAgentAvatar(console)

		if frameOne != frameTwo {
			t.Fatalf("expected plain mode mission avatar to stay static across frames\nframe 1:\n%s\n\nframe 2:\n%s", frameOne, frameTwo)
		}
	})

	t.Run("reduced-motion", func(t *testing.T) {
		t.Setenv("IRONSENTINEL_REDUCED_MOTION", "1")

		app, project := newTestTUIApp(t)
		app.uiMode = uiModeStandard
		console := &liveScanConsole{
			project: project,
			profile: domain.ScanProfile{Mode: domain.ModeSafe, Coverage: domain.CoverageCore},
			run: domain.ScanRun{
				Status: domain.ScanRunning,
			},
			frame: 1,
		}

		frameOne := app.missionAgentAvatar(console)
		console.frame = 4
		frameTwo := app.missionAgentAvatar(console)

		if frameOne != frameTwo {
			t.Fatalf("expected reduced-motion mission avatar to stay static across frames\nframe 1:\n%s\n\nframe 2:\n%s", frameOne, frameTwo)
		}
	})
}
