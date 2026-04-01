package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/core"
	"github.com/batu3384/ironsentinel/internal/domain"
	"github.com/batu3384/ironsentinel/internal/i18n"
)

func newTestTUIApp(t *testing.T) (*App, domain.Project) {
	t.Helper()

	cfg := config.Config{
		DataDir:         filepath.Join(t.TempDir(), "data"),
		OutputDir:       filepath.Join(t.TempDir(), "output"),
		DefaultLanguage: "en",
	}
	service, err := core.New(cfg)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	app := &App{
		cfg:     cfg,
		service: service,
		lang:    i18n.EN,
		catalog: i18n.New(i18n.EN),
	}

	root := t.TempDir()
	project, _, err := app.service.EnsureProject(context.Background(), root, "Fixture", false)
	if err != nil {
		t.Fatalf("ensure project: %v", err)
	}
	return app, project
}

func newFocusedRunFilterFixture(t *testing.T) (*App, domain.ScanRun, string, string) {
	t.Helper()

	app, _ := newTestTUIApp(t)
	root := t.TempDir()
	content := strings.Join([]string{
		`GITHUB_TOKEN="ghp_123456789012345678901234567890123456"`,
		`password = "supersecret123"`,
	}, "\n")
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture file: %v", err)
	}

	project, _, err := app.service.EnsureProject(context.Background(), root, "Focused Filter Fixture", false)
	if err != nil {
		t.Fatalf("ensure focused filter project: %v", err)
	}

	run, err := app.service.EnqueueScan(project.ID, domain.ScanProfile{
		Mode:         domain.ModeSafe,
		Coverage:     domain.CoverageCore,
		Modules:      []string{"secret-heuristics"},
		SeverityGate: domain.SeverityHigh,
	})
	if err != nil {
		t.Fatalf("enqueue focused filter scan: %v", err)
	}
	if err := app.service.RunQueueWorker(context.Background(), true, nil); err != nil {
		t.Fatalf("run queue worker: %v", err)
	}

	findings := app.service.ListFindings(run.ID)
	criticalTitle, mediumTitle := "", ""
	for _, finding := range findings {
		switch finding.Severity {
		case domain.SeverityCritical:
			criticalTitle = finding.Title
		case domain.SeverityMedium:
			mediumTitle = finding.Title
		}
	}
	if criticalTitle == "" || mediumTitle == "" {
		t.Fatalf("expected critical and medium findings, got %+v", findings)
	}

	return app, run, criticalTitle, mediumTitle
}
