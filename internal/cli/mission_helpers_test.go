package cli

import (
	"strings"
	"testing"

	"github.com/batu3384/ironsentinel/internal/domain"
	"github.com/batu3384/ironsentinel/internal/i18n"
)

func TestFindingPriorityAndExposureSummariesHighlightSCASignals(t *testing.T) {
	app, _ := newTestTUIApp(t)
	finding := domain.Finding{
		Category:     domain.CategorySCA,
		Severity:     domain.SeverityHigh,
		Priority:     8.4,
		EPSSPercent:  78.0,
		Reachability: domain.ReachabilityReachable,
		Tags:         []string{"supply-chain:dependency-confusion"},
	}

	priority := app.findingPriorityLabel(finding)
	if !strings.Contains(priority, "reachable path") {
		t.Fatalf("expected priority label to mention reachability, got %q", priority)
	}
	if !strings.Contains(priority, "dependency confusion signal") {
		t.Fatalf("expected priority label to mention supply-chain reason, got %q", priority)
	}

	exposure := app.findingExposureSummary(finding)
	if !strings.Contains(exposure, "Reason reachable path | dependency confusion signal") {
		t.Fatalf("expected exposure summary to explain why the finding is high priority, got %q", exposure)
	}
}

func TestFindingSignalSummaryIncludesVEXState(t *testing.T) {
	app, _ := newTestTUIApp(t)
	finding := domain.Finding{
		Category:         domain.CategorySCA,
		Severity:         domain.SeverityHigh,
		Reachability:     domain.ReachabilityReachable,
		VEXStatus:        domain.VEXStatusNotAffected,
		VEXJustification: "vulnerable_code_not_present",
	}

	signal := app.findingSignalSummary(finding)
	if !strings.Contains(signal, "reachable path") {
		t.Fatalf("expected reachability signal, got %q", signal)
	}
	if !strings.Contains(signal, "not affected") {
		t.Fatalf("expected VEX status signal, got %q", signal)
	}
	if !strings.Contains(signal, "vulnerable code not present") {
		t.Fatalf("expected VEX justification signal, got %q", signal)
	}
}

func TestConsoleDebriefReportLinesIncludeOperationalDecisionAndFixPlan(t *testing.T) {
	app, _ := newTestTUIApp(t)
	run := domain.ScanRun{
		ID:        "run-actionable",
		ProjectID: "prj-actionable",
		Status:    domain.ScanCompleted,
		Profile: domain.ScanProfile{
			Mode:     domain.ModeSafe,
			Coverage: domain.CoveragePremium,
			Modules:  []string{"gitleaks", "osv-scanner", "zaproxy"},
		},
		Summary: domain.ScanSummary{
			TotalFindings: 2,
			CountsBySeverity: map[domain.Severity]int{
				domain.SeverityHigh:   1,
				domain.SeverityMedium: 1,
			},
		},
		ModuleResults: []domain.ModuleResult{
			{Name: "gitleaks", Status: domain.ModuleCompleted, Summary: "Secrets checked"},
			{Name: "osv-scanner", Status: domain.ModuleCompleted, Summary: "Dependency graph checked"},
			{Name: "zaproxy", Status: domain.ModuleSkipped, FailureKind: domain.ModuleFailureSkipped, Summary: "Target URL not configured"},
		},
	}
	findings := []domain.Finding{
		{
			Fingerprint:  "fp-secret",
			Severity:     domain.SeverityHigh,
			Category:     domain.CategorySecret,
			Module:       "gitleaks",
			Title:        "Hardcoded secret",
			Location:     ".env",
			Remediation:  "Rotate the exposed secret and remove it from history.",
			Priority:     9.4,
			Reachability: domain.ReachabilityRepository,
		},
	}

	output := strings.Join(app.consoleDebriefReportLines(run, findings, nil), "\n")
	for _, want := range []string{
		"Execution:",
		"Coverage:",
		"Policy:",
		"Runtime:",
		"P0",
		"P1",
		"Validation:",
		"ironsentinel scan . --strict",
		"ironsentinel campaigns create",
		"--project prj-actionable",
		"--run run-actionable",
		"--finding fp-secret",
		"zaproxy",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected actionable debrief to contain %q\n%s", want, output)
		}
	}
	if strings.Contains(output, "campaign create --from-run") {
		t.Fatalf("debrief should not emit the removed campaign command\n%s", output)
	}
}

func TestTurkishBadgesUseLocaleAwareUppercase(t *testing.T) {
	app, _ := newTestTUIApp(t)
	app.lang = i18n.TR
	app.catalog = i18n.New(i18n.TR)

	output := strings.Join([]string{
		app.severityBadge(domain.SeverityCritical),
		app.severityBadge(domain.SeverityInfo),
		app.modeBadge(domain.ModeSafe),
	}, "\n")
	for _, want := range []string{"KRİTİK", "BİLGİ", "GÜVENLİ"} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected Turkish badge output to contain %q, got %q", want, output)
		}
	}
	for _, bad := range []string{"KRITIK", "BILGI", "GUVENLI"} {
		if strings.Contains(output, bad) {
			t.Fatalf("expected Turkish badge output not to contain ASCII-only %q, got %q", bad, output)
		}
	}
}
