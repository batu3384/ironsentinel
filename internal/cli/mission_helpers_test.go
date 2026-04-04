package cli

import (
	"strings"
	"testing"

	"github.com/batu3384/ironsentinel/internal/domain"
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
