package domain

import "testing"

func TestRecalculateSummaryBlocksAtGate(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityMedium, Category: CategorySAST, Status: FindingInvestigating},
		{Severity: SeverityCritical, Category: CategorySecret, Status: FindingOpen},
		{Severity: SeverityLow, Category: CategoryMaintainability, Status: FindingAcceptedRisk},
	}

	summary := RecalculateSummary(findings, SeverityHigh)

	if !summary.Blocked {
		t.Fatalf("expected gate to block when a critical finding exists")
	}
	if summary.TotalFindings != 3 {
		t.Fatalf("expected 3 findings, got %d", summary.TotalFindings)
	}
	if summary.CountsBySeverity[SeverityCritical] != 1 {
		t.Fatalf("expected 1 critical finding, got %d", summary.CountsBySeverity[SeverityCritical])
	}
	if summary.CountsByCategory[CategorySecret] != 1 {
		t.Fatalf("expected 1 secret finding, got %d", summary.CountsByCategory[CategorySecret])
	}
	if summary.CountsByStatus[FindingInvestigating] != 1 {
		t.Fatalf("expected 1 investigating finding, got %d", summary.CountsByStatus[FindingInvestigating])
	}
}

func TestCalculateRunDeltaClassifiesNewExistingAndResolved(t *testing.T) {
	current := []Finding{
		{Fingerprint: "fp-existing", Severity: SeverityHigh, Title: "Existing finding"},
		{Fingerprint: "fp-new", Severity: SeverityCritical, Title: "New finding"},
	}
	baseline := []Finding{
		{Fingerprint: "fp-existing", Severity: SeverityHigh, Title: "Existing finding"},
		{Fingerprint: "fp-resolved", Severity: SeverityMedium, Title: "Resolved finding"},
	}

	delta := CalculateRunDelta(current, baseline, "run-2", "run-1", "prj-1")

	if delta.CountsByChange[FindingNew] != 1 {
		t.Fatalf("expected 1 new finding, got %d", delta.CountsByChange[FindingNew])
	}
	if delta.CountsByChange[FindingExisting] != 1 {
		t.Fatalf("expected 1 existing finding, got %d", delta.CountsByChange[FindingExisting])
	}
	if delta.CountsByChange[FindingResolved] != 1 {
		t.Fatalf("expected 1 resolved finding, got %d", delta.CountsByChange[FindingResolved])
	}
	if len(delta.NewFindings) != 1 || delta.NewFindings[0].Fingerprint != "fp-new" {
		t.Fatalf("expected fp-new to be classified as new")
	}
	if len(delta.ResolvedFindings) != 1 || delta.ResolvedFindings[0].Fingerprint != "fp-resolved" {
		t.Fatalf("expected fp-resolved to be classified as resolved")
	}
}
