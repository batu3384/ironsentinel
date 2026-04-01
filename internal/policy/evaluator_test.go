package policy

import (
	"testing"

	"github.com/batu3384/ironsentinel/internal/domain"
)

func TestEvaluatePremiumDefaultPolicyFailsOnNewCriticalAndSecrets(t *testing.T) {
	current := []domain.Finding{
		{Fingerprint: "fp-critical", Severity: domain.SeverityCritical, Category: domain.CategorySecret, Title: "Critical secret"},
		{Fingerprint: "fp-maint", Severity: domain.SeverityLow, Category: domain.CategoryMaintainability, Title: "Unused code"},
	}
	delta := domain.CalculateRunDelta(current, nil, "run-2", "", "prj-1")

	evaluation := Evaluate(Builtin(PremiumDefaultPolicy), "run-2", "", current, delta)
	if evaluation.Passed {
		t.Fatalf("expected premium policy to fail on a new critical secret")
	}

	failCount := 0
	for _, result := range evaluation.Results {
		if result.Outcome == domain.PolicyOutcomeFail {
			failCount++
		}
	}
	if failCount < 2 {
		t.Fatalf("expected at least two failing rules, got %d", failCount)
	}
}
