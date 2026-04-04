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

func TestEvaluateSupportsReachabilityAndTagSelectors(t *testing.T) {
	current := []domain.Finding{
		{
			Fingerprint:  "fp-reachable",
			Severity:     domain.SeverityHigh,
			Category:     domain.CategorySCA,
			Reachability: domain.Reachability(" Reachable "),
			Tags:         []string{"sca:reachable"},
			Title:        "Reachable supply-chain finding",
		},
		{
			Fingerprint:  "fp-malicious",
			Severity:     domain.SeverityMedium,
			Category:     domain.CategorySCA,
			Reachability: domain.ReachabilityPossible,
			Tags:         []string{"supply-chain:malicious", "supply-chain:dependency-confusion"},
			Title:        "Dependency confusion signal",
		},
		{
			Fingerprint:  "fp-unknown",
			Severity:     domain.SeverityHigh,
			Category:     domain.CategorySCA,
			Reachability: domain.ReachabilityUnknown,
			Title:        "Unknown reachability finding",
		},
	}
	delta := domain.CalculateRunDelta(current, nil, "run-2", "", "prj-1")

	pack := domain.PolicyPack{
		ID:    "supply-chain",
		Title: "Supply chain selectors",
		Rules: []domain.PolicyRule{
			{
				ID:           "reachable-sca",
				Title:        "Reachable SCA",
				Outcome:      domain.PolicyOutcomeFail,
				Threshold:    1,
				ChangeScope:  domain.FindingNew,
				Category:     domain.CategorySCA,
				Reachability: domain.Reachability("REACHABLE"),
			},
			{
				ID:        "malicious-supply-chain",
				Title:     "Malicious supply chain",
				Outcome:   domain.PolicyOutcomeFail,
				Threshold: 1,
				Category:  domain.CategorySCA,
				TagsAny:   []string{"supply-chain:malicious"},
			},
		},
	}

	evaluation := Evaluate(pack, "run-2", "", current, delta)
	if evaluation.Passed {
		t.Fatalf("expected selector-based policy to fail")
	}
	if len(evaluation.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(evaluation.Results))
	}
	resultsByRule := make(map[string]domain.PolicyRuleResult, len(evaluation.Results))
	for _, result := range evaluation.Results {
		resultsByRule[result.Rule.ID] = result
	}
	reachable := resultsByRule["reachable-sca"]
	if reachable.MatchedCount != 1 {
		t.Fatalf("expected reachable rule to match 1 finding, got %d", reachable.MatchedCount)
	}
	if reachable.Findings[0].Fingerprint != "fp-reachable" {
		t.Fatalf("expected reachable rule to match fp-reachable, got %s", reachable.Findings[0].Fingerprint)
	}
	malicious := resultsByRule["malicious-supply-chain"]
	if malicious.MatchedCount != 1 {
		t.Fatalf("expected malicious selector to match 1 finding, got %d", malicious.MatchedCount)
	}
	if malicious.Findings[0].Fingerprint != "fp-malicious" {
		t.Fatalf("expected malicious selector to match fp-malicious, got %s", malicious.Findings[0].Fingerprint)
	}
}

func TestEvaluatePremiumDefaultPolicyFailsOnReachableAndMaliciousSupplyChainSignals(t *testing.T) {
	current := []domain.Finding{
		{
			Fingerprint:  "fp-reachable-sca",
			Severity:     domain.SeverityHigh,
			Category:     domain.CategorySCA,
			Reachability: domain.ReachabilityReachable,
			Tags:         []string{"sca:reachable"},
			Title:        "Reachable package vulnerability",
		},
		{
			Fingerprint:  "fp-malicious-sca",
			Severity:     domain.SeverityMedium,
			Category:     domain.CategorySCA,
			Reachability: domain.ReachabilityPossible,
			Tags:         []string{"supply-chain:malicious"},
			Title:        "Dependency confusion signal",
		},
	}
	delta := domain.CalculateRunDelta(current, nil, "run-9", "", "prj-1")

	evaluation := Evaluate(Builtin(PremiumDefaultPolicy), "run-9", "", current, delta)
	if evaluation.Passed {
		t.Fatalf("expected premium policy to fail on reachable and malicious supply-chain findings")
	}

	var reachableMatched, maliciousMatched bool
	for _, result := range evaluation.Results {
		switch result.Rule.ID {
		case "reachable-sca-regression":
			reachableMatched = result.MatchedCount == 1 && result.Outcome == domain.PolicyOutcomeFail
		case "malicious-supply-chain":
			maliciousMatched = result.MatchedCount == 1 && result.Outcome == domain.PolicyOutcomeFail
		}
	}
	if !reachableMatched {
		t.Fatalf("expected premium policy to fail reachable-sca-regression")
	}
	if !maliciousMatched {
		t.Fatalf("expected premium policy to fail malicious-supply-chain")
	}
}
