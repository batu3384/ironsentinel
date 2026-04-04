package core

import (
	"testing"
	"time"

	"github.com/batu3384/ironsentinel/internal/domain"
)

func TestEnrichFindingBoostsReachableSCAPriorityAndTags(t *testing.T) {
	project := domain.Project{
		ID:             "prj-1",
		DisplayName:    "fixture",
		TargetHandle:   "fixture",
		LocationHint:   "/tmp/fixture",
		DetectedStacks: []string{"go"},
		CreatedAt:      time.Now().UTC(),
	}

	reachable := enrichFinding(project, domain.Finding{
		ScanID:       "run-1",
		ProjectID:    project.ID,
		Category:     domain.CategorySCA,
		RuleID:       "GO-2026-0001",
		Title:        "Reachable Go advisory",
		Severity:     domain.SeverityHigh,
		Confidence:   0.8,
		Reachability: domain.ReachabilityReachable,
		Location:     "go.mod",
		Module:       "govulncheck",
	})
	unknown := enrichFinding(project, domain.Finding{
		ScanID:       "run-1",
		ProjectID:    project.ID,
		Category:     domain.CategorySCA,
		RuleID:       "CVE-2026-0002",
		Title:        "Unknown package advisory",
		Severity:     domain.SeverityHigh,
		Confidence:   0.8,
		Reachability: domain.ReachabilityUnknown,
		Location:     "go.mod",
		Module:       "trivy",
	})

	if reachable.Priority <= unknown.Priority {
		t.Fatalf("expected reachable SCA finding priority %.2f to exceed unknown priority %.2f", reachable.Priority, unknown.Priority)
	}
	if !containsTag(reachable.Tags, "sca:reachable") {
		t.Fatalf("expected reachable finding to include sca:reachable tag, got %v", reachable.Tags)
	}
	if containsTag(unknown.Tags, "sca:reachable") {
		t.Fatalf("did not expect unknown finding to include sca:reachable tag, got %v", unknown.Tags)
	}
}

func TestEnrichFindingBoostsMaliciousDependencySignals(t *testing.T) {
	project := domain.Project{
		ID:             "prj-1",
		DisplayName:    "fixture",
		TargetHandle:   "fixture",
		LocationHint:   "/tmp/fixture",
		DetectedStacks: []string{"node"},
		CreatedAt:      time.Now().UTC(),
	}

	malicious := enrichFinding(project, domain.Finding{
		ScanID:       "run-1",
		ProjectID:    project.ID,
		Category:     domain.CategorySCA,
		RuleID:       "dependency_confusion.unpinned_npm_scope",
		Title:        "Potential dependency confusion risk for npm package \"@acme/internal-ui\"",
		Severity:     domain.SeverityHigh,
		Confidence:   0.68,
		Reachability: domain.ReachabilityPossible,
		Location:     "package.json",
		Module:       "dependency-confusion",
	})
	ordinary := enrichFinding(project, domain.Finding{
		ScanID:       "run-1",
		ProjectID:    project.ID,
		Category:     domain.CategorySCA,
		RuleID:       "CVE-2026-9999",
		Title:        "Package vulnerability",
		Severity:     domain.SeverityHigh,
		Confidence:   0.68,
		Reachability: domain.ReachabilityPossible,
		Location:     "package.json",
		Module:       "grype",
	})

	if malicious.Priority <= ordinary.Priority {
		t.Fatalf("expected malicious dependency signal priority %.2f to exceed ordinary SCA priority %.2f", malicious.Priority, ordinary.Priority)
	}
	if !containsTag(malicious.Tags, "supply-chain:dependency-confusion") {
		t.Fatalf("expected dependency confusion tag, got %v", malicious.Tags)
	}
	if !containsTag(malicious.Tags, "supply-chain:malicious") {
		t.Fatalf("expected malicious dependency tag, got %v", malicious.Tags)
	}
}

func containsTag(tags []string, target string) bool {
	for _, tag := range tags {
		if tag == target {
			return true
		}
	}
	return false
}
