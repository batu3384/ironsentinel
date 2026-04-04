package vex

import (
	"strings"
	"testing"

	"github.com/batu3384/ironsentinel/internal/domain"
)

func TestApplyOpenVEXMarksMatchingSCAFinding(t *testing.T) {
	doc, err := ParseOpenVEX([]byte(`{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.test/vex",
  "author": "Security Team",
  "role": "VEX Author",
  "timestamp": "2026-04-04T12:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {"name": "CVE-2026-0001"},
      "products": [{"@id": "pkg:npm/lodash@4.17.21"}],
      "status": "not_affected",
      "justification": "vulnerable_code_not_present"
    }
  ]
}`))
	if err != nil {
		t.Fatalf("parse vex: %v", err)
	}

	findings := []domain.Finding{{
		Category:    domain.CategorySCA,
		RuleID:      "CVE-2026-0001",
		Title:       "lodash vulnerability",
		Location:    "lodash",
		Fingerprint: "fp-lodash",
	}}
	sbomProducts := map[string][]string{
		"lodash": {"pkg:npm/lodash@4.17.21"},
	}

	applied, summary := Apply(findings, doc, sbomProducts)
	if got := applied[0].VEXStatus; got != domain.VEXStatusNotAffected {
		t.Fatalf("expected VEX status not_affected, got %q", got)
	}
	if got := applied[0].VEXJustification; got != "vulnerable_code_not_present" {
		t.Fatalf("expected VEX justification to be preserved, got %q", got)
	}
	if summary.AppliedCount != 1 {
		t.Fatalf("expected 1 applied statement, got %d", summary.AppliedCount)
	}
}

func TestApplyOpenVEXDoesNotTouchNonMatchingFinding(t *testing.T) {
	doc, err := ParseOpenVEX([]byte(`{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.test/vex",
  "author": "Security Team",
  "role": "VEX Author",
  "timestamp": "2026-04-04T12:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {"name": "CVE-2026-0001"},
      "products": [{"@id": "pkg:npm/lodash@4.17.21"}],
      "status": "fixed"
    }
  ]
}`))
	if err != nil {
		t.Fatalf("parse vex: %v", err)
	}

	findings := []domain.Finding{{
		Category:    domain.CategorySCA,
		RuleID:      "CVE-2026-0002",
		Location:    "axios",
		Fingerprint: "fp-axios",
	}}

	applied, summary := Apply(findings, doc, map[string][]string{"axios": {"pkg:npm/axios@1.7.0"}})
	if applied[0].VEXStatus != "" {
		t.Fatalf("expected finding to remain untouched, got %q", applied[0].VEXStatus)
	}
	if summary.AppliedCount != 0 {
		t.Fatalf("expected 0 applied statements, got %d", summary.AppliedCount)
	}
}

func TestParseOpenVEXRejectsMissingStatements(t *testing.T) {
	_, err := ParseOpenVEX([]byte(`{"@context":"https://openvex.dev/ns/v0.2.0","version":1}`))
	if err == nil {
		t.Fatalf("expected parse error")
	}
	if !strings.Contains(err.Error(), "statements") {
		t.Fatalf("expected statements error, got %v", err)
	}
}
