package reports

import (
	"strings"
	"testing"

	"github.com/batu3384/ironsentinel/internal/domain"
)

func TestExportCSV(t *testing.T) {
	run := domain.ScanRun{ID: "run-2", ProjectID: "prj-1"}
	findings := []domain.Finding{
		{
			Fingerprint: "fp-1",
			Severity:    domain.SeverityHigh,
			Status:      domain.FindingInvestigating,
			Category:    domain.CategorySAST,
			Module:      "semgrep",
			RuleID:      "xss.rule",
			Title:       "Potential reflected XSS",
			Location:    "src/app.tsx",
			Owner:       "security",
			Tags:        []string{"frontend", "xss"},
			Note:        "Needs confirmation",
			Remediation: "Escape untrusted output.",
		},
	}
	delta := domain.CalculateRunDelta(findings, nil, run.ID, "", run.ProjectID)
	output, err := Export("csv", run, nil, findings, delta, nil)
	if err != nil {
		t.Fatalf("unexpected export error: %v", err)
	}
	if !strings.Contains(output, "Potential reflected XSS") {
		t.Fatalf("expected CSV output to include finding title")
	}
	if !strings.Contains(output, "investigating") {
		t.Fatalf("expected CSV output to include triage status")
	}
	if !strings.Contains(output, "frontend|xss") {
		t.Fatalf("expected CSV output to include tags")
	}
	if !strings.Contains(output, "new") {
		t.Fatalf("expected CSV output to include finding change")
	}
}

func TestExportSARIF(t *testing.T) {
	run := domain.ScanRun{
		ID:        "run-1",
		ProjectID: "prj-1",
		ModuleResults: []domain.ModuleResult{
			{
				Name:         "semgrep",
				Status:       domain.ModuleFailed,
				Attempts:     2,
				DurationMs:   1250,
				TimedOut:     true,
				FailureKind:  domain.ModuleFailureTimeout,
				FindingCount: 1,
			},
		},
	}
	findings := []domain.Finding{
		{
			Fingerprint: "fp-2",
			Severity:    domain.SeverityHigh,
			Status:      domain.FindingAcceptedRisk,
			RuleID:      "GHSA-123",
			Title:       "Package vulnerability",
			Location:    "package-lock.json",
			Owner:       "security",
			Tags:        []string{"dependency"},
		},
	}
	delta := domain.CalculateRunDelta(findings, nil, run.ID, "", run.ProjectID)
	output, err := Export("sarif", run, nil, findings, delta, nil)
	if err != nil {
		t.Fatalf("unexpected export error: %v", err)
	}
	if !strings.Contains(output, "\"version\": \"2.1.0\"") {
		t.Fatalf("expected SARIF version field in output")
	}
	if !strings.Contains(output, "package-lock.json") {
		t.Fatalf("expected SARIF location in output")
	}
	if !strings.Contains(output, "triageStatus") {
		t.Fatalf("expected SARIF properties to include triage status")
	}
	if !strings.Contains(output, "\"change\": \"new\"") {
		t.Fatalf("expected SARIF properties to include finding change")
	}
	if !strings.Contains(output, "\"moduleResultSummaries\"") {
		t.Fatalf("expected SARIF properties to include module execution summaries")
	}
	if !strings.Contains(output, "\"failureKind\": \"timeout\"") {
		t.Fatalf("expected SARIF properties to include module failure kind")
	}
	if !strings.Contains(output, "\"retried\": 1") {
		t.Fatalf("expected SARIF properties to include module execution stats")
	}
}

func TestExportHTMLIncludesModuleExecutionDetails(t *testing.T) {
	run := domain.ScanRun{
		ID:        "run-3",
		ProjectID: "prj-1",
		ModuleResults: []domain.ModuleResult{
			{
				Name:         "gitleaks",
				Status:       domain.ModuleCompleted,
				Attempts:     1,
				DurationMs:   842,
				FindingCount: 2,
				Summary:      "Secrets detected",
			},
			{
				Name:        "codeql",
				Status:      domain.ModuleSkipped,
				Attempts:    0,
				DurationMs:  0,
				FailureKind: domain.ModuleFailureSkipped,
				Summary:     "Tool unavailable",
			},
		},
	}
	findings := []domain.Finding{
		{
			Fingerprint: "fp-3",
			Severity:    domain.SeverityCritical,
			RuleID:      "secret.rule",
			Title:       "Hardcoded secret",
			Location:    "app.env",
			Module:      "gitleaks",
		},
	}
	delta := domain.CalculateRunDelta(findings, nil, run.ID, "", run.ProjectID)
	output, err := Export("html", run, nil, findings, delta, nil)
	if err != nil {
		t.Fatalf("unexpected export error: %v", err)
	}
	if !strings.Contains(output, "Module execution") {
		t.Fatalf("expected HTML output to include module execution section")
	}
	if !strings.Contains(output, "Failed modules: 0 | Skipped modules: 1 | Retried modules: 0") {
		t.Fatalf("expected HTML output to include module execution summary")
	}
	if !strings.Contains(output, "Tool unavailable") {
		t.Fatalf("expected HTML output to include module summary")
	}
	if !strings.Contains(output, "<td>0</td><td>0ms</td><td>skipped</td>") {
		t.Fatalf("expected HTML output to include skipped module execution details")
	}
}
