package reports

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/batu3384/ironsentinel/internal/domain"
)

func testRunReport(run domain.ScanRun, findings []domain.Finding, delta domain.RunDelta) domain.RunReport {
	reportFindings := make([]domain.RunReportFinding, 0, len(findings))
	changeByFingerprint := BuildChangeIndex(delta)
	for _, finding := range findings {
		reportFindings = append(reportFindings, domain.RunReportFinding{
			Finding: finding,
			Change:  DefaultChange(changeByFingerprint[finding.Fingerprint]),
		})
	}
	return domain.RunReport{
		Run:             run,
		Findings:        reportFindings,
		Delta:           delta,
		ModuleStats:     ModuleExecutionStats(run.ModuleResults),
		ModuleSummaries: BuildModuleSummaries(run.ModuleResults),
	}
}

func TestExportCSV(t *testing.T) {
	run := domain.ScanRun{ID: "run-2", ProjectID: "prj-1"}
	findings := []domain.Finding{
		{
			Fingerprint:  "fp-1",
			Severity:     domain.SeverityHigh,
			Status:       domain.FindingInvestigating,
			Category:     domain.CategorySAST,
			Module:       "semgrep",
			RuleID:       "xss.rule",
			Title:        "Potential reflected XSS",
			Location:     "src/app.tsx",
			Reachability: domain.ReachabilityReachable,
			Owner:        "security",
			Tags:         []string{"frontend", "xss"},
			Note:         "Needs confirmation",
			Remediation:  "Escape untrusted output.",
		},
	}
	delta := domain.CalculateRunDelta(findings, nil, run.ID, "", run.ProjectID)
	output, err := Export("csv", testRunReport(run, findings, delta))
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
	if !strings.Contains(output, "reachable") {
		t.Fatalf("expected CSV output to include reachability")
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
			Fingerprint:  "fp-2",
			Severity:     domain.SeverityHigh,
			Status:       domain.FindingAcceptedRisk,
			RuleID:       "GHSA-123",
			Title:        "Package vulnerability",
			Location:     "package-lock.json",
			Reachability: domain.ReachabilityReachable,
			Owner:        "security",
			Tags:         []string{"dependency"},
		},
	}
	delta := domain.CalculateRunDelta(findings, nil, run.ID, "", run.ProjectID)
	output, err := Export("sarif", testRunReport(run, findings, delta))
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
	if !strings.Contains(output, "\"reachability\": \"reachable\"") {
		t.Fatalf("expected SARIF properties to include reachability")
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
	output, err := Export("html", testRunReport(run, findings, delta))
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

func TestExportHTMLSortsFindingsTableByPriority(t *testing.T) {
	run := domain.ScanRun{ID: "run-4", ProjectID: "prj-1"}
	findings := []domain.Finding{
		{
			Fingerprint: "fp-low",
			Severity:    domain.SeverityMedium,
			RuleID:      "CVE-2026-0002",
			Title:       "Lower priority dependency issue",
			Location:    "package-lock.json",
			Module:      "trivy",
			Priority:    2.1,
		},
		{
			Fingerprint: "fp-high",
			Severity:    domain.SeverityHigh,
			RuleID:      "GO-2026-0001",
			Title:       "Reachable dependency issue",
			Location:    "go.mod",
			Module:      "govulncheck",
			Priority:    8.4,
		},
	}
	delta := domain.CalculateRunDelta(findings, nil, run.ID, "", run.ProjectID)
	output, err := Export("html", testRunReport(run, findings, delta))
	if err != nil {
		t.Fatalf("unexpected export error: %v", err)
	}

	tableIndex := strings.Index(output, "<tbody>")
	if tableIndex < 0 {
		t.Fatalf("expected findings table body in HTML output")
	}
	table := output[tableIndex:]
	highIndex := strings.Index(table, "Reachable dependency issue")
	lowIndex := strings.Index(table, "Lower priority dependency issue")
	if highIndex < 0 || lowIndex < 0 {
		t.Fatalf("expected both finding titles in HTML table")
	}
	if highIndex > lowIndex {
		t.Fatalf("expected findings table to sort by priority; high-priority entry appeared after lower-priority entry")
	}
}

func TestExportCSVIncludesVEXColumns(t *testing.T) {
	run := domain.ScanRun{ID: "run-vex-csv", ProjectID: "prj-1"}
	findings := []domain.Finding{{
		Fingerprint:        "fp-1",
		Severity:           domain.SeverityHigh,
		Category:           domain.CategorySCA,
		RuleID:             "CVE-2026-0001",
		Title:              "Dependency issue",
		Location:           "lodash",
		VEXStatus:          domain.VEXStatusNotAffected,
		VEXJustification:   "vulnerable_code_not_present",
		VEXStatementSource: "fixtures/openvex.json",
	}}
	delta := domain.CalculateRunDelta(findings, nil, run.ID, "", run.ProjectID)
	output, err := Export("csv", testRunReport(run, findings, delta))
	if err != nil {
		t.Fatalf("unexpected export error: %v", err)
	}
	for _, want := range []string{"vex_status", "vex_justification", "not_affected", "vulnerable_code_not_present"} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected CSV output to contain %q", want)
		}
	}
}

func TestExportOpenVEXIncludesSCAPackages(t *testing.T) {
	sbomPath := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(sbomPath, []byte(`{"components":[{"name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21"}]}`), 0o644); err != nil {
		t.Fatalf("write sbom: %v", err)
	}

	run := domain.ScanRun{
		ID:        "run-openvex",
		ProjectID: "prj-1",
		ArtifactRefs: []domain.ArtifactRef{
			{Kind: "sbom", Label: "CycloneDX", URI: sbomPath},
		},
	}
	findings := []domain.Finding{{
		Fingerprint: "fp-1",
		Category:    domain.CategorySCA,
		RuleID:      "CVE-2026-0001",
		Title:       "Dependency issue",
		Location:    "lodash",
	}}
	delta := domain.CalculateRunDelta(findings, nil, run.ID, "", run.ProjectID)
	output, err := Export("openvex", testRunReport(run, findings, delta))
	if err != nil {
		t.Fatalf("unexpected export error: %v", err)
	}
	for _, want := range []string{
		`"@context": "https://openvex.dev/ns/v0.2.0"`,
		`"name": "CVE-2026-0001"`,
		`"@id": "pkg:npm/lodash@4.17.21"`,
		`"status": "under_investigation"`,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected OpenVEX output to contain %q, got %q", want, output)
		}
	}
}

func TestExportSBOMAttestationIncludesArtifactDigest(t *testing.T) {
	sbomPath := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX","components":[]}`), 0o644); err != nil {
		t.Fatalf("write sbom: %v", err)
	}

	run := domain.ScanRun{
		ID:        "run-attest",
		ProjectID: "prj-1",
		ArtifactRefs: []domain.ArtifactRef{
			{Kind: "sbom", Label: "CycloneDX", URI: sbomPath},
		},
	}
	output, err := Export("sbom-attestation", testRunReport(run, nil, domain.NewRunDelta(run.ID, "", run.ProjectID)))
	if err != nil {
		t.Fatalf("unexpected export error: %v", err)
	}
	for _, want := range []string{
		`"type": "https://github.com/batu3384/ironsentinel/attestations/sbom/v1"`,
		`"runId": "run-attest"`,
		`"subjects"`,
		`"sha256"`,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected sbom attestation output to contain %q, got %q", want, output)
		}
	}
}
