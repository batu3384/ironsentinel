package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
)

func TestParseGrypeParsesMatches(t *testing.T) {
	output := []byte(`{
  "matches": [
    {
      "vulnerability": {"id": "CVE-2026-0001", "severity": "High", "dataSource": "https://example.test/cve"},
      "artifact": {"name": "openssl", "version": "3.0.0", "locations": [{"path": "dist/app"}]}
    }
  ]
}`)

	result, findings, err := parseGrype(domain.AgentScanRequest{ScanID: "run-1", ProjectID: "prj-1"}, "grype", output)
	if err != nil {
		t.Fatalf("parse grype: %v", err)
	}
	if result.FindingCount != 1 || len(findings) != 1 {
		t.Fatalf("expected one grype finding, got result=%d findings=%d", result.FindingCount, len(findings))
	}
	if findings[0].Category != domain.CategorySCA {
		t.Fatalf("expected SCA category, got %s", findings[0].Category)
	}
	if findings[0].EvidenceRef != "https://example.test/cve" {
		t.Fatalf("expected data source evidence, got %q", findings[0].EvidenceRef)
	}
}

func TestParseTfsecParsesInfrastructureFinding(t *testing.T) {
	output := []byte(`{
  "results": [
    {
      "rule_id": "aws-s3-enable-versioning",
      "long_id": "AVD-AWS-0089",
      "description": "Bucket versioning disabled",
      "severity": "HIGH",
      "resolution": "Enable versioning",
      "location": {"filename": "main.tf"}
    }
  ]
}`)

	result, findings, err := parseTfsec(domain.AgentScanRequest{ScanID: "run-2", ProjectID: "prj-1"}, "tfsec", output)
	if err != nil {
		t.Fatalf("parse tfsec: %v", err)
	}
	if result.FindingCount != 1 || len(findings) != 1 {
		t.Fatalf("expected one tfsec finding, got result=%d findings=%d", result.FindingCount, len(findings))
	}
	if findings[0].RuleID != "AVD-AWS-0089" {
		t.Fatalf("expected long_id as rule id, got %q", findings[0].RuleID)
	}
}

func TestHeuristicDependencyConfusionFlagsUnpinnedInternalPackage(t *testing.T) {
	root := t.TempDir()
	body := `{"name":"acme-console","dependencies":{"acme-console-shared":"1.0.0"}}`
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(body), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	result, findings, err := heuristicDependencyConfusion(context.Background(), config.Config{ArtifactRedaction: true}, domain.AgentScanRequest{
		ScanID:      "run-3",
		ProjectID:   "prj-1",
		DisplayName: "acme-console",
		TargetPath:  root,
	}, t.TempDir())
	if err != nil {
		t.Fatalf("heuristic dependency confusion: %v", err)
	}
	if result.FindingCount == 0 || len(findings) == 0 {
		t.Fatalf("expected dependency confusion finding")
	}
	if !strings.Contains(findings[0].Title, "dependency confusion") {
		t.Fatalf("expected dependency confusion title, got %q", findings[0].Title)
	}
}

func TestHeuristicBinaryEntropyFlagsPackedArtifact(t *testing.T) {
	root := t.TempDir()
	bytes := make([]byte, 8192)
	for i := range bytes {
		bytes[i] = byte(i % 256)
	}
	target := filepath.Join(root, "payload.bin")
	if err := os.WriteFile(target, bytes, 0o755); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	result, findings, err := heuristicBinaryEntropy(context.Background(), config.Config{ArtifactRedaction: true}, domain.AgentScanRequest{
		ScanID:     "run-4",
		ProjectID:  "prj-1",
		TargetPath: root,
	}, t.TempDir())
	if err != nil {
		t.Fatalf("heuristic binary entropy: %v", err)
	}
	if result.FindingCount == 0 || len(findings) == 0 {
		t.Fatalf("expected entropy finding")
	}
	if findings[0].Module != "binary-entropy" {
		t.Fatalf("expected binary-entropy module, got %q", findings[0].Module)
	}
}

func TestHeuristicRuntimeConfigAuditIgnoresHealthyXcodeDebugBlocks(t *testing.T) {
	root := t.TempDir()
	projectDir := filepath.Join(root, "App.xcodeproj")
	if err := os.MkdirAll(projectDir, 0o755); err != nil {
		t.Fatalf("mkdir project dir: %v", err)
	}
	project := `{
/* Begin XCBuildConfiguration section */
		03AD04B2 /* Debug */ = {
			buildSettings = {
				GCC_PREPROCESSOR_DEFINITIONS = (
					"$(inherited)",
					"DEBUG=1",
				);
				ENABLE_TESTABILITY = YES;
				SWIFT_ACTIVE_COMPILATION_CONDITIONS = DEBUG;
				SWIFT_OPTIMIZATION_LEVEL = "-Onone";
			};
			name = Debug;
		};
		E5A58070 /* Release */ = {
			buildSettings = {
				SWIFT_OPTIMIZATION_LEVEL = "-O";
			};
			name = Release;
		};
/* End XCBuildConfiguration section */
}`
	if err := os.WriteFile(filepath.Join(projectDir, "project.pbxproj"), []byte(project), 0o644); err != nil {
		t.Fatalf("write project: %v", err)
	}

	_, findings, err := heuristicRuntimeConfigAudit(context.Background(), config.Config{ArtifactRedaction: true}, domain.AgentScanRequest{
		ScanID:     "run-runtime-xcode",
		ProjectID:  "prj-runtime-xcode",
		TargetPath: root,
	}, t.TempDir())
	if err != nil {
		t.Fatalf("heuristicRuntimeConfigAudit returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for healthy Xcode debug/release split, got %d", len(findings))
	}
}

func TestHeuristicRuntimeConfigAuditFlagsReleaseDebugLeakInXcodeProject(t *testing.T) {
	root := t.TempDir()
	projectDir := filepath.Join(root, "App.xcodeproj")
	if err := os.MkdirAll(projectDir, 0o755); err != nil {
		t.Fatalf("mkdir project dir: %v", err)
	}
	project := `{
/* Begin XCBuildConfiguration section */
		E5A58070 /* Release */ = {
			buildSettings = {
				SWIFT_ACTIVE_COMPILATION_CONDITIONS = DEBUG;
				SWIFT_OPTIMIZATION_LEVEL = "-Onone";
			};
			name = Release;
		};
/* End XCBuildConfiguration section */
}`
	if err := os.WriteFile(filepath.Join(projectDir, "project.pbxproj"), []byte(project), 0o644); err != nil {
		t.Fatalf("write project: %v", err)
	}

	_, findings, err := heuristicRuntimeConfigAudit(context.Background(), config.Config{ArtifactRedaction: true}, domain.AgentScanRequest{
		ScanID:     "run-runtime-xcode-release",
		ProjectID:  "prj-runtime-xcode-release",
		TargetPath: root,
	}, t.TempDir())
	if err != nil {
		t.Fatalf("heuristicRuntimeConfigAudit returned error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected release debug leakage to be flagged")
	}
}

func TestParseGrypeMatchesGoldenFindingShape(t *testing.T) {
	output := []byte(`{
  "matches": [
    {
      "vulnerability": {"id": "CVE-2026-0001", "severity": "High", "dataSource": "https://example.test/cve"},
      "artifact": {"name": "openssl", "version": "3.0.0", "locations": [{"path": "dist/app"}]}
    }
  ]
}`)

	_, findings, err := parseGrype(domain.AgentScanRequest{ScanID: "run-1", ProjectID: "prj-1"}, "grype", output)
	if err != nil {
		t.Fatalf("parse grype: %v", err)
	}
	bytes, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		t.Fatalf("marshal findings: %v", err)
	}
	golden, err := os.ReadFile(filepath.Join("testdata", "grype_findings.golden.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if strings.TrimSpace(string(bytes)) != strings.TrimSpace(string(golden)) {
		t.Fatalf("grype finding output drifted\nwant:\n%s\n\ngot:\n%s", string(golden), string(bytes))
	}
}

func TestParseTfsecMatchesGoldenFindingShape(t *testing.T) {
	output := []byte(`{
  "results": [
    {
      "rule_id": "aws-s3-enable-versioning",
      "long_id": "AVD-AWS-0089",
      "description": "Bucket versioning disabled",
      "severity": "HIGH",
      "resolution": "Enable versioning",
      "location": {"filename": "main.tf"}
    }
  ]
}`)

	_, findings, err := parseTfsec(domain.AgentScanRequest{ScanID: "run-2", ProjectID: "prj-1"}, "tfsec", output)
	if err != nil {
		t.Fatalf("parse tfsec: %v", err)
	}
	assertGoldenFindings(t, "tfsec_findings.golden.json", findings)
}

func TestParseLicenseeMatchesGoldenFindingShape(t *testing.T) {
	output := []byte(`{
  "matched_license": "AGPL-3.0-only",
  "confidence": 98
}`)

	_, findings, err := parseLicensee(domain.AgentScanRequest{ScanID: "run-3", ProjectID: "prj-1"}, "licensee", output)
	if err != nil {
		t.Fatalf("parse licensee: %v", err)
	}
	assertGoldenFindings(t, "licensee_findings.golden.json", findings)
}

func TestParseScancodeMatchesGoldenFindingShape(t *testing.T) {
	output := []byte(`{
  "files": [
    {
      "path": "vendor/libfoo/LICENSE",
      "license_expressions": ["AGPL-3.0-or-later"]
    }
  ]
}`)

	_, findings, err := parseScancode(domain.AgentScanRequest{ScanID: "run-4", ProjectID: "prj-1"}, "scancode", output)
	if err != nil {
		t.Fatalf("parse scancode: %v", err)
	}
	assertGoldenFindings(t, "scancode_findings.golden.json", findings)
}

func TestParseTrivyImageMatchesGoldenFindingShape(t *testing.T) {
	output := []byte(`{
  "Results": [
    {
      "Target": "ghcr.io/acme/api:latest (alpine 3.18)",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2026-9999",
          "Title": "BusyBox privilege escalation",
          "Severity": "CRITICAL",
          "PrimaryURL": "https://example.test/trivy/cve-2026-9999"
        }
      ]
    }
  ]
}`)

	_, findings, err := parseTrivyImage(domain.AgentScanRequest{ScanID: "run-5", ProjectID: "prj-1"}, "trivy-image", output)
	if err != nil {
		t.Fatalf("parse trivy image: %v", err)
	}
	assertGoldenFindings(t, "trivy_image_findings.golden.json", findings)
}

func TestParseCheckovMatchesGoldenFindingShape(t *testing.T) {
	output := []byte(`{
  "results": {
    "failed_checks": [
      {
        "check_id": "CKV_AWS_20",
        "check_name": "S3 Bucket has an ACL defined which allows public READ access.",
        "file_path": "/terraform/main.tf",
        "severity": "HIGH"
      }
    ]
  }
}`)

	_, findings, err := parseCheckov(domain.AgentScanRequest{ScanID: "run-6", ProjectID: "prj-1"}, "checkov", output)
	if err != nil {
		t.Fatalf("parse checkov: %v", err)
	}
	assertGoldenFindings(t, "checkov_findings.golden.json", findings)
}

func TestParseYARAXMatchesGoldenFindingShape(t *testing.T) {
	output := []byte(`{
  "matches": [
    {
      "rule": "SuspiciousPackedBinary",
      "path": "dist/packed.bin"
    }
  ]
}`)

	_, findings, err := parseYARAX(domain.AgentScanRequest{ScanID: "run-7", ProjectID: "prj-1"}, "yara-x", output)
	if err != nil {
		t.Fatalf("parse yara-x: %v", err)
	}
	assertGoldenFindings(t, "yarax_findings.golden.json", findings)
}

func TestParseNucleiMatchesGoldenFindingShape(t *testing.T) {
	output := []byte(`{"template-id":"cves/2026/CVE-2026-9001","matched-at":"https://staging.example.test/login","info":{"name":"Authentication bypass","severity":"critical"}}`)

	_, findings, err := parseNuclei(domain.AgentScanRequest{ScanID: "run-8", ProjectID: "prj-1"}, "nuclei", output)
	if err != nil {
		t.Fatalf("parse nuclei: %v", err)
	}
	assertGoldenFindings(t, "nuclei_findings.golden.json", findings)
}

func TestParseSARIFMatchesGoldenFindingShape(t *testing.T) {
	output := []byte(`{
  "runs": [
    {
      "tool": {
        "driver": {
          "rules": [
            {
              "id": "go/sql-injection",
              "name": "Possible SQL injection",
              "helpUri": "https://codeql.github.com/docs/",
              "shortDescription": {"text": "Unsanitized SQL query"},
              "fullDescription": {"text": "Validate user-controlled query parameters."},
              "defaultConfiguration": {"level": "error"}
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "go/sql-injection",
          "level": "error",
          "message": {"text": "User input reaches a SQL query sink."},
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {"uri": "internal/db/query.go"}
              }
            }
          ],
          "fingerprints": {
            "primaryLocationLineHash": "sarif-fp-1"
          }
        }
      ]
    }
  ]
}`)

	parser := parseSARIFCategory(domain.CategorySAST, "CodeQL")
	_, findings, err := parser(domain.AgentScanRequest{ScanID: "run-9", ProjectID: "prj-1"}, "codeql", output)
	if err != nil {
		t.Fatalf("parse sarif: %v", err)
	}
	assertGoldenFindings(t, "sarif_findings.golden.json", findings)
}

func assertGoldenFindings(t *testing.T, goldenName string, findings []domain.Finding) {
	t.Helper()

	bytes, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		t.Fatalf("marshal findings: %v", err)
	}
	goldenPath := filepath.Join("testdata", goldenName)
	if os.Getenv("UPDATE_AGENT_GOLDEN") == "1" {
		if err := os.WriteFile(goldenPath, bytes, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	golden, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if strings.TrimSpace(string(bytes)) != strings.TrimSpace(string(golden)) {
		t.Fatalf("%s drifted\nwant:\n%s\n\ngot:\n%s", goldenName, string(golden), string(bytes))
	}
}
