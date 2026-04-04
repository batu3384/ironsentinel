package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
)

func TestHeuristicSecretsWritesEvidenceArtifact(t *testing.T) {
	root := t.TempDir()
	outputDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("token="+heuristicTestGitHubPAT()+"\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	result, findings, err := heuristicSecrets(context.Background(), config.Config{ArtifactRedaction: true}, domain.AgentScanRequest{
		ScanID:     "run-test",
		ProjectID:  "prj-test",
		TargetPath: root,
	}, outputDir)
	if err != nil {
		t.Fatalf("heuristicSecrets returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if len(result.Artifacts) == 0 {
		t.Fatalf("expected evidence artifact")
	}
	if findings[0].EvidenceRef == "" {
		t.Fatalf("expected finding evidence ref to be populated")
	}
	if findings[0].EvidenceRef != result.Artifacts[0].URI {
		t.Fatalf("expected finding evidence ref to match artifact uri, got %q want %q", findings[0].EvidenceRef, result.Artifacts[0].URI)
	}
	if _, err := os.Stat(result.Artifacts[0].URI); err != nil {
		t.Fatalf("expected evidence artifact to exist: %v", err)
	}
}

func heuristicTestGitHubPAT() string {
	return strings.Join([]string{"gh", "p_", strings.Repeat("a", 36)}, "")
}

func TestHeuristicSurfaceInventoryFlagsSensitiveFilesAndBinaryArtifacts(t *testing.T) {
	root := t.TempDir()
	outputDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("APP_SECRET=test\n"), 0o644); err != nil {
		t.Fatalf("write sensitive fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "agent.bin"), []byte{0x7f, 'E', 'L', 'F', 0x00, 0x01}, 0o755); err != nil {
		t.Fatalf("write binary fixture: %v", err)
	}

	result, findings, err := heuristicSurfaceInventory(context.Background(), config.Config{ArtifactRedaction: true}, domain.AgentScanRequest{
		ScanID:     "run-surface",
		ProjectID:  "prj-surface",
		TargetPath: root,
	}, outputDir)
	if err != nil {
		t.Fatalf("heuristicSurfaceInventory returned error: %v", err)
	}
	if result.Name != "surface-inventory" {
		t.Fatalf("unexpected module name: %s", result.Name)
	}
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(findings))
	}
	if len(result.Artifacts) == 0 || findings[0].EvidenceRef == "" {
		t.Fatalf("expected evidence artifact to be attached")
	}
}

func TestHeuristicSurfaceInventoryIgnoresManagedRuntimeAndUserStateArtifacts(t *testing.T) {
	root := t.TempDir()
	outputDir := filepath.Join(root, "runtime", "output")
	dataDir := filepath.Join(root, "runtime", "data")
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		t.Fatalf("mkdir output dir: %v", err)
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir data dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "App.xcodeproj", "project.xcworkspace", "xcuserdata", "user.xcuserdatad"), 0o755); err != nil {
		t.Fatalf("mkdir xcuserdata: %v", err)
	}
	for _, target := range []string{
		filepath.Join(root, ".DS_Store"),
		filepath.Join(root, "App.xcodeproj", "project.xcworkspace", "xcuserdata", "user.xcuserdatad", "UserInterfaceState.xcuserstate"),
		filepath.Join(dataDir, "state.db"),
		filepath.Join(dataDir, "state.db-shm"),
		filepath.Join(dataDir, "state.db-wal"),
	} {
		if err := os.WriteFile(target, []byte{0x00, 0x01, 0x02}, 0o644); err != nil {
			t.Fatalf("write %s: %v", target, err)
		}
	}

	_, findings, err := heuristicSurfaceInventory(context.Background(), config.Config{
		ArtifactRedaction: true,
		DataDir:           dataDir,
		OutputDir:         outputDir,
	}, domain.AgentScanRequest{
		ScanID:     "run-surface-noise",
		ProjectID:  "prj-surface-noise",
		TargetPath: root,
	}, outputDir)
	if err != nil {
		t.Fatalf("heuristicSurfaceInventory returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for managed runtime or user-state artifacts, got %d", len(findings))
	}
}

func TestHeuristicScriptAuditFindsRiskyExecutionPatterns(t *testing.T) {
	root := t.TempDir()
	outputDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"scripts":{"bootstrap":"curl https://example.com/bootstrap.sh | sh","unsafe":"docker run --privileged alpine"}}`), 0o644); err != nil {
		t.Fatalf("write package fixture: %v", err)
	}
	workflowDir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatalf("mkdir workflow dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workflowDir, "ci.yml"), []byte("steps:\n  - run: wget https://example.com/agent.sh | bash\n"), 0o644); err != nil {
		t.Fatalf("write workflow fixture: %v", err)
	}

	result, findings, err := heuristicScriptAudit(context.Background(), config.Config{ArtifactRedaction: true}, domain.AgentScanRequest{
		ScanID:     "run-script",
		ProjectID:  "prj-script",
		TargetPath: root,
	}, outputDir)
	if err != nil {
		t.Fatalf("heuristicScriptAudit returned error: %v", err)
	}
	if result.Name != "script-audit" {
		t.Fatalf("unexpected module name: %s", result.Name)
	}
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(findings))
	}
	if len(result.Artifacts) == 0 || findings[0].EvidenceRef == "" {
		t.Fatalf("expected evidence artifact to be attached")
	}
}
