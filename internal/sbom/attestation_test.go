package sbom

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/batu3384/ironsentinel/internal/domain"
)

func TestBuildAndVerifyAttestation(t *testing.T) {
	sbomPath := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX","components":[]}`), 0o644); err != nil {
		t.Fatalf("write sbom: %v", err)
	}
	run := domain.ScanRun{
		ID:        "run-1",
		ProjectID: "project-1",
		ArtifactRefs: []domain.ArtifactRef{
			{Kind: "sbom", Label: "CycloneDX", URI: sbomPath},
		},
	}

	attestation, err := BuildAttestation(run)
	if err != nil {
		t.Fatalf("build attestation: %v", err)
	}
	if err := VerifyAttestation(run, attestation); err != nil {
		t.Fatalf("verify attestation: %v", err)
	}
}

func TestVerifyAttestationRejectsDigestMismatch(t *testing.T) {
	sbomPath := filepath.Join(t.TempDir(), "sbom.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX","components":[]}`), 0o644); err != nil {
		t.Fatalf("write sbom: %v", err)
	}
	run := domain.ScanRun{
		ID:        "run-1",
		ProjectID: "project-1",
		ArtifactRefs: []domain.ArtifactRef{
			{Kind: "sbom", Label: "CycloneDX", URI: sbomPath},
		},
	}

	attestation, err := BuildAttestation(run)
	if err != nil {
		t.Fatalf("build attestation: %v", err)
	}
	attestation.Subjects[0].SHA256 = "deadbeef"
	if err := VerifyAttestation(run, attestation); err == nil {
		t.Fatalf("expected digest mismatch error")
	}
}
