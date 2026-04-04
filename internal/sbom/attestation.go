package sbom

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/batu3384/ironsentinel/internal/domain"
)

const AttestationType = "https://github.com/batu3384/ironsentinel/attestations/sbom/v1"

func BuildAttestation(run domain.ScanRun) (domain.SBOMAttestation, error) {
	subjects, err := buildSubjects(run.ArtifactRefs)
	if err != nil {
		return domain.SBOMAttestation{}, err
	}
	return domain.SBOMAttestation{
		Type:      AttestationType,
		RunID:     run.ID,
		ProjectID: run.ProjectID,
		Timestamp: time.Now().UTC(),
		Subjects:  subjects,
	}, nil
}

func ParseAttestation(body []byte) (domain.SBOMAttestation, error) {
	var attestation domain.SBOMAttestation
	if err := json.Unmarshal(body, &attestation); err != nil {
		return domain.SBOMAttestation{}, err
	}
	if strings.TrimSpace(attestation.Type) == "" {
		return domain.SBOMAttestation{}, fmt.Errorf("sbom attestation type is required")
	}
	if strings.TrimSpace(attestation.RunID) == "" {
		return domain.SBOMAttestation{}, fmt.Errorf("sbom attestation runId is required")
	}
	return attestation, nil
}

func ParseAttestationFile(path string) (domain.SBOMAttestation, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return domain.SBOMAttestation{}, err
	}
	return ParseAttestation(body)
}

func VerifyAttestation(run domain.ScanRun, attestation domain.SBOMAttestation) error {
	expected, err := BuildAttestation(run)
	if err != nil {
		return err
	}
	if strings.TrimSpace(attestation.Type) != AttestationType {
		return fmt.Errorf("sbom attestation type mismatch: %s", attestation.Type)
	}
	if attestation.RunID != expected.RunID {
		return fmt.Errorf("sbom attestation runId mismatch: %s", attestation.RunID)
	}
	if attestation.ProjectID != expected.ProjectID {
		return fmt.Errorf("sbom attestation projectId mismatch: %s", attestation.ProjectID)
	}
	if len(attestation.Subjects) != len(expected.Subjects) {
		return fmt.Errorf("sbom attestation subject count mismatch: got %d want %d", len(attestation.Subjects), len(expected.Subjects))
	}
	expectedByURI := make(map[string]domain.SBOMAttestationSubject, len(expected.Subjects))
	for _, subject := range expected.Subjects {
		expectedByURI[subject.URI] = subject
	}
	for _, subject := range attestation.Subjects {
		expectedSubject, ok := expectedByURI[subject.URI]
		if !ok {
			return fmt.Errorf("sbom attestation includes unexpected subject: %s", subject.URI)
		}
		if subject.SHA256 != expectedSubject.SHA256 {
			return fmt.Errorf("sbom attestation digest mismatch for %s", subject.URI)
		}
	}
	return nil
}

func buildSubjects(artifacts []domain.ArtifactRef) ([]domain.SBOMAttestationSubject, error) {
	subjects := make([]domain.SBOMAttestationSubject, 0)
	for _, artifact := range artifacts {
		if artifact.Kind != "sbom" || strings.TrimSpace(artifact.URI) == "" || artifact.URI == "inline" {
			continue
		}
		body, err := os.ReadFile(artifact.URI)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(body)
		subjects = append(subjects, domain.SBOMAttestationSubject{
			Name:   fallback(artifact.Label, "sbom"),
			URI:    artifact.URI,
			SHA256: fmt.Sprintf("%x", sum[:]),
		})
	}
	return subjects, nil
}

func fallback(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}
