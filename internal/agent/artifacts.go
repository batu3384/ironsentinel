package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
	"github.com/batu3384/ironsentinel/internal/evidence"
)

type moduleManifest struct {
	Module       string                   `json:"module"`
	Category     domain.FindingCategory   `json:"category"`
	Status       domain.ModuleStatus      `json:"status"`
	Summary      string                   `json:"summary"`
	StartedAt    time.Time                `json:"startedAt"`
	FinishedAt   time.Time                `json:"finishedAt"`
	DurationMs   int64                    `json:"durationMs"`
	Executable   string                   `json:"executable,omitempty"`
	Args         []string                 `json:"args,omitempty"`
	WorkingDir   string                   `json:"workingDir,omitempty"`
	Environment  []string                 `json:"environment,omitempty"`
	ReadOnly     bool                     `json:"readOnlyTarget"`
	AllowBuild   bool                     `json:"allowBuild"`
	AllowNetwork bool                     `json:"allowNetwork"`
	Attempts     int                      `json:"attempts,omitempty"`
	TimedOut     bool                     `json:"timedOut,omitempty"`
	FailureKind  domain.ModuleFailureKind `json:"failureKind,omitempty"`
	ExitCode     *int                     `json:"exitCode,omitempty"`
	Artifacts    []domain.ArtifactRef     `json:"artifacts,omitempty"`
}

func ensureModuleDir(root, module string) (string, error) {
	moduleDir := filepath.Join(root, sanitizeName(module))
	return moduleDir, os.MkdirAll(moduleDir, 0o755)
}

func writeArtifact(cfg config.Config, moduleDir, filename, kind, label string, body []byte) (domain.ArtifactRef, error) {
	return evidence.PolicyFromConfig(cfg).WriteFile(filepath.Join(moduleDir, filename), kind, label, body)
}

func copyArtifact(cfg config.Config, moduleDir, sourcePath, filename, kind, label string) (domain.ArtifactRef, error) {
	body, err := os.ReadFile(sourcePath)
	if err != nil {
		return domain.ArtifactRef{}, err
	}
	return writeArtifact(cfg, moduleDir, filename, kind, label, body)
}

func writeManifest(cfg config.Config, moduleDir string, manifest moduleManifest) (domain.ArtifactRef, error) {
	body, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return domain.ArtifactRef{}, err
	}
	return writeArtifact(cfg, moduleDir, "manifest.json", "manifest", "Module execution manifest", body)
}

func writeExecutionJournal(cfg config.Config, moduleDir string, journal domain.ModuleExecutionTrace) (domain.ArtifactRef, error) {
	body, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return domain.ArtifactRef{}, err
	}
	return writeArtifact(cfg, moduleDir, "execution-journal.json", "execution-journal", "Module execution journal", body)
}

func rawOutputFilename(body []byte) string {
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return "raw-output.json"
	}
	return "raw-output.log"
}

func attemptFilename(attempt int, base string) string {
	if attempt <= 1 {
		return base
	}
	return fmt.Sprintf("attempt-%d-%s", attempt, base)
}

func collectAttemptArtifacts(cfg config.Config, moduleDir, moduleName, hostOutputDir, artifactPath string, output []byte, attempt int) ([]domain.ArtifactRef, []byte, error) {
	artifacts := make([]domain.ArtifactRef, 0, 2)

	hostArtifactPath := translateArtifactPath(artifactPath, hostOutputDir)
	if hostArtifactPath != "" {
		fileOutput, err := os.ReadFile(hostArtifactPath)
		if err != nil {
			return nil, nil, err
		}
		reportArtifact, err := copyArtifact(cfg, moduleDir, hostArtifactPath, attemptFilename(attempt, filepath.Base(hostArtifactPath)), "report", moduleName+" report")
		if err != nil {
			return nil, nil, err
		}
		artifacts = append(artifacts, reportArtifact)
		return artifacts, fileOutput, nil
	}

	if len(output) == 0 {
		return artifacts, output, nil
	}

	rawArtifact, err := writeArtifact(cfg, moduleDir, attemptFilename(attempt, rawOutputFilename(output)), "raw-output", moduleName+" raw output", output)
	if err != nil {
		return nil, nil, err
	}
	artifacts = append(artifacts, rawArtifact)
	return artifacts, output, nil
}

func attachDefaultEvidence(findings []domain.Finding, artifacts []domain.ArtifactRef) []domain.Finding {
	if len(artifacts) == 0 {
		return findings
	}
	evidenceURI := ""
	for _, artifact := range artifacts {
		if artifact.Kind == "evidence" || artifact.Kind == "report" || artifact.Kind == "raw-output" || artifact.Kind == "sbom" {
			evidenceURI = artifact.URI
			break
		}
	}
	if evidenceURI == "" {
		evidenceURI = artifacts[0].URI
	}

	enriched := make([]domain.Finding, len(findings))
	for index, finding := range findings {
		if strings.TrimSpace(finding.EvidenceRef) == "" {
			finding.EvidenceRef = evidenceURI
		}
		enriched[index] = finding
	}
	return enriched
}

func replaceInlineArtifacts(artifacts []domain.ArtifactRef, replacement domain.ArtifactRef) []domain.ArtifactRef {
	if replacement.URI == "" {
		return artifacts
	}
	out := make([]domain.ArtifactRef, 0, len(artifacts))
	for _, artifact := range artifacts {
		if artifact.URI == "inline" {
			artifact.URI = replacement.URI
		}
		out = append(out, artifact)
	}
	return out
}

func sanitizeName(input string) string {
	replacer := strings.NewReplacer("/", "-", "\\", "-", " ", "-")
	return replacer.Replace(strings.TrimSpace(input))
}
