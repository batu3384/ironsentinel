package github

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/batu3384/ironsentinel/internal/domain"
)

const dependencySubmissionVersion = "dev"

type DependencyPackage struct {
	Name         string
	Version      string
	Ecosystem    string
	PackageURL   string
	Relationship string
}

type DependencyPackageOccurrence struct {
	PackageURL   string `json:"package_url"`
	Relationship string `json:"relationship"`
}

type DependencyFile struct {
	SourceLocation string `json:"source_location"`
}

type DependencyManifest struct {
	Name     string                                 `json:"name"`
	File     DependencyFile                         `json:"file"`
	Resolved map[string]DependencyPackageOccurrence `json:"resolved"`
}

type DependencyDetector struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	URL     string `json:"url"`
}

type DependencyJob struct {
	ID         string `json:"id"`
	Correlator string `json:"correlator"`
}

type DependencySnapshot struct {
	Version   int                           `json:"version"`
	Sha       string                        `json:"sha"`
	Ref       string                        `json:"ref"`
	Detector  DependencyDetector            `json:"detector"`
	Job       DependencyJob                 `json:"job"`
	Scanned   string                        `json:"scanned"`
	Manifests map[string]DependencyManifest `json:"manifests"`
}

func BuildDependencySnapshot(project domain.Project, run *domain.ScanRun, stacks []string, packages []DependencyPackage) (DependencySnapshot, error) {
	if len(packages) == 0 {
		return DependencySnapshot{}, fmt.Errorf("no dependency inventory available")
	}

	manifestKey := dependencyManifestKey(project)
	if manifestKey == "" {
		return DependencySnapshot{}, fmt.Errorf("no dependency inventory available")
	}

	resolved := make(map[string]DependencyPackageOccurrence, len(packages))
	for _, pkg := range packages {
		packageURL := dependencyPackageURL(pkg)
		if packageURL == "" {
			continue
		}
		resolved[packageURL] = DependencyPackageOccurrence{
			PackageURL:   packageURL,
			Relationship: dependencyPackageRelationship(pkg),
		}
	}
	if len(resolved) == 0 {
		return DependencySnapshot{}, fmt.Errorf("no dependency inventory available")
	}

	return DependencySnapshot{
		Version: 0,
		Detector: DependencyDetector{
			Name:    "ironsentinel",
			Version: dependencySubmissionVersion,
			URL:     "https://github.com/batu3384/ironsentinel",
		},
		Job: DependencyJob{
			ID:         dependencySubmissionJobID(run, project),
			Correlator: "ironsentinel/github-submit-deps",
		},
		Scanned: time.Now().UTC().Format(time.RFC3339),
		Manifests: map[string]DependencyManifest{
			manifestKey: {
				Name:     dependencyManifestName(project, manifestKey),
				File:     DependencyFile{SourceLocation: manifestKey},
				Resolved: resolved,
			},
		},
	}, nil
}

func (c *Client) SubmitDependencies(ctx context.Context, repo Repository, snapshot DependencySnapshot) error {
	resp, err := c.postJSON(ctx, fmt.Sprintf("/repos/%s/%s/dependency-graph/snapshots", repo.Owner, repo.Name), snapshot)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusCreated {
		return mapHTTPError("dependency submission", repo, resp)
	}
	_ = readBody(resp)
	return nil
}

func dependencyPackageURL(pkg DependencyPackage) string {
	if url := strings.TrimSpace(pkg.PackageURL); url != "" {
		return url
	}
	name := strings.TrimSpace(pkg.Name)
	version := strings.TrimSpace(pkg.Version)
	if name == "" || version == "" {
		return ""
	}
	ecosystem := strings.TrimSpace(pkg.Ecosystem)
	if ecosystem == "" {
		ecosystem = "generic"
	}
	return fmt.Sprintf("pkg:%s/%s@%s", ecosystem, name, version)
}

func dependencyPackageRelationship(pkg DependencyPackage) string {
	relationship := strings.TrimSpace(pkg.Relationship)
	if relationship == "" {
		return "indirect"
	}
	return relationship
}

func dependencySubmissionJobID(run *domain.ScanRun, project domain.Project) string {
	if run != nil && strings.TrimSpace(run.ID) != "" {
		return strings.TrimSpace(run.ID)
	}
	return strings.TrimSpace(project.ID)
}

func dependencyManifestKey(project domain.Project) string {
	for _, candidate := range []string{
		project.LocationHint,
		project.DisplayName,
		project.TargetHandle,
		project.ID,
	} {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		base := filepath.Base(candidate)
		if base == "" || base == "." || base == string(filepath.Separator) {
			base = candidate
		}
		base = strings.TrimSpace(base)
		if base != "" && base != "." {
			return base
		}
	}
	return ""
}

func dependencyManifestName(project domain.Project, fallback string) string {
	name := strings.TrimSpace(project.DisplayName)
	if name != "" {
		return name
	}
	if strings.TrimSpace(fallback) != "" {
		return fallback
	}
	return project.ID
}
