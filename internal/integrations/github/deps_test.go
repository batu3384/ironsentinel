package github

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/batu3384/ironsentinel/internal/domain"
)

func TestBuildDependencySnapshotIncludesDetectorAndManifest(t *testing.T) {
	project := domain.Project{
		ID:             "prj-1",
		DisplayName:    "ironsentinel",
		LocationHint:   "/workspace/ironsentinel",
		DetectedStacks: []string{"go", "terraform"},
	}
	run := domain.ScanRun{ID: "run-1", ProjectID: "prj-1"}

	snapshot, err := BuildDependencySnapshot(project, &run, []string{"go", "terraform"}, []DependencyPackage{
		{Name: "github.com/spf13/cobra", Version: "1.9.1", Ecosystem: "go", PackageURL: "pkg:go/github.com/spf13/cobra@1.9.1", Relationship: "indirect"},
	})
	if err != nil {
		t.Fatalf("build dependency snapshot: %v", err)
	}

	if snapshot.Detector.Name != "ironsentinel" {
		t.Fatalf("expected ironsentinel detector, got %+v", snapshot.Detector)
	}
	if snapshot.Job.ID != "run-1" {
		t.Fatalf("expected job id to use run id, got %+v", snapshot.Job)
	}
	if snapshot.Job.Correlator != "ironsentinel/github-submit-deps" {
		t.Fatalf("expected stable correlator, got %+v", snapshot.Job)
	}
	if len(snapshot.Manifests) != 1 {
		t.Fatalf("expected one manifest, got %d", len(snapshot.Manifests))
	}
	manifest, ok := snapshot.Manifests["ironsentinel"]
	if !ok {
		t.Fatalf("expected manifest keyed by workspace name, got %+v", snapshot.Manifests)
	}
	if manifest.File.SourceLocation != "ironsentinel" {
		t.Fatalf("expected workspace source location, got %+v", manifest.File)
	}
	if len(manifest.Resolved) != 1 {
		t.Fatalf("expected one resolved dependency, got %d", len(manifest.Resolved))
	}
	dep, ok := manifest.Resolved["pkg:go/github.com/spf13/cobra@1.9.1"]
	if !ok {
		t.Fatalf("expected canonical package url to be preserved, got %+v", manifest.Resolved)
	}
	if dep.Relationship != "indirect" {
		t.Fatalf("expected safe fallback relationship indirect, got %+v", dep)
	}
}

func TestSubmitDependenciesPostsCanonicalPayload(t *testing.T) {
	var path string
	var body string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		data, _ := io.ReadAll(r.Body)
		body = string(data)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"id":"snapshot-1"}`))
	}))
	defer server.Close()

	client, err := NewClient("ghs-test", server.Client())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	client.baseURL = server.URL

	err = client.SubmitDependencies(context.Background(), Repository{Owner: "batu3384", Name: "ironsentinel"}, DependencySnapshot{
		Version: 0,
		Sha:     "abc123",
		Ref:     "refs/heads/main",
		Detector: DependencyDetector{
			Name:    "ironsentinel",
			Version: "dev",
			URL:     "https://github.com/batu3384/ironsentinel",
		},
		Job: DependencyJob{
			ID:         "run-1",
			Correlator: "ironsentinel/github-submit-deps",
		},
		Manifests: map[string]DependencyManifest{
			"ironsentinel": {
				Name: "ironsentinel",
				File: DependencyFile{SourceLocation: "ironsentinel"},
				Resolved: map[string]DependencyPackageOccurrence{
					"pkg:go/github.com/spf13/cobra@1.9.1": {
						PackageURL:   "pkg:go/github.com/spf13/cobra@1.9.1",
						Relationship: "indirect",
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("submit dependencies: %v", err)
	}

	if path != "/repos/batu3384/ironsentinel/dependency-graph/snapshots" {
		t.Fatalf("expected dependency graph endpoint, got %s", path)
	}
	if !strings.Contains(body, `"sha":"abc123"`) {
		t.Fatalf("expected commit sha in request body: %s", body)
	}
	if !strings.Contains(body, `"job":{"id":"run-1","correlator":"ironsentinel/github-submit-deps"}`) {
		t.Fatalf("expected job shape in request body: %s", body)
	}
	if !strings.Contains(body, `"file":{"source_location":"ironsentinel"}`) {
		t.Fatalf("expected file source_location in request body: %s", body)
	}
	if !strings.Contains(body, `"detector":{"name":"ironsentinel"`) {
		t.Fatalf("expected detector metadata in request body: %s", body)
	}
	if !strings.Contains(body, `"package_url":"pkg:go/github.com/spf13/cobra@1.9.1"`) {
		t.Fatalf("expected resolved dependency in request body: %s", body)
	}
}

func TestBuildDependencySnapshotPreservesCanonicalPackageURLAndRelationship(t *testing.T) {
	project := domain.Project{
		ID:           "prj-1",
		DisplayName:  "ironsentinel",
		LocationHint: "/workspace/ironsentinel",
	}
	run := domain.ScanRun{ID: "run-1", ProjectID: "prj-1"}

	snapshot, err := BuildDependencySnapshot(project, &run, []string{"go"}, []DependencyPackage{
		{
			Name:         "github.com/spf13/cobra",
			Version:      "1.9.1",
			Ecosystem:    "library",
			PackageURL:   "pkg:go/github.com/spf13/cobra@1.9.1",
			Relationship: "indirect",
		},
		{
			Name:      "left-pad",
			Ecosystem: "npm",
		},
	})
	if err != nil {
		t.Fatalf("build dependency snapshot: %v", err)
	}

	manifest, ok := snapshot.Manifests["ironsentinel"]
	if !ok {
		t.Fatalf("expected manifest keyed by workspace name, got %+v", snapshot.Manifests)
	}
	if len(manifest.Resolved) != 1 {
		t.Fatalf("expected invalid dependency to be skipped, got %+v", manifest.Resolved)
	}
	dependency, ok := manifest.Resolved["pkg:go/github.com/spf13/cobra@1.9.1"]
	if !ok {
		t.Fatalf("expected canonical purl to be preserved, got %+v", manifest.Resolved)
	}
	if dependency.Relationship != "indirect" {
		t.Fatalf("expected relationship fallback to remain indirect, got %+v", dependency)
	}
}

func TestBuildDependencySnapshotRejectsPackagesWithoutCanonicalURLOrVersion(t *testing.T) {
	project := domain.Project{
		ID:           "prj-1",
		DisplayName:  "ironsentinel",
		LocationHint: "/workspace/ironsentinel",
	}
	run := domain.ScanRun{ID: "run-1", ProjectID: "prj-1"}

	_, err := BuildDependencySnapshot(project, &run, []string{"go"}, []DependencyPackage{
		{Name: "left-pad", Ecosystem: "npm"},
	})
	if err == nil || !strings.Contains(err.Error(), "no dependency inventory available") {
		t.Fatalf("expected empty inventory error, got %v", err)
	}
}
