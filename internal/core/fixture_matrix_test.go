package core

import (
	"context"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
)

func TestFixtureMatrixScans(t *testing.T) {
	testCases := []struct {
		name              string
		expectedStacks    []string
		expectedCategory  domain.FindingCategory
		expectedMinCount  int
		expectedArtifacts int
	}{
		{
			name:              "js-risk",
			expectedStacks:    []string{"javascript", "typescript", "docker", "container"},
			expectedCategory:  domain.CategorySecret,
			expectedMinCount:  1,
			expectedArtifacts: 2,
		},
		{
			name:              "python-risk",
			expectedStacks:    []string{"python", "terraform", "iac"},
			expectedCategory:  domain.CategoryMalware,
			expectedMinCount:  1,
			expectedArtifacts: 2,
		},
		{
			name:              "go-risk",
			expectedStacks:    []string{"go"},
			expectedCategory:  "",
			expectedMinCount:  0,
			expectedArtifacts: 2,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := config.Config{
				DataDir:   filepath.Join(t.TempDir(), "data"),
				OutputDir: filepath.Join(t.TempDir(), "output"),
			}

			service, err := New(cfg)
			if err != nil {
				t.Fatalf("new service: %v", err)
			}

			project, existed, err := service.EnsureProject(context.Background(), fixturePath(t, testCase.name), testCase.name, false)
			if err != nil {
				t.Fatalf("ensure project: %v", err)
			}
			if existed {
				t.Fatalf("fixture project should not already exist")
			}

			for _, expectedStack := range testCase.expectedStacks {
				if !slices.Contains(project.DetectedStacks, expectedStack) {
					t.Fatalf("expected stack %q in %v", expectedStack, project.DetectedStacks)
				}
			}

			run, findings, err := service.Scan(context.Background(), project.ID, domain.ScanProfile{
				Mode:         domain.ModeSafe,
				Modules:      []string{"stack-detector", "secret-heuristics", "malware-signature"},
				SeverityGate: domain.SeverityHigh,
			}, nil)
			if err != nil {
				t.Fatalf("scan fixture: %v", err)
			}
			if run.Status != domain.ScanCompleted {
				t.Fatalf("expected completed run, got %s", run.Status)
			}
			if len(run.ModuleResults) != 3 {
				t.Fatalf("expected 3 module results, got %d", len(run.ModuleResults))
			}
			if len(run.ArtifactRefs) < testCase.expectedArtifacts {
				t.Fatalf("expected at least %d artifacts, got %d", testCase.expectedArtifacts, len(run.ArtifactRefs))
			}

			if testCase.expectedMinCount == 0 {
				if len(findings) != 0 {
					t.Fatalf("expected no findings, got %d", len(findings))
				}
				return
			}

			matching := 0
			for _, finding := range findings {
				if finding.Category == testCase.expectedCategory {
					matching++
				}
				if finding.EvidenceRef == "" {
					t.Fatalf("expected evidence ref on finding %s", finding.Fingerprint)
				}
			}
			if matching < testCase.expectedMinCount {
				t.Fatalf("expected at least %d %s finding(s), got %d", testCase.expectedMinCount, testCase.expectedCategory, matching)
			}
		})
	}
}

func fixturePath(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "testdata", "fixtures", name)
}
