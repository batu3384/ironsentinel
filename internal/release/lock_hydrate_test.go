package release

import (
	"errors"
	"strings"
	"testing"
)

func TestHydrateLockChecksumsUpdatesKnownTool(t *testing.T) {
	lock := BundleLock{
		Channels: map[string][]LockSpec{
			"safe": {
				{Name: "trivy", Version: "0.69.1"},
			},
		},
	}

	updated, reports, err := HydrateLockChecksums(lock, LockHydrateOptions{
		Tools: []string{"trivy"},
		Fetch: func(url string) ([]byte, error) {
			switch url {
			case "https://github.com/aquasecurity/trivy/archive/refs/tags/v0.69.1.tar.gz":
				return []byte("trivy-source"), nil
			case "https://github.com/aquasecurity/trivy/releases/download/v0.69.1/trivy_0.69.1_checksums.txt":
				return []byte(strings.Join([]string{
					"90d13686937ac7429b97a3acbf1e1d0ce90d92ae2d0cf46a690bd8ae5230bea0  trivy_0.69.1_macOS-ARM64.tar.gz",
					"f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0  trivy_0.69.1_Linux-64bit.tar.gz",
				}, "\n")), nil
			default:
				t.Fatalf("unexpected checksum url: %s", url)
				return nil, nil
			}
		},
	})
	if err != nil {
		t.Fatalf("hydrate lock: %v", err)
	}
	if len(reports) != 1 || reports[0].Status != "updated" {
		t.Fatalf("expected one updated report, got %+v", reports)
	}
	spec := updated.Channels["safe"][0]
	if spec.Checksums["darwin/arm64"] == "" || spec.Checksums["linux/amd64"] == "" {
		t.Fatalf("expected platform checksums to be populated, got %+v", spec.Checksums)
	}
}

func TestHydrateLockChecksumsReportsFetchFailure(t *testing.T) {
	lock := BundleLock{
		Channels: map[string][]LockSpec{
			"safe": {
				{Name: "trivy", Version: "0.69.1"},
			},
		},
	}

	_, reports, err := HydrateLockChecksums(lock, LockHydrateOptions{
		Tools: []string{"trivy"},
		Fetch: func(string) ([]byte, error) {
			return nil, errors.New("upstream unavailable")
		},
	})
	if err != nil {
		t.Fatalf("hydrate lock: %v", err)
	}
	if len(reports) != 1 || reports[0].Status != "failed" {
		t.Fatalf("expected failed report, got %+v", reports)
	}
}

func TestHydrateLockChecksumsUpdatesSourceIntegrityForSourceOnlyTool(t *testing.T) {
	lock := BundleLock{
		Channels: map[string][]LockSpec{
			"safe": {
				{Name: "checkov", Version: "3.2.489"},
			},
		},
	}

	updated, reports, err := HydrateLockChecksums(lock, LockHydrateOptions{
		Tools: []string{"checkov"},
		Fetch: func(url string) ([]byte, error) {
			if want := "https://pypi.org/pypi/checkov/3.2.489/json"; url != want {
				t.Fatalf("unexpected source url: %s", url)
			}
			return []byte(`{"urls":[{"filename":"checkov-3.2.489.tar.gz","packagetype":"sdist","url":"https://files.pythonhosted.org/packages/checkov-3.2.489.tar.gz","digests":{"sha256":"abc123"}}]}`), nil
		},
	})
	if err != nil {
		t.Fatalf("hydrate lock: %v", err)
	}
	if len(reports) != 1 || reports[0].Status != "updated" {
		t.Fatalf("expected source-only updated report, got %+v", reports)
	}
	spec := updated.Channels["safe"][0]
	if spec.SourceIntegrity.Kind != "pypi-sdist" || spec.SourceIntegrity.Digest != "abc123" {
		t.Fatalf("expected source integrity to be populated, got %+v", spec.SourceIntegrity)
	}
}

func TestHydrateLockChecksumsUpdatesSourceIntegrityForGrype(t *testing.T) {
	lock := BundleLock{
		Channels: map[string][]LockSpec{
			"safe": {
				{Name: "grype", Version: "0.94.0"},
			},
		},
	}

	updated, reports, err := HydrateLockChecksums(lock, LockHydrateOptions{
		Tools: []string{"grype"},
		Fetch: func(url string) ([]byte, error) {
			if want := "https://github.com/anchore/grype/archive/refs/tags/v0.94.0.tar.gz"; url != want {
				t.Fatalf("unexpected source url: %s", url)
			}
			return []byte("grype-source"), nil
		},
	})
	if err != nil {
		t.Fatalf("hydrate lock: %v", err)
	}
	if len(reports) != 1 || reports[0].Status != "updated" {
		t.Fatalf("expected updated report, got %+v", reports)
	}
	spec := updated.Channels["safe"][0]
	if spec.SourceIntegrity.Kind != "github-source-archive" || spec.SourceIntegrity.Digest == "" {
		t.Fatalf("expected grype source integrity, got %+v", spec.SourceIntegrity)
	}
}

func TestHydrateLockChecksumsUpdatesNpmAndGoSourceIntegrity(t *testing.T) {
	lock := BundleLock{
		Channels: map[string][]LockSpec{
			"deep": {
				{Name: "knip", Version: "5.70.1"},
			},
			"safe": {
				{Name: "govulncheck", Version: "1.1.4"},
			},
		},
	}

	updated, reports, err := HydrateLockChecksums(lock, LockHydrateOptions{
		Tools: []string{"knip", "govulncheck"},
		Fetch: func(url string) ([]byte, error) {
			switch url {
			case "https://registry.npmjs.org/knip/5.70.1":
				return []byte(`{"dist":{"tarball":"https://registry.npmjs.org/knip/-/knip-5.70.1.tgz","integrity":"sha512-AQID"}}`), nil
			case "https://proxy.golang.org/golang.org/x/vuln/@v/v1.1.4.zip":
				return []byte("go-module-zip"), nil
			default:
				t.Fatalf("unexpected source url: %s", url)
				return nil, nil
			}
		},
	})
	if err != nil {
		t.Fatalf("hydrate lock: %v", err)
	}
	if len(reports) != 2 {
		t.Fatalf("expected 2 reports, got %+v", reports)
	}
	if updated.Channels["deep"][0].SourceIntegrity.Kind != "npm-tarball" {
		t.Fatalf("expected npm source integrity, got %+v", updated.Channels["deep"][0].SourceIntegrity)
	}
	if updated.Channels["safe"][0].SourceIntegrity.Kind != "go-module-zip" {
		t.Fatalf("expected go source integrity, got %+v", updated.Channels["safe"][0].SourceIntegrity)
	}
}

func TestHydrateLockChecksumsUpdatesGitHubReleaseAssetDigests(t *testing.T) {
	lock := BundleLock{
		Channels: map[string][]LockSpec{
			"safe": {
				{Name: "osv-scanner", Version: "2.2.2"},
			},
			"deep": {
				{Name: "codeql", Version: "2.23.3"},
			},
		},
	}

	updated, reports, err := HydrateLockChecksums(lock, LockHydrateOptions{
		Tools: []string{"osv-scanner", "codeql"},
		Fetch: func(url string) ([]byte, error) {
			switch url {
			case "https://api.github.com/repos/google/osv-scanner/releases/tags/v2.2.2":
				return []byte(`{"assets":[{"name":"osv-scanner_linux_amd64","digest":"sha256:abc123"},{"name":"osv-scanner_windows_amd64.exe","digest":"sha256:def456"}]}`), nil
			case "https://api.github.com/repos/github/codeql-action/releases/tags/codeql-bundle-v2.23.3":
				return []byte(`{"assets":[{"name":"codeql-bundle-linux64.tar.gz","digest":"sha256:aaa111"},{"name":"codeql-bundle-osx64.tar.gz","digest":"sha256:bbb222"},{"name":"codeql-bundle-win64.tar.gz","digest":"sha256:ccc333"}]}`), nil
			default:
				t.Fatalf("unexpected url: %s", url)
				return nil, nil
			}
		},
	})
	if err != nil {
		t.Fatalf("hydrate lock: %v", err)
	}
	if len(reports) != 2 {
		t.Fatalf("expected 2 reports, got %+v", reports)
	}
	if got := updated.Channels["safe"][0].Checksums["linux/amd64"]; got != "abc123" {
		t.Fatalf("expected osv checksum, got %q", got)
	}
	if got := updated.Channels["deep"][0].Checksums["windows/amd64"]; got != "ccc333" {
		t.Fatalf("expected codeql checksum, got %q", got)
	}
}

func TestHydrateLockChecksumsSwitchesSemgrepToSourceIntegrity(t *testing.T) {
	lock := BundleLock{
		Channels: map[string][]LockSpec{
			"safe": {
				{
					Name:    "semgrep",
					Version: "1.119.0",
					Checksums: map[string]string{
						"darwin/arm64": "old-digest",
					},
				},
			},
		},
	}

	updated, reports, err := HydrateLockChecksums(lock, LockHydrateOptions{
		Tools: []string{"semgrep"},
		Fetch: func(url string) ([]byte, error) {
			if want := "https://pypi.org/pypi/semgrep/1.119.0/json"; url != want {
				t.Fatalf("unexpected url: %s", url)
			}
			return []byte(`{"urls":[{"filename":"semgrep-1.119.0.tar.gz","packagetype":"sdist","url":"https://files.pythonhosted.org/packages/semgrep-1.119.0.tar.gz","digests":{"sha256":"semgrep-sdist"}}]}`), nil
		},
	})
	if err != nil {
		t.Fatalf("hydrate lock: %v", err)
	}
	if len(reports) != 1 || reports[0].Status != "updated" {
		t.Fatalf("expected updated report, got %+v", reports)
	}
	spec := updated.Channels["safe"][0]
	if len(spec.Checksums) != 0 {
		t.Fatalf("expected release checksums to be cleared, got %+v", spec.Checksums)
	}
	if spec.SourceIntegrity.Kind != "pypi-sdist" || spec.SourceIntegrity.Digest != "semgrep-sdist" {
		t.Fatalf("expected semgrep source integrity, got %+v", spec.SourceIntegrity)
	}
}

func TestHydrateLockChecksumsSwitchesNucleiToSourceIntegrity(t *testing.T) {
	lock := BundleLock{
		Channels: map[string][]LockSpec{
			"active": {
				{
					Name:    "nuclei",
					Version: "3.4.10",
					Checksums: map[string]string{
						"darwin/arm64": "old-digest",
					},
				},
			},
		},
	}

	updated, reports, err := HydrateLockChecksums(lock, LockHydrateOptions{
		Tools: []string{"nuclei"},
		Fetch: func(url string) ([]byte, error) {
			if want := "https://github.com/projectdiscovery/nuclei/archive/refs/tags/v3.4.10.tar.gz"; url != want {
				t.Fatalf("unexpected url: %s", url)
			}
			return []byte("nuclei-source"), nil
		},
	})
	if err != nil {
		t.Fatalf("hydrate lock: %v", err)
	}
	if len(reports) != 1 || reports[0].Status != "updated" {
		t.Fatalf("expected updated report, got %+v", reports)
	}
	spec := updated.Channels["active"][0]
	if len(spec.Checksums) != 0 {
		t.Fatalf("expected release checksums to be cleared, got %+v", spec.Checksums)
	}
	if spec.SourceIntegrity.Kind != "github-source-archive" || spec.SourceIntegrity.URL != "https://github.com/projectdiscovery/nuclei/archive/refs/tags/v3.4.10.tar.gz" {
		t.Fatalf("expected nuclei source integrity, got %+v", spec.SourceIntegrity)
	}
}

func TestHydratePyPISdistOrFirstWheelFallsBackToWheel(t *testing.T) {
	hydrate := hydratePyPISdistOrFirstWheel("semgrep")
	source, err := hydrate("1.119.0", func(url string) ([]byte, error) {
		if want := "https://pypi.org/pypi/semgrep/1.119.0/json"; url != want {
			t.Fatalf("unexpected url: %s", url)
		}
		return []byte(`{"urls":[
			{"filename":"semgrep-1.119.0-cp39-none-macosx_11_0_arm64.whl","packagetype":"bdist_wheel","url":"https://files.pythonhosted.org/arm64.whl","digests":{"sha256":"arm64digest"}},
			{"filename":"semgrep-1.119.0-cp39-none-macosx_10_14_x86_64.whl","packagetype":"bdist_wheel","url":"https://files.pythonhosted.org/x64.whl","digests":{"sha256":"x64digest"}}
		]}`), nil
	})
	if err != nil {
		t.Fatalf("hydrate source integrity: %v", err)
	}
	if source.Kind != "pypi-wheel" || source.Digest != "x64digest" {
		t.Fatalf("expected deterministic wheel fallback, got %+v", source)
	}
}

func TestHydrateLockChecksumsSwitchesStaticcheckToSourceIntegrity(t *testing.T) {
	lock := BundleLock{
		Channels: map[string][]LockSpec{
			"safe": {
				{
					Name:    "staticcheck",
					Version: "2025.1.1",
					Checksums: map[string]string{
						"darwin/arm64": "old-digest",
					},
				},
			},
		},
	}

	updated, reports, err := HydrateLockChecksums(lock, LockHydrateOptions{
		Tools: []string{"staticcheck"},
		Fetch: func(url string) ([]byte, error) {
			switch url {
			case "https://api.github.com/repos/dominikh/go-tools/releases/tags/2025.1.1":
				return []byte(`{"assets":[
					{"name":"staticcheck_darwin_amd64.tar.gz"},
					{"name":"staticcheck_linux_amd64.tar.gz"},
					{"name":"staticcheck_windows_amd64.tar.gz"}
				]}`), nil
			case "https://github.com/dominikh/go-tools/releases/download/2025.1.1/staticcheck_darwin_amd64.tar.gz.sha256":
				return []byte("abc111  staticcheck_darwin_amd64.tar.gz\n"), nil
			case "https://github.com/dominikh/go-tools/releases/download/2025.1.1/staticcheck_linux_amd64.tar.gz.sha256":
				return []byte("abc222  staticcheck_linux_amd64.tar.gz\n"), nil
			case "https://github.com/dominikh/go-tools/releases/download/2025.1.1/staticcheck_windows_amd64.tar.gz.sha256":
				return []byte("abc333  staticcheck_windows_amd64.tar.gz\n"), nil
			case "https://github.com/dominikh/go-tools/archive/refs/tags/2025.1.1.tar.gz":
				return []byte("source-archive"), nil
			default:
				t.Fatalf("unexpected url: %s", url)
				return nil, nil
			}
		},
	})
	if err != nil {
		t.Fatalf("hydrate lock: %v", err)
	}
	if len(reports) != 1 || reports[0].Status != "updated" {
		t.Fatalf("expected updated report, got %+v", reports)
	}
	spec := updated.Channels["safe"][0]
	if len(spec.Checksums) != 0 {
		t.Fatalf("expected staticcheck release checksums to be cleared, got %+v", spec.Checksums)
	}
	if spec.SourceIntegrity.Kind != "github-source-archive" {
		t.Fatalf("expected staticcheck source integrity, got %+v", spec.SourceIntegrity)
	}
}

func TestHydrateLockChecksumsUpdatesSourceArchiveIntegrity(t *testing.T) {
	lock := BundleLock{
		Channels: map[string][]LockSpec{
			"active": {
				{Name: "zap", Version: "2.16.1"},
			},
			"safe": {
				{Name: "trivy", Version: "0.69.1"},
				{Name: "clamav", Version: "1.4.3"},
			},
		},
	}

	updated, reports, err := HydrateLockChecksums(lock, LockHydrateOptions{
		Tools: []string{"zap", "trivy", "clamav"},
		Fetch: func(url string) ([]byte, error) {
			switch url {
			case "https://github.com/zaproxy/zaproxy/archive/refs/tags/v2.16.1.tar.gz":
				return []byte("zap-source"), nil
			case "https://github.com/aquasecurity/trivy/archive/refs/tags/v0.69.1.tar.gz":
				return []byte("trivy-source"), nil
			case "https://www.clamav.net/downloads/production/clamav-1.4.3.tar.gz":
				return []byte("clamav-source"), nil
			case "https://github.com/aquasecurity/trivy/releases/download/v0.69.1/trivy_0.69.1_checksums.txt":
				return nil, errors.New("404")
			default:
				t.Fatalf("unexpected url: %s", url)
				return nil, nil
			}
		},
	})
	if err != nil {
		t.Fatalf("hydrate lock: %v", err)
	}
	if len(reports) != 3 {
		t.Fatalf("expected 3 reports, got %+v", reports)
	}
	if updated.Channels["active"][0].SourceIntegrity.Kind != "github-source-archive" {
		t.Fatalf("expected zap source integrity, got %+v", updated.Channels["active"][0].SourceIntegrity)
	}
	if updated.Channels["safe"][1].SourceIntegrity.Kind != "http-tarball" {
		t.Fatalf("expected clamav source integrity, got %+v", updated.Channels["safe"][1].SourceIntegrity)
	}
	reportByName := make(map[string]LockHydrateReport, len(reports))
	for _, report := range reports {
		reportByName[report.Name] = report
	}
	if reportByName["trivy"].Status != "failed" || !strings.Contains(reportByName["trivy"].Note, "source digest updated") {
		t.Fatalf("expected trivy checksum fetch to fail while source integrity is retained, got %+v", reportByName["trivy"])
	}
}

func TestInferReleasePlatformSupportsCommonAssetNames(t *testing.T) {
	cases := map[string]string{
		"gitleaks_8.24.2_darwin_x64.tar.gz": "darwin/amd64",
		"nuclei_3.4.10_macOS_arm64.zip":     "darwin/arm64",
		"syft_1.22.0_linux_amd64.tar.gz":    "linux/amd64",
		"asset_windows_386.zip":             "windows/386",
	}

	for name, want := range cases {
		got, ok := inferReleasePlatform(name)
		if !ok || got != want {
			t.Fatalf("expected %s -> %s, got %s ok=%t", name, want, got, ok)
		}
	}
}
