package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
)

func TestMatchesExpectedVersionNormalizesPrefixes(t *testing.T) {
	if !matchesExpectedVersion("1.119.0", "v1.119.0") {
		t.Fatalf("expected version matcher to normalize v-prefixed actual versions")
	}
	if matchesExpectedVersion("1.119.0", "1.118.9") {
		t.Fatalf("expected mismatched version to be rejected")
	}
}

func TestEvaluateBundleHealthDetectsMissingAndOutdatedTools(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "scanner-bundle.lock.json")
	if err := os.WriteFile(lockPath, []byte(`{
  "version": 1,
  "channels": {
    "safe": [
      { "name": "semgrep", "version": "1.119.0" }
    ]
  }
}`), 0o644); err != nil {
		t.Fatalf("write lock file: %v", err)
	}

	binaryPath := filepath.Join(dir, "semgrep")
	if err := os.WriteFile(binaryPath, []byte("#!/usr/bin/env bash\necho 'semgrep 1.118.0'\n"), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}

	originalPath := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+originalPath)

	cfg := config.Config{
		BundleLockPath: lockPath,
		InstallScript:  filepath.Join(dir, "install_scanners.sh"),
	}
	profile := domain.ScanProfile{Mode: domain.ModeSafe}

	loose := EvaluateBundleHealth(cfg, profile, false, false)
	if !loose.Ready {
		t.Fatalf("expected non-strict doctor to ignore version drift")
	}
	if len(loose.Missing) != 0 {
		t.Fatalf("expected no missing tools, got %d", len(loose.Missing))
	}

	strict := EvaluateBundleHealth(cfg, profile, true, false)
	if strict.Ready {
		t.Fatalf("expected strict doctor to fail on version drift")
	}
	if len(strict.Outdated) != 1 {
		t.Fatalf("expected 1 outdated tool, got %d", len(strict.Outdated))
	}
	if strict.Outdated[0].Name != "semgrep" {
		t.Fatalf("expected semgrep to be marked outdated, got %s", strict.Outdated[0].Name)
	}
}

func TestEvaluateBundleHealthRequireIntegrityFailsOnUnverifiedTool(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "scanner-bundle.lock.json")
	if err := os.WriteFile(lockPath, []byte(`{
  "version": 1,
  "channels": {
    "safe": [
      { "name": "semgrep", "version": "1.119.0" }
    ]
  }
}`), 0o644); err != nil {
		t.Fatalf("write lock file: %v", err)
	}

	binaryPath := filepath.Join(dir, "semgrep")
	if err := os.WriteFile(binaryPath, []byte("#!/usr/bin/env bash\necho 'semgrep 1.119.0'\n"), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}

	originalPath := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+originalPath)

	cfg := config.Config{
		BundleLockPath: lockPath,
		InstallScript:  filepath.Join(dir, "install_scanners.sh"),
	}
	profile := domain.ScanProfile{Mode: domain.ModeSafe}

	doctor := EvaluateBundleHealth(cfg, profile, false, true)
	if doctor.Ready {
		t.Fatalf("expected require-integrity doctor to fail on unverified tool")
	}
	if !doctor.RequireIntegrity {
		t.Fatalf("expected doctor to record require-integrity mode")
	}
	if len(doctor.Unverified) != 1 || doctor.Unverified[0].Name != "semgrep" {
		t.Fatalf("expected semgrep to be marked unverified, got %+v", doctor.Unverified)
	}
}

func TestDetectVersionUsesToolSpecificPatterns(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]struct {
		output string
		want   string
	}{
		"syft":        {output: "Application: syft\nVersion:    1.22.0\nGoVersion:  go1.24.1\n", want: "1.22.0"},
		"grype":       {output: "Application: grype\nVersion: 0.94.0\nSyft Version: v1.27.1\n", want: "0.94.0"},
		"trivy":       {output: "Version: 0.69.4\nDownloadedAt: 2026-03-18 12:44:49.8218 +0000 UTC\n", want: "0.69.4"},
		"osv-scanner": {output: "osv-scanner version: 2.2.2\nosv-scalibr version: 0.3.1\n", want: "2.2.2"},
		"zaproxy":     {output: "Found Java version 17.0.14\nNo check for updates for over 3 month - add-ons may well be out of date\n2.16.1\n", want: "2.16.1"},
	}

	for name, tc := range cases {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/usr/bin/env bash\ncat <<'EOF'\n"+tc.output+"EOF\n"), 0o755); err != nil {
			t.Fatalf("write fake binary %s: %v", name, err)
		}
		if got := detectVersion(path, []string{"--version"}); got != tc.want {
			t.Fatalf("expected %s version %s, got %s", name, tc.want, got)
		}
	}
}

func TestDetectVersionReadsManagedKnipPackageVersion(t *testing.T) {
	root := t.TempDir()
	toolsDir := filepath.Join(root, "bin")
	npmPackageDir := filepath.Join(root, "npm", "node_modules", "knip")
	if err := os.MkdirAll(toolsDir, 0o755); err != nil {
		t.Fatalf("mkdir tools dir: %v", err)
	}
	if err := os.MkdirAll(npmPackageDir, 0o755); err != nil {
		t.Fatalf("mkdir knip package dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(npmPackageDir, "package.json"), []byte(`{"name":"knip","version":"5.70.1"}`), 0o644); err != nil {
		t.Fatalf("write package json: %v", err)
	}
	binaryPath := filepath.Join(toolsDir, "knip")
	if err := os.WriteFile(binaryPath, []byte("#!/usr/bin/env bash\nexit 1\n"), 0o755); err != nil {
		t.Fatalf("write knip wrapper: %v", err)
	}

	if got := detectVersion(binaryPath, []string{"--version"}); got != "5.70.1" {
		t.Fatalf("expected knip version 5.70.1, got %s", got)
	}
}

func TestDetectVersionTimeoutsSlowProbe(t *testing.T) {
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "slow-tool")
	if err := os.WriteFile(binaryPath, []byte("#!/usr/bin/env bash\nsleep 5\necho 'slow-tool 1.2.3'\n"), 0o755); err != nil {
		t.Fatalf("write slow wrapper: %v", err)
	}

	started := time.Now()
	got := detectVersion(binaryPath, []string{"--version"})
	elapsed := time.Since(started)

	if got != "" {
		t.Fatalf("expected timed out probe to return empty version, got %q", got)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("expected runtime probe timeout to return quickly, took %s", elapsed)
	}
}

func TestDetectZAPVersionUsesBundleJarName(t *testing.T) {
	root := t.TempDir()
	macOSDir := filepath.Join(root, "ZAP.app", "Contents", "MacOS")
	javaDir := filepath.Join(root, "ZAP.app", "Contents", "Java")
	if err := os.MkdirAll(macOSDir, 0o755); err != nil {
		t.Fatalf("mkdir macos dir: %v", err)
	}
	if err := os.MkdirAll(javaDir, 0o755); err != nil {
		t.Fatalf("mkdir java dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(javaDir, "zap-2.16.1.jar"), []byte("stub"), 0o644); err != nil {
		t.Fatalf("write zap jar: %v", err)
	}
	binaryPath := filepath.Join(macOSDir, "ZAP.sh")
	if err := os.WriteFile(binaryPath, []byte("#!/usr/bin/env bash\nexit 1\n"), 0o755); err != nil {
		t.Fatalf("write zap wrapper: %v", err)
	}

	if got := detectZAPVersion(binaryPath); got != "2.16.1" {
		t.Fatalf("expected filesystem-based zap version, got %q", got)
	}
}

func TestEffectiveSpecVersionUsesPlatformOverride(t *testing.T) {
	spec := bundleSpec{
		Version: "0.69.1",
		PlatformVersions: map[string]string{
			currentPlatformKey(): "0.69.4",
		},
	}
	if got := effectiveSpecVersion(spec); got != "0.69.4" {
		t.Fatalf("expected platform override, got %s", got)
	}
}
