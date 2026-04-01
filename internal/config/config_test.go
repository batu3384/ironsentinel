package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultLanguageFromExplicitEnv(t *testing.T) {
	t.Setenv("AEGIS_LANG", "tr")
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_MESSAGES", "")
	t.Setenv("LANG", "")

	if got := defaultLanguage(); got != "tr" {
		t.Fatalf("defaultLanguage() = %q, want tr", got)
	}
}

func TestDefaultLanguageFromLocale(t *testing.T) {
	t.Setenv("AEGIS_LANG", "")
	t.Setenv("LC_ALL", "tr_TR.UTF-8")
	t.Setenv("LC_MESSAGES", "")
	t.Setenv("LANG", "")

	if got := defaultLanguage(); got != "tr" {
		t.Fatalf("defaultLanguage() = %q, want tr", got)
	}
}

func TestDefaultLanguageFallsBackToEnglish(t *testing.T) {
	t.Setenv("AEGIS_LANG", "")
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_MESSAGES", "")
	t.Setenv("LANG", "en_US.UTF-8")

	if got := defaultLanguage(); got != "en" {
		t.Fatalf("defaultLanguage() = %q, want en", got)
	}
}

func TestResolveAppRootPrefersCurrentWorkspaceWhenBundleAssetsExist(t *testing.T) {
	cwd := t.TempDir()
	writeAppRootFixture(t, cwd)

	got := resolveAppRoot(cwd, "", filepath.Join(t.TempDir(), "fallback"))
	if got != cwd {
		t.Fatalf("resolveAppRoot() = %q, want %q", got, cwd)
	}
}

func TestResolveAppRootFallsBackToBuildWorkspace(t *testing.T) {
	cwd := t.TempDir()
	buildRoot := t.TempDir()
	writeAppRootFixture(t, buildRoot)

	got := resolveAppRoot(cwd, buildRoot, filepath.Join(t.TempDir(), "fallback"))
	if got != buildRoot {
		t.Fatalf("resolveAppRoot() = %q, want %q", got, buildRoot)
	}
}

func TestResolveAppRootFallsBackToUserConfigHome(t *testing.T) {
	cwd := t.TempDir()
	buildRoot := t.TempDir()
	fallback := filepath.Join(t.TempDir(), "IronSentinel")

	got := resolveAppRoot(cwd, buildRoot, fallback)
	if got != fallback {
		t.Fatalf("resolveAppRoot() = %q, want %q", got, fallback)
	}
}

func writeAppRootFixture(t *testing.T, root string) {
	t.Helper()
	dirs := []string{
		filepath.Join(root, "scripts"),
		filepath.Join(root, "deploy"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	files := map[string]string{
		filepath.Join(root, "scanner-bundle.lock.json"):               "{}",
		filepath.Join(root, "scripts", "install_scanners.sh"):         "#!/usr/bin/env bash\n",
		filepath.Join(root, "deploy", "scanner-bundle.Containerfile"): "FROM scratch\n",
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
}
