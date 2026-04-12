package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultLanguageFromExplicitEnv(t *testing.T) {
	t.Setenv("APPSEC_LANG", "tr")
	t.Setenv("IRONSENTINEL_LANG", "")
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_MESSAGES", "")
	t.Setenv("LANG", "")

	if got := defaultLanguage(); got != "tr" {
		t.Fatalf("defaultLanguage() = %q, want tr", got)
	}
}

func TestDefaultLanguageFromLocale(t *testing.T) {
	t.Setenv("APPSEC_LANG", "")
	t.Setenv("IRONSENTINEL_LANG", "")
	t.Setenv("LC_ALL", "tr_TR.UTF-8")
	t.Setenv("LC_MESSAGES", "")
	t.Setenv("LANG", "")

	if got := defaultLanguage(); got != "tr" {
		t.Fatalf("defaultLanguage() = %q, want tr", got)
	}
}

func TestDefaultLanguageFallsBackToEnglish(t *testing.T) {
	t.Setenv("APPSEC_LANG", "")
	t.Setenv("IRONSENTINEL_LANG", "")
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_MESSAGES", "")
	t.Setenv("LANG", "en_US.UTF-8")

	if got := defaultLanguage(); got != "en" {
		t.Fatalf("defaultLanguage() = %q, want en", got)
	}
}

func TestDefaultLanguagePrefersIronSentinelNamespace(t *testing.T) {
	t.Setenv("IRONSENTINEL_LANG", "tr")
	t.Setenv("APPSEC_LANG", "en")
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_MESSAGES", "")
	t.Setenv("LANG", "")

	if got := defaultLanguage(); got != "tr" {
		t.Fatalf("defaultLanguage() = %q, want tr from IRONSENTINEL_LANG", got)
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

func TestResolveAppRootPrefersIronSentinelHomeAlias(t *testing.T) {
	cwd := t.TempDir()
	buildRoot := t.TempDir()
	home := t.TempDir()
	t.Setenv("IRONSENTINEL_HOME", home)
	t.Setenv("APPSEC_HOME", filepath.Join(t.TempDir(), "appsec"))
	t.Setenv("APPSEC_HOME", filepath.Join(t.TempDir(), "appsec"))

	got := resolveAppRoot(cwd, buildRoot, filepath.Join(t.TempDir(), "fallback"))
	if got != home {
		t.Fatalf("resolveAppRoot() = %q, want %q", got, home)
	}
}

func TestLoadPrefersIronSentinelEnvAliases(t *testing.T) {
	root := t.TempDir()
	writeAppRootFixture(t, root)
	t.Setenv("IRONSENTINEL_HOME", root)
	t.Setenv("IRONSENTINEL_DATA_DIR", filepath.Join(root, "custom-data"))
	t.Setenv("IRONSENTINEL_OUTPUT_DIR", filepath.Join(root, "custom-output"))
	t.Setenv("IRONSENTINEL_TOOLS_DIR", filepath.Join(root, "custom-tools"))
	t.Setenv("IRONSENTINEL_CONTAINER_IMAGE", "ghcr.io/example/ironsentinel:test")
	t.Setenv("IRONSENTINEL_OFFLINE_MODE", "true")
	t.Setenv("APPSEC_DATA_DIR", filepath.Join(root, "legacy-data"))
	t.Setenv("APPSEC_TOOLS_DIR", filepath.Join(root, "legacy-tools"))
	t.Setenv("APPSEC_CONTAINER_IMAGE", "ghcr.io/example/legacy:test")

	cfg := Load()
	if cfg.DataDir != filepath.Join(root, "custom-data") {
		t.Fatalf("Load().DataDir = %q, want IRONSENTINEL alias", cfg.DataDir)
	}
	if cfg.OutputDir != filepath.Join(root, "custom-output") {
		t.Fatalf("Load().OutputDir = %q, want IRONSENTINEL alias", cfg.OutputDir)
	}
	if cfg.ToolsDir != filepath.Join(root, "custom-tools") {
		t.Fatalf("Load().ToolsDir = %q, want IRONSENTINEL alias", cfg.ToolsDir)
	}
	if cfg.ContainerImage != "ghcr.io/example/ironsentinel:test" {
		t.Fatalf("Load().ContainerImage = %q, want IRONSENTINEL alias", cfg.ContainerImage)
	}
	if !cfg.OfflineMode {
		t.Fatalf("Load().OfflineMode = false, want true from IRONSENTINEL_OFFLINE_MODE")
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
