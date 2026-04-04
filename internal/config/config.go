package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type Config struct {
	AppRoot               string
	ProjectRoot           string
	DataDir               string
	OutputDir             string
	DistDir               string
	MirrorDir             string
	ToolsDir              string
	YARARulesDir          string
	ArtifactRetentionDays int
	ArtifactRedaction     bool
	ArtifactEncryptionKey string
	DefaultLanguage       string
	BundleLockPath        string
	InstallScript         string
	ImageBuildScript      string
	ContainerfilePath     string
	SandboxMode           string
	ContainerEngine       string
	ContainerImage        string
	ContainerPlatform     string
	OfflineMode           bool
}

func Load() Config {
	cwd, _ := os.Getwd()
	appRoot := resolveAppRoot(cwd, buildWorkspaceRoot(), appHomeFallback())
	projectRuntimeRoot := filepath.Join(cwd, "runtime")
	sharedRuntimeRoot := filepath.Join(appRoot, "runtime")
	installScript := filepath.Join(appRoot, "scripts", "install_scanners.sh")
	imageBuildScript := filepath.Join(appRoot, "scripts", "build_scanner_image.sh")
	if runtime.GOOS == "windows" {
		installScript = filepath.Join(appRoot, "scripts", "install_scanners.ps1")
		imageBuildScript = filepath.Join(appRoot, "scripts", "build_scanner_image.ps1")
	}

	return Config{
		AppRoot:               appRoot,
		ProjectRoot:           cwd,
		DataDir:               envFirst(filepath.Join(projectRuntimeRoot, "data"), "IRONSENTINEL_DATA_DIR", "APPSEC_DATA_DIR"),
		OutputDir:             envFirst(filepath.Join(projectRuntimeRoot, "output"), "IRONSENTINEL_OUTPUT_DIR", "APPSEC_OUTPUT_DIR"),
		DistDir:               envFirst(filepath.Join(appRoot, "dist"), "IRONSENTINEL_DIST_DIR", "AEGIS_DIST_DIR"),
		MirrorDir:             envFirst(filepath.Join(sharedRuntimeRoot, "mirrors"), "IRONSENTINEL_MIRROR_DIR", "APPSEC_MIRROR_DIR"),
		ToolsDir:              envFirst(filepath.Join(sharedRuntimeRoot, "tools", "bin"), "IRONSENTINEL_TOOLS_DIR", "AEGIS_TOOLS_DIR"),
		YARARulesDir:          envFirst(filepath.Join(sharedRuntimeRoot, "rules", "yara"), "IRONSENTINEL_YARA_RULES_DIR", "APPSEC_YARA_RULES_DIR"),
		ArtifactRetentionDays: envIntFirst(30, "IRONSENTINEL_ARTIFACT_RETENTION_DAYS", "APPSEC_ARTIFACT_RETENTION_DAYS"),
		ArtifactRedaction:     envBoolFirst(true, "IRONSENTINEL_ARTIFACT_REDACTION", "APPSEC_ARTIFACT_REDACTION"),
		ArtifactEncryptionKey: envFirst("", "IRONSENTINEL_ARTIFACT_ENCRYPTION_KEY", "APPSEC_ARTIFACT_ENCRYPTION_KEY"),
		DefaultLanguage:       defaultLanguage(),
		BundleLockPath:        envFirst(filepath.Join(appRoot, "scanner-bundle.lock.json"), "IRONSENTINEL_BUNDLE_LOCK_PATH", "APPSEC_BUNDLE_LOCK_PATH"),
		InstallScript:         envFirst(installScript, "IRONSENTINEL_INSTALL_SCRIPT", "APPSEC_INSTALL_SCRIPT"),
		ImageBuildScript:      envFirst(imageBuildScript, "IRONSENTINEL_IMAGE_BUILD_SCRIPT", "APPSEC_IMAGE_BUILD_SCRIPT"),
		ContainerfilePath:     envFirst(filepath.Join(appRoot, "deploy", "scanner-bundle.Containerfile"), "IRONSENTINEL_CONTAINERFILE_PATH", "APPSEC_CONTAINERFILE_PATH"),
		SandboxMode:           envFirst("auto", "IRONSENTINEL_SANDBOX_MODE", "AEGIS_SANDBOX_MODE"),
		ContainerEngine:       envFirst("auto", "IRONSENTINEL_CONTAINER_ENGINE", "AEGIS_CONTAINER_ENGINE"),
		ContainerImage:        envFirst("ghcr.io/batu3384/ironsentinel-scanner-bundle:latest", "IRONSENTINEL_CONTAINER_IMAGE", "AEGIS_CONTAINER_IMAGE"),
		ContainerPlatform:     envFirst(defaultContainerPlatform(), "IRONSENTINEL_CONTAINER_PLATFORM", "AEGIS_CONTAINER_PLATFORM"),
		OfflineMode:           envBoolFirst(false, "IRONSENTINEL_OFFLINE_MODE", "APPSEC_OFFLINE_MODE"),
	}
}

func resolveAppRoot(cwd, buildRoot, fallback string) string {
	for _, envKey := range []string{"IRONSENTINEL_HOME", "APPSEC_HOME", "AEGIS_HOME"} {
		if root := strings.TrimSpace(os.Getenv(envKey)); root != "" {
			return root
		}
	}
	for _, candidate := range []string{cwd, buildRoot} {
		if looksLikeAppRoot(candidate) {
			return candidate
		}
	}
	return fallback
}

func looksLikeAppRoot(root string) bool {
	root = strings.TrimSpace(root)
	if root == "" {
		return false
	}
	required := []string{
		filepath.Join(root, "scanner-bundle.lock.json"),
		filepath.Join(root, "scripts", "install_scanners.sh"),
		filepath.Join(root, "deploy", "scanner-bundle.Containerfile"),
	}
	if runtime.GOOS == "windows" {
		required[1] = filepath.Join(root, "scripts", "install_scanners.ps1")
	}
	for _, path := range required {
		if _, err := os.Stat(path); err != nil {
			return false
		}
	}
	return true
}

func buildWorkspaceRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func appHomeFallback() string {
	if dir, err := os.UserConfigDir(); err == nil && strings.TrimSpace(dir) != "" {
		return filepath.Join(dir, "IronSentinel")
	}
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, ".ironsentinel")
	}
	return ".ironsentinel"
}

func defaultContainerPlatform() string {
	if runtime.GOARCH == "arm64" && (runtime.GOOS == "darwin" || runtime.GOOS == "windows") {
		return "linux/amd64"
	}
	return ""
}

func defaultLanguage() string {
	for _, key := range []string{"IRONSENTINEL_LANG", "AEGIS_LANG", "APPSEC_LANG"} {
		if explicit := strings.TrimSpace(os.Getenv(key)); explicit != "" {
			return explicit
		}
	}
	for _, key := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if value := strings.ToLower(strings.TrimSpace(os.Getenv(key))); strings.HasPrefix(value, "tr") {
			return "tr"
		}
	}
	return "en"
}

func envFirst(fallback string, keys ...string) string {
	for _, key := range keys {
		value := os.Getenv(key)
		if value != "" {
			return value
		}
	}
	return fallback
}

func envBoolFirst(fallback bool, keys ...string) bool {
	for _, key := range keys {
		value := os.Getenv(key)
		if value == "" {
			continue
		}
		switch value {
		case "1", "true", "TRUE", "yes", "YES", "on", "ON":
			return true
		case "0", "false", "FALSE", "no", "NO", "off", "OFF":
			return false
		default:
			return fallback
		}
	}
	return fallback
}

func envIntFirst(fallback int, keys ...string) int {
	for _, key := range keys {
		value := os.Getenv(key)
		if value == "" {
			continue
		}
		parsed, err := strconv.Atoi(value)
		if err == nil {
			return parsed
		}
		return fallback
	}
	return fallback
}
