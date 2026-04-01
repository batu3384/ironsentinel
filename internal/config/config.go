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
		DataDir:               envOr("APPSEC_DATA_DIR", filepath.Join(projectRuntimeRoot, "data")),
		OutputDir:             envOr("APPSEC_OUTPUT_DIR", filepath.Join(projectRuntimeRoot, "output")),
		DistDir:               envOr("AEGIS_DIST_DIR", filepath.Join(appRoot, "dist")),
		MirrorDir:             envOr("APPSEC_MIRROR_DIR", filepath.Join(sharedRuntimeRoot, "mirrors")),
		ToolsDir:              envOr("AEGIS_TOOLS_DIR", filepath.Join(sharedRuntimeRoot, "tools", "bin")),
		YARARulesDir:          envOr("APPSEC_YARA_RULES_DIR", filepath.Join(sharedRuntimeRoot, "rules", "yara")),
		ArtifactRetentionDays: envInt("APPSEC_ARTIFACT_RETENTION_DAYS", 30),
		ArtifactRedaction:     envBool("APPSEC_ARTIFACT_REDACTION", true),
		ArtifactEncryptionKey: envOr("APPSEC_ARTIFACT_ENCRYPTION_KEY", ""),
		DefaultLanguage:       defaultLanguage(),
		BundleLockPath:        envOr("APPSEC_BUNDLE_LOCK_PATH", filepath.Join(appRoot, "scanner-bundle.lock.json")),
		InstallScript:         envOr("APPSEC_INSTALL_SCRIPT", installScript),
		ImageBuildScript:      envOr("APPSEC_IMAGE_BUILD_SCRIPT", imageBuildScript),
		ContainerfilePath:     envOr("APPSEC_CONTAINERFILE_PATH", filepath.Join(appRoot, "deploy", "scanner-bundle.Containerfile")),
		SandboxMode:           envOr("AEGIS_SANDBOX_MODE", "auto"),
		ContainerEngine:       envOr("AEGIS_CONTAINER_ENGINE", "auto"),
		ContainerImage:        envOr("AEGIS_CONTAINER_IMAGE", "ghcr.io/batu3384/ironsentinel-scanner-bundle:latest"),
		ContainerPlatform:     envOr("AEGIS_CONTAINER_PLATFORM", defaultContainerPlatform()),
		OfflineMode:           envBool("APPSEC_OFFLINE_MODE", false),
	}
}

func resolveAppRoot(cwd, buildRoot, fallback string) string {
	for _, envKey := range []string{"APPSEC_HOME", "AEGIS_HOME"} {
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
	if explicit := strings.TrimSpace(os.Getenv("AEGIS_LANG")); explicit != "" {
		return explicit
	}
	for _, key := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if value := strings.ToLower(strings.TrimSpace(os.Getenv(key))); strings.HasPrefix(value, "tr") {
			return "tr"
		}
	}
	return "en"
}

func envOr(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func envBool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
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

func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
