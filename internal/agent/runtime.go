package agent

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strings"
	"time"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
)

func discoverIsolation(cfg config.Config) domain.RuntimeIsolation {
	preferred := parseIsolationMode(cfg.SandboxMode)
	engineName, enginePath := resolveContainerEngine(cfg.ContainerEngine)
	info := domain.RuntimeIsolation{
		PreferredMode:  preferred,
		EffectiveMode:  domain.IsolationLocal,
		Engine:         engineName,
		EnginePath:     enginePath,
		Platform:       strings.TrimSpace(cfg.ContainerPlatform),
		ContainerImage: cfg.ContainerImage,
	}
	if enginePath == "" {
		info.DefaultContract = domain.ResolveIsolationContract(domain.ScanProfile{Mode: domain.ModeSafe}, info.EffectiveMode, cfg.OfflineMode)
		return info
	}

	info.Rootless = detectRootless(engineName, enginePath)
	info.ImagePresent = detectImagePresent(enginePath, cfg.ContainerImage)
	info.Ready = containerHostSupportsIsolation(engineName, info.Rootless) && info.ImagePresent
	switch preferred {
	case domain.IsolationContainer:
		if info.Ready {
			info.EffectiveMode = domain.IsolationContainer
		}
	case domain.IsolationAuto:
		if info.Ready {
			info.EffectiveMode = domain.IsolationContainer
		}
	default:
		info.EffectiveMode = domain.IsolationLocal
	}
	info.DefaultContract = domain.ResolveIsolationContract(domain.ScanProfile{Mode: domain.ModeSafe}, info.EffectiveMode, cfg.OfflineMode)
	return info
}

func discoverMirrors(cfg config.Config) []domain.RuntimeMirror {
	mirrors := []domain.RuntimeMirror{
		describeMirror("trivy", filepath.Join(cfg.MirrorDir, "trivy-db")),
		describeMirror("osv-scanner", filepath.Join(cfg.MirrorDir, "osv-cache")),
	}
	sort.Slice(mirrors, func(i, j int) bool { return mirrors[i].Tool < mirrors[j].Tool })
	return mirrors
}

func describeMirror(tool, path string) domain.RuntimeMirror {
	mirror := domain.RuntimeMirror{Tool: tool, Path: path}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		mirror.Notes = "mirror not initialized"
		return mirror
	}
	mirror.Available = dirHasEntries(path)
	if !mirror.Available {
		mirror.Notes = "directory exists but is empty"
		return mirror
	}
	if updatedAt := newestModTime(path); !updatedAt.IsZero() {
		timestamp := updatedAt
		mirror.UpdatedAt = &timestamp
	}
	return mirror
}

func dirHasEntries(path string) bool {
	entries, err := os.ReadDir(path)
	return err == nil && len(entries) > 0
}

func newestModTime(root string) time.Time {
	latest := time.Time{}
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if info.ModTime().After(latest) {
			latest = info.ModTime()
		}
		return nil
	})
	return latest
}

func parseIsolationMode(input string) domain.IsolationMode {
	switch strings.ToLower(strings.TrimSpace(input)) {
	case string(domain.IsolationContainer):
		return domain.IsolationContainer
	case string(domain.IsolationLocal):
		return domain.IsolationLocal
	default:
		return domain.IsolationAuto
	}
}

func resolveContainerEngine(preferred string) (string, string) {
	order := []string{"podman", "docker"}
	switch strings.ToLower(strings.TrimSpace(preferred)) {
	case "podman":
		order = []string{"podman"}
	case "docker":
		order = []string{"docker"}
	}

	for _, candidate := range order {
		path, err := exec.LookPath(candidate)
		if err == nil {
			return candidate, path
		}
	}
	return "", ""
}

func detectRootless(engineName, enginePath string) bool {
	switch engineName {
	case "podman":
		output, err := runProbeCommand(enginePath, "info", "--format", "json")
		if err != nil {
			return false
		}
		var payload map[string]any
		if json.Unmarshal(output, &payload) != nil {
			return strings.Contains(strings.ToLower(string(output)), `"rootless":true`)
		}
		host, _ := payload["host"].(map[string]any)
		if host == nil {
			return false
		}
		if value, ok := host["rootless"].(bool); ok {
			return value
		}
		return strings.Contains(strings.ToLower(string(output)), `"rootless":true`)
	case "docker":
		output, err := runProbeCommand(enginePath, "info", "--format", "{{json .SecurityOptions}}")
		if err != nil {
			return false
		}
		return strings.Contains(strings.ToLower(string(output)), "rootless")
	default:
		return false
	}
}

func containerHostSupportsIsolation(engineName string, rootless bool) bool {
	if rootless {
		return true
	}
	if engineName == "docker" && (goruntime.GOOS == "darwin" || goruntime.GOOS == "windows") {
		return true
	}
	return false
}

func detectImagePresent(enginePath, image string) bool {
	if strings.TrimSpace(enginePath) == "" || strings.TrimSpace(image) == "" {
		return false
	}
	_, err := runProbeCommand(enginePath, "image", "inspect", image)
	return err == nil
}
