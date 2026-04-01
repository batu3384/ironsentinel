package agent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/batu3384/ironsentinel/internal/config"
)

func managedToolPath(cfg config.Config) string {
	managed := strings.TrimSpace(cfg.ToolsDir)
	systemPath := os.Getenv("PATH")
	if managed == "" {
		return systemPath
	}
	if systemPath == "" {
		return managed
	}
	return managed + string(os.PathListSeparator) + systemPath
}

func runtimePathEnv(cfg config.Config) string {
	return "PATH=" + managedToolPath(cfg)
}

func findBinary(cfg config.Config, name string) (string, error) {
	if path, ok := findInManagedTools(cfg.ToolsDir, name); ok {
		return path, nil
	}
	return exec.LookPath(name)
}

func findInManagedTools(root, name string) (string, bool) {
	root = strings.TrimSpace(root)
	name = strings.TrimSpace(name)
	if root == "" || name == "" {
		return "", false
	}

	for _, candidate := range managedBinaryCandidates(root, name) {
		info, err := os.Stat(candidate)
		if err != nil || info.IsDir() {
			continue
		}
		return candidate, true
	}
	return "", false
}

func managedBinaryCandidates(root, name string) []string {
	candidates := []string{filepath.Join(root, name)}
	if runtime.GOOS != "windows" {
		return candidates
	}

	ext := strings.TrimSpace(filepath.Ext(name))
	if ext != "" {
		return candidates
	}

	for _, suffix := range pathExts() {
		candidates = append(candidates, filepath.Join(root, name+suffix))
	}
	return candidates
}

func pathExts() []string {
	raw := os.Getenv("PATHEXT")
	if strings.TrimSpace(raw) == "" {
		raw = ".COM;.EXE;.BAT;.CMD"
	}

	parts := strings.Split(raw, ";")
	exts := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(strings.ToLower(part))
		if part == "" {
			continue
		}
		exts = append(exts, part)
	}
	return exts
}

func CommandForScript(script string, resolver func(string) (string, error), args ...string) (*exec.Cmd, error) {
	switch strings.ToLower(filepath.Ext(strings.TrimSpace(script))) {
	case ".ps1":
		for _, candidate := range []string{"pwsh", "powershell"} {
			if _, err := resolver(candidate); err == nil {
				allArgs := append([]string{"-NoLogo", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script}, args...)
				return exec.Command(candidate, allArgs...), nil
			}
		}
		return nil, fmt.Errorf("PowerShell not found: install pwsh or powershell to run %s", script)
	case ".sh":
		if _, err := resolver("bash"); err != nil {
			return nil, fmt.Errorf("bash not found: %w", err)
		}
		return exec.Command("bash", append([]string{script}, args...)...), nil
	default:
		return exec.Command(script, args...), nil
	}
}
