package agent

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
)

var osvMirrorEcosystems = []string{"Go", "Maven", "NuGet", "PyPI", "npm"}

var mirrorHTTPClient = &http.Client{}
var downloadMirrorFileBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"

func refreshMirror(cfg config.Config, tool string) (domain.RuntimeMirror, error) {
	switch tool {
	case "trivy":
		target := filepath.Join(cfg.MirrorDir, "trivy-db")
		if err := os.MkdirAll(target, 0o755); err != nil {
			return domain.RuntimeMirror{}, err
		}
		binary, err := findBinary(cfg, "trivy")
		if err != nil {
			return domain.RuntimeMirror{}, fmt.Errorf("trivy binary not found on PATH or managed tools dir")
		}
		command := exec.Command(binary, "image", "--download-db-only", "--download-java-db-only", "--cache-dir", target)
		command.Env = buildSandboxEnv(domain.ScanProfile{
			Mode:         domain.ModeSafe,
			AllowBuild:   false,
			AllowNetwork: true,
		})
		command.Env = append(command.Env, runtimePathEnv(cfg))
		command.Env = uniqueEnv(command.Env)
		if output, err := command.CombinedOutput(); err != nil {
			return domain.RuntimeMirror{}, fmt.Errorf("trivy mirror refresh failed: %s", string(output))
		}
		return describeMirror(tool, target), nil
	case "osv-scanner":
		target := filepath.Join(cfg.MirrorDir, "osv-cache")
		if err := seedOSVMirror(target); err != nil {
			return domain.RuntimeMirror{}, err
		}
		return describeMirror(tool, target), nil
	default:
		return domain.RuntimeMirror{}, fmt.Errorf("mirror refresh not supported for %s", tool)
	}
}

func uniqueEnv(env []string) []string {
	seen := make(map[string]int, len(env))
	for index, entry := range env {
		key, _, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		seen[key] = index
	}

	result := make([]string, 0, len(seen))
	for index, entry := range env {
		key, _, found := strings.Cut(entry, "=")
		if !found {
			result = append(result, entry)
			continue
		}
		if seen[key] == index {
			result = append(result, entry)
		}
	}
	return result
}

func seedOSVMirror(root string) error {
	base := filepath.Join(root, "osv-scanner")
	for _, ecosystem := range osvMirrorEcosystems {
		url := fmt.Sprintf("%s/%s/all.zip", strings.TrimRight(downloadMirrorFileBaseURL, "/"), ecosystem)
		targetDir := filepath.Join(base, ecosystem)
		if err := os.MkdirAll(targetDir, 0o755); err != nil {
			return err
		}
		targetPath := filepath.Join(targetDir, "all.zip")
		if err := downloadMirrorFile(url, targetPath); err != nil {
			return fmt.Errorf("osv-scanner mirror refresh failed for %s: %w", ecosystem, err)
		}
	}
	return nil
}

func downloadMirrorFile(url, destination string) error {
	response, err := mirrorHTTPClient.Get(url)
	if err != nil {
		return err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return fmt.Errorf("unexpected HTTP %d from %s: %s", response.StatusCode, url, strings.TrimSpace(string(body)))
	}

	tmpPath := destination + ".tmp"
	file, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	if _, err := io.Copy(file, response.Body); err != nil {
		_ = file.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, destination); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}
