package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/batu3384/ironsentinel/internal/config"
)

func TestFindBinaryPrefersManagedToolsDir(t *testing.T) {
	toolsDir := t.TempDir()
	binaryPath := filepath.Join(toolsDir, "scanner-test")
	if err := os.WriteFile(binaryPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write managed binary: %v", err)
	}

	path, err := findBinary(config.Config{ToolsDir: toolsDir}, "scanner-test")
	if err != nil {
		t.Fatalf("expected managed binary to resolve: %v", err)
	}
	if path != binaryPath {
		t.Fatalf("expected managed binary path %q, got %q", binaryPath, path)
	}
}

func TestCommandForScriptUsesBashForShellScripts(t *testing.T) {
	cmd, err := CommandForScript("/tmp/script.sh", execLookPathResolver("bash"), "--help")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := filepath.Base(cmd.Path); got != "bash" {
		t.Fatalf("expected bash runner, got %q", got)
	}
}

func TestCommandForScriptUsesPowerShellForPs1Scripts(t *testing.T) {
	cmd, err := CommandForScript("C:\\temp\\script.ps1", execLookPathResolver("pwsh"), "--mode", "safe")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := filepath.Base(cmd.Path); got != "pwsh" {
		t.Fatalf("expected pwsh runner, got %q", got)
	}
	if len(cmd.Args) < 7 {
		t.Fatalf("expected powershell arguments to be populated, got %v", cmd.Args)
	}
}

func execLookPathResolver(existing ...string) func(string) (string, error) {
	index := make(map[string]struct{}, len(existing))
	for _, name := range existing {
		index[name] = struct{}{}
	}
	return func(name string) (string, error) {
		if _, ok := index[name]; ok {
			return "/usr/bin/" + name, nil
		}
		return "", os.ErrNotExist
	}
}
