package cli

import (
	"os"
	"path/filepath"
	"strings"
)

func (a *App) installCommandHint(mode string) string {
	mode = strings.TrimSpace(mode)
	if mode == "" {
		mode = "safe"
	}

	scriptPath := a.cfg.InstallScript
	if cwd, err := os.Getwd(); err == nil {
		if rel, relErr := filepath.Rel(cwd, scriptPath); relErr == nil && !strings.HasPrefix(rel, "..") {
			scriptPath = rel
		}
	}
	scriptPath = filepath.ToSlash(scriptPath)

	switch strings.ToLower(filepath.Ext(scriptPath)) {
	case ".ps1":
		return "`pwsh " + scriptPath + " --mode " + mode + "`"
	default:
		return "`bash " + scriptPath + " --mode " + mode + "`"
	}
}
