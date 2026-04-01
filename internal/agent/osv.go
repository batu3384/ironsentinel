package agent

import (
	"os/exec"
	"strings"

	"github.com/batu3384/ironsentinel/internal/config"
)

func buildOSVCommand(cfg config.Config, binary string, execution moduleExecution) *exec.Cmd {
	args := []string{"--recursive", "--format", "json"}
	mirrorRoot := mirrorPathForRequest(cfg, execution.request, "osv-scanner")
	if dirHasEntries(mirrorRoot) {
		args = append(args, "--offline-vulnerabilities")
	}
	if cfg.OfflineMode && !containsArg(args, "--offline-vulnerabilities") {
		args = append(args, "--offline-vulnerabilities")
	}
	args = append(args, execution.request.TargetPath)

	command := exec.Command(binary, args...)
	if strings.TrimSpace(mirrorRoot) != "" && (cfg.OfflineMode || dirHasEntries(mirrorRoot)) {
		command.Env = append(command.Env, "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="+mirrorRoot)
	}
	return command
}

func containsArg(args []string, target string) bool {
	for _, arg := range args {
		if strings.TrimSpace(arg) == target {
			return true
		}
	}
	return false
}
