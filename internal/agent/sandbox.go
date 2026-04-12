package agent

import (
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/batu3384/ironsentinel/internal/domain"
)

var sandboxEnvAllowlist = map[string]struct{}{
	"HOME":       {},
	"LANG":       {},
	"LC_ALL":     {},
	"LC_CTYPE":   {},
	"PATH":       {},
	"SHELL":      {},
	"SYSTEMROOT": {},
	"TEMP":       {},
	"TERM":       {},
	"TMP":        {},
	"TMPDIR":     {},
	"USER":       {},
}

func applySandbox(command *exec.Cmd, request domain.AgentScanRequest) []string {
	if strings.TrimSpace(command.Dir) == "" {
		command.Dir = request.TargetPath
	}
	env := buildSandboxEnv(request.Profile)
	if len(command.Env) > 0 {
		env = append(env, command.Env...)
		env = uniqueEnv(env)
	}
	command.Env = env
	return envKeys(env)
}

func buildSandboxEnv(profile domain.ScanProfile) []string {
	env := make([]string, 0, len(sandboxEnvAllowlist)+3)
	for _, entry := range os.Environ() {
		key, _, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		if _, ok := sandboxEnvAllowlist[key]; ok {
			env = append(env, entry)
		}
	}
	env = append(env,
		"IRONSENTINEL_ALLOW_BUILD="+boolString(profile.AllowBuild),
		"IRONSENTINEL_ALLOW_NETWORK="+boolString(profile.AllowNetwork),
		"IRONSENTINEL_SCAN_MODE="+string(profile.Mode),
	)
	sort.Strings(env)
	return env
}

func envKeys(env []string) []string {
	keys := make([]string, 0, len(env))
	for _, entry := range env {
		key, _, found := strings.Cut(entry, "=")
		if found {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
