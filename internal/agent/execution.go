package agent

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
)

type moduleExecution struct {
	mode              domain.IsolationMode
	contract          domain.IsolationContract
	engine            string
	enginePath        string
	image             string
	platform          string
	mirrorDir         string
	binary            string
	hostTargetPath    string
	hostOutputDir     string
	request           domain.AgentScanRequest
	outputDir         string
	containerReady    bool
	containerRootless bool
}

func resolveModuleExecution(cfg config.Config, request domain.AgentScanRequest, binary, outputDir string) moduleExecution {
	isolation := discoverIsolation(cfg)
	contract := resolveIsolationContract(cfg, request.Profile)
	mode := contract.Mode

	execRequest := request
	execOutputDir := outputDir
	execBinary := binary
	if mode == domain.IsolationContainer {
		execRequest.TargetPath = "/workspace"
		execOutputDir = "/artifacts"
		execBinary = filepath.Base(binary)
	}

	return moduleExecution{
		mode:              mode,
		contract:          contract,
		engine:            isolation.Engine,
		enginePath:        isolation.EnginePath,
		image:             isolation.ContainerImage,
		platform:          isolation.Platform,
		mirrorDir:         cfg.MirrorDir,
		binary:            execBinary,
		hostTargetPath:    request.TargetPath,
		hostOutputDir:     outputDir,
		request:           execRequest,
		outputDir:         execOutputDir,
		containerReady:    isolation.Ready,
		containerRootless: isolation.Rootless,
	}
}

func (m moduleExecution) unavailableReason() string {
	if m.mode != domain.IsolationContainer {
		return ""
	}
	if !m.containerReady {
		return "container isolation requested but rootless engine or scanner image is unavailable"
	}
	return ""
}

func (m moduleExecution) build(command *exec.Cmd, hostTargetPath, hostOutputDir string) *exec.Cmd {
	if m.mode != domain.IsolationContainer {
		return command
	}

	args := []string{"run", "--rm"}
	if strings.TrimSpace(m.platform) != "" {
		args = append(args, "--platform", m.platform)
	}
	if m.contract.RootfsReadOnly {
		args = append(args, "--read-only")
	}
	if m.contract.DropAllCapabilities {
		args = append(args, "--cap-drop", "ALL")
	}
	if m.contract.NoNewPrivileges {
		args = append(args, "--security-opt", "no-new-privileges")
	}
	if m.contract.NetworkPolicy == domain.IsolationNetworkNone {
		args = append(args, "--network", "none")
	} else {
		args = append(args, "--add-host", "host.docker.internal:host-gateway")
	}
	if m.contract.PidsLimit > 0 {
		args = append(args, "--pids-limit", strconv.Itoa(m.contract.PidsLimit))
	}
	if m.contract.MemoryMiB > 0 {
		args = append(args, "--memory", fmt.Sprintf("%dm", m.contract.MemoryMiB))
	}
	if m.contract.CPUMilli > 0 {
		args = append(args, "--cpus", fmt.Sprintf("%.1f", float64(m.contract.CPUMilli)/1000))
	}
	for _, path := range m.contract.TmpfsPaths {
		args = append(args, "--tmpfs", tmpfsMountSpec(path))
	}
	if m.engine == "podman" && m.containerRootless {
		args = append(args, "--userns=keep-id")
	}
	args = append(args,
		"-e", "PATH=/root/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"-v", hostTargetPath+":/workspace:ro",
		"-v", hostOutputDir+":/artifacts:rw",
		"-w", "/workspace",
	)

	if strings.TrimSpace(m.mirrorDir) != "" {
		args = append(args, "-v", m.mirrorDir+":/mirror:ro")
	}

	args = append(args, "--entrypoint", "/bin/bash", m.image, "-c", wrapContainerCommand(command))
	wrapped := exec.Command(m.enginePath, args...)
	wrapped.Dir = hostTargetPath
	return wrapped
}

func commandArgs(command *exec.Cmd) []string {
	if len(command.Args) > 0 {
		return append([]string(nil), command.Args...)
	}
	if strings.TrimSpace(command.Path) == "" {
		return nil
	}
	return []string{command.Path}
}

func shellJoin(args []string) string {
	if len(args) == 0 {
		return ""
	}
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, shellQuote(arg))
	}
	return strings.Join(quoted, " ")
}

func wrapContainerCommand(command *exec.Cmd) string {
	const (
		containerHome     = "/artifacts/.runtime/home"
		containerCache    = "/artifacts/.runtime/cache"
		containerTempRoot = "/artifacts/.runtime/tmp"
	)
	args := shellJoin(commandArgs(command))
	setup := []string{
		"mkdir -p " + shellQuote(containerHome) + " " + shellQuote(containerCache) + " " + shellQuote(containerTempRoot),
		"export HOME=" + shellQuote(containerHome),
		"export XDG_CACHE_HOME=" + shellQuote(containerCache),
		"export TMPDIR=" + shellQuote(containerTempRoot),
		"export PATH=" + shellQuote("/root/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
		"export PYTHONPATH=" + shellQuote("/usr/lib/python3/dist-packages"),
	}
	if args != "" {
		setup = append(setup, "exec "+args)
	}
	return strings.Join(setup, " && ")
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	if !strings.ContainsAny(value, " \t\n'\"\\$`!&*()[]{}|;<>?~") {
		return value
	}
	var builder strings.Builder
	builder.WriteByte('\'')
	for _, ch := range value {
		if ch == '\'' {
			builder.WriteString("'\"'\"'")
			continue
		}
		builder.WriteRune(ch)
	}
	builder.WriteByte('\'')
	return builder.String()
}

func translateArtifactPath(containerPath, hostOutputDir string) string {
	if strings.TrimSpace(containerPath) == "" {
		return ""
	}
	if strings.HasPrefix(containerPath, "/artifacts/") {
		return filepath.Join(hostOutputDir, strings.TrimPrefix(containerPath, "/artifacts/"))
	}
	if containerPath == "/artifacts" {
		return hostOutputDir
	}
	return containerPath
}

func mirrorPathForRequest(cfg config.Config, request domain.AgentScanRequest, tool string) string {
	root := cfg.MirrorDir
	if request.TargetPath == "/workspace" {
		root = "/mirror"
	}
	switch tool {
	case "trivy":
		return filepath.Join(root, "trivy-db")
	case "osv-scanner":
		return filepath.Join(root, "osv-cache")
	default:
		return root
	}
}

func validateIsolationRequest(cfg config.Config, profile domain.ScanProfile) error {
	requested := profile.Isolation
	if requested == "" {
		requested = parseIsolationMode(cfg.SandboxMode)
	}
	if requested != domain.IsolationContainer {
		return nil
	}
	isolation := discoverIsolation(cfg)
	if isolation.Ready {
		return nil
	}
	return fmt.Errorf("container isolation requested but runtime is not ready")
}

func resolveIsolationContract(cfg config.Config, profile domain.ScanProfile) domain.IsolationContract {
	return domain.ResolveIsolationContract(profile, resolveEffectiveIsolationMode(cfg, profile), cfg.OfflineMode)
}

func resolveEffectiveIsolationMode(cfg config.Config, profile domain.ScanProfile) domain.IsolationMode {
	requested := profile.Isolation
	if requested == "" {
		requested = parseIsolationMode(cfg.SandboxMode)
	}
	isolation := discoverIsolation(cfg)

	switch requested {
	case domain.IsolationContainer:
		if isolation.Ready {
			return domain.IsolationContainer
		}
		return domain.IsolationLocal
	case domain.IsolationAuto:
		if isolation.EffectiveMode == domain.IsolationContainer {
			return domain.IsolationContainer
		}
		return domain.IsolationLocal
	default:
		return domain.IsolationLocal
	}
}

func tmpfsMountSpec(path string) string {
	size := "64m"
	switch path {
	case "/tmp":
		size = "256m"
	case "/var/tmp":
		size = "128m"
	case "/run":
		size = "32m"
	}
	return path + ":rw,noexec,nosuid,nodev,size=" + size
}
