package agent

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/batu3384/ironsentinel/internal/domain"
)

type moduleJobPolicy struct {
	Timeout          time.Duration
	MaxAttempts      int
	RetryBackoffBase time.Duration
}

type scanExecutionPolicy struct {
	WorkerCount      int
	RetryBackoffBase time.Duration
}

type builtCommand struct {
	command      *exec.Cmd
	workingDir   string
	environment  []string
	artifactPath string
}

func resolveModuleJobPolicy(name string, profile domain.ScanProfile) moduleJobPolicy {
	policy := moduleJobPolicy{
		Timeout:          90 * time.Second,
		MaxAttempts:      2,
		RetryBackoffBase: 300 * time.Millisecond,
	}

	switch profile.Mode {
	case domain.ModeDeep:
		policy.Timeout = 3 * time.Minute
		policy.RetryBackoffBase = 450 * time.Millisecond
	case domain.ModeActive:
		policy.Timeout = 4 * time.Minute
		policy.RetryBackoffBase = 700 * time.Millisecond
	}

	switch name {
	case "codeql":
		policy.Timeout = 10 * time.Minute
		policy.MaxAttempts = 1
	case "zaproxy":
		policy.Timeout = 5 * time.Minute
		policy.MaxAttempts = 1
	case "semgrep", "trivy", "syft", "osv-scanner", "checkov":
		policy.Timeout = 2 * time.Minute
	}

	return policy
}

func resolveScanExecutionPolicy(profile domain.ScanProfile, moduleCount int) scanExecutionPolicy {
	workerCount := 2
	cpuCount := runtime.NumCPU()
	if cpuCount < 1 {
		cpuCount = 1
	}
	switch profile.Mode {
	case domain.ModeDeep:
		workerCount = 3
	case domain.ModeActive:
		workerCount = 1
	}
	if profile.Coverage == domain.CoverageCore {
		workerCount = 1
	}
	if profile.Mode == domain.ModeSafe && profile.Coverage != domain.CoverageCore && cpuCount >= 6 && moduleCount >= 4 {
		workerCount = 2
	}
	if profile.Mode == domain.ModeDeep && cpuCount >= 8 && moduleCount >= 8 {
		workerCount = 4
	}
	if moduleCount > 0 && workerCount > moduleCount {
		workerCount = moduleCount
	}
	if workerCount < 1 {
		workerCount = 1
	}

	base := 300 * time.Millisecond
	switch profile.Mode {
	case domain.ModeDeep:
		base = 450 * time.Millisecond
	case domain.ModeActive:
		base = 700 * time.Millisecond
	}

	return scanExecutionPolicy{
		WorkerCount:      workerCount,
		RetryBackoffBase: base,
	}
}

func shouldRetryModuleAttempt(kind domain.ModuleFailureKind, attempt, maxAttempts int) bool {
	if attempt >= maxAttempts {
		return false
	}
	switch kind {
	case domain.ModuleFailureTimeout, domain.ModuleFailureCommand, domain.ModuleFailureParse, domain.ModuleFailureInfra, domain.ModuleFailureArtifactIO:
		return true
	default:
		return false
	}
}

func retryBackoffForAttempt(base time.Duration, attempt int) time.Duration {
	if base <= 0 {
		base = 250 * time.Millisecond
	}
	if attempt < 1 {
		attempt = 1
	}
	return time.Duration(attempt) * base
}

func executeModuleAttempt(ctx context.Context, timeout time.Duration, build func() (builtCommand, error)) (builtCommand, []byte, *int, bool, domain.ModuleFailureKind, error) {
	spec, err := build()
	if err != nil {
		if errors.Is(err, errModuleSkipped) {
			return builtCommand{}, nil, nil, false, domain.ModuleFailureSkipped, err
		}
		return builtCommand{}, nil, nil, false, domain.ModuleFailureInfra, err
	}

	attemptCtx := ctx
	cancel := func() {}
	if timeout > 0 {
		attemptCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	command := cloneCommandWithContext(attemptCtx, spec.command)
	output, runErr := command.CombinedOutput()

	var exitCode *int
	if runErr != nil {
		code := 1
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			code = exitErr.ExitCode()
		}
		exitCode = &code
	}

	if errors.Is(attemptCtx.Err(), context.DeadlineExceeded) {
		return spec, output, exitCode, true, domain.ModuleFailureTimeout, runErr
	}
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			return spec, output, exitCode, false, domain.ModuleFailureCommand, runErr
		}
		return spec, output, exitCode, false, domain.ModuleFailureInfra, runErr
	}

	return spec, output, exitCode, false, domain.ModuleFailureNone, nil
}

func cloneCommandWithContext(ctx context.Context, source *exec.Cmd) *exec.Cmd {
	cloned := exec.CommandContext(ctx, source.Path, source.Args[1:]...)
	cloned.Dir = source.Dir
	cloned.Env = append([]string(nil), source.Env...)
	return cloned
}

func summarizeModuleFailure(output []byte, err error, kind domain.ModuleFailureKind) string {
	trimmed := strings.TrimSpace(string(output))
	switch kind {
	case domain.ModuleFailureTimeout:
		return "Module execution timed out."
	case domain.ModuleFailureParse:
		if err != nil {
			return err.Error()
		}
	case domain.ModuleFailureArtifactIO:
		if err != nil {
			return err.Error()
		}
	}
	if trimmed != "" {
		return trimmed
	}
	if err != nil {
		return err.Error()
	}
	if kind != domain.ModuleFailureNone {
		return string(kind)
	}
	return "Module execution failed."
}
