package agent

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
)

func TestExecuteModuleAttemptClassifiesTimeout(t *testing.T) {
	spec, output, exitCode, timedOut, failureKind, err := executeModuleAttempt(context.Background(), 50*time.Millisecond, func() (builtCommand, error) {
		return builtCommand{
			command: exec.Command("sh", "-c", "sleep 1"),
		}, nil
	})

	if spec.command == nil {
		t.Fatalf("expected built command metadata to be returned")
	}
	if !timedOut {
		t.Fatalf("expected attempt to time out")
	}
	if failureKind != domain.ModuleFailureTimeout {
		t.Fatalf("expected timeout failure kind, got %s", failureKind)
	}
	if err == nil {
		t.Fatalf("expected timeout error")
	}
	if exitCode == nil {
		t.Fatalf("expected exit code to be captured")
	}
	if len(output) != 0 {
		t.Fatalf("expected no output for timed out command")
	}
}

func TestShouldRetryModuleAttempt(t *testing.T) {
	if !shouldRetryModuleAttempt(domain.ModuleFailureParse, 1, 2) {
		t.Fatalf("expected parse error to be retried on first attempt")
	}
	if shouldRetryModuleAttempt(domain.ModuleFailureSkipped, 1, 2) {
		t.Fatalf("did not expect skipped modules to retry")
	}
	if shouldRetryModuleAttempt(domain.ModuleFailureCommand, 2, 2) {
		t.Fatalf("did not expect retry after max attempts")
	}
}

func TestResolveScanExecutionPolicy(t *testing.T) {
	policy := resolveScanExecutionPolicy(domain.ScanProfile{Mode: domain.ModeDeep}, 5)
	if policy.WorkerCount != 3 {
		t.Fatalf("expected deep mode to use 3 workers, got %d", policy.WorkerCount)
	}
	if policy.RetryBackoffBase <= 0 {
		t.Fatalf("expected positive retry backoff base")
	}

	corePolicy := resolveScanExecutionPolicy(domain.ScanProfile{Mode: domain.ModeSafe, Coverage: domain.CoverageCore}, 3)
	if corePolicy.WorkerCount != 1 {
		t.Fatalf("expected core coverage to collapse to 1 worker, got %d", corePolicy.WorkerCount)
	}
}

func TestResolveScanExecutionPolicyScalesDeepForLargePlans(t *testing.T) {
	policy := resolveScanExecutionPolicy(domain.ScanProfile{Mode: domain.ModeDeep, Coverage: domain.CoverageFull}, 12)
	if policy.WorkerCount < 3 {
		t.Fatalf("expected deep mode large plans to keep at least 3 workers, got %d", policy.WorkerCount)
	}
	if policy.WorkerCount > 4 {
		t.Fatalf("expected deep mode large plans to cap worker count, got %d", policy.WorkerCount)
	}
}

func TestRetryBackoffForAttemptIncreases(t *testing.T) {
	first := retryBackoffForAttempt(200*time.Millisecond, 1)
	second := retryBackoffForAttempt(200*time.Millisecond, 2)
	if first != 200*time.Millisecond {
		t.Fatalf("unexpected first backoff: %s", first)
	}
	if second <= first {
		t.Fatalf("expected second backoff to increase, got %s <= %s", second, first)
	}
}

func TestBuildModulePlanOrdersFastSignalLanesFirst(t *testing.T) {
	modules := buildModulePlan(config.Config{}, []string{"javascript", "typescript", "terraform", "iac"}, domain.ScanProfile{
		Mode:         domain.ModeDeep,
		Coverage:     domain.CoverageFull,
		SeverityGate: domain.SeverityHigh,
		Modules: []string{
			"zaproxy",
			"semgrep",
			"stack-detector",
			"trivy",
			"secret-heuristics",
			"checkov",
		},
	})
	got := make([]string, 0, len(modules))
	for _, module := range modules {
		got = append(got, module.name)
	}
	want := []string{
		"stack-detector",
		"secret-heuristics",
		"semgrep",
		"trivy",
		"checkov",
		"zaproxy",
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d modules, got %d (%v)", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected module order at %d: got %v want %v", i, got, want)
		}
	}
}
