package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
)

func TestExternalModuleChaosRecoversAfterTransientParseFailure(t *testing.T) {
	cfg := config.Config{
		DataDir:   filepath.Join(t.TempDir(), "data"),
		OutputDir: filepath.Join(t.TempDir(), "output"),
		ToolsDir:  filepath.Join(t.TempDir(), "tools"),
	}
	target := t.TempDir()
	flagPath := filepath.Join(target, ".chaos-retry-flag")

	module := externalModule(cfg, "sh", domain.CategorySAST, func(binary string, execution moduleExecution, _ []string) (*exec.Cmd, string, error) {
		script := "if [ -f \"$FLAG\" ]; then printf '{\"title\":\"Recovered semantic flow\"}'; else touch \"$FLAG\"; printf 'transient-corruption'; fi"
		cmd := exec.Command(binary, "-c", script)
		cmd.Env = append(os.Environ(), "FLAG="+flagPath)
		cmd.Dir = execution.request.TargetPath
		return cmd, "", nil
	}, func(request domain.AgentScanRequest, module string, output []byte) (domain.ModuleResult, []domain.Finding, error) {
		var payload struct {
			Title string `json:"title"`
		}
		if err := json.Unmarshal(output, &payload); err != nil {
			return domain.ModuleResult{}, nil, err
		}
		return domain.ModuleResult{
				Status:       domain.ModuleCompleted,
				Summary:      payload.Title,
				FindingCount: 1,
			}, []domain.Finding{{
				ScanID:       request.ScanID,
				ProjectID:    request.ProjectID,
				Fingerprint:  "fp-chaos-recovery",
				Severity:     domain.SeverityHigh,
				Category:     domain.CategorySAST,
				Title:        payload.Title,
				Module:       module,
				Confidence:   0.8,
				Reachability: "likely",
			}}, nil
	})

	request := domain.AgentScanRequest{
		ScanID:      "run-chaos-recovery",
		ProjectID:   "prj-chaos",
		TargetPath:  target,
		DisplayName: "Chaos Fixture",
		Profile: domain.ScanProfile{
			Mode:      domain.ModeSafe,
			Coverage:  domain.CoverageCore,
			Isolation: domain.IsolationLocal,
		},
	}

	var traces []domain.ModuleExecutionTrace
	result, findings, err := module.run(context.Background(), request, nil, cfg.OutputDir, func(event domain.AgentEvent) error {
		if event.Type == "module.execution" && event.Execution != nil {
			traces = append(traces, *event.Execution)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("module run: %v", err)
	}
	if result.Status != domain.ModuleCompleted {
		t.Fatalf("expected completed result, got %s", result.Status)
	}
	if result.Attempts != 2 {
		t.Fatalf("expected recovery on second attempt, got %d attempts", result.Attempts)
	}
	if len(findings) != 1 || findings[0].Title != "Recovered semantic flow" {
		t.Fatalf("unexpected normalized findings: %+v", findings)
	}
	if len(traces) == 0 || traces[len(traces)-1].AttemptsUsed != 2 {
		t.Fatalf("expected final execution trace to record 2 attempts, got %+v", traces)
	}
}

func TestExternalModuleChaosCancelsDuringRetryBackoff(t *testing.T) {
	cfg := config.Config{
		DataDir:   filepath.Join(t.TempDir(), "data"),
		OutputDir: filepath.Join(t.TempDir(), "output"),
		ToolsDir:  filepath.Join(t.TempDir(), "tools"),
	}
	target := t.TempDir()

	module := externalModule(cfg, "sh", domain.CategorySAST, func(binary string, execution moduleExecution, _ []string) (*exec.Cmd, string, error) {
		cmd := exec.Command(binary, "-c", "printf 'still-corrupt'")
		cmd.Dir = execution.request.TargetPath
		return cmd, "", nil
	}, func(_ domain.AgentScanRequest, _ string, output []byte) (domain.ModuleResult, []domain.Finding, error) {
		return domain.ModuleResult{}, nil, errors.New(string(output))
	})

	request := domain.AgentScanRequest{
		ScanID:      "run-chaos-cancel",
		ProjectID:   "prj-chaos",
		TargetPath:  target,
		DisplayName: "Chaos Cancel Fixture",
		Profile: domain.ScanProfile{
			Mode:      domain.ModeSafe,
			Coverage:  domain.CoverageCore,
			Isolation: domain.IsolationLocal,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, _, err := module.run(ctx, request, nil, cfg.OutputDir, func(event domain.AgentEvent) error {
		if event.Type == "module.execution" && event.Execution != nil && event.Execution.AttemptsUsed == 1 {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation during retry backoff, got %v", err)
	}
}

func TestChaosRetryLoopExhaustsTimeoutBudget(t *testing.T) {
	policy := moduleJobPolicy{
		Timeout:          25 * time.Millisecond,
		MaxAttempts:      2,
		RetryBackoffBase: 5 * time.Millisecond,
	}

	started := time.Now()
	attempts, failureKind, err := runChaosRetryLoop(context.Background(), policy, func() (builtCommand, error) {
		return builtCommand{
			command: exec.Command("sh", "-c", "sleep 1"),
		}, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded after retries, got %v", err)
	}
	if failureKind != domain.ModuleFailureTimeout {
		t.Fatalf("expected timeout failure kind, got %s", failureKind)
	}
	if attempts != 2 {
		t.Fatalf("expected timeout loop to consume 2 attempts, got %d", attempts)
	}
	if time.Since(started) < policy.Timeout {
		t.Fatalf("expected timeout loop to spend at least one timeout window")
	}
}

func runChaosRetryLoop(ctx context.Context, policy moduleJobPolicy, build func() (builtCommand, error)) (int, domain.ModuleFailureKind, error) {
	lastFailure := domain.ModuleFailureNone
	var lastErr error

	for attempt := 1; attempt <= policy.MaxAttempts; attempt++ {
		_, _, _, _, failureKind, err := executeModuleAttempt(ctx, policy.Timeout, build)
		if err == nil {
			return attempt, domain.ModuleFailureNone, nil
		}
		lastFailure = failureKind
		lastErr = err
		if failureKind == domain.ModuleFailureTimeout {
			lastErr = context.DeadlineExceeded
		}
		if !shouldRetryModuleAttempt(failureKind, attempt, policy.MaxAttempts) {
			return attempt, lastFailure, lastErr
		}
		backoff := retryBackoffForAttempt(policy.RetryBackoffBase, attempt)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return attempt, lastFailure, ctx.Err()
		case <-timer.C:
		}
	}

	return policy.MaxAttempts, lastFailure, lastErr
}
