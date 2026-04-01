package agent

import (
	"strings"
	"testing"
	"time"

	"github.com/batu3384/ironsentinel/internal/domain"
)

func TestEmitModuleExecutionEventPublishesExecutionSnapshot(t *testing.T) {
	start := time.Now().UTC().Add(-2 * time.Second)
	policy := moduleJobPolicy{
		Timeout:     30 * time.Second,
		MaxAttempts: 2,
	}
	attempt := domain.ModuleAttemptTrace{
		Attempt:     1,
		StartedAt:   start,
		FinishedAt:  start.Add(500 * time.Millisecond),
		DurationMs:  500,
		FailureKind: domain.ModuleFailureTimeout,
		TimedOut:    true,
	}

	var captured domain.AgentEvent
	err := emitModuleExecutionEvent(func(event domain.AgentEvent) error {
		captured = event
		return nil
	}, "semgrep", domain.CategorySAST, domain.ModuleRunning, domain.ModuleFailureTimeout, policy, start, []domain.ModuleAttemptTrace{attempt}, &attempt)
	if err != nil {
		t.Fatalf("unexpected emit error: %v", err)
	}
	if captured.Type != "module.execution" {
		t.Fatalf("expected module.execution event, got %s", captured.Type)
	}
	if captured.Module == nil || captured.Module.Name != "semgrep" || captured.Module.Attempts != 1 {
		t.Fatalf("expected module snapshot in event, got %+v", captured.Module)
	}
	if captured.Execution == nil || captured.Execution.AttemptsUsed != 1 || captured.Execution.MaxAttempts != 2 {
		t.Fatalf("expected execution snapshot in event, got %+v", captured.Execution)
	}
	if captured.Attempt == nil || !captured.Attempt.TimedOut {
		t.Fatalf("expected last attempt details in event, got %+v", captured.Attempt)
	}
}

func TestParseSemgrepIgnoresWarningPrefix(t *testing.T) {
	request := domain.AgentScanRequest{ScanID: "scan-1", ProjectID: "project-1"}
	output := []byte("warning line\n{\"results\":[],\"errors\":[]}")

	result, findings, err := parseSemgrep(request, "semgrep", output)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if result.Status != domain.ModuleCompleted || len(findings) != 0 {
		t.Fatalf("expected empty completed result, got result=%+v findings=%+v", result, findings)
	}
}

func TestParseCheckovIgnoresWarningPrefix(t *testing.T) {
	request := domain.AgentScanRequest{ScanID: "scan-1", ProjectID: "project-1"}
	output := []byte("warn\n{\"results\":{\"failed_checks\":[]}}")

	result, findings, err := parseCheckov(request, "checkov", output)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if result.Status != domain.ModuleCompleted || len(findings) != 0 {
		t.Fatalf("expected empty completed result, got result=%+v findings=%+v", result, findings)
	}
}

func TestExtractJSONPayloadSkipsBracketedLogPrefix(t *testing.T) {
	output := []byte("[MainThread] warning\n{\"results\":{\"failed_checks\":[]}}")
	payload := string(extractJSONPayload(output))
	if !strings.HasPrefix(payload, "{\"results\"") {
		t.Fatalf("expected JSON payload after log prefix, got %q", payload)
	}
}

func TestExtractJSONPayloadSkipsBracketedCounterPrefix(t *testing.T) {
	output := []byte("[0000] WARN no explicit name and version provided\n{\"matches\":[]}")
	payload := string(extractJSONPayload(output))
	if payload != "{\"matches\":[]}" {
		t.Fatalf("expected grype JSON payload after bracketed counter prefix, got %q", payload)
	}
}

func TestParseOSVHandlesNoPackageSources(t *testing.T) {
	request := domain.AgentScanRequest{ScanID: "scan-1", ProjectID: "project-1"}
	output := []byte("Scanning dir /tmp/repo\nNo package sources found, --help for usage information.\n")

	result, findings, err := parseOSV(request, "osv-scanner", output)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if result.Status != domain.ModuleCompleted || len(findings) != 0 {
		t.Fatalf("expected no-package-sources to complete cleanly, got result=%+v findings=%+v", result, findings)
	}
}
