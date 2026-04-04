package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
)

func TestStreamScanQueuesModulesBeforeExecution(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("GITHUB_TOKEN="+streamScanTestGitHubPAT()+"\n"), 0o644); err != nil {
		t.Fatalf("write fixture file: %v", err)
	}

	service := NewService(config.Config{
		OutputDir: filepath.Join(t.TempDir(), "output"),
	})

	events := make([]domain.AgentEvent, 0, 16)
	err := service.StreamScan(context.Background(), domain.AgentScanRequest{
		ScanID:      "run-test",
		ProjectID:   "prj-1",
		TargetPath:  root,
		DisplayName: "fixture",
		Profile: domain.ScanProfile{
			Modules: []string{"stack-detector", "secret-heuristics", "malware-signature"},
		},
	}, func(event domain.AgentEvent) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected stream scan error: %v", err)
	}

	if len(events) < 5 {
		t.Fatalf("expected multiple scan events, got %d", len(events))
	}
	if events[0].Type != "scan.accepted" {
		t.Fatalf("expected first event to be scan.accepted, got %s", events[0].Type)
	}
	for index := 1; index <= 3; index++ {
		if events[index].Type != "module.queued" {
			t.Fatalf("expected queued event at index %d, got %s", index, events[index].Type)
		}
		if events[index].Module == nil || events[index].Module.Status != domain.ModuleQueued {
			t.Fatalf("expected queued module metadata at index %d, got %+v", index, events[index].Module)
		}
	}
}

func streamScanTestGitHubPAT() string {
	return strings.Join([]string{"gh", "p_", strings.Repeat("1", 36)}, "")
}

func TestResolveTargetHonorsCanceledContext(t *testing.T) {
	service := NewService(config.Config{})
	root := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := service.ResolveTarget(ctx, domain.ResolveTargetRequest{
		Path:        root,
		DisplayName: "fixture",
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled context error, got %v", err)
	}
}

func TestResolveTargetRejectsCanceledInteractiveFlowBeforePicker(t *testing.T) {
	service := NewService(config.Config{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := service.ResolveTarget(ctx, domain.ResolveTargetRequest{
		Interactive: true,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled interactive resolution, got %v", err)
	}
}
