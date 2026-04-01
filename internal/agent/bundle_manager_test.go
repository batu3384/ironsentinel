package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/batu3384/ironsentinel/internal/config"
)

func TestUpdateManagedBundleCreatesSnapshotAndRollbackRestoresFiles(t *testing.T) {
	root := t.TempDir()
	cfg := config.Config{
		DataDir:  filepath.Join(root, "data"),
		ToolsDir: filepath.Join(root, "tools", "bin"),
	}
	toolsRoot := managedToolsRoot(cfg)
	if err := os.MkdirAll(filepath.Join(toolsRoot, "bin"), 0o755); err != nil {
		t.Fatalf("mkdir tools root: %v", err)
	}
	originalFile := filepath.Join(toolsRoot, "bin", "scanner")
	if err := os.WriteFile(originalFile, []byte("old"), 0o755); err != nil {
		t.Fatalf("write original tool: %v", err)
	}

	snapshot, err := UpdateManagedBundle(cfg, "safe", func(mode string) error {
		return os.WriteFile(originalFile, []byte("new"), 0o755)
	})
	if err != nil {
		t.Fatalf("update managed bundle: %v", err)
	}
	if snapshot.ID == "" {
		t.Fatalf("expected snapshot ID to be set")
	}
	updated, err := os.ReadFile(originalFile)
	if err != nil {
		t.Fatalf("read updated tool: %v", err)
	}
	if string(updated) != "new" {
		t.Fatalf("expected updated tool contents, got %q", string(updated))
	}

	history, err := ListBundleSnapshots(cfg)
	if err != nil {
		t.Fatalf("list snapshots: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("expected 1 snapshot, got %d", len(history))
	}

	restored, err := RollbackManagedBundle(cfg, snapshot.ID)
	if err != nil {
		t.Fatalf("rollback managed bundle: %v", err)
	}
	if restored.ID != snapshot.ID {
		t.Fatalf("expected rollback to use snapshot %s, got %s", snapshot.ID, restored.ID)
	}
	rolledBack, err := os.ReadFile(originalFile)
	if err != nil {
		t.Fatalf("read rolled back tool: %v", err)
	}
	if string(rolledBack) != "old" {
		t.Fatalf("expected rollback to restore old contents, got %q", string(rolledBack))
	}
}
