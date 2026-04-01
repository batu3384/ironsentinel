package agent

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
)

func TestBuildOSVCommandUsesMirrorAndOfflineFlags(t *testing.T) {
	cfg := config.Config{MirrorDir: t.TempDir()}
	mirrorRoot := filepath.Join(cfg.MirrorDir, "osv-cache", "osv-scanner", "Go")
	if err := os.MkdirAll(mirrorRoot, 0o755); err != nil {
		t.Fatalf("mkdir mirror root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(mirrorRoot, "all.zip"), []byte("db"), 0o644); err != nil {
		t.Fatalf("write db: %v", err)
	}

	execution := moduleExecution{
		request: domain.AgentScanRequest{
			TargetPath: "/tmp/project",
			Profile:    domain.ScanProfile{Mode: domain.ModeSafe},
		},
	}
	command := buildOSVCommand(cfg, "osv-scanner", execution)

	if !slices.Contains(command.Args, "--offline-vulnerabilities") {
		t.Fatalf("expected offline flag when mirror exists, got %v", command.Args)
	}
	joined := strings.Join(command.Env, "\n")
	if !strings.Contains(joined, "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="+filepath.Join(cfg.MirrorDir, "osv-cache")) {
		t.Fatalf("expected mirror env to be set, got %v", command.Env)
	}
}

func TestBuildOSVCommandRespectsOfflineModeWithoutMirror(t *testing.T) {
	cfg := config.Config{
		MirrorDir:   t.TempDir(),
		OfflineMode: true,
	}
	execution := moduleExecution{
		request: domain.AgentScanRequest{
			TargetPath: "/tmp/project",
			Profile:    domain.ScanProfile{Mode: domain.ModeSafe},
		},
	}
	command := buildOSVCommand(cfg, "osv-scanner", execution)
	if !slices.Contains(command.Args, "--offline-vulnerabilities") {
		t.Fatalf("expected offline flag in offline mode, got %v", command.Args)
	}
}
