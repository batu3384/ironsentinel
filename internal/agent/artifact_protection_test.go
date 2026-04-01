package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/batu3384/ironsentinel/internal/config"
)

func TestWriteArtifactRedactsSecrets(t *testing.T) {
	moduleDir := t.TempDir()
	cfg := config.Config{
		ArtifactRedaction:     true,
		ArtifactRetentionDays: 14,
	}

	artifact, err := writeArtifact(cfg, moduleDir, "evidence.json", "evidence", "test evidence", []byte(`{"token":"ghp_1234567890abcdef1234567890abcdef1234"}`))
	if err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	if !artifact.Redacted {
		t.Fatalf("expected artifact to be marked redacted")
	}
	if artifact.ExpiresAt == nil {
		t.Fatalf("expected artifact retention expiry to be set")
	}

	body, err := os.ReadFile(artifact.URI)
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	text := string(body)
	if strings.Contains(text, "ghp_1234567890abcdef1234567890abcdef1234") {
		t.Fatalf("expected secret to be redacted, got %s", text)
	}
	if !strings.Contains(text, "[REDACTED_GITHUB_TOKEN]") {
		t.Fatalf("expected redacted token marker, got %s", text)
	}
}

func TestWriteArtifactEncryptsProtectedKinds(t *testing.T) {
	moduleDir := t.TempDir()
	cfg := config.Config{
		ArtifactRedaction:     true,
		ArtifactEncryptionKey: "unit-test-secret",
		ArtifactRetentionDays: 7,
	}

	artifact, err := writeArtifact(cfg, moduleDir, "report.json", "report", "scanner report", []byte(`{"ok":true}`))
	if err != nil {
		t.Fatalf("write encrypted artifact: %v", err)
	}
	if !artifact.Encrypted {
		t.Fatalf("expected report artifact to be encrypted")
	}
	if !strings.HasSuffix(artifact.URI, ".enc") {
		t.Fatalf("expected encrypted artifact to use .enc suffix, got %s", artifact.URI)
	}
	body, err := os.ReadFile(artifact.URI)
	if err != nil {
		t.Fatalf("read encrypted artifact: %v", err)
	}
	if strings.Contains(string(body), `"ok":true`) {
		t.Fatalf("expected encrypted envelope instead of plaintext body, got %s", string(body))
	}
	if !strings.Contains(string(body), `"algorithm": "AES-256-GCM"`) {
		t.Fatalf("expected encryption envelope, got %s", string(body))
	}
}

func TestPruneExpiredArtifactRunsRemovesOldDirectories(t *testing.T) {
	root := t.TempDir()
	oldDir := filepath.Join(root, "run-old")
	newDir := filepath.Join(root, "run-new")
	if err := os.MkdirAll(oldDir, 0o755); err != nil {
		t.Fatalf("mkdir old dir: %v", err)
	}
	if err := os.MkdirAll(newDir, 0o755); err != nil {
		t.Fatalf("mkdir new dir: %v", err)
	}

	oldTime := time.Now().Add(-40 * 24 * time.Hour)
	if err := os.Chtimes(oldDir, oldTime, oldTime); err != nil {
		t.Fatalf("chtimes old dir: %v", err)
	}

	if err := pruneExpiredArtifactRuns(root, 30); err != nil {
		t.Fatalf("prune artifact runs: %v", err)
	}
	if _, err := os.Stat(oldDir); !os.IsNotExist(err) {
		t.Fatalf("expected old artifact dir to be pruned, stat err=%v", err)
	}
	if _, err := os.Stat(newDir); err != nil {
		t.Fatalf("expected new artifact dir to remain: %v", err)
	}
}
