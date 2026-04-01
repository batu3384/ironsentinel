package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSignedReleaseFixture(t *testing.T, provenance Provenance) (string, string, Manifest) {
	t.Helper()

	dir := t.TempDir()
	releaseDir := filepath.Join(dir, "dist")
	if err := os.MkdirAll(releaseDir, 0o755); err != nil {
		t.Fatalf("mkdir release dir: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	lock := map[string]any{
		"signing": map[string]any{
			"type":      "ed25519",
			"signer":    "test-root",
			"publicKey": base64.StdEncoding.EncodeToString(pub),
		},
	}
	lockBytes, err := json.Marshal(lock)
	if err != nil {
		t.Fatalf("marshal lock: %v", err)
	}
	lockPath := filepath.Join(dir, "scanner-bundle.lock.json")
	if err := os.WriteFile(lockPath, lockBytes, 0o644); err != nil {
		t.Fatalf("write lock: %v", err)
	}

	artifactPath := filepath.Join(releaseDir, "ironsentinel_v1.2.3_linux_amd64.tar.gz")
	if err := os.WriteFile(artifactPath, []byte("artifact-bytes"), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	anchor, err := LoadTrustAnchor(lockPath)
	if err != nil {
		t.Fatalf("load trust anchor: %v", err)
	}
	manifest, checksums, err := BuildManifest(releaseDir, "v1.2.3", "github.com/batu3384/ironsentinel", anchor, provenance)
	if err != nil {
		t.Fatalf("build manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(releaseDir, ChecksumsFile), checksums, 0o644); err != nil {
		t.Fatalf("write checksums: %v", err)
	}
	manifestBytes, err := WriteManifest(releaseDir, manifest)
	if err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	attestationBytes, err := WriteAttestation(releaseDir, BuildAttestation(manifest))
	if err != nil {
		t.Fatalf("write attestation: %v", err)
	}
	signature, err := Sign(manifestBytes, base64.StdEncoding.EncodeToString(priv))
	if err != nil {
		t.Fatalf("sign manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(releaseDir, SignatureFile), signature, 0o644); err != nil {
		t.Fatalf("write signature: %v", err)
	}
	attestationSignature, err := Sign(attestationBytes, base64.StdEncoding.EncodeToString(priv))
	if err != nil {
		t.Fatalf("sign attestation: %v", err)
	}
	if err := os.WriteFile(filepath.Join(releaseDir, AttestationSignatureFile), attestationSignature, 0o644); err != nil {
		t.Fatalf("write attestation signature: %v", err)
	}
	if _, err := WriteExternalAttestation(releaseDir, BuildExternalAttestation(manifest, "github-actions", "https://example.invalid/ironsentinel/runs/123")); err != nil {
		t.Fatalf("write external attestation: %v", err)
	}

	return releaseDir, lockPath, manifest
}

func TestBuildManifestAndVerify(t *testing.T) {
	releaseDir, lockPath, manifest := writeSignedReleaseFixture(t, Provenance{
		Commit:       "abcdef0123456789",
		Ref:          "refs/tags/v1.2.3",
		Builder:      "test",
		GoVersion:    "go1.25.1",
		HostPlatform: "darwin/arm64",
	})
	if len(manifest.Artifacts) != 1 {
		t.Fatalf("expected 1 artifact, got %d", len(manifest.Artifacts))
	}
	if manifest.Artifacts[0].OS != "linux" || manifest.Artifacts[0].Arch != "amd64" {
		t.Fatalf("expected parsed platform, got %s/%s", manifest.Artifacts[0].OS, manifest.Artifacts[0].Arch)
	}

	if err := VerifyWithOptions(releaseDir, lockPath, VerifyOptions{
		RequireSignature:           true,
		RequireAttestation:         true,
		RequireExternalAttestation: true,
	}); err != nil {
		t.Fatalf("verify manifest: %v", err)
	}

	manifestOut, result, err := Inspect(releaseDir, lockPath)
	if err != nil {
		t.Fatalf("inspect release: %v", err)
	}
	if manifestOut.Provenance.Repository != "" {
		t.Fatalf("expected empty repository in this fixture, got %s", manifestOut.Provenance.Repository)
	}
	if !result.Attested || !result.AttestationVerification.SignatureVerified {
		t.Fatalf("expected signed attestation verification, got %+v", result.AttestationVerification)
	}
	if !result.ExternalAttested || result.ExternalAttestationVerification.Status() != "verified" {
		t.Fatalf("expected verified external attestation, got %+v", result.ExternalAttestationVerification)
	}
	if result.ExternalAttestationProvider != "github-actions" {
		t.Fatalf("expected external attestation provider, got %s", result.ExternalAttestationProvider)
	}
}

func TestVerifyWithOptionsMissingManifestReturnsContextualError(t *testing.T) {
	lockDir := t.TempDir()
	lockPath := filepath.Join(lockDir, "scanner-bundle.lock.json")
	if err := os.WriteFile(lockPath, []byte(`{"signing":{"type":"ed25519","signer":"test-root","publicKey":"c21va2U="}}`), 0o644); err != nil {
		t.Fatalf("write lock: %v", err)
	}

	err := VerifyWithOptions(filepath.Join(lockDir, "dist"), lockPath, VerifyOptions{})
	if err == nil {
		t.Fatal("expected verify error")
	}
	if !strings.Contains(err.Error(), "inspect release bundle: read release manifest") {
		t.Fatalf("expected contextual manifest read error, got %v", err)
	}
}

func TestVerifyWithOptionsExternalAttestationMismatchIncludesReason(t *testing.T) {
	releaseDir, lockPath, manifest := writeSignedReleaseFixture(t, Provenance{
		Commit:       "abcdef0123456789",
		Ref:          "refs/tags/v1.2.3",
		Builder:      "test",
		GoVersion:    "go1.25.1",
		HostPlatform: "darwin/arm64",
		Repository:   "https://github.com/batu3384/ironsentinel",
		Workflow:     "release-publish",
		RunID:        "123",
		RunAttempt:   "1",
	})

	mismatched := BuildExternalAttestation(manifest, "github-actions", "https://example.invalid/ironsentinel/runs/123")
	mismatched.RunID = "999"
	if _, err := WriteExternalAttestation(releaseDir, mismatched); err != nil {
		t.Fatalf("overwrite external attestation: %v", err)
	}

	err := VerifyWithOptions(releaseDir, lockPath, VerifyOptions{
		RequireSignature:           true,
		RequireAttestation:         true,
		RequireExternalAttestation: true,
	})
	if err == nil {
		t.Fatal("expected external attestation verification error")
	}
	if !strings.Contains(err.Error(), "external attestation run id mismatch") {
		t.Fatalf("expected external attestation mismatch reason, got %v", err)
	}
}
