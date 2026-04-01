package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/batu3384/ironsentinel/internal/config"
	releaselib "github.com/batu3384/ironsentinel/internal/release"
)

func TestDiscoverReleaseBundlesReturnsVerifiedBundle(t *testing.T) {
	root := t.TempDir()
	distDir := filepath.Join(root, "dist")
	releaseDir := filepath.Join(distDir, "v1.0.0")
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
	lockPath := filepath.Join(root, "scanner-bundle.lock.json")
	if err := os.WriteFile(lockPath, lockBytes, 0o644); err != nil {
		t.Fatalf("write lock: %v", err)
	}

	artifactPath := filepath.Join(releaseDir, "ironsentinel_v1.0.0_darwin_arm64.tar.gz")
	if err := os.WriteFile(artifactPath, []byte("artifact"), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	anchor, err := releaselib.LoadTrustAnchor(lockPath)
	if err != nil {
		t.Fatalf("load trust anchor: %v", err)
	}
	manifest, checksums, err := releaselib.BuildManifest(releaseDir, "v1.0.0", "github.com/batu3384/ironsentinel", anchor, releaselib.Provenance{
		Commit:       "abcdef0123456789",
		Ref:          "refs/tags/v1.0.0",
		Builder:      "test",
		GoVersion:    "go1.25.1",
		HostPlatform: "darwin/arm64",
	})
	if err != nil {
		t.Fatalf("build manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(releaseDir, releaselib.ChecksumsFile), checksums, 0o644); err != nil {
		t.Fatalf("write checksums: %v", err)
	}
	manifestBytes, err := releaselib.WriteManifest(releaseDir, manifest)
	if err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if _, err := releaselib.WriteAttestation(releaseDir, releaselib.BuildAttestation(manifest)); err != nil {
		t.Fatalf("write attestation: %v", err)
	}
	if _, err := releaselib.WriteExternalAttestation(releaseDir, releaselib.BuildExternalAttestation(manifest, "github-actions", "https://example.invalid/ironsentinel/runs/456")); err != nil {
		t.Fatalf("write external attestation: %v", err)
	}
	signature, err := releaselib.Sign(manifestBytes, base64.StdEncoding.EncodeToString(priv))
	if err != nil {
		t.Fatalf("sign manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(releaseDir, releaselib.SignatureFile), signature, 0o644); err != nil {
		t.Fatalf("write signature: %v", err)
	}

	bundles := discoverReleaseBundles(config.Config{
		DistDir:        distDir,
		BundleLockPath: lockPath,
	})
	if len(bundles) != 1 {
		t.Fatalf("expected 1 release bundle, got %d", len(bundles))
	}
	bundle := bundles[0]
	if bundle.Version != "v1.0.0" {
		t.Fatalf("expected version v1.0.0, got %s", bundle.Version)
	}
	if bundle.Verification.Status() != "verified" {
		t.Fatalf("expected verified bundle, got %s (%s)", bundle.Verification.Status(), bundle.Verification.Notes)
	}
	if bundle.Provenance.Commit != "abcdef0123456789" {
		t.Fatalf("expected provenance commit to be preserved, got %s", bundle.Provenance.Commit)
	}
	if !bundle.Attested || bundle.AttestationPath == "" {
		t.Fatalf("expected attestation metadata to be discovered: %+v", bundle)
	}
	if bundle.AttestationVerification.Status() != "verified" {
		t.Fatalf("expected discovered attestation structure to verify, got %s", bundle.AttestationVerification.Status())
	}
	if !bundle.ExternalAttested || bundle.ExternalAttestationVerification.Status() != "verified" {
		t.Fatalf("expected discovered external attestation to verify, got %+v", bundle.ExternalAttestationVerification)
	}
	if bundle.ExternalAttestationProvider != "github-actions" {
		t.Fatalf("expected external provider to be preserved, got %s", bundle.ExternalAttestationProvider)
	}
	if bundle.ArtifactCount != 1 || len(bundle.Artifacts) != 1 {
		t.Fatalf("expected single release artifact, got count=%d len=%d", bundle.ArtifactCount, len(bundle.Artifacts))
	}
}
