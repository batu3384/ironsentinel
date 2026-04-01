package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
)

func TestDiscoverRuntimeVerifiesToolChecksum(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "scanner-bundle.lock.json")
	binaryPath := filepath.Join(dir, "semgrep")
	binaryPayload := []byte("#!/usr/bin/env bash\necho 'semgrep 1.119.0'\n")
	if err := os.WriteFile(binaryPath, binaryPayload, 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}

	sum := sha256.Sum256(binaryPayload)
	lock := `{
  "version": 1,
  "channels": {
    "safe": [
      { "name": "semgrep", "version": "1.119.0", "checksums": { "` + runtime.GOOS + `/` + runtime.GOARCH + `": "` + hex.EncodeToString(sum[:]) + `" } }
    ]
  }
}`
	if err := os.WriteFile(lockPath, []byte(lock), 0o644); err != nil {
		t.Fatalf("write lock file: %v", err)
	}

	originalPath := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+originalPath)

	runtimeStatus := DiscoverRuntime(config.Config{BundleLockPath: lockPath})
	if len(runtimeStatus.ScannerBundle) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(runtimeStatus.ScannerBundle))
	}
	tool := runtimeStatus.ScannerBundle[0]
	if tool.Verification.Status() != "verified" {
		t.Fatalf("expected verified checksum, got %s (%s)", tool.Verification.Status(), tool.Verification.Notes)
	}
	if !tool.ChecksumCovered || runtimeStatus.SupplyChain.ChecksumCoveredTools != 1 {
		t.Fatalf("expected checksum coverage to be counted, got tool=%t count=%d", tool.ChecksumCovered, runtimeStatus.SupplyChain.ChecksumCoveredTools)
	}
	if runtimeStatus.SupplyChain.IntegrityGapTools != 0 {
		t.Fatalf("expected no integrity gap tools, got %d", runtimeStatus.SupplyChain.IntegrityGapTools)
	}
}

func TestDiscoverRuntimeReportsLockCoverageGaps(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "scanner-bundle.lock.json")
	lock := `{
  "version": 1,
  "channels": {
    "safe": [
      { "name": "semgrep", "version": "1.119.0", "checksums": { "` + runtime.GOOS + `/` + runtime.GOARCH + `": "deadbeef" } },
      { "name": "gitleaks", "version": "8.24.2" }
    ]
  }
}`
	if err := os.WriteFile(lockPath, []byte(lock), 0o644); err != nil {
		t.Fatalf("write lock file: %v", err)
	}

	runtimeStatus := DiscoverRuntime(config.Config{BundleLockPath: lockPath})
	if runtimeStatus.SupplyChain.ChecksumCoveredTools != 1 {
		t.Fatalf("expected 1 checksum-covered tool, got %d", runtimeStatus.SupplyChain.ChecksumCoveredTools)
	}
	if runtimeStatus.SupplyChain.IntegrityGapTools != 1 {
		t.Fatalf("expected 1 integrity gap tool, got %d", runtimeStatus.SupplyChain.IntegrityGapTools)
	}
	if len(runtimeStatus.SupplyChain.LockCoverage) != 2 {
		t.Fatalf("expected 2 lock coverage entries, got %d", len(runtimeStatus.SupplyChain.LockCoverage))
	}
}

func TestDiscoverRuntimeVerifiesTrustedAssetSignature(t *testing.T) {
	dir := t.TempDir()
	assetPath := filepath.Join(dir, "scripts", "install_scanners.sh")
	if err := os.MkdirAll(filepath.Dir(assetPath), 0o755); err != nil {
		t.Fatalf("mkdir scripts: %v", err)
	}

	assetPayload := []byte("#!/usr/bin/env bash\necho ok\n")
	if err := os.WriteFile(assetPath, assetPayload, 0o755); err != nil {
		t.Fatalf("write asset: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signature := ed25519.Sign(priv, assetPayload)
	sum := sha256.Sum256(assetPayload)

	lockPath := filepath.Join(dir, "scanner-bundle.lock.json")
	lock := `{
  "version": 1,
  "signing": {
    "type": "ed25519",
    "signer": "test-root",
    "publicKey": "` + base64.StdEncoding.EncodeToString(pub) + `"
  },
  "trustedAssets": [
    {
      "name": "install-script",
      "kind": "installer",
      "path": "scripts/install_scanners.sh",
      "sha256": "` + hex.EncodeToString(sum[:]) + `",
      "signature": {
        "value": "` + base64.StdEncoding.EncodeToString(signature) + `"
      }
    }
  ],
  "channels": {}
}`
	if err := os.WriteFile(lockPath, []byte(lock), 0o644); err != nil {
		t.Fatalf("write lock file: %v", err)
	}

	runtimeStatus := DiscoverRuntime(config.Config{BundleLockPath: lockPath})
	if runtimeStatus.SupplyChain.VerifiedAssets != 1 {
		t.Fatalf("expected 1 verified asset, got %d", runtimeStatus.SupplyChain.VerifiedAssets)
	}
	if len(runtimeStatus.SupplyChain.TrustedAssets) != 1 {
		t.Fatalf("expected 1 trusted asset, got %d", len(runtimeStatus.SupplyChain.TrustedAssets))
	}
	asset := runtimeStatus.SupplyChain.TrustedAssets[0]
	if asset.Verification.Status() != "verified" {
		t.Fatalf("expected trusted asset verification to succeed, got %s (%s)", asset.Verification.Status(), asset.Verification.Notes)
	}
	if !asset.Verification.SignatureVerified {
		t.Fatalf("expected trusted asset signature to verify")
	}
}

func TestEvaluateBundleHealthFailsOnTrustedAssetMismatch(t *testing.T) {
	dir := t.TempDir()
	assetPath := filepath.Join(dir, "deploy", "scanner-bundle.Containerfile")
	if err := os.MkdirAll(filepath.Dir(assetPath), 0o755); err != nil {
		t.Fatalf("mkdir deploy: %v", err)
	}

	assetPayload := []byte("FROM scratch\n")
	if err := os.WriteFile(assetPath, assetPayload, 0o644); err != nil {
		t.Fatalf("write asset: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signature := ed25519.Sign(priv, assetPayload)

	lockPath := filepath.Join(dir, "scanner-bundle.lock.json")
	lock := `{
  "version": 1,
  "signing": {
    "type": "ed25519",
    "signer": "test-root",
    "publicKey": "` + base64.StdEncoding.EncodeToString(pub) + `"
  },
  "trustedAssets": [
    {
      "name": "containerfile",
      "kind": "containerfile",
      "path": "deploy/scanner-bundle.Containerfile",
      "sha256": "deadbeef",
      "signature": {
        "value": "` + base64.StdEncoding.EncodeToString(signature) + `"
      }
    }
  ],
  "channels": {}
}`
	if err := os.WriteFile(lockPath, []byte(lock), 0o644); err != nil {
		t.Fatalf("write lock file: %v", err)
	}

	doctor := EvaluateBundleHealth(config.Config{BundleLockPath: lockPath}, domain.ScanProfile{Mode: domain.ModeSafe}, false, false)
	if doctor.Ready {
		t.Fatalf("expected doctor to fail when a trusted asset checksum mismatches")
	}
	if len(doctor.FailedAssets) != 1 {
		t.Fatalf("expected 1 failed asset, got %d", len(doctor.FailedAssets))
	}
}
