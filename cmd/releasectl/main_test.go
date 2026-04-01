package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/batu3384/ironsentinel/internal/release"
)

func executeRootCommand(args ...string) (string, string, error) {
	root := newRootCommand()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(args)

	err := root.Execute()
	return stdout.String(), stderr.String(), err
}

func writeSignedReleaseFixture(t *testing.T, provenance release.Provenance) (string, string, release.Manifest) {
	t.Helper()

	dir := t.TempDir()
	releaseDir := filepath.Join(dir, "dist")
	if err := os.MkdirAll(releaseDir, 0o755); err != nil {
		t.Fatalf("mkdir release dir: %v", err)
	}

	pair, err := release.GenerateKeyPair("cli-test")
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	lockBytes, err := pair.LockJSON()
	if err != nil {
		t.Fatalf("lock json: %v", err)
	}
	lockPath := filepath.Join(dir, "scanner-bundle.lock.json")
	if err := os.WriteFile(lockPath, lockBytes, 0o644); err != nil {
		t.Fatalf("write lock: %v", err)
	}

	artifactPath := filepath.Join(releaseDir, "ironsentinel_v1.2.3_linux_amd64.tar.gz")
	if err := os.WriteFile(artifactPath, []byte("artifact-bytes"), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	anchor, err := release.LoadTrustAnchor(lockPath)
	if err != nil {
		t.Fatalf("load trust anchor: %v", err)
	}
	manifest, checksums, err := release.BuildManifest(releaseDir, "v1.2.3", "github.com/batu3384/ironsentinel", anchor, provenance)
	if err != nil {
		t.Fatalf("build manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(releaseDir, release.ChecksumsFile), checksums, 0o644); err != nil {
		t.Fatalf("write checksums: %v", err)
	}
	manifestBytes, err := release.WriteManifest(releaseDir, manifest)
	if err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	attestationBytes, err := release.WriteAttestation(releaseDir, release.BuildAttestation(manifest))
	if err != nil {
		t.Fatalf("write attestation: %v", err)
	}
	signature, err := release.Sign(manifestBytes, pair.PrivateKey)
	if err != nil {
		t.Fatalf("sign manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(releaseDir, release.SignatureFile), signature, 0o644); err != nil {
		t.Fatalf("write manifest signature: %v", err)
	}
	attestationSignature, err := release.Sign(attestationBytes, pair.PrivateKey)
	if err != nil {
		t.Fatalf("sign attestation: %v", err)
	}
	if err := os.WriteFile(filepath.Join(releaseDir, release.AttestationSignatureFile), attestationSignature, 0o644); err != nil {
		t.Fatalf("write attestation signature: %v", err)
	}
	if _, err := release.WriteExternalAttestation(releaseDir, release.BuildExternalAttestation(manifest, "github-actions", "https://example.invalid/ironsentinel/runs/123")); err != nil {
		t.Fatalf("write external attestation: %v", err)
	}

	return releaseDir, lockPath, manifest
}

func TestKeygenJSONUsesCommandStdout(t *testing.T) {
	stdout, stderr, err := executeRootCommand("keygen", "--json", "--signer", "unit-test")
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}

	var pair release.GeneratedKeyPair
	if err := json.Unmarshal([]byte(stdout), &pair); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	if pair.Signer != "unit-test" {
		t.Fatalf("pair.Signer = %q, want unit-test", pair.Signer)
	}
	if pair.Type != "ed25519" {
		t.Fatalf("pair.Type = %q, want ed25519", pair.Type)
	}
	if pair.PublicKey == "" || pair.PrivateKey == "" {
		t.Fatalf("expected key material in JSON output")
	}
}

func TestManifestCommandMissingSigningEnvReturnsContextualError(t *testing.T) {
	releaseDir, lockPath, _ := writeSignedReleaseFixture(t, release.Provenance{
		Commit:       "abcdef0123456789",
		Ref:          "refs/tags/v1.2.3",
		Builder:      "test",
		GoVersion:    "go1.25.1",
		HostPlatform: "darwin/arm64",
	})
	for _, name := range []string{
		release.ChecksumsFile,
		release.ManifestFile,
		release.AttestationFile,
		release.SignatureFile,
		release.AttestationSignatureFile,
		release.ExternalAttestationFile,
	} {
		if err := os.Remove(filepath.Join(releaseDir, name)); err != nil && !os.IsNotExist(err) {
			t.Fatalf("remove existing fixture file %s: %v", name, err)
		}
	}

	stdout, stderr, err := executeRootCommand(
		"manifest",
		"--dir", releaseDir,
		"--version", "v1.2.3",
		"--lock", lockPath,
		"--private-key-env", "MISSING_RELEASE_KEY",
	)
	if err == nil {
		t.Fatal("expected manifest error")
	}
	if !strings.Contains(err.Error(), "MISSING_RELEASE_KEY is empty") {
		t.Fatalf("expected missing env error, got %v", err)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
}

func TestVerifyCommandMissingManifestReturnsContextualError(t *testing.T) {
	dir := t.TempDir()
	pair, err := release.GenerateKeyPair("cli-test")
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	lockBytes, err := pair.LockJSON()
	if err != nil {
		t.Fatalf("lock json: %v", err)
	}
	lockPath := filepath.Join(dir, "scanner-bundle.lock.json")
	if err := os.WriteFile(lockPath, lockBytes, 0o644); err != nil {
		t.Fatalf("write lock: %v", err)
	}

	stdout, stderr, err := executeRootCommand("verify", "--dir", filepath.Join(dir, "dist"), "--lock", lockPath)
	if err == nil {
		t.Fatal("expected verify error")
	}
	if !strings.Contains(err.Error(), "inspect release bundle: read release manifest") {
		t.Fatalf("expected contextual inspect error, got %v", err)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
}

func TestVerifyCommandExternalAttestationMismatchReturnsReason(t *testing.T) {
	releaseDir, lockPath, manifest := writeSignedReleaseFixture(t, release.Provenance{
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
	mismatched := release.BuildExternalAttestation(manifest, "github-actions", "https://example.invalid/ironsentinel/runs/123")
	mismatched.RunID = "999"
	if _, err := release.WriteExternalAttestation(releaseDir, mismatched); err != nil {
		t.Fatalf("overwrite external attestation: %v", err)
	}

	stdout, stderr, err := executeRootCommand(
		"verify",
		"--dir", releaseDir,
		"--lock", lockPath,
		"--require-signature",
		"--require-attestation",
		"--require-external-attestation",
	)
	if err == nil {
		t.Fatal("expected verify error")
	}
	if !strings.Contains(err.Error(), "external attestation run id mismatch") {
		t.Fatalf("expected external attestation mismatch reason, got %v", err)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
}

func TestNotesCommandRendersReleaseBodyToStdout(t *testing.T) {
	releaseDir, lockPath, _ := writeSignedReleaseFixture(t, release.Provenance{
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

	stdout, stderr, err := executeRootCommand("notes", "--dir", releaseDir, "--lock", lockPath)
	if err != nil {
		t.Fatalf("expected notes output, got error %v", err)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	for _, want := range []string{
		"# IronSentinel v1.2.3",
		"## Verification",
		"## Artifacts",
		"## Provenance",
		"`ironsentinel_v1.2.3_linux_amd64.tar.gz`",
		"Commit: `abcdef0123456789`",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected notes to contain %q, got:\n%s", want, stdout)
		}
	}
}
