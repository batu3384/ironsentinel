package release

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRefreshTrustedAssetsSignsAssetsAndRotatesAnchor(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "scanner-bundle.lock.json")
	assetPath := filepath.Join(dir, "scripts", "install_scanners.sh")
	if err := os.MkdirAll(filepath.Dir(assetPath), 0o755); err != nil {
		t.Fatalf("mkdir assets: %v", err)
	}
	if err := os.WriteFile(assetPath, []byte("echo trusted\n"), 0o755); err != nil {
		t.Fatalf("write asset: %v", err)
	}

	pair, err := GenerateKeyPair("ironsentinel-test-root")
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	lock := BundleLock{
		Version: 1,
		TrustedAssets: []TrustedAsset{
			{Name: "local-installer-posix", Kind: "installer", Path: "scripts/install_scanners.sh"},
		},
		Channels: map[string][]LockSpec{},
	}

	updated, reports, err := RefreshTrustedAssets(lock, lockPath, pair.PrivateKey, pair.Signer)
	if err != nil {
		t.Fatalf("refresh trusted assets: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("expected 1 report, got %+v", reports)
	}
	if updated.Signing.PublicKey != pair.PublicKey || updated.Signing.Signer != pair.Signer {
		t.Fatalf("expected rotated anchor, got %+v", updated.Signing)
	}
	if updated.TrustedAssets[0].SHA256 == "" || updated.TrustedAssets[0].Signature.Value == "" {
		t.Fatalf("expected trusted asset metadata, got %+v", updated.TrustedAssets[0])
	}
}
