package release

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type TrustedAssetReport struct {
	Name      string
	Kind      string
	Path      string
	SHA256    string
	Signature string
}

func RefreshTrustedAssets(lock BundleLock, lockPath, privateKeyB64, signer string) (BundleLock, []TrustedAssetReport, error) {
	publicKey, err := PublicKeyFromPrivateKey(privateKeyB64)
	if err != nil {
		return lock, nil, err
	}
	if strings.TrimSpace(signer) == "" {
		signer = strings.TrimSpace(lock.Signing.Signer)
	}
	if strings.TrimSpace(signer) == "" {
		signer = "ironsentinel-release-root"
	}

	lock.Signing = TrustAnchor{
		Type:                 "ed25519",
		Signer:               signer,
		PublicKey:            publicKey,
		PublicKeyFingerprint: fingerprint(publicKey),
	}

	baseDir := filepath.Dir(lockPath)
	reports := make([]TrustedAssetReport, 0, len(lock.TrustedAssets))
	for index := range lock.TrustedAssets {
		asset := &lock.TrustedAssets[index]
		resolvedPath := strings.TrimSpace(asset.Path)
		if !filepath.IsAbs(resolvedPath) {
			resolvedPath = filepath.Join(baseDir, filepath.FromSlash(resolvedPath))
		}
		bytes, err := os.ReadFile(resolvedPath)
		if err != nil {
			return lock, nil, fmt.Errorf("read trusted asset %s: %w", asset.Name, err)
		}
		sum := sha256.Sum256(bytes)
		signature, err := Sign(bytes, privateKeyB64)
		if err != nil {
			return lock, nil, fmt.Errorf("sign trusted asset %s: %w", asset.Name, err)
		}
		asset.SHA256 = hex.EncodeToString(sum[:])
		asset.Signature = BundleSignature{
			Value:  strings.TrimSpace(string(signature)),
			Signer: signer,
		}
		reports = append(reports, TrustedAssetReport{
			Name:      asset.Name,
			Kind:      asset.Kind,
			Path:      asset.Path,
			SHA256:    asset.SHA256,
			Signature: asset.Signature.Signer,
		})
	}
	return lock, reports, nil
}
