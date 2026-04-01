package agent

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
)

func discoverSupplyChain(cfg config.Config, lock bundleLock, tools []domain.RuntimeTool) domain.RuntimeSupplyChain {
	status := domain.RuntimeSupplyChain{
		Signer:        lock.Signing.Signer,
		SignatureType: lock.Signing.Type,
	}
	if fingerprint := trustAnchorFingerprint(lock.Signing); fingerprint != "" {
		status.PublicKeyFingerprint = fingerprint
	}

	for _, tool := range tools {
		if tool.ChecksumCovered {
			status.ChecksumCoveredTools++
		}
		if tool.SignatureCovered {
			status.SignatureCoveredTools++
		}
		if tool.SourceIntegrityCovered {
			status.SourceIntegrityTools++
		}
		if !tool.ChecksumCovered && !tool.SignatureCovered && !tool.SourceIntegrityCovered {
			status.IntegrityGapTools++
		}
		switch tool.Verification.Status() {
		case "verified":
			status.VerifiedTools++
		case "failed":
			status.FailedTools++
		default:
			status.UnverifiedTools++
		}
	}

	status.LockCoverage = buildLockCoverage(lock)

	for _, asset := range lock.TrustedAssets {
		verified := verifyTrustedAsset(cfg, asset, lock.Signing)
		status.TrustedAssets = append(status.TrustedAssets, verified)
		switch verified.Verification.Status() {
		case "verified":
			status.VerifiedAssets++
		case "failed":
			status.FailedAssets++
		default:
			status.UnverifiedAssets++
		}
	}
	status.ReleaseBundles = discoverReleaseBundles(cfg)
	sort.Slice(status.TrustedAssets, func(i, j int) bool { return status.TrustedAssets[i].Name < status.TrustedAssets[j].Name })
	sort.Slice(status.LockCoverage, func(i, j int) bool {
		if status.LockCoverage[i].Channel == status.LockCoverage[j].Channel {
			return status.LockCoverage[i].Name < status.LockCoverage[j].Name
		}
		return status.LockCoverage[i].Channel < status.LockCoverage[j].Channel
	})
	return status
}

func buildLockCoverage(lock bundleLock) []domain.RuntimeLockCoverage {
	items := make([]domain.RuntimeLockCoverage, 0, len(lock.Channels)*4)
	for channel, specs := range lock.Channels {
		for _, spec := range specs {
			items = append(items, domain.RuntimeLockCoverage{
				Name:                   spec.Name,
				Channel:                channel,
				Version:                spec.Version,
				Source:                 strings.TrimSpace(spec.Source),
				ChecksumCovered:        len(spec.Checksums) > 0,
				SignatureCovered:       strings.TrimSpace(spec.Signature.Value) != "",
				SourceIntegrityCovered: strings.TrimSpace(spec.SourceIntegrity.Digest) != "" && strings.TrimSpace(spec.SourceIntegrity.Algorithm) != "",
				Platforms:              checksumPlatforms(spec.Checksums),
			})
		}
	}
	return items
}

func checksumPlatforms(checksums map[string]string) []string {
	if len(checksums) == 0 {
		return nil
	}
	keys := make([]string, 0, len(checksums))
	for key, value := range checksums {
		if strings.TrimSpace(value) == "" {
			continue
		}
		keys = append(keys, strings.TrimSpace(key))
	}
	sort.Strings(keys)
	return keys
}

func verifyToolIntegrity(path string, spec bundleSpec, anchor bundleTrustAnchor) domain.RuntimeVerification {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return domain.RuntimeVerification{Notes: fmt.Sprintf("read failed: %v", err)}
	}
	return verifyData(bytes, spec.Checksums, spec.Signature, anchor)
}

func verifyTrustedAsset(cfg config.Config, asset bundleTrustedAsset, anchor bundleTrustAnchor) domain.RuntimeTrustedAsset {
	resolvedPath := resolveTrustedAssetPath(cfg, asset)

	verification := domain.RuntimeVerification{}
	bytes, err := os.ReadFile(resolvedPath)
	if err != nil {
		verification.ChecksumConfigured = strings.TrimSpace(asset.SHA256) != ""
		verification.ChecksumExpected = strings.TrimSpace(asset.SHA256)
		verification.SignatureConfigured = strings.TrimSpace(asset.Signature.Value) != ""
		verification.SignatureType = anchor.Type
		verification.SignatureSigner = signatureSigner(asset.Signature, anchor)
		verification.Notes = fmt.Sprintf("asset unavailable: %v", err)
		return domain.RuntimeTrustedAsset{
			Name:         asset.Name,
			Kind:         asset.Kind,
			Path:         resolvedPath,
			Verification: verification,
		}
	}

	verification = verifyData(bytes, map[string]string{"default": asset.SHA256}, asset.Signature, anchor)
	return domain.RuntimeTrustedAsset{
		Name:         asset.Name,
		Kind:         asset.Kind,
		Path:         resolvedPath,
		Verification: verification,
	}
}

func resolveTrustedAssetPath(cfg config.Config, asset bundleTrustedAsset) string {
	assetBase := filepath.Base(filepath.FromSlash(asset.Path))
	switch strings.ToLower(strings.TrimSpace(asset.Kind)) {
	case "installer":
		if strings.TrimSpace(cfg.InstallScript) != "" && filepath.Base(cfg.InstallScript) == assetBase {
			return cfg.InstallScript
		}
	case "builder":
		if strings.TrimSpace(cfg.ImageBuildScript) != "" && filepath.Base(cfg.ImageBuildScript) == assetBase {
			return cfg.ImageBuildScript
		}
	case "containerfile":
		if strings.TrimSpace(cfg.ContainerfilePath) != "" && filepath.Base(cfg.ContainerfilePath) == assetBase {
			return cfg.ContainerfilePath
		}
	}

	resolvedPath := asset.Path
	if !filepath.IsAbs(resolvedPath) {
		resolvedPath = filepath.Join(filepath.Dir(cfg.BundleLockPath), filepath.FromSlash(asset.Path))
	}
	return resolvedPath
}

func verifyData(data []byte, checksums map[string]string, signature bundleSignature, anchor bundleTrustAnchor) domain.RuntimeVerification {
	verification := domain.RuntimeVerification{}

	if expected, ok := expectedChecksumForCurrentPlatform(checksums); ok {
		actual := sha256.Sum256(data)
		verification.ChecksumConfigured = true
		verification.ChecksumExpected = normalizeDigest(expected)
		verification.ChecksumActual = hex.EncodeToString(actual[:])
		verification.ChecksumVerified = strings.EqualFold(verification.ChecksumExpected, verification.ChecksumActual)
		if !verification.ChecksumVerified {
			verification.Notes = "checksum mismatch"
		}
	}

	if strings.TrimSpace(signature.Value) != "" {
		verification.SignatureConfigured = true
		verification.SignatureType = coalesceSignatureType(anchor.Type)
		verification.SignatureSigner = signatureSigner(signature, anchor)
		ok, note := verifySignature(data, signature.Value, anchor)
		verification.SignatureVerified = ok
		verification.Notes = appendVerificationNote(verification.Notes, note)
	}

	if !verification.ChecksumConfigured && !verification.SignatureConfigured {
		verification.Notes = appendVerificationNote(verification.Notes, fmt.Sprintf("no verification metadata for %s/%s", runtime.GOOS, runtimeArchAliases()[0]))
	}
	return verification
}

func expectedChecksumForCurrentPlatform(checksums map[string]string) (string, bool) {
	if len(checksums) == 0 {
		return "", false
	}

	for _, key := range platformChecksumKeys() {
		value := strings.TrimSpace(checksums[key])
		if value != "" {
			return value, true
		}
	}
	return "", false
}

func platformChecksumKeys() []string {
	keys := make([]string, 0, 8)
	for _, arch := range runtimeArchAliases() {
		keys = append(keys, runtime.GOOS+"/"+arch)
	}
	keys = append(keys, runtime.GOOS+"/all", "default", "any")
	return keys
}

func runtimeArchAliases() []string {
	switch runtime.GOARCH {
	case "amd64":
		return []string{"amd64", "x64", "x86_64"}
	case "arm64":
		return []string{"arm64", "aarch64"}
	default:
		return []string{runtime.GOARCH}
	}
}

func verifySignature(data []byte, signatureValue string, anchor bundleTrustAnchor) (bool, string) {
	if strings.TrimSpace(anchor.Type) == "" {
		return false, "signature configured but trust anchor type missing"
	}
	if !strings.EqualFold(strings.TrimSpace(anchor.Type), "ed25519") {
		return false, fmt.Sprintf("unsupported signature type: %s", anchor.Type)
	}
	if strings.TrimSpace(anchor.PublicKey) == "" {
		return false, "signature configured but public key missing"
	}

	publicKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(anchor.PublicKey))
	if err != nil {
		return false, fmt.Sprintf("invalid public key: %v", err)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return false, "invalid public key length"
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signatureValue))
	if err != nil {
		return false, fmt.Sprintf("invalid signature: %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), data, signatureBytes) {
		return false, "signature verification failed"
	}
	return true, ""
}

func trustAnchorFingerprint(anchor bundleTrustAnchor) string {
	if strings.TrimSpace(anchor.PublicKey) == "" {
		return ""
	}
	bytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(anchor.PublicKey))
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:8])
}

func signatureSigner(signature bundleSignature, anchor bundleTrustAnchor) string {
	if strings.TrimSpace(signature.Signer) != "" {
		return strings.TrimSpace(signature.Signer)
	}
	return strings.TrimSpace(anchor.Signer)
}

func coalesceSignatureType(value string) string {
	if strings.TrimSpace(value) == "" {
		return "signature"
	}
	return strings.TrimSpace(value)
}

func normalizeDigest(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.TrimPrefix(value, "sha256:")
}

func appendVerificationNote(existing, addition string) string {
	existing = strings.TrimSpace(existing)
	addition = strings.TrimSpace(addition)
	if addition == "" {
		return existing
	}
	if existing == "" {
		return addition
	}
	return existing + "; " + addition
}
