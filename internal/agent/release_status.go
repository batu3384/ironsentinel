package agent

import (
	"os"
	"path/filepath"
	"sort"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
	releaselib "github.com/batu3384/ironsentinel/internal/release"
)

func discoverReleaseBundles(cfg config.Config) []domain.RuntimeReleaseBundle {
	if cfg.DistDir == "" {
		return nil
	}
	entries, err := os.ReadDir(cfg.DistDir)
	if err != nil {
		return nil
	}

	bundles := make([]domain.RuntimeReleaseBundle, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(cfg.DistDir, entry.Name())
		bundle, ok := inspectReleaseBundle(dir, cfg.BundleLockPath)
		if !ok {
			continue
		}
		bundles = append(bundles, bundle)
	}
	sort.Slice(bundles, func(i, j int) bool {
		left := bundles[i].GeneratedAt
		right := bundles[j].GeneratedAt
		switch {
		case left == nil && right == nil:
			return bundles[i].Version > bundles[j].Version
		case left == nil:
			return false
		case right == nil:
			return true
		default:
			return left.After(*right)
		}
	})
	return bundles
}

func inspectReleaseBundle(dir, lockPath string) (domain.RuntimeReleaseBundle, bool) {
	manifest, result, err := releaselib.Inspect(dir, lockPath)
	if err != nil {
		return domain.RuntimeReleaseBundle{}, false
	}

	artifacts := make([]domain.RuntimeReleaseArtifact, 0, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		artifacts = append(artifacts, domain.RuntimeReleaseArtifact{
			Name:   artifact.Name,
			Path:   filepath.Join(dir, artifact.Path),
			OS:     artifact.OS,
			Arch:   artifact.Arch,
			Format: artifact.Format,
			Size:   artifact.Size,
			SHA256: artifact.SHA256,
		})
	}

	generatedAt := manifest.GeneratedAt
	return domain.RuntimeReleaseBundle{
		Version:       manifest.Version,
		Path:          dir,
		GeneratedAt:   &generatedAt,
		ArtifactCount: len(artifacts),
		Signed:        result.Signed,
		Verification:  result.Verification,
		TrustAnchor: domain.RuntimeTrustedAsset{
			Name: filepath.Base(lockPath),
			Kind: "release-trust-anchor",
			Path: lockPath,
			Verification: domain.RuntimeVerification{
				SignatureConfigured: manifest.TrustAnchor.PublicKey != "",
				SignatureType:       manifest.TrustAnchor.Type,
				SignatureSigner:     manifest.TrustAnchor.Signer,
				Notes:               manifest.TrustAnchor.PublicKeyFingerprint,
			},
		},
		ChecksumsPath:                   result.ChecksumsPath,
		ManifestPath:                    result.ManifestPath,
		SignaturePath:                   result.SignaturePath,
		Attested:                        result.Attested,
		AttestationPath:                 result.AttestationPath,
		AttestationSignaturePath:        result.AttestationSignaturePath,
		AttestationVerification:         result.AttestationVerification,
		ExternalAttested:                result.ExternalAttested,
		ExternalAttestationPath:         result.ExternalAttestationPath,
		ExternalAttestationProvider:     result.ExternalAttestationProvider,
		ExternalAttestationSourceURI:    result.ExternalAttestationSourceURI,
		ExternalAttestationVerification: result.ExternalAttestationVerification,
		Artifacts:                       artifacts,
		Provenance: domain.RuntimeReleaseProvenance{
			Commit:       manifest.Provenance.Commit,
			Ref:          manifest.Provenance.Ref,
			Builder:      manifest.Provenance.Builder,
			GoVersion:    manifest.Provenance.GoVersion,
			HostPlatform: manifest.Provenance.HostPlatform,
			Repository:   manifest.Provenance.Repository,
			Workflow:     manifest.Provenance.Workflow,
			RunID:        manifest.Provenance.RunID,
			RunAttempt:   manifest.Provenance.RunAttempt,
			SourceDirty:  manifest.Provenance.SourceDirty,
		},
	}, true
}
