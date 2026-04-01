package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/batu3384/ironsentinel/internal/domain"
)

const (
	ManifestFile             = "release-manifest.json"
	SignatureFile            = "release-manifest.sig"
	ChecksumsFile            = "SHA256SUMS"
	AttestationFile          = "release-attestation.json"
	AttestationSignatureFile = "release-attestation.sig"
	ExternalAttestationFile  = "release-external-attestation.json"
)

type TrustAnchor struct {
	Type                 string `json:"type,omitempty"`
	Signer               string `json:"signer,omitempty"`
	PublicKey            string `json:"publicKey,omitempty"`
	PublicKeyFingerprint string `json:"publicKeyFingerprint,omitempty"`
}

type Artifact struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	OS     string `json:"os,omitempty"`
	Arch   string `json:"arch,omitempty"`
	Format string `json:"format,omitempty"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Provenance struct {
	Commit       string `json:"commit,omitempty"`
	Ref          string `json:"ref,omitempty"`
	Builder      string `json:"builder,omitempty"`
	GoVersion    string `json:"goVersion,omitempty"`
	HostPlatform string `json:"hostPlatform,omitempty"`
	Repository   string `json:"repository,omitempty"`
	Workflow     string `json:"workflow,omitempty"`
	RunID        string `json:"runId,omitempty"`
	RunAttempt   string `json:"runAttempt,omitempty"`
	SourceDirty  bool   `json:"sourceDirty,omitempty"`
}

type Manifest struct {
	Version     string      `json:"version"`
	GeneratedAt time.Time   `json:"generatedAt"`
	Module      string      `json:"module"`
	Checksums   string      `json:"checksums"`
	TrustAnchor TrustAnchor `json:"trustAnchor,omitempty"`
	Artifacts   []Artifact  `json:"artifacts"`
	Provenance  Provenance  `json:"provenance,omitempty"`
}

type AttestationPredicate struct {
	Manifest   string     `json:"manifest"`
	Checksums  string     `json:"checksums"`
	Provenance Provenance `json:"provenance"`
}

type Attestation struct {
	Type          string               `json:"type"`
	PredicateType string               `json:"predicateType"`
	Version       string               `json:"version"`
	GeneratedAt   time.Time            `json:"generatedAt"`
	Module        string               `json:"module"`
	Subjects      []Artifact           `json:"subjects"`
	Predicate     AttestationPredicate `json:"predicate"`
}

type ExternalAttestation struct {
	Provider    string     `json:"provider"`
	SourceURI   string     `json:"sourceUri,omitempty"`
	Repository  string     `json:"repository,omitempty"`
	Workflow    string     `json:"workflow,omitempty"`
	RunID       string     `json:"runId,omitempty"`
	RunAttempt  string     `json:"runAttempt,omitempty"`
	Ref         string     `json:"ref,omitempty"`
	Commit      string     `json:"commit,omitempty"`
	GeneratedAt time.Time  `json:"generatedAt"`
	Subjects    []Artifact `json:"subjects"`
}

type bundleLock struct {
	Signing struct {
		Type      string `json:"type,omitempty"`
		Signer    string `json:"signer,omitempty"`
		PublicKey string `json:"publicKey,omitempty"`
	} `json:"signing,omitempty"`
}

func LoadTrustAnchor(lockPath string) (TrustAnchor, error) {
	if strings.TrimSpace(lockPath) == "" {
		return TrustAnchor{}, nil
	}
	bytes, err := os.ReadFile(lockPath)
	if err != nil {
		return TrustAnchor{}, err
	}
	var lock bundleLock
	if err := json.Unmarshal(bytes, &lock); err != nil {
		return TrustAnchor{}, err
	}
	anchor := TrustAnchor{
		Type:      strings.TrimSpace(lock.Signing.Type),
		Signer:    strings.TrimSpace(lock.Signing.Signer),
		PublicKey: strings.TrimSpace(lock.Signing.PublicKey),
	}
	anchor.PublicKeyFingerprint = fingerprint(anchor.PublicKey)
	return anchor, nil
}

func BuildManifest(dir, version, module string, anchor TrustAnchor, provenance Provenance) (Manifest, []byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return Manifest{}, nil, err
	}

	artifacts := make([]Artifact, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == ManifestFile || name == SignatureFile || name == ChecksumsFile || name == AttestationFile || name == AttestationSignatureFile || name == ExternalAttestationFile {
			continue
		}
		path := filepath.Join(dir, name)
		info, err := entry.Info()
		if err != nil {
			return Manifest{}, nil, err
		}
		sum, err := fileSHA256(path)
		if err != nil {
			return Manifest{}, nil, err
		}
		artifact := Artifact{
			Name:   name,
			Path:   name,
			Size:   info.Size(),
			SHA256: sum,
		}
		populateArtifactPlatform(&artifact, version)
		artifacts = append(artifacts, artifact)
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Name < artifacts[j].Name })

	lines := make([]string, 0, len(artifacts))
	for _, artifact := range artifacts {
		lines = append(lines, fmt.Sprintf("%s  %s", artifact.SHA256, artifact.Name))
	}
	checksumBytes := []byte(strings.Join(lines, "\n") + "\n")

	return Manifest{
		Version:     version,
		GeneratedAt: time.Now().UTC(),
		Module:      module,
		Checksums:   ChecksumsFile,
		TrustAnchor: anchor,
		Artifacts:   artifacts,
		Provenance:  provenance,
	}, checksumBytes, nil
}

func WriteManifest(dir string, manifest Manifest) ([]byte, error) {
	bytes, err := MarshalManifest(manifest)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, ManifestFile), bytes, 0o644); err != nil {
		return nil, err
	}
	return bytes, nil
}

func MarshalManifest(manifest Manifest) ([]byte, error) {
	return json.MarshalIndent(manifest, "", "  ")
}

func BuildAttestation(manifest Manifest) Attestation {
	subjects := make([]Artifact, len(manifest.Artifacts))
	copy(subjects, manifest.Artifacts)
	return Attestation{
		Type:          "https://github.com/batu3384/ironsentinel/attestations/release/v1",
		PredicateType: "https://slsa.dev/provenance/v1",
		Version:       manifest.Version,
		GeneratedAt:   manifest.GeneratedAt,
		Module:        manifest.Module,
		Subjects:      subjects,
		Predicate: AttestationPredicate{
			Manifest:   ManifestFile,
			Checksums:  manifest.Checksums,
			Provenance: manifest.Provenance,
		},
	}
}

func WriteAttestation(dir string, attestation Attestation) ([]byte, error) {
	bytes, err := MarshalAttestation(attestation)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, AttestationFile), bytes, 0o644); err != nil {
		return nil, err
	}
	return bytes, nil
}

func MarshalAttestation(attestation Attestation) ([]byte, error) {
	return json.MarshalIndent(attestation, "", "  ")
}

func BuildExternalAttestation(manifest Manifest, provider, sourceURI string) ExternalAttestation {
	subjects := make([]Artifact, len(manifest.Artifacts))
	copy(subjects, manifest.Artifacts)
	return ExternalAttestation{
		Provider:    strings.TrimSpace(provider),
		SourceURI:   strings.TrimSpace(sourceURI),
		Repository:  manifest.Provenance.Repository,
		Workflow:    manifest.Provenance.Workflow,
		RunID:       manifest.Provenance.RunID,
		RunAttempt:  manifest.Provenance.RunAttempt,
		Ref:         manifest.Provenance.Ref,
		Commit:      manifest.Provenance.Commit,
		GeneratedAt: manifest.GeneratedAt,
		Subjects:    subjects,
	}
}

func WriteExternalAttestation(dir string, attestation ExternalAttestation) ([]byte, error) {
	bytes, err := MarshalExternalAttestation(attestation)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, ExternalAttestationFile), bytes, 0o644); err != nil {
		return nil, err
	}
	return bytes, nil
}

func MarshalExternalAttestation(attestation ExternalAttestation) ([]byte, error) {
	return json.MarshalIndent(attestation, "", "  ")
}

func Sign(bytes []byte, privateKeyB64 string) ([]byte, error) {
	raw := strings.TrimSpace(privateKeyB64)
	if raw == "" {
		return nil, fmt.Errorf("private key is required")
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	switch len(decoded) {
	case ed25519.SeedSize:
		decoded = ed25519.NewKeyFromSeed(decoded)
	case ed25519.PrivateKeySize:
	default:
		return nil, fmt.Errorf("invalid private key length")
	}
	signature := ed25519.Sign(ed25519.PrivateKey(decoded), bytes)
	return []byte(base64.StdEncoding.EncodeToString(signature) + "\n"), nil
}

type VerifyOptions struct {
	RequireSignature           bool
	RequireAttestation         bool
	RequireExternalAttestation bool
	RequireCleanSource         bool
}

func VerifyWithOptions(dir, lockPath string, options VerifyOptions) error {
	manifest, result, err := Inspect(dir, lockPath)
	if err != nil {
		return fmt.Errorf("inspect release bundle: %w", err)
	}
	if result.Verification.Status() == "failed" {
		return fmt.Errorf("release manifest verification failed: %s", coalesceReleaseNote(result.Verification.Notes, "checksum/signature mismatch"))
	}
	if options.RequireSignature {
		if !result.Signed {
			return fmt.Errorf("release manifest signature is required")
		}
		if !result.Verification.SignatureVerified {
			return fmt.Errorf("release manifest signature verification failed")
		}
	}
	if options.RequireAttestation {
		if !result.Attested {
			return fmt.Errorf("release attestation is required")
		}
		if result.AttestationVerification.Status() == "failed" {
			return fmt.Errorf("release attestation verification failed: %s", coalesceReleaseNote(result.AttestationVerification.Notes, "attestation mismatch"))
		}
	}
	if options.RequireExternalAttestation {
		if !result.ExternalAttested {
			return fmt.Errorf("external provenance attestation is required")
		}
		if result.ExternalAttestationVerification.Status() == "failed" {
			return fmt.Errorf("external provenance attestation verification failed: %s", coalesceReleaseNote(result.ExternalAttestationVerification.Notes, "external attestation mismatch"))
		}
	}
	if options.RequireSignature && result.Attested && result.AttestationSignaturePath == "" {
		return fmt.Errorf("release attestation signature is required")
	}
	if options.RequireSignature && result.Attested && !result.AttestationVerification.SignatureVerified {
		return fmt.Errorf("release attestation signature verification failed")
	}
	if options.RequireCleanSource && manifest.Provenance.SourceDirty {
		return fmt.Errorf("release provenance requires a clean source tree")
	}
	return nil
}

func coalesceReleaseNote(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func Inspect(dir, lockPath string) (Manifest, RuntimeVerificationResult, error) {
	manifestPath := filepath.Join(dir, ManifestFile)
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return Manifest{}, RuntimeVerificationResult{}, fmt.Errorf("read release manifest %s: %w", manifestPath, err)
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return Manifest{}, RuntimeVerificationResult{}, fmt.Errorf("parse release manifest %s: %w", manifestPath, err)
	}
	checksumPath := filepath.Join(dir, manifest.Checksums)
	checksumBytes, err := os.ReadFile(checksumPath)
	if err != nil {
		return manifest, RuntimeVerificationResult{}, fmt.Errorf("read release checksums %s: %w", checksumPath, err)
	}
	anchor, err := LoadTrustAnchor(lockPath)
	if err != nil {
		return manifest, RuntimeVerificationResult{}, fmt.Errorf("load release trust anchor %s: %w", lockPath, err)
	}
	result := RuntimeVerificationResult{
		ManifestPath:  manifestPath,
		ChecksumsPath: checksumPath,
	}
	sigPath := filepath.Join(dir, SignatureFile)
	if _, err := os.Stat(sigPath); err == nil {
		result.SignaturePath = sigPath
		result.Signed = true
	}
	if strings.TrimSpace(anchor.PublicKey) != "" && result.Signed {
		signatureBytes, err := os.ReadFile(sigPath)
		if err != nil {
			return manifest, result, err
		}
		signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signatureBytes)))
		if err != nil {
			result.Verification.Notes = fmt.Sprintf("invalid signature: %v", err)
			return manifest, result, nil
		}
		publicKey, err := base64.StdEncoding.DecodeString(anchor.PublicKey)
		if err != nil {
			result.Verification.Notes = fmt.Sprintf("invalid public key: %v", err)
			return manifest, result, nil
		}
		result.Verification.SignatureConfigured = true
		result.Verification.SignatureType = anchor.Type
		result.Verification.SignatureSigner = anchor.Signer
		result.Verification.SignatureVerified = len(publicKey) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(publicKey), manifestBytes, signature)
		if !result.Verification.SignatureVerified {
			result.Verification.Notes = appendReleaseVerificationNote(result.Verification.Notes, "signature verification failed")
		}
	}

	expectedManifest, expectedChecksums, err := BuildManifest(dir, manifest.Version, manifest.Module, anchor, manifest.Provenance)
	if err != nil {
		return manifest, result, err
	}
	sum := sha256.Sum256(checksumBytes)
	result.Verification.ChecksumConfigured = true
	result.Verification.ChecksumExpected = hex.EncodeToString(sum[:])
	expectedSum := sha256.Sum256(expectedChecksums)
	result.Verification.ChecksumActual = hex.EncodeToString(expectedSum[:])
	result.Verification.ChecksumVerified = string(expectedChecksums) == string(checksumBytes)
	if !result.Verification.ChecksumVerified {
		result.Verification.Notes = appendReleaseVerificationNote(result.Verification.Notes, "checksum file mismatch")
	}
	if len(expectedManifest.Artifacts) != len(manifest.Artifacts) {
		result.Verification.Notes = appendReleaseVerificationNote(result.Verification.Notes, "artifact count mismatch")
		result.Verification.ChecksumVerified = false
	}
	limit := len(manifest.Artifacts)
	if len(expectedManifest.Artifacts) < limit {
		limit = len(expectedManifest.Artifacts)
	}
	for index := 0; index < limit; index++ {
		actual := manifest.Artifacts[index]
		expected := expectedManifest.Artifacts[index]
		if actual.Name != expected.Name || actual.SHA256 != expected.SHA256 || actual.Size != expected.Size {
			result.Verification.ChecksumVerified = false
			result.Verification.Notes = appendReleaseVerificationNote(result.Verification.Notes, fmt.Sprintf("artifact mismatch: %s", actual.Name))
			break
		}
	}
	if _, attestationResult, err := inspectAttestation(dir, manifest, anchor); err == nil {
		result.Attested = attestationResult.Attested
		result.AttestationPath = attestationResult.AttestationPath
		result.AttestationSignaturePath = attestationResult.AttestationSignaturePath
		result.AttestationVerification = attestationResult.AttestationVerification
	} else if !os.IsNotExist(err) {
		result.Attested = true
		result.AttestationVerification = domain.RuntimeVerification{
			ChecksumConfigured: true,
			ChecksumExpected:   "attestation",
			ChecksumActual:     "attestation",
			ChecksumVerified:   false,
			Notes:              err.Error(),
		}
	}
	if _, externalResult, err := inspectExternalAttestation(dir, manifest); err == nil {
		result.ExternalAttested = externalResult.ExternalAttested
		result.ExternalAttestationPath = externalResult.ExternalAttestationPath
		result.ExternalAttestationProvider = externalResult.ExternalAttestationProvider
		result.ExternalAttestationSourceURI = externalResult.ExternalAttestationSourceURI
		result.ExternalAttestationVerification = externalResult.ExternalAttestationVerification
	} else if !os.IsNotExist(err) {
		result.ExternalAttested = true
		result.ExternalAttestationVerification = domain.RuntimeVerification{
			ChecksumConfigured: true,
			ChecksumExpected:   "external-attestation",
			ChecksumActual:     "external-attestation",
			ChecksumVerified:   false,
			Notes:              err.Error(),
		}
	}
	return manifest, result, nil
}

type RuntimeVerificationResult struct {
	Signed                          bool
	ManifestPath                    string
	ChecksumsPath                   string
	SignaturePath                   string
	Verification                    domain.RuntimeVerification
	Attested                        bool
	AttestationPath                 string
	AttestationSignaturePath        string
	AttestationVerification         domain.RuntimeVerification
	ExternalAttested                bool
	ExternalAttestationPath         string
	ExternalAttestationProvider     string
	ExternalAttestationSourceURI    string
	ExternalAttestationVerification domain.RuntimeVerification
}

func inspectAttestation(dir string, manifest Manifest, anchor TrustAnchor) (Attestation, RuntimeVerificationResult, error) {
	attestationPath := filepath.Join(dir, AttestationFile)
	bytes, err := os.ReadFile(attestationPath)
	if err != nil {
		return Attestation{}, RuntimeVerificationResult{}, fmt.Errorf("read release attestation %s: %w", attestationPath, err)
	}

	var attestation Attestation
	if err := json.Unmarshal(bytes, &attestation); err != nil {
		return Attestation{}, RuntimeVerificationResult{}, fmt.Errorf("parse release attestation %s: %w", attestationPath, err)
	}

	verification := domain.RuntimeVerification{
		ChecksumConfigured: true,
		ChecksumExpected:   "attestation",
		ChecksumActual:     "attestation",
		ChecksumVerified:   true,
	}
	if attestation.Type == "" || attestation.PredicateType == "" {
		verification.ChecksumVerified = false
		verification.Notes = appendReleaseVerificationNote(verification.Notes, "attestation type metadata missing")
	}
	if attestation.Version != manifest.Version || attestation.Module != manifest.Module {
		verification.ChecksumVerified = false
		verification.Notes = appendReleaseVerificationNote(verification.Notes, "attestation metadata mismatch")
	}
	if attestation.Predicate.Manifest != ManifestFile || attestation.Predicate.Checksums != manifest.Checksums {
		verification.ChecksumVerified = false
		verification.Notes = appendReleaseVerificationNote(verification.Notes, "attestation predicate mismatch")
	}
	if attestation.Predicate.Provenance != manifest.Provenance {
		verification.ChecksumVerified = false
		verification.Notes = appendReleaseVerificationNote(verification.Notes, "attestation provenance mismatch")
	}
	if note := validateReleaseProvenance(attestation.Predicate.Provenance); note != "" {
		verification.ChecksumVerified = false
		verification.Notes = appendReleaseVerificationNote(verification.Notes, note)
	}
	if len(attestation.Subjects) != len(manifest.Artifacts) {
		verification.ChecksumVerified = false
		verification.Notes = appendReleaseVerificationNote(verification.Notes, "attestation subject count mismatch")
	}
	limit := len(attestation.Subjects)
	if len(manifest.Artifacts) < limit {
		limit = len(manifest.Artifacts)
	}
	for index := 0; index < limit; index++ {
		subject := attestation.Subjects[index]
		artifact := manifest.Artifacts[index]
		if subject.Name != artifact.Name || subject.SHA256 != artifact.SHA256 || subject.Size != artifact.Size || subject.OS != artifact.OS || subject.Arch != artifact.Arch || subject.Format != artifact.Format {
			verification.ChecksumVerified = false
			verification.Notes = appendReleaseVerificationNote(verification.Notes, fmt.Sprintf("attestation subject mismatch: %s", subject.Name))
			break
		}
	}

	result := RuntimeVerificationResult{
		Attested:                true,
		AttestationPath:         attestationPath,
		AttestationVerification: verification,
	}
	sigPath := filepath.Join(dir, AttestationSignatureFile)
	if _, err := os.Stat(sigPath); err == nil {
		result.AttestationSignaturePath = sigPath
		result.AttestationVerification.SignatureConfigured = true
		result.AttestationVerification.SignatureType = anchor.Type
		result.AttestationVerification.SignatureSigner = anchor.Signer
		signatureBytes, err := os.ReadFile(sigPath)
		if err != nil {
			result.AttestationVerification.SignatureVerified = false
			result.AttestationVerification.Notes = appendReleaseVerificationNote(result.AttestationVerification.Notes, fmt.Sprintf("read attestation signature failed: %v", err))
			return attestation, result, nil
		}
		signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signatureBytes)))
		if err != nil {
			result.AttestationVerification.SignatureVerified = false
			result.AttestationVerification.Notes = appendReleaseVerificationNote(result.AttestationVerification.Notes, fmt.Sprintf("invalid attestation signature: %v", err))
			return attestation, result, nil
		}
		publicKey, err := base64.StdEncoding.DecodeString(anchor.PublicKey)
		if err != nil {
			result.AttestationVerification.SignatureVerified = false
			result.AttestationVerification.Notes = appendReleaseVerificationNote(result.AttestationVerification.Notes, fmt.Sprintf("invalid public key: %v", err))
			return attestation, result, nil
		}
		result.AttestationVerification.SignatureVerified = len(publicKey) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(publicKey), bytes, signature)
		if !result.AttestationVerification.SignatureVerified {
			result.AttestationVerification.Notes = appendReleaseVerificationNote(result.AttestationVerification.Notes, "attestation signature verification failed")
		}
	}

	return attestation, result, nil
}

func inspectExternalAttestation(dir string, manifest Manifest) (ExternalAttestation, RuntimeVerificationResult, error) {
	attestationPath := filepath.Join(dir, ExternalAttestationFile)
	bytes, err := os.ReadFile(attestationPath)
	if err != nil {
		return ExternalAttestation{}, RuntimeVerificationResult{}, fmt.Errorf("read external release attestation %s: %w", attestationPath, err)
	}

	var attestation ExternalAttestation
	if err := json.Unmarshal(bytes, &attestation); err != nil {
		return ExternalAttestation{}, RuntimeVerificationResult{}, fmt.Errorf("parse external release attestation %s: %w", attestationPath, err)
	}

	verification := domain.RuntimeVerification{
		ChecksumConfigured: true,
		ChecksumExpected:   "external-attestation",
		ChecksumActual:     "external-attestation",
		ChecksumVerified:   true,
	}
	if strings.TrimSpace(attestation.Provider) == "" {
		verification.ChecksumVerified = false
		verification.Notes = appendReleaseVerificationNote(verification.Notes, "external attestation provider missing")
	}
	if attestation.Commit != manifest.Provenance.Commit || attestation.Ref != manifest.Provenance.Ref {
		verification.ChecksumVerified = false
		verification.Notes = appendReleaseVerificationNote(verification.Notes, "external attestation source mismatch")
	}
	if manifest.Provenance.Repository != "" && attestation.Repository != manifest.Provenance.Repository {
		verification.ChecksumVerified = false
		verification.Notes = appendReleaseVerificationNote(verification.Notes, "external attestation repository mismatch")
	}
	if manifest.Provenance.Workflow != "" && attestation.Workflow != manifest.Provenance.Workflow {
		verification.ChecksumVerified = false
		verification.Notes = appendReleaseVerificationNote(verification.Notes, "external attestation workflow mismatch")
	}
	if manifest.Provenance.RunID != "" && attestation.RunID != manifest.Provenance.RunID {
		verification.ChecksumVerified = false
		verification.Notes = appendReleaseVerificationNote(verification.Notes, "external attestation run id mismatch")
	}
	if manifest.Provenance.RunAttempt != "" && attestation.RunAttempt != manifest.Provenance.RunAttempt {
		verification.ChecksumVerified = false
		verification.Notes = appendReleaseVerificationNote(verification.Notes, "external attestation run attempt mismatch")
	}
	if len(attestation.Subjects) != len(manifest.Artifacts) {
		verification.ChecksumVerified = false
		verification.Notes = appendReleaseVerificationNote(verification.Notes, "external attestation subject count mismatch")
	}
	limit := len(attestation.Subjects)
	if len(manifest.Artifacts) < limit {
		limit = len(manifest.Artifacts)
	}
	for index := 0; index < limit; index++ {
		subject := attestation.Subjects[index]
		artifact := manifest.Artifacts[index]
		if subject.Name != artifact.Name || subject.SHA256 != artifact.SHA256 || subject.Size != artifact.Size {
			verification.ChecksumVerified = false
			verification.Notes = appendReleaseVerificationNote(verification.Notes, fmt.Sprintf("external attestation subject mismatch: %s", subject.Name))
			break
		}
	}

	return attestation, RuntimeVerificationResult{
		ExternalAttested:                true,
		ExternalAttestationPath:         attestationPath,
		ExternalAttestationProvider:     attestation.Provider,
		ExternalAttestationSourceURI:    attestation.SourceURI,
		ExternalAttestationVerification: verification,
	}, nil
}

func validateReleaseProvenance(provenance Provenance) string {
	missing := make([]string, 0, 5)
	if strings.TrimSpace(provenance.Commit) == "" {
		missing = append(missing, "commit")
	}
	if strings.TrimSpace(provenance.Ref) == "" {
		missing = append(missing, "ref")
	}
	if strings.TrimSpace(provenance.Builder) == "" {
		missing = append(missing, "builder")
	}
	if strings.TrimSpace(provenance.GoVersion) == "" {
		missing = append(missing, "goVersion")
	}
	if strings.TrimSpace(provenance.HostPlatform) == "" {
		missing = append(missing, "hostPlatform")
	}
	if len(missing) == 0 {
		return ""
	}
	return "attestation provenance missing: " + strings.Join(missing, ", ")
}

func fileSHA256(path string) (string, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:]), nil
}

func populateArtifactPlatform(artifact *Artifact, version string) {
	base := artifact.Name
	artifact.Format = artifactFormat(base)
	trimmed := strings.TrimSuffix(base, ".tar.gz")
	trimmed = strings.TrimSuffix(trimmed, ".zip")
	prefix := "ironsentinel_" + version + "_"
	if !strings.HasPrefix(trimmed, prefix) {
		return
	}
	parts := strings.Split(strings.TrimPrefix(trimmed, prefix), "_")
	if len(parts) < 2 {
		return
	}
	artifact.OS = parts[0]
	artifact.Arch = parts[1]
}

func artifactFormat(name string) string {
	switch {
	case strings.HasSuffix(name, ".tar.gz"):
		return "tar.gz"
	case strings.HasSuffix(name, ".zip"):
		return "zip"
	default:
		return filepath.Ext(name)
	}
}

func fingerprint(publicKey string) string {
	if strings.TrimSpace(publicKey) == "" {
		return ""
	}
	bytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKey))
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:8])
}

func appendReleaseVerificationNote(existing, addition string) string {
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
