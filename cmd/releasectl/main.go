package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/batu3384/ironsentinel/internal/cmdutil"
	"github.com/batu3384/ironsentinel/internal/release"
)

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "releasectl",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	var (
		keySigner  string
		lockOut    string
		publicOut  string
		privateOut string
		jsonOut    bool
	)
	keygen := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an Ed25519 release signing key pair",
		RunE: func(cmd *cobra.Command, _ []string) error {
			pair, err := release.GenerateKeyPair(keySigner)
			if err != nil {
				return err
			}
			if lockOut != "" {
				lockBytes, err := pair.LockJSON()
				if err != nil {
					return err
				}
				if err := os.WriteFile(lockOut, lockBytes, 0o644); err != nil {
					return err
				}
			}
			if publicOut != "" {
				if err := os.WriteFile(publicOut, []byte(pair.PublicKey+"\n"), 0o600); err != nil {
					return err
				}
			}
			if privateOut != "" {
				if err := os.WriteFile(privateOut, []byte(pair.PrivateKey+"\n"), 0o600); err != nil {
					return err
				}
			}
			if jsonOut || (lockOut == "" && publicOut == "" && privateOut == "") {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(pair)
			}
			return nil
		},
	}
	keygen.Flags().StringVar(&keySigner, "signer", "ironsentinel-smoke-root", "Signer identity to embed in the generated key pair")
	keygen.Flags().StringVar(&lockOut, "lock-out", "", "Write a minimal bundle lock with the public key to this path")
	keygen.Flags().StringVar(&publicOut, "public-out", "", "Write the base64 public key to this path")
	keygen.Flags().StringVar(&privateOut, "private-out", "", "Write the base64 private key to this path")
	keygen.Flags().BoolVar(&jsonOut, "json", false, "Print the generated key pair as JSON")

	var (
		manifestDir       string
		manifestVersion   string
		manifestModule    string
		lockPath          string
		privateKeyEnv     string
		commit            string
		ref               string
		builder           string
		goVersion         string
		hostPlatform      string
		repository        string
		workflow          string
		runID             string
		runAttempt        string
		externalProvider  string
		externalSourceURI string
		sourceDirty       bool
	)
	manifest := &cobra.Command{
		Use:   "manifest",
		Short: "Generate release checksums, manifest, and optional signature",
		RunE: func(_ *cobra.Command, _ []string) error {
			if manifestDir == "" || manifestVersion == "" {
				return fmt.Errorf("dir and version are required")
			}
			anchor, err := release.LoadTrustAnchor(lockPath)
			if err != nil {
				return err
			}
			manifest, checksums, err := release.BuildManifest(manifestDir, manifestVersion, manifestModule, anchor, release.Provenance{
				Commit:       commit,
				Ref:          ref,
				Builder:      builder,
				GoVersion:    goVersion,
				HostPlatform: hostPlatform,
				Repository:   repository,
				Workflow:     workflow,
				RunID:        runID,
				RunAttempt:   runAttempt,
				SourceDirty:  sourceDirty,
			})
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(manifestDir, release.ChecksumsFile), checksums, 0o644); err != nil {
				return err
			}
			manifestBytes, err := release.WriteManifest(manifestDir, manifest)
			if err != nil {
				return err
			}
			attestationBytes, err := release.WriteAttestation(manifestDir, release.BuildAttestation(manifest))
			if err != nil {
				return err
			}
			if externalProvider != "" {
				if _, err := release.WriteExternalAttestation(manifestDir, release.BuildExternalAttestation(manifest, externalProvider, externalSourceURI)); err != nil {
					return err
				}
			}
			if privateKeyEnv == "" {
				return nil
			}
			privateKey := os.Getenv(privateKeyEnv)
			if privateKey == "" {
				return fmt.Errorf("%s is empty", privateKeyEnv)
			}
			signature, err := release.Sign(manifestBytes, privateKey)
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(manifestDir, release.SignatureFile), signature, 0o644); err != nil {
				return err
			}
			attestationSignature, err := release.Sign(attestationBytes, privateKey)
			if err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(manifestDir, release.AttestationSignatureFile), attestationSignature, 0o644)
		},
	}
	manifest.Flags().StringVar(&manifestDir, "dir", "", "Release directory")
	manifest.Flags().StringVar(&manifestVersion, "version", "", "Release version")
	manifest.Flags().StringVar(&manifestModule, "module", "github.com/batu3384/ironsentinel", "Module path")
	manifest.Flags().StringVar(&lockPath, "lock", "scanner-bundle.lock.json", "Bundle lock path with trust anchor")
	manifest.Flags().StringVar(&privateKeyEnv, "private-key-env", "", "Environment variable containing the base64 Ed25519 private key")
	manifest.Flags().StringVar(&commit, "commit", "", "Source commit")
	manifest.Flags().StringVar(&ref, "ref", "", "Source ref or tag")
	manifest.Flags().StringVar(&builder, "builder", "", "Builder identity")
	manifest.Flags().StringVar(&goVersion, "go-version", "", "Go toolchain version")
	manifest.Flags().StringVar(&hostPlatform, "host-platform", "", "Builder host platform")
	manifest.Flags().StringVar(&repository, "repository", "", "Source repository URL")
	manifest.Flags().StringVar(&workflow, "workflow", "", "CI workflow identity")
	manifest.Flags().StringVar(&runID, "run-id", "", "CI run identifier")
	manifest.Flags().StringVar(&runAttempt, "run-attempt", "", "CI run attempt")
	manifest.Flags().StringVar(&externalProvider, "external-provider", "", "Optional external provenance provider")
	manifest.Flags().StringVar(&externalSourceURI, "external-source-uri", "", "Optional external provenance source URI")
	manifest.Flags().BoolVar(&sourceDirty, "source-dirty", false, "Whether the source tree was dirty during packaging")

	var (
		verifyDir                  string
		requireSignature           bool
		requireAttestation         bool
		requireExternalAttestation bool
		requireCleanSource         bool
	)
	verify := &cobra.Command{
		Use:   "verify",
		Short: "Verify release manifest, signature, and checksums",
		RunE: func(_ *cobra.Command, _ []string) error {
			if verifyDir == "" {
				return fmt.Errorf("dir is required")
			}
			return release.VerifyWithOptions(verifyDir, lockPath, release.VerifyOptions{
				RequireSignature:           requireSignature,
				RequireAttestation:         requireAttestation,
				RequireExternalAttestation: requireExternalAttestation,
				RequireCleanSource:         requireCleanSource,
			})
		},
	}
	verify.Flags().StringVar(&verifyDir, "dir", "", "Release directory")
	verify.Flags().StringVar(&lockPath, "lock", "scanner-bundle.lock.json", "Bundle lock path with trust anchor")
	verify.Flags().BoolVar(&requireSignature, "require-signature", false, "Require signed manifest and attestation")
	verify.Flags().BoolVar(&requireAttestation, "require-attestation", false, "Require a release attestation")
	verify.Flags().BoolVar(&requireExternalAttestation, "require-external-attestation", false, "Require an external provenance attestation")
	verify.Flags().BoolVar(&requireCleanSource, "require-clean-source", false, "Require provenance to report a clean source tree")

	var (
		notesDir string
		notesOut string
	)
	notes := &cobra.Command{
		Use:   "notes",
		Short: "Render release notes from a packaged release directory",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if notesDir == "" {
				return fmt.Errorf("dir is required")
			}
			manifest, result, err := release.Inspect(notesDir, lockPath)
			if err != nil {
				return fmt.Errorf("inspect release bundle: %w", err)
			}
			body := release.RenderReleaseNotes(manifest, result)
			if notesOut == "" {
				_, err = fmt.Fprint(cmd.OutOrStdout(), body)
				return err
			}
			return os.WriteFile(notesOut, []byte(body), 0o644)
		},
	}
	notes.Flags().StringVar(&notesDir, "dir", "", "Release directory")
	notes.Flags().StringVar(&notesOut, "out", "", "Write rendered release notes to this path instead of stdout")
	notes.Flags().StringVar(&lockPath, "lock", "scanner-bundle.lock.json", "Bundle lock path with trust anchor")

	var (
		hydrateLockPath string
		hydrateTools    []string
		hydrateWrite    bool
		trustPrivateEnv string
		trustSigner     string
		trustGenerate   bool
		trustWrite      bool
	)
	lockCmd := &cobra.Command{
		Use:   "lock",
		Short: "Inspect or update the scanner bundle lock",
	}
	hydrate := &cobra.Command{
		Use:   "hydrate",
		Short: "Fetch upstream checksum manifests and enrich bundle lock entries",
		RunE: func(cmd *cobra.Command, _ []string) error {
			lock, err := release.LoadBundleLock(hydrateLockPath)
			if err != nil {
				return err
			}
			updated, reports, err := release.HydrateLockChecksums(lock, release.LockHydrateOptions{Tools: hydrateTools})
			if err != nil {
				return err
			}
			for _, report := range reports {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\t%s\n", report.Name, report.Channel, report.Status, report.Version, report.Note)
			}
			if hydrateWrite {
				return release.WriteBundleLock(hydrateLockPath, updated)
			}
			return nil
		},
	}
	hydrate.Flags().StringVar(&hydrateLockPath, "lock", "scanner-bundle.lock.json", "Bundle lock path to update")
	hydrate.Flags().StringSliceVar(&hydrateTools, "tool", nil, "Tool name(s) to hydrate; defaults to all supported tools present in the lock")
	hydrate.Flags().BoolVar(&hydrateWrite, "write", false, "Write the updated lock back to disk")

	trustAssets := &cobra.Command{
		Use:   "trust-assets",
		Short: "Refresh trusted asset checksums and signatures in the bundle lock",
		RunE: func(cmd *cobra.Command, _ []string) error {
			lock, err := release.LoadBundleLock(hydrateLockPath)
			if err != nil {
				return err
			}

			privateKey := ""
			if trustGenerate {
				pair, err := release.GenerateKeyPair(trustSigner)
				if err != nil {
					return err
				}
				privateKey = pair.PrivateKey
				if trustSigner == "" {
					trustSigner = pair.Signer
				}
			} else {
				if trustPrivateEnv == "" {
					return fmt.Errorf("either --generate-key or --private-key-env is required")
				}
				privateKey = strings.TrimSpace(os.Getenv(trustPrivateEnv))
				if privateKey == "" {
					return fmt.Errorf("%s is empty", trustPrivateEnv)
				}
			}

			updated, reports, err := release.RefreshTrustedAssets(lock, hydrateLockPath, privateKey, trustSigner)
			if err != nil {
				return err
			}
			for _, report := range reports {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\n", report.Name, report.Kind, report.SHA256, report.Signature)
			}
			if !trustWrite {
				return nil
			}
			return release.WriteBundleLock(hydrateLockPath, updated)
		},
	}
	trustAssets.Flags().StringVar(&hydrateLockPath, "lock", "scanner-bundle.lock.json", "Bundle lock path to update")
	trustAssets.Flags().StringVar(&trustPrivateEnv, "private-key-env", "", "Environment variable containing the base64 Ed25519 private key")
	trustAssets.Flags().StringVar(&trustSigner, "signer", "ironsentinel-release-root", "Signer identity to record in the lock")
	trustAssets.Flags().BoolVar(&trustGenerate, "generate-key", false, "Generate a fresh key pair and rotate the lock trust anchor")
	trustAssets.Flags().BoolVar(&trustWrite, "write", false, "Write the updated lock back to disk")
	lockCmd.AddCommand(hydrate, trustAssets)

	root.AddCommand(keygen, manifest, verify, notes, lockCmd)
	return root
}

func main() {
	root := newRootCommand()
	os.Exit(cmdutil.Run(os.Stderr, func() (cmdutil.ExecuteContexter, error) {
		return root, nil
	}, nil))
}
