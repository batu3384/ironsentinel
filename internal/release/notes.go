package release

import (
	"fmt"
	"strings"
)

func RenderReleaseNotes(manifest Manifest, result RuntimeVerificationResult) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# IronSentinel %s\n\n", manifest.Version)
	b.WriteString("## Verification\n\n")
	fmt.Fprintf(&b, "- Manifest: `%s`\n", result.Verification.Status())
	fmt.Fprintf(&b, "- Signature: `%s`\n", verificationState(result.Signed, result.Verification.SignatureVerified))
	fmt.Fprintf(&b, "- Attestation: `%s`\n", verificationState(result.Attested, result.AttestationVerification.Status() == "verified"))
	fmt.Fprintf(&b, "- External provenance: `%s`\n", verificationState(result.ExternalAttested, result.ExternalAttestationVerification.Status() == "verified"))
	if signer := strings.TrimSpace(manifest.TrustAnchor.Signer); signer != "" {
		fmt.Fprintf(&b, "- Signer: `%s`\n", signer)
	}
	if note := joinedNotes(result); note != "" {
		fmt.Fprintf(&b, "- Notes: %s\n", note)
	}

	b.WriteString("\n## Artifacts\n\n")
	b.WriteString("| Name | Platform | Format | Size |\n")
	b.WriteString("| --- | --- | --- | ---: |\n")
	for _, artifact := range manifest.Artifacts {
		fmt.Fprintf(&b, "| `%s` | `%s/%s` | `%s` | %d |\n",
			artifact.Name,
			fallbackValue(artifact.OS, "-"),
			fallbackValue(artifact.Arch, "-"),
			fallbackValue(artifact.Format, "-"),
			artifact.Size,
		)
	}

	b.WriteString("\n## Provenance\n\n")
	provenanceLines := []struct {
		label string
		value string
	}{
		{label: "Commit", value: fallbackValue(manifest.Provenance.Commit, "-")},
		{label: "Ref", value: fallbackValue(manifest.Provenance.Ref, "-")},
		{label: "Builder", value: fallbackValue(manifest.Provenance.Builder, "-")},
		{label: "Go Version", value: fallbackValue(manifest.Provenance.GoVersion, "-")},
		{label: "Host Platform", value: fallbackValue(manifest.Provenance.HostPlatform, "-")},
		{label: "Repository", value: fallbackValue(manifest.Provenance.Repository, "-")},
		{label: "Workflow", value: fallbackValue(manifest.Provenance.Workflow, "-")},
		{label: "Run ID", value: fallbackValue(manifest.Provenance.RunID, "-")},
		{label: "Run Attempt", value: fallbackValue(manifest.Provenance.RunAttempt, "-")},
	}
	for _, line := range provenanceLines {
		fmt.Fprintf(&b, "- %s: `%s`\n", line.label, line.value)
	}
	fmt.Fprintf(&b, "- Source Dirty: `%t`\n", manifest.Provenance.SourceDirty)

	return b.String()
}

func verificationState(present bool, verified bool) string {
	switch {
	case !present:
		return "missing"
	case verified:
		return "verified"
	default:
		return "failed"
	}
}

func fallbackValue(value, fallback string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fallback
	}
	return trimmed
}

func joinedNotes(result RuntimeVerificationResult) string {
	parts := make([]string, 0, 3)
	for _, note := range []string{
		strings.TrimSpace(result.Verification.Notes),
		strings.TrimSpace(result.AttestationVerification.Notes),
		strings.TrimSpace(result.ExternalAttestationVerification.Notes),
	} {
		if note == "" {
			continue
		}
		parts = append(parts, note)
	}
	return strings.Join(parts, "; ")
}
