package github

import (
	"strings"
	"testing"
)

func TestBuildCustomPatternManifestEmitsPushProtectionFriendlyPatterns(t *testing.T) {
	manifest := BuildCustomPatternManifest([]CustomPatternSource{
		{
			RuleID:      "secret.github_pat",
			Title:       "Potential GitHub personal access token",
			Description: "Generated from IronSentinel push protection.",
			Pattern:     `gh[pousr]_[A-Za-z0-9]{20,}`,
		},
		{
			RuleID:      "secret.aws_access_key",
			Title:       "Potential AWS access key detected",
			Description: "Generated from IronSentinel push protection.",
			Pattern:     `AKIA[0-9A-Z]{16}`,
		},
	})

	if got, want := manifest.Version, "1"; got != want {
		t.Fatalf("expected manifest version %q, got %q", want, got)
	}
	if len(manifest.Patterns) != 2 {
		t.Fatalf("expected 2 custom patterns, got %d", len(manifest.Patterns))
	}
	first := manifest.Patterns[0]
	if !strings.Contains(first.Name, "secret.github_pat") {
		t.Fatalf("expected pattern name to include rule id, got %q", first.Name)
	}
	if got, want := first.BeforeSecret, `\A|[^0-9A-Za-z_]`; got != want {
		t.Fatalf("expected before_secret %q, got %q", want, got)
	}
	if got, want := first.AfterSecret, `\z|[^0-9A-Za-z_]`; got != want {
		t.Fatalf("expected after_secret %q, got %q", want, got)
	}
	if !first.PushProtection {
		t.Fatalf("expected push protection flag to be enabled")
	}
}
