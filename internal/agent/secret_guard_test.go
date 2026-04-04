package agent

import (
	"strings"
	"testing"

	"github.com/batu3384/ironsentinel/internal/domain"
)

func TestDetectPushProtectedSecretsFlagsHighConfidenceTokensOnly(t *testing.T) {
	findings := DetectPushProtectedSecrets("scan-1", "prj-1", []PushProtectionBlob{
		{
			CommitSHA: "abc1234",
			Path:      "src/secrets.env",
			Content:   []byte(`token="` + fakePushProtectGitHubPAT() + `"`),
		},
		{
			CommitSHA: "def5678",
			Path:      "src/config.env",
			Content:   []byte(`password = "supersecret123"`),
		},
	})

	if len(findings) != 1 {
		t.Fatalf("expected 1 high-confidence finding, got %d", len(findings))
	}
	if got, want := findings[0].RuleID, "secret.github_pat"; got != want {
		t.Fatalf("expected rule %q, got %q", want, got)
	}
	if got, want := findings[0].Severity, domain.SeverityCritical; got != want {
		t.Fatalf("expected severity %q, got %q", want, got)
	}
}

func TestDetectPushProtectedSecretsSkipsFixtureLikePaths(t *testing.T) {
	findings := DetectPushProtectedSecrets("scan-1", "prj-1", []PushProtectionBlob{
		{
			CommitSHA: "abc1234",
			Path:      "internal/testdata/fixtures/token.txt",
			Content:   []byte(fakePushProtectGitHubPAT()),
		},
		{
			CommitSHA: "def5678",
			Path:      "docs/example.env",
			Content:   []byte(fakePushProtectAWSAccessKey()),
		},
	})

	if len(findings) != 0 {
		t.Fatalf("expected fixture/example paths to be skipped, got %d findings", len(findings))
	}
}

func fakePushProtectGitHubPAT() string {
	return strings.Join([]string{"gh", "p_", strings.Repeat("a", 32)}, "")
}

func fakePushProtectAWSAccessKey() string {
	return strings.Join([]string{"AK", "IA", strings.Repeat("A", 16)}, "")
}

func TestPushProtectionCustomPatternsIncludesOnlyHighConfidenceSecretRules(t *testing.T) {
	patterns := PushProtectionCustomPatterns()
	if len(patterns) != 2 {
		t.Fatalf("expected 2 push protection custom patterns, got %d", len(patterns))
	}

	ruleIDs := []string{patterns[0].RuleID, patterns[1].RuleID}
	if ruleIDs[0] != "secret.aws_access_key" && ruleIDs[1] != "secret.aws_access_key" {
		t.Fatalf("expected AWS access key pattern in export set, got %v", ruleIDs)
	}
	if ruleIDs[0] != "secret.github_pat" && ruleIDs[1] != "secret.github_pat" {
		t.Fatalf("expected GitHub PAT pattern in export set, got %v", ruleIDs)
	}
}
