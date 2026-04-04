package agent

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/batu3384/ironsentinel/internal/domain"
)

type PushProtectionBlob struct {
	CommitSHA string
	Path      string
	Content   []byte
}

type PushProtectionCustomPattern struct {
	RuleID      string
	Title       string
	Description string
	Pattern     string
	Severity    domain.Severity
	Remediation string
}

func DetectPushProtectedSecrets(scanID, projectID string, blobs []PushProtectionBlob) []domain.Finding {
	findings := make([]domain.Finding, 0, len(blobs))
	seen := make(map[string]struct{}, len(blobs))
	index := 0

	for _, blob := range blobs {
		if len(blob.Content) == 0 || len(blob.Content) > 1024*1024 {
			continue
		}
		lowerPath := filepath.ToSlash(strings.ToLower(strings.TrimSpace(blob.Path)))
		if lowerPath == "" || isSampleFixture(lowerPath) || !isCandidateTextFile(blob.Path) {
			continue
		}

		for _, matcher := range secretPatterns {
			if !isPushProtectionRuleID(matcher.ruleID) || !matcher.pattern.Match(blob.Content) {
				continue
			}
			key := matcher.ruleID + "|" + lowerPath
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			location := blob.Path
			if short := strings.TrimSpace(blob.CommitSHA); short != "" {
				if len(short) > 7 {
					short = short[:7]
				}
				location = fmt.Sprintf("%s @ %s", blob.Path, short)
			}

			findings = append(findings, domain.Finding{
				ID:           domain.NewFindingID(scanID, index),
				ScanID:       scanID,
				ProjectID:    projectID,
				Category:     domain.CategorySecret,
				RuleID:       matcher.ruleID,
				Title:        matcher.title,
				Severity:     matcher.severity,
				Confidence:   0.95,
				Reachability: domain.ReachabilityRepository,
				Fingerprint:  domain.MakeFingerprint("push-protect", matcher.ruleID, lowerPath),
				Remediation:  matcher.remediation,
				Location:     location,
				Module:       "push-protect",
			})
			index++
		}
	}

	return findings
}

func PushProtectionCustomPatterns() []PushProtectionCustomPattern {
	patterns := make([]PushProtectionCustomPattern, 0, 2)
	for _, matcher := range secretPatterns {
		if isPushProtectionRuleID(matcher.ruleID) {
			patterns = append(patterns, PushProtectionCustomPattern{
				RuleID:      matcher.ruleID,
				Title:       matcher.title,
				Description: "Generated from IronSentinel push protection rules.",
				Pattern:     matcher.pattern.String(),
				Severity:    matcher.severity,
				Remediation: matcher.remediation,
			})
		}
	}
	return patterns
}

func isPushProtectionRuleID(ruleID string) bool {
	switch ruleID {
	case "secret.github_pat", "secret.aws_access_key":
		return true
	default:
		return false
	}
}
