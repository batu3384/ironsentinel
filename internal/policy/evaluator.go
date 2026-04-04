package policy

import (
	"sort"
	"strings"

	"github.com/batu3384/ironsentinel/internal/domain"
	"github.com/batu3384/ironsentinel/internal/vex"
)

func Evaluate(pack domain.PolicyPack, runID, baselineRunID string, current []domain.Finding, delta domain.RunDelta) domain.PolicyEvaluation {
	evaluation := domain.PolicyEvaluation{
		PolicyID:      pack.ID,
		RunID:         runID,
		BaselineRunID: baselineRunID,
		Passed:        true,
		Results:       make([]domain.PolicyRuleResult, 0, len(pack.Rules)),
	}

	for _, rule := range pack.Rules {
		matched := matchRule(rule, current, delta)
		outcome := domain.PolicyOutcomePass
		if len(matched) >= rule.Threshold {
			outcome = rule.Outcome
		}
		if outcome == domain.PolicyOutcomeFail {
			evaluation.Passed = false
		}
		evaluation.Results = append(evaluation.Results, domain.PolicyRuleResult{
			Rule:         rule,
			Outcome:      outcome,
			MatchedCount: len(matched),
			Findings:     matched,
		})
	}

	sort.Slice(evaluation.Results, func(i, j int) bool {
		return evaluation.Results[i].Rule.ID < evaluation.Results[j].Rule.ID
	})
	return evaluation
}

func matchRule(rule domain.PolicyRule, current []domain.Finding, delta domain.RunDelta) []domain.Finding {
	source := current
	switch rule.ChangeScope {
	case domain.FindingNew:
		source = delta.NewFindings
	case domain.FindingExisting:
		source = delta.ExistingFindings
	case domain.FindingResolved:
		source = delta.ResolvedFindings
	}

	matched := make([]domain.Finding, 0, len(source))
	for _, finding := range source {
		if vex.SuppressesFinding(finding) {
			continue
		}
		if rule.Category != "" && finding.Category != rule.Category {
			continue
		}
		if rule.Severity != "" && domain.SeverityRank(finding.Severity) > domain.SeverityRank(rule.Severity) {
			continue
		}
		if rule.Reachability != "" && finding.Reachability.String() != rule.Reachability.String() {
			continue
		}
		if len(rule.TagsAny) > 0 && !findingHasAnyTag(finding.Tags, rule.TagsAny) {
			continue
		}
		matched = append(matched, finding)
	}
	return matched
}

func findingHasAnyTag(tags []string, targets []string) bool {
	if len(tags) == 0 || len(targets) == 0 {
		return false
	}
	normalized := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		value := strings.ToLower(strings.TrimSpace(tag))
		if value == "" {
			continue
		}
		normalized[value] = struct{}{}
	}
	for _, target := range targets {
		value := strings.ToLower(strings.TrimSpace(target))
		if value == "" {
			continue
		}
		if _, ok := normalized[value]; ok {
			return true
		}
	}
	return false
}
