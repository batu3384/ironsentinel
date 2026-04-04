package policy

import "github.com/batu3384/ironsentinel/internal/domain"

const PremiumDefaultPolicy = "premium-default"

func Builtin(policyID string) domain.PolicyPack {
	switch policyID {
	case "", PremiumDefaultPolicy:
		return domain.PolicyPack{
			ID:    PremiumDefaultPolicy,
			Title: "Premium Default Policy",
			Rules: []domain.PolicyRule{
				{
					ID:          "new-critical-regression",
					Title:       "Block new critical regressions",
					Description: "Fails when any new critical finding appears relative to the baseline run.",
					Outcome:     domain.PolicyOutcomeFail,
					Threshold:   1,
					ChangeScope: domain.FindingNew,
					Severity:    domain.SeverityCritical,
				},
				{
					ID:          "new-high-regression",
					Title:       "Block new high regressions",
					Description: "Fails when any new high severity finding appears relative to the baseline run.",
					Outcome:     domain.PolicyOutcomeFail,
					Threshold:   1,
					ChangeScope: domain.FindingNew,
					Severity:    domain.SeverityHigh,
				},
				{
					ID:           "reachable-sca-regression",
					Title:        "Block new reachable supply-chain regressions",
					Description:  "Fails when any new high-or-higher reachable software composition finding appears relative to the baseline run.",
					Outcome:      domain.PolicyOutcomeFail,
					Threshold:    1,
					ChangeScope:  domain.FindingNew,
					Category:     domain.CategorySCA,
					Severity:     domain.SeverityHigh,
					Reachability: domain.ReachabilityReachable,
				},
				{
					ID:          "malicious-supply-chain",
					Title:       "Block malicious supply-chain signals",
					Description: "Fails when any active malicious-package or dependency-confusion signal exists in the run.",
					Outcome:     domain.PolicyOutcomeFail,
					Threshold:   1,
					Category:    domain.CategorySCA,
					TagsAny:     []string{"supply-chain:malicious"},
				},
				{
					ID:          "secret-present",
					Title:       "Block active secrets",
					Description: "Fails when any active secret finding exists in the run.",
					Outcome:     domain.PolicyOutcomeFail,
					Threshold:   1,
					Category:    domain.CategorySecret,
				},
				{
					ID:          "malware-present",
					Title:       "Block malware hits",
					Description: "Fails when any malware finding exists in the run.",
					Outcome:     domain.PolicyOutcomeFail,
					Threshold:   1,
					Category:    domain.CategoryMalware,
				},
				{
					ID:          "maintainability-warning",
					Title:       "Warn on dead code accumulation",
					Description: "Warns when maintainability findings accumulate beyond a low threshold.",
					Outcome:     domain.PolicyOutcomeWarn,
					Threshold:   5,
					Category:    domain.CategoryMaintainability,
				},
			},
		}
	case "pci-dss":
		return domain.PolicyPack{
			ID:    "pci-dss",
			Title: "PCI-DSS Policy",
			Rules: []domain.PolicyRule{
				{ID: "pci-new-high", Title: "Block new high regressions", Outcome: domain.PolicyOutcomeFail, Threshold: 1, ChangeScope: domain.FindingNew, Severity: domain.SeverityHigh},
				{ID: "pci-secret", Title: "Block secrets", Outcome: domain.PolicyOutcomeFail, Threshold: 1, Category: domain.CategorySecret},
				{ID: "pci-container", Title: "Warn on container and IaC drift", Outcome: domain.PolicyOutcomeWarn, Threshold: 1, Category: domain.CategoryContainer},
				{ID: "pci-compliance", Title: "Warn on compliance gaps", Outcome: domain.PolicyOutcomeWarn, Threshold: 1, Category: domain.CategoryCompliance},
			},
		}
	case "soc2":
		return domain.PolicyPack{
			ID:    "soc2",
			Title: "SOC 2 Policy",
			Rules: []domain.PolicyRule{
				{ID: "soc2-new-high", Title: "Block new high regressions", Outcome: domain.PolicyOutcomeFail, Threshold: 1, ChangeScope: domain.FindingNew, Severity: domain.SeverityHigh},
				{ID: "soc2-secret", Title: "Block secrets", Outcome: domain.PolicyOutcomeFail, Threshold: 1, Category: domain.CategorySecret},
				{ID: "soc2-malware", Title: "Block malware", Outcome: domain.PolicyOutcomeFail, Threshold: 1, Category: domain.CategoryMalware},
				{ID: "soc2-compliance", Title: "Warn on compliance gaps", Outcome: domain.PolicyOutcomeWarn, Threshold: 1, Category: domain.CategoryCompliance},
			},
		}
	case "owasp-top10":
		return domain.PolicyPack{
			ID:    "owasp-top10",
			Title: "OWASP Top 10 Policy",
			Rules: []domain.PolicyRule{
				{ID: "owasp-new-medium", Title: "Block new medium or higher regressions", Outcome: domain.PolicyOutcomeFail, Threshold: 1, ChangeScope: domain.FindingNew, Severity: domain.SeverityMedium},
				{ID: "owasp-sast", Title: "Warn on SAST findings", Outcome: domain.PolicyOutcomeWarn, Threshold: 1, Category: domain.CategorySAST},
				{ID: "owasp-dast", Title: "Warn on DAST findings", Outcome: domain.PolicyOutcomeWarn, Threshold: 1, Category: domain.CategoryDAST},
				{ID: "owasp-secret", Title: "Block secrets", Outcome: domain.PolicyOutcomeFail, Threshold: 1, Category: domain.CategorySecret},
			},
		}
	case "sans-top25":
		return domain.PolicyPack{
			ID:    "sans-top25",
			Title: "SANS Top 25 Policy",
			Rules: []domain.PolicyRule{
				{ID: "sans-new-medium", Title: "Block new medium regressions", Outcome: domain.PolicyOutcomeFail, Threshold: 1, ChangeScope: domain.FindingNew, Severity: domain.SeverityMedium},
				{ID: "sans-sast", Title: "Warn on code weakness findings", Outcome: domain.PolicyOutcomeWarn, Threshold: 1, Category: domain.CategorySAST},
				{ID: "sans-compliance", Title: "Warn on taxonomy mapping gaps", Outcome: domain.PolicyOutcomeWarn, Threshold: 1, Category: domain.CategoryCompliance},
			},
		}
	default:
		return domain.PolicyPack{
			ID:    policyID,
			Title: policyID,
		}
	}
}
