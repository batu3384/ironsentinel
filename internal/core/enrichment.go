package core

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/batu3384/ironsentinel/internal/domain"
)

func enrichFinding(project domain.Project, finding domain.Finding) domain.Finding {
	enriched := finding
	enriched.Reachability = domain.NormalizeReachability(finding.Reachability.String())
	enriched.CWEs = inferCWEs(finding)
	enriched.CVSS31 = inferCVSS31(finding)
	enriched.CVSS40 = inferCVSS40(finding, enriched.CVSS31)
	enriched.KEV = inferKEV(finding)
	enriched.EPSSScore, enriched.EPSSPercent = inferEPSS(enriched)
	enriched.AssetValue = inferAssetValue(project, finding)
	enriched.Compliance = inferComplianceMappings(enriched)
	enriched.Tags = mergeFindingTags(finding.Tags, deriveFindingTags(enriched)...)
	enriched.Priority = remediationPriority(enriched)
	enriched.AttackChain = inferAttackChainSeed(project, finding)
	return enriched
}

func enrichFindings(project domain.Project, findings []domain.Finding) []domain.Finding {
	enriched := make([]domain.Finding, 0, len(findings))
	for _, finding := range findings {
		enriched = append(enriched, enrichFinding(project, finding))
	}
	correlateAttackChains(enriched)
	return enriched
}

func correlateAttackChains(findings []domain.Finding) {
	groups := make(map[string][]int)
	for index := range findings {
		key := strings.TrimSpace(findings[index].AttackChain)
		if key == "" {
			continue
		}
		groups[key] = append(groups[key], index)
	}

	for key, indexes := range groups {
		if len(indexes) < 2 {
			findings[indexes[0]].AttackChain = ""
			continue
		}
		groupID := "chain:" + key
		related := make([]string, 0, len(indexes)-1)
		for _, idx := range indexes {
			related = related[:0]
			for _, other := range indexes {
				if other == idx {
					continue
				}
				related = append(related, findings[other].Fingerprint)
			}
			findings[idx].AttackChain = groupID
			findings[idx].Related = append([]string(nil), related...)
		}
	}
}

func trendPointsForProject(runs []domain.ScanRun, projectID string) []domain.RunTrendPoint {
	points := make([]domain.RunTrendPoint, 0, len(runs))
	for _, run := range runs {
		if run.ProjectID != projectID || run.Status == domain.ScanQueued {
			continue
		}
		points = append(points, domain.RunTrendPoint{
			RunID:          run.ID,
			StartedAt:      run.StartedAt,
			TotalFindings:  run.Summary.TotalFindings,
			Critical:       run.Summary.CountsBySeverity[domain.SeverityCritical],
			High:           run.Summary.CountsBySeverity[domain.SeverityHigh],
			Medium:         run.Summary.CountsBySeverity[domain.SeverityMedium],
			Low:            run.Summary.CountsBySeverity[domain.SeverityLow],
			ComplianceHits: run.Summary.CountsByCategory[domain.CategoryCompliance],
		})
	}
	sort.Slice(points, func(i, j int) bool {
		return points[i].StartedAt.Before(points[j].StartedAt)
	})
	if len(points) > 8 {
		points = points[len(points)-8:]
	}
	return points
}

func inferCWEs(finding domain.Finding) []string {
	ruleID := strings.ToLower(strings.TrimSpace(finding.RuleID))
	title := strings.ToLower(strings.TrimSpace(finding.Title))
	switch {
	case finding.Category == domain.CategorySecret:
		return []string{"CWE-798"}
	case strings.Contains(ruleID, "sql") || strings.Contains(title, "sql injection"):
		return []string{"CWE-89"}
	case strings.Contains(ruleID, "xss") || strings.Contains(title, "cross-site scripting"):
		return []string{"CWE-79"}
	case strings.Contains(ruleID, "command") || strings.Contains(title, "command injection"):
		return []string{"CWE-78"}
	case strings.Contains(ruleID, "path") && strings.Contains(ruleID, "travers"):
		return []string{"CWE-22"}
	case strings.Contains(ruleID, "tls") || strings.Contains(title, "tls verification"):
		return []string{"CWE-295"}
	case strings.Contains(ruleID, "chmod") || strings.Contains(title, "world-writable"):
		return []string{"CWE-732"}
	case strings.Contains(ruleID, "dependency") || finding.Module == "dependency-confusion":
		return []string{"CWE-610", "CWE-829"}
	case finding.Category == domain.CategoryMalware:
		return []string{"CWE-506"}
	case finding.Category == domain.CategoryIaC:
		return []string{"CWE-16"}
	case finding.Category == domain.CategoryCompliance:
		return []string{"CWE-1104"}
	default:
		return nil
	}
}

func inferCVSS31(finding domain.Finding) float64 {
	switch finding.Severity {
	case domain.SeverityCritical:
		return 9.8
	case domain.SeverityHigh:
		return 8.1
	case domain.SeverityMedium:
		return 6.4
	case domain.SeverityLow:
		return 3.7
	default:
		return 1.0
	}
}

func inferCVSS40(finding domain.Finding, fallback float64) float64 {
	value := fallback + 0.1
	if finding.Category == domain.CategoryDAST || finding.Category == domain.CategorySecret {
		value += 0.2
	}
	if value > 10 {
		value = 10
	}
	return value
}

func inferKEV(finding domain.Finding) bool {
	id := strings.ToUpper(strings.TrimSpace(finding.RuleID))
	switch id {
	case "CVE-2021-44228", "CVE-2023-34362", "CVE-2024-3094":
		return true
	default:
		return false
	}
}

func inferEPSS(finding domain.Finding) (float64, float64) {
	base := 0.02
	switch finding.Severity {
	case domain.SeverityCritical:
		base = 0.78
	case domain.SeverityHigh:
		base = 0.49
	case domain.SeverityMedium:
		base = 0.19
	case domain.SeverityLow:
		base = 0.06
	}
	if finding.KEV {
		base = 0.97
	}
	percentile := base * 100
	if percentile > 99.9 {
		percentile = 99.9
	}
	return base, percentile
}

func inferAssetValue(project domain.Project, finding domain.Finding) float64 {
	location := strings.ToLower(strings.TrimSpace(finding.Location))
	value := 1.0
	switch {
	case strings.Contains(location, ".github/workflows"), strings.Contains(location, "dockerfile"), strings.Contains(location, ".env"), strings.Contains(location, "terraform"), strings.Contains(location, "helm"):
		value = 1.4
	case strings.Contains(location, "auth"), strings.Contains(location, "payment"), strings.Contains(location, "admin"), strings.Contains(location, "secret"), strings.Contains(location, "prod"):
		value = 1.6
	case strings.Contains(location, "test"), strings.Contains(location, "spec"), strings.Contains(location, "fixture"):
		value = 0.7
	}
	for _, stack := range project.DetectedStacks {
		if stack == "kubernetes" || stack == "container" {
			value += 0.05
			break
		}
	}
	return value
}

func inferComplianceMappings(finding domain.Finding) []string {
	mappings := make(map[string]struct{})
	add := func(items ...string) {
		for _, item := range items {
			if strings.TrimSpace(item) != "" {
				mappings[item] = struct{}{}
			}
		}
	}

	switch finding.Category {
	case domain.CategorySecret:
		add("OWASP:A02", "SANS25:HardcodedSecrets", "PCI-DSS:3.3", "SOC2:CC6.1")
	case domain.CategorySCA:
		add("OWASP:A06", "SANS25:VulnerableComponents", "PCI-DSS:6.3.3", "SOC2:CC8.1")
	case domain.CategoryIaC:
		add("OWASP:A05", "PCI-DSS:2.2", "SOC2:CC7.1")
	case domain.CategoryDAST:
		add("OWASP:A01", "SANS25:ExternalAttackSurface", "PCI-DSS:6.4.2")
	case domain.CategoryMalware:
		add("OWASP:A08", "PCI-DSS:5.2", "SOC2:CC7.2")
	case domain.CategoryCompliance:
		add("OWASP:A06", "PCI-DSS:6.3.2", "SOC2:CC8.1")
	}
	for _, cwe := range finding.CWEs {
		switch cwe {
		case "CWE-89", "CWE-79", "CWE-78":
			add("OWASP:A03", "SANS25:Injection")
		case "CWE-798":
			add("OWASP:A02", "PCI-DSS:8.3.6")
		case "CWE-295":
			add("OWASP:A02", "PCI-DSS:4.2.1")
		case "CWE-732":
			add("OWASP:A05", "SOC2:CC6.6")
		}
	}

	items := make([]string, 0, len(mappings))
	for item := range mappings {
		items = append(items, item)
	}
	sort.Strings(items)
	return items
}

func remediationPriority(finding domain.Finding) float64 {
	severityWeight := map[domain.Severity]float64{
		domain.SeverityCritical: 1.00,
		domain.SeverityHigh:     0.82,
		domain.SeverityMedium:   0.58,
		domain.SeverityLow:      0.33,
		domain.SeverityInfo:     0.10,
	}[finding.Severity]
	score := severityWeight * (0.5 + finding.Confidence) * (0.7 + finding.AssetValue) * (1 + finding.EPSSScore)
	if finding.KEV {
		score *= 1.25
	}
	score *= scaPriorityMultiplier(finding)
	if score > 10 {
		score = 10
	}
	return score
}

func scaPriorityMultiplier(finding domain.Finding) float64 {
	if finding.Category != domain.CategorySCA {
		return 1.0
	}

	multiplier := reachabilityPriorityMultiplier(finding.Reachability)
	if hasDependencyConfusionSignal(finding) {
		multiplier *= 1.25
	}
	if hasMaliciousDependencySignal(finding) {
		multiplier *= 1.15
	}
	return multiplier
}

func reachabilityPriorityMultiplier(reachability domain.Reachability) float64 {
	switch domain.NormalizeReachability(reachability.String()) {
	case domain.ReachabilityReachable:
		return 1.35
	case domain.ReachabilityPossible:
		return 1.10
	case domain.ReachabilityRepository:
		return 1.05
	case domain.ReachabilityImage:
		return 1.02
	case domain.ReachabilityUnknown:
		return 0.90
	default:
		return 1.0
	}
}

func deriveFindingTags(finding domain.Finding) []string {
	tags := make([]string, 0, 3)
	if finding.Category == domain.CategorySCA {
		if reachabilityTag := scaReachabilityTag(finding.Reachability); reachabilityTag != "" {
			tags = append(tags, reachabilityTag)
		}
		if hasDependencyConfusionSignal(finding) {
			tags = append(tags, "supply-chain:dependency-confusion")
		}
		if hasMaliciousDependencySignal(finding) {
			tags = append(tags, "supply-chain:malicious")
		}
	}
	return tags
}

func scaReachabilityTag(reachability domain.Reachability) string {
	value := domain.NormalizeReachability(reachability.String())
	if value == "" || value == domain.ReachabilityNotApplicable {
		return ""
	}
	return "sca:" + value.String()
}

func hasDependencyConfusionSignal(finding domain.Finding) bool {
	module := strings.ToLower(strings.TrimSpace(finding.Module))
	ruleID := strings.ToLower(strings.TrimSpace(finding.RuleID))
	title := strings.ToLower(strings.TrimSpace(finding.Title))
	return module == "dependency-confusion" ||
		strings.HasPrefix(ruleID, "dependency_confusion.") ||
		strings.Contains(ruleID, "dependency-confusion") ||
		strings.Contains(title, "dependency confusion")
}

func hasMaliciousDependencySignal(finding domain.Finding) bool {
	if hasDependencyConfusionSignal(finding) {
		return true
	}
	ruleID := strings.ToLower(strings.TrimSpace(finding.RuleID))
	title := strings.ToLower(strings.TrimSpace(finding.Title))
	return strings.Contains(ruleID, "malicious") ||
		strings.Contains(ruleID, "typosquat") ||
		strings.Contains(ruleID, "repojacking") ||
		strings.Contains(title, "malicious package") ||
		strings.Contains(title, "malicious dependency") ||
		strings.Contains(title, "typosquat") ||
		strings.Contains(title, "repojacking") ||
		strings.Contains(title, "package hijack")
}

func mergeFindingTags(existing []string, derived ...string) []string {
	if len(existing) == 0 && len(derived) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(existing)+len(derived))
	merged := make([]string, 0, len(existing)+len(derived))
	appendTag := func(tag string) {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			return
		}
		key := strings.ToLower(tag)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		merged = append(merged, tag)
	}
	for _, tag := range existing {
		appendTag(tag)
	}
	for _, tag := range derived {
		appendTag(tag)
	}
	return merged
}

func inferAttackChainSeed(project domain.Project, finding domain.Finding) string {
	location := strings.TrimSpace(finding.Location)
	if location == "" {
		location = strings.TrimSpace(finding.Module)
	}
	dir := filepath.Dir(location)
	if dir == "." || dir == "/" {
		dir = location
	}
	if strings.TrimSpace(dir) == "" {
		dir = project.DisplayName
	}
	return strings.ToLower(strings.Join([]string{string(finding.Category), finding.Module, dir}, "|"))
}
