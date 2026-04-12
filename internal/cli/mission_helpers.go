package cli

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/batu3384/ironsentinel/internal/domain"
)

var asciiSparkLevels = []rune(" .:-=+*#%@")

func (a *App) prioritizedFindings(findings []domain.Finding, limit int) []domain.Finding {
	if len(findings) == 0 {
		return nil
	}
	ranked := append([]domain.Finding(nil), findings...)
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].Priority == ranked[j].Priority {
			if ranked[i].Severity == ranked[j].Severity {
				return strings.ToLower(ranked[i].Title) < strings.ToLower(ranked[j].Title)
			}
			return domain.SeverityRank(ranked[i].Severity) < domain.SeverityRank(ranked[j].Severity)
		}
		return ranked[i].Priority > ranked[j].Priority
	})
	if limit > 0 && len(ranked) > limit {
		ranked = ranked[:limit]
	}
	return ranked
}

func severityCounts(findings []domain.Finding) map[domain.Severity]int {
	counts := make(map[domain.Severity]int, len(domain.AllSeverities()))
	for _, finding := range findings {
		counts[finding.Severity]++
	}
	return counts
}

func countKEVFindings(findings []domain.Finding) int {
	total := 0
	for _, finding := range findings {
		if finding.KEV {
			total++
		}
	}
	return total
}

func countComplianceSignals(findings []domain.Finding) int {
	total := 0
	for _, finding := range findings {
		if len(finding.Compliance) > 0 {
			total++
		}
	}
	return total
}

func countAttackChains(findings []domain.Finding) int {
	groups := map[string]struct{}{}
	for _, finding := range findings {
		if strings.TrimSpace(finding.AttackChain) != "" {
			groups[finding.AttackChain] = struct{}{}
		}
	}
	return len(groups)
}

func averagePriority(findings []domain.Finding) float64 {
	if len(findings) == 0 {
		return 0
	}
	total := 0.0
	for _, finding := range findings {
		total += finding.Priority
	}
	return total / float64(len(findings))
}

func recentCompletedRuns(runs []domain.ScanRun, limit int) []domain.ScanRun {
	items := make([]domain.ScanRun, 0, len(runs))
	for _, run := range runs {
		if run.Status == domain.ScanQueued {
			continue
		}
		items = append(items, run)
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].StartedAt.Before(items[j].StartedAt)
	})
	if limit > 0 && len(items) > limit {
		items = items[len(items)-limit:]
	}
	return items
}

func runsFindingTotals(runs []domain.ScanRun) []int {
	values := make([]int, 0, len(runs))
	for _, run := range runs {
		values = append(values, run.Summary.TotalFindings)
	}
	return values
}

func asciiSparkline(values []int) string {
	if len(values) == 0 {
		return "-"
	}
	minValue := values[0]
	maxValue := values[0]
	for _, value := range values[1:] {
		if value < minValue {
			minValue = value
		}
		if value > maxValue {
			maxValue = value
		}
	}
	if maxValue == minValue {
		return strings.Repeat(string(asciiSparkLevels[len(asciiSparkLevels)-2]), len(values))
	}
	builder := strings.Builder{}
	for _, value := range values {
		index := 0
		if maxValue > minValue {
			ratio := float64(value-minValue) / float64(maxValue-minValue)
			index = int(ratio * float64(len(asciiSparkLevels)-1))
		}
		if index < 0 {
			index = 0
		}
		if index >= len(asciiSparkLevels) {
			index = len(asciiSparkLevels) - 1
		}
		builder.WriteRune(asciiSparkLevels[index])
	}
	return builder.String()
}

func (a *App) runTrendLabel(runs []domain.ScanRun, limit int) string {
	window := recentCompletedRuns(runs, limit)
	if len(window) == 0 {
		return a.catalog.T("overview_trend_empty")
	}
	latest := window[len(window)-1]
	return fmt.Sprintf("%s | %s %d", asciiSparkline(runsFindingTotals(window)), a.catalog.T("summary_total"), latest.Summary.TotalFindings)
}

func (a *App) renderQueueHeadlineFromSnapshot(snapshot portfolioSnapshot, runs []domain.ScanRun) string {
	return a.renderQueueHeadlineWithProjectLabel(runs, snapshot.projectLabel)
}

func (a *App) renderQueueHeadlineWithProjectLabel(runs []domain.ScanRun, projectLabel func(string) string) string {
	active := a.activeQueueRuns(runs, 2)
	if len(active) == 0 {
		return a.catalog.T("watch_no_active_runs")
	}
	lines := make([]string, 0, len(active))
	for _, run := range active {
		lines = append(lines, fmt.Sprintf("%s | %s | %s", run.ID, a.displayUpper(a.scanStatusLabel(run.Status)), projectLabel(run.ProjectID)))
	}
	return strings.Join(lines, "\n")
}

func distinctProjectStacks(projects []domain.Project) int {
	seen := map[string]struct{}{}
	for _, project := range projects {
		for _, stack := range project.DetectedStacks {
			stack = strings.TrimSpace(stack)
			if stack == "" {
				continue
			}
			seen[strings.ToLower(stack)] = struct{}{}
		}
	}
	return len(seen)
}

func topProjectStacks(projects []domain.Project, limit int) string {
	if len(projects) == 0 {
		return "-"
	}
	counts := map[string]int{}
	for _, project := range projects {
		for _, stack := range project.DetectedStacks {
			stack = strings.TrimSpace(stack)
			if stack == "" {
				continue
			}
			counts[stack]++
		}
	}
	if len(counts) == 0 {
		return "-"
	}
	type pair struct {
		name  string
		count int
	}
	items := make([]pair, 0, len(counts))
	for name, count := range counts {
		items = append(items, pair{name: name, count: count})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].count == items[j].count {
			return items[i].name < items[j].name
		}
		return items[i].count > items[j].count
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, fmt.Sprintf("%s %d", item.name, item.count))
	}
	return strings.Join(parts, " | ")
}

func latestProject(projects []domain.Project) *domain.Project {
	if len(projects) == 0 {
		return nil
	}
	items := append([]domain.Project(nil), projects...)
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	return &items[0]
}

func latestRun(runs []domain.ScanRun) *domain.ScanRun {
	if len(runs) == 0 {
		return nil
	}
	items := append([]domain.ScanRun(nil), runs...)
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].StartedAt.After(items[j].StartedAt)
	})
	return &items[0]
}

func artifactKindCounts(artifacts []domain.ArtifactRef) map[string]int {
	counts := map[string]int{}
	for _, artifact := range artifacts {
		kind := strings.TrimSpace(artifact.Kind)
		if kind == "" {
			kind = "unknown"
		}
		counts[kind]++
	}
	return counts
}

func artifactProtectionCounts(artifacts []domain.ArtifactRef) (redacted, encrypted int) {
	for _, artifact := range artifacts {
		if artifact.Redacted {
			redacted++
		}
		if artifact.Encrypted {
			encrypted++
		}
	}
	return redacted, encrypted
}

func topArtifactKinds(artifacts []domain.ArtifactRef, limit int) string {
	if len(artifacts) == 0 {
		return "-"
	}
	type pair struct {
		kind  string
		count int
	}
	pairs := make([]pair, 0, len(artifacts))
	for kind, count := range artifactKindCounts(artifacts) {
		pairs = append(pairs, pair{kind: kind, count: count})
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		if pairs[i].count == pairs[j].count {
			return pairs[i].kind < pairs[j].kind
		}
		return pairs[i].count > pairs[j].count
	})
	if limit > 0 && len(pairs) > limit {
		pairs = pairs[:limit]
	}
	parts := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		parts = append(parts, fmt.Sprintf("%s %d", pair.kind, pair.count))
	}
	return strings.Join(parts, " | ")
}

func triageOwnerCount(items []domain.FindingTriage) int {
	seen := map[string]struct{}{}
	for _, item := range items {
		owner := strings.TrimSpace(item.Owner)
		if owner == "" {
			continue
		}
		seen[strings.ToLower(owner)] = struct{}{}
	}
	return len(seen)
}

func countTriageStatus(items []domain.FindingTriage, status domain.FindingStatus) int {
	total := 0
	for _, item := range items {
		if item.Status == status {
			total++
		}
	}
	return total
}

func latestTriageUpdate(items []domain.FindingTriage) *time.Time {
	if len(items) == 0 {
		return nil
	}
	latest := items[0].UpdatedAt
	for _, item := range items[1:] {
		if item.UpdatedAt.After(latest) {
			latest = item.UpdatedAt
		}
	}
	return &latest
}

func suppressionOwnerCount(items []domain.Suppression) int {
	seen := map[string]struct{}{}
	for _, item := range items {
		owner := strings.TrimSpace(item.Owner)
		if owner == "" {
			continue
		}
		seen[strings.ToLower(owner)] = struct{}{}
	}
	return len(seen)
}

func suppressionExpiringCount(items []domain.Suppression, within time.Duration) int {
	deadline := time.Now().Add(within)
	total := 0
	for _, item := range items {
		if item.ExpiresAt.Before(deadline) {
			total++
		}
	}
	return total
}

func (a *App) findingPriorityLabel(finding domain.Finding) string {
	parts := []string{fmt.Sprintf("P%.1f", finding.Priority)}
	if finding.KEV {
		parts = append(parts, "KEV")
	}
	if finding.EPSSPercent > 0 {
		parts = append(parts, fmt.Sprintf("EPSS %.1f%%", finding.EPSSPercent))
	}
	if signal := a.findingSignalSummary(finding); signal != "-" {
		parts = append(parts, signal)
	}
	return strings.Join(parts, " | ")
}

func (a *App) findingExposureSummary(finding domain.Finding) string {
	parts := []string{}
	if finding.CVSS31 > 0 {
		parts = append(parts, fmt.Sprintf("CVSS 3.1 %.1f", finding.CVSS31))
	}
	if finding.CVSS40 > 0 {
		parts = append(parts, fmt.Sprintf("CVSS 4.0 %.1f", finding.CVSS40))
	}
	if finding.EPSSPercent > 0 {
		parts = append(parts, fmt.Sprintf("EPSS %.1f%%", finding.EPSSPercent))
	}
	if finding.KEV {
		parts = append(parts, "KEV")
	}
	if signal := a.findingSignalSummary(finding); signal != "-" {
		parts = append(parts, fmt.Sprintf("%s %s", a.catalog.T("reason"), signal))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " | ")
}

func (a *App) findingSignalSummary(finding domain.Finding) string {
	signals := a.findingSignals(finding)
	if len(signals) == 0 {
		return "-"
	}
	return strings.Join(signals, " | ")
}

func (a *App) findingSignals(finding domain.Finding) []string {
	if finding.Category != domain.CategorySCA {
		return nil
	}
	signals := make([]string, 0, 5)
	if reachability := a.reachabilitySignal(finding.Reachability); reachability != "" {
		signals = append(signals, reachability)
	}
	if reason := a.findingSupplyChainReasonLabel(finding.Tags); reason != "" {
		signals = append(signals, reason)
	}
	if vexStatus := a.findingVEXStatusLabel(finding.VEXStatus); vexStatus != "" {
		signals = append(signals, vexStatus)
	}
	if vexJustification := a.findingVEXJustificationLabel(finding.VEXJustification); vexJustification != "" {
		signals = append(signals, vexJustification)
	}
	return signals
}

func (a *App) findingVEXStatusLabel(status domain.VEXStatus) string {
	switch status {
	case domain.VEXStatusAffected:
		return a.catalog.T("finding_vex_affected")
	case domain.VEXStatusNotAffected:
		return a.catalog.T("finding_vex_not_affected")
	case domain.VEXStatusFixed:
		return a.catalog.T("finding_vex_fixed")
	case domain.VEXStatusUnderInvestigation:
		return a.catalog.T("finding_vex_under_investigation")
	default:
		return ""
	}
}

func (a *App) findingVEXJustificationLabel(justification string) string {
	value := strings.TrimSpace(justification)
	if value == "" {
		return ""
	}
	switch strings.ToLower(value) {
	case "vulnerable_code_not_present":
		return a.catalog.T("finding_vex_justification_vulnerable_code_not_present")
	default:
		value = strings.ReplaceAll(value, "_", " ")
		return value
	}
}

func (a *App) reachabilityDisplay(value domain.Reachability) string {
	switch domain.NormalizeReachability(value.String()) {
	case domain.ReachabilityReachable:
		return a.catalog.T("finding_reachability_reachable")
	case domain.ReachabilityPossible:
		return a.catalog.T("finding_reachability_possible")
	case domain.ReachabilityUnknown:
		return a.catalog.T("finding_reachability_unknown")
	case domain.ReachabilityRepository:
		return a.catalog.T("finding_reachability_repository")
	case domain.ReachabilityImage:
		return a.catalog.T("finding_reachability_image")
	case domain.ReachabilityInfrastructure:
		return a.catalog.T("finding_reachability_infrastructure")
	case domain.ReachabilityExecutionSurface:
		return a.catalog.T("finding_reachability_execution_surface")
	case domain.ReachabilityNotApplicable:
		return a.catalog.T("finding_reachability_not_applicable")
	default:
		return value.String()
	}
}

func (a *App) reachabilitySignal(value domain.Reachability) string {
	switch domain.NormalizeReachability(value.String()) {
	case domain.ReachabilityReachable:
		return a.catalog.T("finding_signal_reachable_path")
	case domain.ReachabilityPossible:
		return a.catalog.T("finding_signal_possible_path")
	case domain.ReachabilityRepository:
		return a.catalog.T("finding_signal_repository_exposure")
	case domain.ReachabilityImage:
		return a.catalog.T("finding_signal_image_exposure")
	case domain.ReachabilityInfrastructure:
		return a.catalog.T("finding_signal_infrastructure_exposure")
	case domain.ReachabilityExecutionSurface:
		return a.catalog.T("finding_signal_execution_surface")
	default:
		return ""
	}
}

func (a *App) findingSupplyChainReasonLabel(tags []string) string {
	for _, tag := range tags {
		switch strings.ToLower(strings.TrimSpace(tag)) {
		case "supply-chain:dependency-confusion":
			return a.catalog.T("finding_signal_dependency_confusion")
		case "supply-chain:malicious":
			return a.catalog.T("finding_signal_malicious_package")
		}
	}
	return ""
}

func (a *App) findingAttackChainSummary(finding domain.Finding) string {
	if strings.TrimSpace(finding.AttackChain) == "" {
		return a.catalog.T("finding_attack_chain_none")
	}
	if len(finding.Related) == 0 {
		return finding.AttackChain
	}
	return fmt.Sprintf("%s | %s %d", finding.AttackChain, a.catalog.T("finding_related_short"), len(finding.Related))
}

func (a *App) findingOwnershipSummary(finding domain.Finding) string {
	parts := []string{}
	if strings.TrimSpace(finding.Owner) != "" {
		parts = append(parts, fmt.Sprintf("%s: %s", a.catalog.T("owner"), finding.Owner))
	}
	if len(finding.Tags) > 0 {
		parts = append(parts, fmt.Sprintf("%s: %s", a.catalog.T("tags"), strings.Join(finding.Tags, ", ")))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " | ")
}

func (a *App) hottestFindingLine(finding domain.Finding, width int) string {
	title := trimForSelect(a.displayFindingTitle(finding), width)
	return fmt.Sprintf("%s | %s | %s", a.severityLabel(finding.Severity), a.findingPriorityLabel(finding), title)
}

func (a *App) hotFindingSummary(findings []domain.Finding, limit, width int) string {
	if len(findings) == 0 {
		return a.catalog.T("overview_no_findings")
	}
	lines := make([]string, 0, limit)
	seen := map[string]struct{}{}
	for _, finding := range a.prioritizedFindings(findings, 0) {
		key := strings.ToLower(strings.TrimSpace(finding.Title))
		if key == "" {
			key = strings.ToLower(strings.TrimSpace(finding.Fingerprint))
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		lines = append(lines, a.hottestFindingLine(finding, width))
		if limit > 0 && len(lines) >= limit {
			break
		}
	}
	if len(lines) == 0 {
		return a.catalog.T("overview_no_findings")
	}
	return strings.Join(lines, " || ")
}

func (a *App) findingTriageSummary(findings []domain.Finding) string {
	return fmt.Sprintf(
		"%s %d | %s %d | %s %d",
		a.catalog.T("triage_open"),
		countFindingStatus(findings, domain.FindingOpen),
		a.catalog.T("triage_investigating"),
		countFindingStatus(findings, domain.FindingInvestigating),
		a.catalog.T("triage_fixed"),
		countFindingStatus(findings, domain.FindingFixed),
	)
}

func (a *App) portfolioPosture(snapshot portfolioSnapshot) string {
	switch a.portfolioPostureToken(snapshot) {
	case "degraded":
		return a.catalog.T("scan_posture_degraded")
	case "breach":
		return a.catalog.T("scan_posture_breach")
	case "warning":
		return a.catalog.T("scan_posture_warning")
	default:
		return a.catalog.T("scan_posture_clean")
	}
}

func (a *App) portfolioPostureToken(snapshot portfolioSnapshot) string {
	critical := 0
	high := 0
	failedRuns := 0
	for _, finding := range snapshot.Findings {
		switch finding.Severity {
		case domain.SeverityCritical:
			critical++
		case domain.SeverityHigh:
			high++
		}
	}
	for _, run := range snapshot.Runs {
		if run.Status == domain.ScanFailed {
			failedRuns++
		}
	}
	switch {
	case failedRuns > 0:
		return "degraded"
	case critical > 0:
		return "breach"
	case high > 0:
		return "warning"
	default:
		return "clean"
	}
}

func runtimeToolHealthCounts(runtime domain.RuntimeStatus) (available, drift, missing, failed int) {
	for _, tool := range runtime.ScannerBundle {
		switch {
		case !tool.Available:
			missing++
		case tool.Verification.Status() == "failed":
			failed++
		case tool.Healthy:
			available++
		default:
			drift++
		}
	}
	return available, drift, missing, failed
}

func runtimeMirrorHealth(runtime domain.RuntimeStatus) (available, missing int) {
	for _, mirror := range runtime.Mirrors {
		if mirror.Available {
			available++
			continue
		}
		missing++
	}
	return available, missing
}

func runtimeSupportCounts(matrix domain.RuntimeSupportMatrix) (supported, partial, unsupported int) {
	for _, tier := range matrix.Tiers {
		switch tier.Level {
		case domain.RuntimeSupportSupported:
			supported++
		case domain.RuntimeSupportPartial:
			partial++
		case domain.RuntimeSupportUnsupported:
			unsupported++
		}
	}
	return supported, partial, unsupported
}

func summarizeRuntimeTools(tools []domain.RuntimeTool, limit int) string {
	if len(tools) == 0 {
		return "-"
	}
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		if strings.TrimSpace(tool.Name) == "" {
			continue
		}
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "-"
	}
	if limit > 0 && len(names) > limit {
		return strings.Join(names[:limit], ", ") + fmt.Sprintf(" +%d", len(names)-limit)
	}
	return strings.Join(names, ", ")
}

func summarizeReleaseArtifacts(artifacts []domain.RuntimeReleaseArtifact, limit int) string {
	if len(artifacts) == 0 {
		return "-"
	}
	items := append([]domain.RuntimeReleaseArtifact(nil), artifacts...)
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Size == items[j].Size {
			return items[i].Name < items[j].Name
		}
		return items[i].Size > items[j].Size
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	parts := make([]string, 0, len(items))
	for _, artifact := range items {
		parts = append(parts, fmt.Sprintf("%s %s/%s", artifact.Name, coalesceString(artifact.OS, "-"), coalesceString(artifact.Arch, "-")))
	}
	return strings.Join(parts, " | ")
}

func (a *App) summarizeDoctorIssues(doctor domain.RuntimeDoctor, limit int) string {
	parts := make([]string, 0, 4)
	if len(doctor.Missing) > 0 {
		parts = append(parts, fmt.Sprintf("%s: %s", a.catalog.T("runtime_missing"), summarizeRuntimeTools(doctor.Missing, limit)))
	}
	if len(doctor.Outdated) > 0 {
		parts = append(parts, fmt.Sprintf("%s: %s", a.catalog.T("runtime_doctor_outdated"), summarizeRuntimeTools(doctor.Outdated, limit)))
	}
	if len(doctor.FailedVerification) > 0 {
		parts = append(parts, fmt.Sprintf("%s: %s", a.catalog.T("runtime_doctor_verification_failed"), summarizeRuntimeTools(doctor.FailedVerification, limit)))
	}
	if len(doctor.Unverified) > 0 {
		parts = append(parts, fmt.Sprintf("%s: %s", a.catalog.T("runtime_doctor_integrity_gap"), summarizeRuntimeTools(doctor.Unverified, limit)))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " | ")
}

func runtimeDoctorCheckCounts(doctor domain.RuntimeDoctor) (pass, warn, fail, skip int) {
	for _, check := range doctor.Checks {
		switch check.Status {
		case domain.RuntimeCheckPass:
			pass++
		case domain.RuntimeCheckWarn:
			warn++
		case domain.RuntimeCheckFail:
			fail++
		default:
			skip++
		}
	}
	return pass, warn, fail, skip
}
