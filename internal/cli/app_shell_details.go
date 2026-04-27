package cli

import (
	"fmt"
	"strings"

	"github.com/batu3384/ironsentinel/internal/domain"
)

func (m appShellModel) runRows() selectableRows {
	rows := make(selectableRows, 0, len(m.snapshot.Portfolio.Runs))
	for _, run := range m.snapshot.Portfolio.Runs {
		rows = append(rows, appSelectableRow{
			Label: fmt.Sprintf("%s • %s", strings.ToUpper(string(run.Status)), m.app.projectLabel(run.ProjectID)),
			Hint:  fmt.Sprintf("%s • %d %s", strings.ToUpper(m.app.modeLabel(run.Profile.Mode)), run.Summary.TotalFindings, strings.ToLower(m.app.catalog.T("scan_findings"))),
			Value: run.ID,
		})
	}
	return rows
}

func (m appShellModel) findingRows(findings []domain.Finding) selectableRows {
	rows := make(selectableRows, 0, len(findings))
	for _, finding := range findings {
		hintDetail := trimForSelect(coalesceString(finding.Location, "-"), 44)
		if signal := m.app.findingSignalSummary(finding); signal != "-" {
			hintDetail = trimForSelect(signal, 44)
		}
		rows = append(rows, appSelectableRow{
			Label: fmt.Sprintf("%s • %s", strings.ToUpper(m.app.severityLabel(finding.Severity)), trimForSelect(m.app.displayFindingTitle(finding), 34)),
			Hint:  fmt.Sprintf("%s • %s", m.app.findingStatusLabel(m.normalizedFindingStatus(finding.Status)), hintDetail),
			Value: finding.Fingerprint,
		})
	}
	return rows
}

func (m appShellModel) runtimeRows() selectableRows {
	rows := make(selectableRows, 0, len(m.snapshot.Runtime.ScannerBundle))
	for _, tool := range m.snapshot.Runtime.ScannerBundle {
		status := m.app.catalog.T("runtime_missing")
		if tool.Available {
			status = m.app.catalog.T("runtime_available")
		}
		rows = append(rows, appSelectableRow{
			Label: fmt.Sprintf("%s • %s", tool.Name, strings.ToUpper(status)),
			Hint:  fmt.Sprintf("%s • %s", strings.ToUpper(tool.Channel), coalesceString(tool.ActualVersion, tool.ExpectedVersion)),
			Value: tool.Name,
		})
	}
	return rows
}

func (m appShellModel) currentFindingsSeverityFilter() string {
	if m.findingsSeverityIdx < 0 || m.findingsSeverityIdx >= len(runFindingSeverityFilters) {
		return "all"
	}
	return runFindingSeverityFilters[m.findingsSeverityIdx]
}

func (m appShellModel) currentFindingsSeverityFilterLabel() string {
	filter := m.currentFindingsSeverityFilter()
	if filter == "all" {
		return m.app.catalog.T("artifact_filter_all")
	}
	return m.app.severityLabel(domain.Severity(filter))
}

func (m appShellModel) currentFindingsStatusFilter() string {
	if m.findingsStatusIdx < 0 || m.findingsStatusIdx >= len(runFindingStatusFilters) {
		return "all"
	}
	return runFindingStatusFilters[m.findingsStatusIdx]
}

func (m appShellModel) currentFindingsStatusFilterLabel() string {
	filter := m.currentFindingsStatusFilter()
	if filter == "all" {
		return m.app.catalog.T("artifact_filter_all")
	}
	return m.app.findingStatusLabel(domain.FindingStatus(filter))
}

func (m appShellModel) currentFindingsCategoryFilter() string {
	if m.findingsCategoryIdx < 0 || m.findingsCategoryIdx >= len(runFindingCategoryFilters) {
		return "all"
	}
	return runFindingCategoryFilters[m.findingsCategoryIdx]
}

func (m appShellModel) renderRunQueueSummary() string {
	counts := m.app.countRunStatuses(m.snapshot.Portfolio.Runs)
	return fmt.Sprintf("%s: %d • %s: %d • %s: %d",
		m.app.catalog.T("status_queued"), counts.Queued,
		m.app.catalog.T("status_running"), counts.Running,
		m.app.catalog.T("status_canceled"), counts.Canceled,
	)
}

func (m appShellModel) renderFindingPressureSummary(findings []domain.Finding) string {
	counts := severityCounts(findings)
	return fmt.Sprintf("%s: %d • %s: %d • %s: %d • %s: %d",
		m.app.catalog.T("summary_critical"), counts[domain.SeverityCritical],
		m.app.catalog.T("summary_high"), counts[domain.SeverityHigh],
		m.app.catalog.T("summary_medium"), counts[domain.SeverityMedium],
		m.app.catalog.T("summary_low"), counts[domain.SeverityLow],
	)
}

func (m appShellModel) filterFindings(findings []domain.Finding) []domain.Finding {
	severityFilter := m.currentFindingsSeverityFilter()
	statusFilter := m.currentFindingsStatusFilter()
	categoryFilter := m.currentFindingsCategoryFilter()
	if severityFilter == "all" && statusFilter == "all" && categoryFilter == "all" {
		return findings
	}
	filtered := make([]domain.Finding, 0, len(findings))
	for _, finding := range findings {
		if severityFilter != "all" && finding.Severity != domain.Severity(severityFilter) {
			continue
		}
		if statusFilter != "all" && m.normalizedFindingStatus(finding.Status) != domain.FindingStatus(statusFilter) {
			continue
		}
		if categoryFilter != "all" && string(finding.Category) != categoryFilter {
			continue
		}
		filtered = append(filtered, finding)
	}
	return filtered
}

func (m appShellModel) renderRunDetailContent(width int) string {
	run, ok := m.selectedRun()
	if !ok {
		return m.app.catalog.T("no_runs")
	}
	cacheKey := run.ID
	findings, _ := m.snapshotFindingsForRun(run.ID)
	entry, ok := m.runDetailCache[cacheKey]
	projectName := m.app.projectLabel(run.ProjectID)
	lines := []string{
		m.renderSection(m.app.catalog.T("overview_operator_focus"),
			m.renderFactLines(width,
				factPair{Label: m.app.catalog.T("app_label_project"), Value: projectName},
				factPair{Label: m.app.catalog.T("app_label_health"), Value: m.app.scanPostureSummary(run)},
				factPair{Label: m.app.catalog.T("app_label_findings"), Value: fmt.Sprintf("%d", run.Summary.TotalFindings)},
				factPair{Label: m.app.catalog.T("app_label_baseline"), Value: coalesceString(entry.baselineLabel, m.app.catalog.T("app_loading_short"))},
				factPair{Label: m.app.catalog.T("app_label_blocked"), Value: ternary(run.Summary.Blocked, m.app.catalog.T("boolean_yes"), m.app.catalog.T("boolean_no"))},
				factPair{Label: m.app.catalog.T("app_label_scope"), Value: trimForSelect(run.ID, maxInt(24, width-18))},
			)...,
		),
		m.renderSection(m.app.catalog.T("campaigns_title"),
			m.campaignCreateCommandHint(run.ProjectID, run.ID, ""),
			"ironsentinel campaigns publish-github <campaign-id> --repo owner/repo",
		),
	}
	if total := len(findings); total > 0 {
		lines = append(lines, m.renderSection(m.app.catalog.T("overview_hot_findings"), strings.Split(m.renderFindingDigest(findings, min(3, total)), "\n")...))
	}
	if !ok {
		lines = append(lines, m.renderSection(m.app.catalog.T("app_loading_title"), m.app.catalog.T("app_loading_short")))
		return strings.Join(lines, "\n\n")
	}
	if entry.err != "" {
		lines = append(lines, m.renderSection(m.app.catalog.T("status"), entry.err))
		return strings.Join(lines, "\n\n")
	}
	if len(entry.traceLines) > 0 {
		lines = append(lines, m.renderSection(m.app.catalog.T("execution_timeline_title"), entry.traceLines...))
	} else {
		lines = append(lines, m.renderSection(m.app.catalog.T("module_execution_title"), m.renderLiveRunDigest(run)))
	}
	return strings.Join(lines, "\n\n")
}

func (m appShellModel) renderFindingDetailContent(width int) string {
	finding, ok := m.selectedFinding()
	if !ok {
		return m.app.catalog.T("overview_no_findings")
	}
	reachability := coalesceString(m.app.reachabilityDisplay(finding.Reachability), "-")
	reason := m.app.findingSignalSummary(finding)
	lines := []string{
		m.renderSection(m.app.displayFindingTitle(finding),
			m.renderFactLines(width,
				factPair{Label: m.app.catalog.T("app_label_severity"), Value: strings.ToUpper(m.app.severityLabel(finding.Severity))},
				factPair{Label: m.app.catalog.T("app_label_health"), Value: m.app.findingStatusLabel(m.normalizedFindingStatus(finding.Status))},
				factPair{Label: m.app.catalog.T("app_label_location"), Value: coalesceString(finding.Location, "-")},
				factPair{Label: m.app.catalog.T("app_label_module"), Value: finding.Module},
				factPair{Label: m.app.catalog.T("app_label_scope"), Value: finding.Fingerprint},
			)...,
		),
		m.renderSection(m.app.catalog.T("finding_exposure_title"),
			append([]string{m.app.findingExposureSummary(finding)}, append(m.renderFactLines(width,
				factPair{Label: m.app.catalog.T("reachability"), Value: reachability},
				factPair{Label: m.app.catalog.T("reason"), Value: reason},
				factPair{Label: m.app.catalog.T("confidence"), Value: fmt.Sprintf("%.2f", finding.Confidence)},
			), coalesceString(strings.Join(finding.Compliance, ", "), "-"))...)...,
		),
		m.renderSection(m.app.catalog.T("remediation"), coalesceString(finding.Remediation, "-")),
		m.renderSection(m.app.catalog.T("campaigns_title"),
			m.campaignCreateCommandHint(finding.ProjectID, coalesceString(finding.ScanID, m.findingsScopeRun), finding.Fingerprint),
			"ironsentinel campaigns publish-github <campaign-id> --repo owner/repo",
		),
		m.renderSection(m.app.catalog.T("finding_operator_context_title"), m.app.findingOwnershipSummary(finding)),
	}
	if vexStatus := m.app.findingVEXStatusLabel(finding.VEXStatus); vexStatus != "" {
		vexLines := m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("status"), Value: vexStatus},
			factPair{Label: m.app.catalog.T("reason"), Value: coalesceString(m.app.findingVEXJustificationLabel(finding.VEXJustification), "-")},
			factPair{Label: m.app.catalog.T("artifact_uri"), Value: coalesceString(finding.VEXStatementSource, "-")},
		)
		lines = append(lines, m.renderSection("VEX", vexLines...))
	}
	if strings.TrimSpace(m.findingsScopeRun) != "" {
		lines = append(lines, m.renderSection(m.app.catalog.T("app_findings_scope_title"), m.findingsScopeLabel()))
	}
	return strings.Join(lines, "\n\n")
}

func (m appShellModel) campaignCreateCommandHint(projectID, runID, fingerprint string) string {
	parts := []string{"ironsentinel", "campaigns", "create"}
	if strings.TrimSpace(projectID) != "" {
		parts = append(parts, "--project", strings.TrimSpace(projectID))
	}
	if strings.TrimSpace(runID) != "" {
		parts = append(parts, "--run", strings.TrimSpace(runID))
	}
	parts = append(parts, "--title", "\"Campaign title\"")
	if strings.TrimSpace(fingerprint) != "" {
		parts = append(parts, "--finding", strings.TrimSpace(fingerprint))
	}
	return strings.Join(parts, " ")
}

func (m appShellModel) renderRuntimeDetailContent(width int) string {
	tool, ok := m.selectedRuntimeTool()
	if !ok {
		return strings.Join(m.routeEmptyStateLines(appRouteRuntime), "\n")
	}
	available, drift, missing, failed := runtimeToolHealthCounts(m.snapshot.Runtime)
	lines := []string{
		m.renderSection(tool.Name,
			m.renderFactLines(width,
				factPair{Label: m.app.catalog.T("app_label_health"), Value: ternary(tool.Available, m.app.catalog.T("runtime_available"), m.app.catalog.T("runtime_missing"))},
				factPair{Label: m.app.catalog.T("app_label_channel"), Value: strings.ToUpper(tool.Channel)},
				factPair{Label: m.app.catalog.T("app_label_expected"), Value: coalesceString(tool.ExpectedVersion, "-")},
				factPair{Label: m.app.catalog.T("app_label_actual"), Value: coalesceString(tool.ActualVersion, "-")},
				factPair{Label: m.app.catalog.T("app_label_binary"), Value: coalesceString(tool.Path, "-")},
				factPair{Label: m.app.catalog.T("app_label_verify"), Value: strings.ToUpper(tool.Verification.Status())},
			)...,
		),
		m.renderSection(m.app.catalog.T("runtime_trust_signal_title"),
			append(m.renderFactLines(width,
				factPair{Label: m.app.catalog.T("app_label_health"), Value: m.runtimeFocusMessage()},
				factPair{Label: m.app.catalog.T("app_label_sync"), Value: fmt.Sprintf("%d/%d/%d/%d", available, drift, missing, failed)},
				factPair{Label: m.app.catalog.T("app_label_daemon"), Value: m.app.daemonStateLabel(m.snapshot.Runtime.Daemon)},
				factPair{Label: m.app.catalog.T("app_label_isolation"), Value: strings.ToUpper(string(m.snapshot.Runtime.Isolation.EffectiveMode))},
			), fmt.Sprintf("%d %s • %d %s",
				m.snapshot.Runtime.SupplyChain.VerifiedAssets, strings.ToLower(m.app.catalog.T("runtime_verified_assets")),
				m.snapshot.Runtime.SupplyChain.FailedAssets, strings.ToLower(m.app.catalog.T("runtime_failed_assets")),
			))...,
		),
		m.renderSection(m.app.catalog.T("runtime_supply_chain_title"), m.runtimeSupplyChainDigest()),
	}
	return strings.Join(lines, "\n\n")
}

func (m appShellModel) normalizedFindingStatus(status domain.FindingStatus) domain.FindingStatus {
	if strings.TrimSpace(string(status)) == "" {
		return domain.FindingOpen
	}
	return status
}

func (m appShellModel) runtimeFocusMessage() string {
	available, drift, missing, failed := runtimeToolHealthCounts(m.snapshot.Runtime)
	mirrorAvailable, mirrorMissing := runtimeMirrorHealth(m.snapshot.Runtime)
	switch {
	case missing > 0 || failed > 0 || drift > 0:
		return m.app.catalog.T("runtime_focus_repair")
	case mirrorMissing > 0 && mirrorAvailable == 0:
		return m.app.catalog.T("runtime_focus_mirror")
	case available == 0:
		return m.app.catalog.T("runtime_focus_repair")
	default:
		return m.app.catalog.T("runtime_focus_ready")
	}
}

func (m appShellModel) renderRuntimeRefreshPanel(width int) string {
	if !m.refreshing || m.refreshTargetRoute() != appRouteRuntime || !m.manualRefresh {
		return ""
	}
	return m.renderPanelCard(width, m.app.catalog.T("app_refreshing"),
		append(m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_sync"), Value: m.snapshotFreshnessHint()},
			factPair{Label: m.app.catalog.T("app_label_health"), Value: m.runtimeSnapshotSummary()},
		), m.app.catalog.T("runtime_command_title"))...,
	)
}

func (m appShellModel) projectFocusLines(width int) []string {
	row, ok := m.projectRows().at(m.cursor)
	if !ok {
		return append(m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_project"), Value: m.currentProjectLabel()},
		), m.app.catalog.T("app_projects_enter_hint"))
	}
	switch row.Action {
	case appShellActionSelectCurrent:
		return []string{
			m.app.catalog.T("app_action_select_current"),
			m.app.catalog.T("app_action_select_current_hint"),
			m.app.catalog.T("app_projects_enter_hint"),
		}
	case appShellActionPickFolder:
		return []string{
			m.app.catalog.T("app_action_pick_folder"),
			m.app.catalog.T("app_action_pick_folder_hint"),
			m.app.catalog.T("app_projects_enter_hint"),
		}
	default:
		project, ok := m.selectedProject()
		if !ok {
			return append(m.renderFactLines(width,
				factPair{Label: m.app.catalog.T("app_label_project"), Value: m.currentProjectLabel()},
			), m.app.catalog.T("app_projects_enter_hint"))
		}
		lines := m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_project"), Value: project.DisplayName},
			factPair{Label: m.app.catalog.T("app_label_target"), Value: trimForSelect(project.LocationHint, 56)},
			factPair{Label: m.app.catalog.T("app_label_trend"), Value: m.projectTrend(project.ID)},
		)
		return append(lines, m.app.catalog.T("app_projects_pick_hint"))
	}
}

func (m appShellModel) projectPreviewLines(width int) []string {
	row, ok := m.projectRows().at(m.cursor)
	if !ok {
		return []string{m.app.catalog.T("projects_focus_empty")}
	}
	switch row.Action {
	case appShellActionSelectCurrent:
		return []string{
			m.app.catalog.T("app_action_select_current"),
			m.app.catalog.T("app_action_select_current_hint"),
		}
	case appShellActionPickFolder:
		return []string{
			m.app.catalog.T("app_action_pick_folder"),
			m.app.catalog.T("app_action_pick_folder_hint"),
		}
	default:
		project, ok := m.selectedProject()
		if !ok {
			return []string{m.app.catalog.T("projects_focus_empty")}
		}
		return m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_project"), Value: project.DisplayName},
			factPair{Label: m.app.catalog.T("app_label_target"), Value: trimForSelect(project.LocationHint, 64)},
			factPair{Label: m.app.catalog.T("app_label_stacks"), Value: coalesceString(strings.Join(project.DetectedStacks, ", "), "-")},
		)
	}
}

func (m appShellModel) reviewPreviewLines(width int, project domain.Project, profile domain.ScanProfile, doctor domain.RuntimeDoctor, ready bool, blockers []string) []string {
	switch m.cursor {
	case 0:
		return m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_project"), Value: project.DisplayName},
			factPair{Label: m.app.catalog.T("app_label_target"), Value: trimForSelect(project.LocationHint, 64)},
			factPair{Label: m.app.catalog.T("app_label_stacks"), Value: coalesceString(strings.Join(project.DetectedStacks, ", "), "-")},
		)
	case 1:
		return m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_profile"), Value: m.reviewPresetLabel()},
			factPair{Label: m.app.catalog.T("app_label_mode"), Value: m.app.modeLabel(profile.Mode)},
			factPair{Label: m.app.catalog.T("app_label_coverage"), Value: m.app.coverageLabel(profile.Coverage)},
		)
	case 2:
		return append(m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_profile"), Value: m.reviewComplianceLabel()},
		), ternary(m.review.Preset == reviewPresetCompliance, m.app.catalog.T("app_scan_review_enter_hint"), m.app.catalog.T("app_scan_review_not_applicable")))
	case 3:
		return m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_isolation"), Value: strings.ToUpper(string(m.review.Isolation))},
			factPair{Label: m.app.catalog.T("app_label_mode"), Value: strings.ToUpper(string(profile.Isolation))},
		)
	case 4:
		return m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_mode"), Value: m.boolLabel(m.review.ActiveValidation)},
			factPair{Label: m.app.catalog.T("app_label_target"), Value: coalesceString(m.review.DASTTarget, m.app.catalog.T("app_scan_review_target_empty"))},
		)
	case 5:
		return append(m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_target"), Value: coalesceString(m.review.DASTTarget, m.app.catalog.T("app_scan_review_target_empty"))},
		), m.app.catalog.T("app_scan_review_keys_hint"))
	default:
		lines := m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_health"), Value: ternary(ready, m.app.catalog.T("app_scan_review_ready"), m.app.catalog.T("app_scan_review_start_blocked"))},
			factPair{Label: m.app.catalog.T("app_label_profile"), Value: m.reviewPresetLabel()},
		)
		lines = append(lines, doctorSummaryLine(m.app, doctor))
		if len(blockers) > 0 {
			lines = append(lines, blockers[0])
		}
		return lines
	}
}

func (m appShellModel) runtimeFocusLines(width int) []string {
	tool, ok := m.selectedRuntimeTool()
	if !ok {
		return []string{m.runtimeFocusMessage(), m.runtimeSnapshotSummary()}
	}
	status := m.app.catalog.T("runtime_missing")
	if tool.Available {
		status = m.app.catalog.T("runtime_available")
	}
	return append(m.renderFactLines(width,
		factPair{Label: m.app.catalog.T("app_label_tools"), Value: tool.Name},
		factPair{Label: m.app.catalog.T("app_label_health"), Value: status},
		factPair{Label: m.app.catalog.T("app_label_actual"), Value: coalesceString(tool.ActualVersion, tool.ExpectedVersion)},
	), m.runtimeFocusMessage())
}

func (m appShellModel) runPreviewLines(width int) []string {
	run, ok := m.selectedRun()
	if !ok {
		return []string{m.app.catalog.T("runs_focus_empty")}
	}
	return m.renderFactLines(width,
		factPair{Label: m.app.catalog.T("app_label_project"), Value: m.app.projectLabel(run.ProjectID)},
		factPair{Label: m.app.catalog.T("app_label_health"), Value: strings.ToUpper(string(run.Status))},
		factPair{Label: m.app.catalog.T("app_label_findings"), Value: fmt.Sprintf("%d", run.Summary.TotalFindings)},
		factPair{Label: m.app.catalog.T("app_label_scope"), Value: trimForSelect(run.ID, maxInt(24, width-18))},
	)
}

func (m appShellModel) runBriefSummary() string {
	run, ok := m.selectedRun()
	if !ok {
		return m.app.catalog.T("runs_focus_empty")
	}
	return trimForSelect(fmt.Sprintf("%s • %s • %d %s",
		strings.ToUpper(string(run.Status)),
		m.app.projectLabel(run.ProjectID),
		run.Summary.TotalFindings,
		m.app.catalog.T("app_label_findings"),
	), 72)
}

func (m appShellModel) findingPreviewLines(width int) []string {
	finding, ok := m.selectedFinding()
	if !ok {
		return []string{m.app.catalog.T("findings_focus_clean")}
	}
	pairs := []factPair{
		{Label: m.app.catalog.T("app_label_severity"), Value: strings.ToUpper(m.app.severityLabel(finding.Severity))},
		{Label: m.app.catalog.T("app_label_health"), Value: m.app.findingStatusLabel(m.normalizedFindingStatus(finding.Status))},
		{Label: m.app.catalog.T("app_label_module"), Value: finding.Module},
		{Label: m.app.catalog.T("app_label_location"), Value: coalesceString(finding.Location, "-")},
		{Label: m.app.catalog.T("show_title"), Value: trimForSelect(m.app.displayFindingTitle(finding), maxInt(24, width-18))},
	}
	if signal := m.app.findingSignalSummary(finding); signal != "-" {
		pairs = append([]factPair{{Label: m.app.catalog.T("reason"), Value: trimForSelect(signal, maxInt(24, width-18))}}, pairs...)
	}
	return m.renderFactLines(width,
		pairs...,
	)
}

func (m appShellModel) findingBriefSummary() string {
	finding, ok := m.selectedFinding()
	if !ok {
		return m.app.catalog.T("findings_focus_clean")
	}
	parts := []string{
		strings.ToUpper(m.app.severityLabel(finding.Severity)),
		m.app.findingStatusLabel(m.normalizedFindingStatus(finding.Status)),
	}
	if signal := m.app.findingSignalSummary(finding); signal != "-" {
		parts = append(parts, signal)
	} else {
		parts = append(parts, coalesceString(finding.Module, "-"))
	}
	return trimForSelect(strings.Join(parts, " • "), 72)
}

func (m appShellModel) runtimePreviewLines(width int) []string {
	tool, ok := m.selectedRuntimeTool()
	if !ok {
		return []string{m.runtimeFocusMessage()}
	}
	status := m.app.catalog.T("runtime_missing")
	if tool.Available {
		status = m.app.catalog.T("runtime_available")
	}
	return m.renderFactLines(width,
		factPair{Label: m.app.catalog.T("app_label_tools"), Value: fmt.Sprintf("%s • %s", tool.Name, strings.ToUpper(status))},
		factPair{Label: m.app.catalog.T("app_label_channel"), Value: strings.ToUpper(tool.Channel)},
		factPair{Label: m.app.catalog.T("app_label_actual"), Value: coalesceString(tool.ActualVersion, tool.ExpectedVersion)},
		factPair{Label: m.app.catalog.T("app_label_verify"), Value: strings.ToUpper(tool.Verification.Status())},
	)
}

func (m appShellModel) runFocusLines(width int) []string {
	run, ok := m.selectedRun()
	if !ok {
		return []string{m.app.catalog.T("no_runs")}
	}
	lines := []string{
		m.app.scanPostureSummary(run),
		trimForSelect(run.ID, maxInt(24, width-6)),
	}
	if run.Summary.TotalFindings > 0 {
		if findings, _ := m.snapshotFindingsForRun(run.ID); len(findings) > 0 {
			if hot := m.app.prioritizedFindings(findings, 1); len(hot) > 0 {
				lines = append(lines, trimForSelect(m.app.hottestFindingLine(hot[0], maxInt(32, width-6)), maxInt(32, width-6)))
			}
		}
		lines = append(lines, trimForSelect(m.campaignCreateCommandHint(run.ProjectID, run.ID, ""), maxInt(32, width-6)))
		lines = append(lines, m.app.catalog.T("app_action_open_run_findings_hint"))
	} else {
		lines = append(lines, m.app.catalog.T("app_live_scan_next_runs"))
	}
	return lines
}

func (m appShellModel) findingFocusLines(width int) []string {
	finding, ok := m.selectedFinding()
	if !ok {
		return []string{m.app.catalog.T("overview_no_findings")}
	}
	lines := []string{
		trimForSelect(m.app.displayFindingTitle(finding), maxInt(24, width-6)),
	}
	if signal := m.app.findingSignalSummary(finding); signal != "-" {
		lines = append(lines, trimForSelect(signal, maxInt(24, width-6)))
	}
	lines = append(lines, coalesceString(finding.Location, "-"))
	lines = append(lines, trimForSelect(m.campaignCreateCommandHint(finding.ProjectID, coalesceString(finding.ScanID, m.findingsScopeRun), finding.Fingerprint), maxInt(32, width-6)))
	if strings.TrimSpace(m.findingsScopeRun) == "" {
		lines = append(lines, m.app.catalog.T("app_action_open_run_findings_hint"))
	} else {
		lines = append(lines, m.app.catalog.T("app_action_clear_findings_scope_hint"))
	}
	return lines
}

func (m appShellModel) runtimeSupplyChainDigest() string {
	rows := m.app.supplyChainRows(m.snapshot.Runtime.SupplyChain)
	if len(rows) == 0 {
		return "-"
	}
	lines := make([]string, 0, min(4, len(rows)))
	for _, row := range rows[:min(4, len(rows))] {
		lines = append(lines, fmt.Sprintf("%s: %s", row[0], row[1]))
	}
	return strings.Join(lines, "\n")
}

func (m appShellModel) snapshotRun(runID string) (domain.ScanRun, bool) {
	for _, run := range m.snapshot.Portfolio.Runs {
		if run.ID == runID {
			return run, true
		}
	}
	return domain.ScanRun{}, false
}

func (m appShellModel) snapshotProject(projectID string) (domain.Project, bool) {
	for _, project := range m.snapshot.Portfolio.Projects {
		if project.ID == projectID {
			return project, true
		}
	}
	return domain.Project{}, false
}

func (m appShellModel) projectTreeCacheKey(projectID string) string {
	return "project-tree:" + strings.TrimSpace(projectID)
}

func projectTreeSlice(lines []string, limit int, empty string) []string {
	if len(lines) == 0 {
		return []string{empty}
	}
	if limit <= 0 || limit >= len(lines) {
		return append([]string(nil), lines...)
	}
	return append([]string(nil), lines[:limit]...)
}

func (m appShellModel) snapshotFindingsForRun(runID string) ([]domain.Finding, bool) {
	if strings.TrimSpace(runID) == "" {
		return nil, false
	}
	_, hasRun := m.snapshotRun(runID)
	findings := make([]domain.Finding, 0)
	for _, finding := range m.snapshot.Portfolio.Findings {
		if finding.ScanID == runID {
			findings = append(findings, finding)
		}
	}
	return findings, hasRun
}

func (m appShellModel) scopedFindings() []domain.Finding {
	if strings.TrimSpace(m.findingsScopeRun) == "" {
		return m.snapshot.Portfolio.Findings
	}
	if findings, ok := m.scopedFindingsMap[m.findingsScopeRun]; ok {
		return findings
	}
	findings, ok := m.snapshotFindingsForRun(m.findingsScopeRun)
	if !ok {
		findings = nil
	}
	m.scopedFindingsMap[m.findingsScopeRun] = findings
	return findings
}

func (m appShellModel) filteredScopedFindings() []domain.Finding {
	return m.filterFindings(m.scopedFindings())
}

func (m appShellModel) findingsScopeLabel() string {
	if strings.TrimSpace(m.findingsScopeRun) == "" {
		return m.app.catalog.T("app_findings_scope_all")
	}
	if run, ok := m.snapshotRun(m.findingsScopeRun); ok {
		return m.app.catalog.T("app_findings_scope_run", m.app.projectLabel(run.ProjectID))
	}
	return m.app.catalog.T("app_findings_scope_run", trimForSelect(m.findingsScopeRun, 20))
}
