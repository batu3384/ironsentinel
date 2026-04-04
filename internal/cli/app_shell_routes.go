package cli

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func (m appShellModel) renderHomeContent(width int) string {
	projects := m.homeRows()
	veryCompact := m.height < 29
	project, projectSelected := m.selectedProject()
	leftWidth, rightWidth, _ := splitShellColumns(width, len(m.app.tuiTheme().gap()), 42, 42)

	nextAction := m.app.catalog.T("app_home_next_select_current")
	if projectSelected {
		nextAction = m.app.catalog.T("app_home_next_review")
	}
	heroTitle := m.currentWorkspaceTitle()
	if projectSelected {
		heroTitle = project.DisplayName
	}
	hero := m.renderHeroPanel(
		width,
		m.app.catalog.T("app_home_launchpad_title"),
		heroTitle,
		nextAction,
		m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_workspace"), Value: m.currentWorkspaceTitle()},
			factPair{Label: m.app.catalog.T("app_label_project"), Value: m.currentProjectValue()},
			factPair{Label: m.app.catalog.T("app_label_health"), Value: m.runtimeSnapshotSummary()},
		)...,
	)
	if veryCompact {
		compactCards := []string{
			hero,
			m.renderPanelCard(width, m.app.catalog.T("app_home_actions"), m.renderSelectableList(width, projects, m.cursor, 0)),
		}
		focusLines := m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_workspace"), Value: m.currentWorkspaceTitle()},
			factPair{Label: m.app.catalog.T("app_label_health"), Value: m.runtimeHealthHeadline()},
			factPair{Label: m.app.catalog.T("app_label_next"), Value: nextAction},
		)
		if projectSelected {
			focusLines = append(focusLines, m.renderFactLines(width,
				factPair{Label: m.app.catalog.T("app_label_project"), Value: project.DisplayName},
				factPair{Label: m.app.catalog.T("app_label_target"), Value: trimForSelect(project.LocationHint, max(30, width-18))},
			)...)
		}
		focusLines = append(focusLines, "", m.app.catalog.T("app_home_guide_step_1"), m.app.catalog.T("app_home_guide_step_2"), m.app.catalog.T("app_home_guide_step_3"))
		focusLines = append(focusLines, "", m.renderActionHintRow(width, m.commandHintActions(m.routePrimerHints())))
		compactCards = append(compactCards, m.renderPanelCard(width, m.app.catalog.T("app_home_focus_title"), focusLines...))
		return strings.Join(compactCards, "\n\n")
	}

	left := []string{
		m.renderPanelCardWithSummary(leftWidth, m.app.catalog.T("app_home_actions"),
			fmt.Sprintf("%s • P • %s", nextAction, m.app.catalog.T("app_action_open_project_picker")),
			m.renderSelectableList(leftWidth, projects, m.cursor, 0),
		),
	}

	var focusLines []string
	focusSummaryParts := []string{}
	if projectSelected {
		focusLines = m.renderFactLines(rightWidth,
			factPair{Label: m.app.catalog.T("app_label_target"), Value: trimForSelect(project.LocationHint, 56)},
			factPair{Label: m.app.catalog.T("app_label_trend"), Value: m.projectTrend(project.ID)},
			factPair{Label: m.app.catalog.T("app_label_next"), Value: nextAction},
		)
		focusSummaryParts = append(focusSummaryParts, trimForSelect(project.DisplayName, 24))
	} else {
		focusLines = m.renderFactLines(rightWidth,
			factPair{Label: m.app.catalog.T("app_label_workspace"), Value: m.currentWorkspaceTitle()},
			factPair{Label: m.app.catalog.T("app_label_project"), Value: m.currentProjectLabel()},
			factPair{Label: m.app.catalog.T("app_label_next"), Value: nextAction},
		)
		focusSummaryParts = append(focusSummaryParts, m.runtimeHealthHeadline())
	}
	if recent := m.homeRecentProjectSummary(3); recent != "" {
		focusSummaryParts = append(focusSummaryParts, fmt.Sprintf("%s %s", m.app.catalog.T("app_label_recent"), recent))
	}
	if risk := m.homeHotFindingSummary(1); risk != "" {
		focusSummaryParts = append(focusSummaryParts, fmt.Sprintf("%s %s", m.app.catalog.T("app_label_risk"), risk))
	}
	guideLines := []string{
		m.app.catalog.T("app_home_guide_step_1"),
		m.app.catalog.T("app_home_guide_step_2"),
		m.app.catalog.T("app_home_guide_step_3"),
	}
	right := []string{
		m.renderPanelCardWithSummary(rightWidth, m.app.catalog.T("app_home_focus_title"), strings.Join(focusSummaryParts, " • "), focusLines...),
		m.renderSelectionBriefCard(rightWidth, m.app.catalog.T("app_home_guide_title"), m.app.catalog.T("app_route_home_primer"), guideLines, m.commandHintActions(m.routePrimerHints())),
	}

	leftPanel := strings.Join(left, "\n\n")
	rightPanel := strings.Join(right, "\n\n")
	return m.renderDeckAndColumns(width, hero, leftPanel, rightPanel, 42, 42)
}

func (m appShellModel) renderProjectsContent(width int) string {
	rows := m.projectRows()
	project, _ := m.selectedProject()
	treeLimit := 12
	if width < 112 {
		treeLimit = 8
	}
	topCards := []tuiMetricCard{
		{Title: m.app.catalog.T("projects_title"), Value: fmt.Sprintf("%d", len(m.snapshot.Portfolio.Projects)), Hint: m.app.catalog.T("app_route_projects_subtitle")},
		{Title: m.app.catalog.T("projects_roster_title"), Value: topProjectStacks(m.snapshot.Portfolio.Projects, 4), Hint: m.app.catalog.T("app_projects_enter_hint")},
	}
	return m.renderMasterDetailRoute(width, topCards, 2,
		m.app.catalog.T("projects_title"),
		fmt.Sprintf("%d %s • %s", len(m.snapshot.Portfolio.Projects), strings.ToLower(m.app.catalog.T("projects_title")), strings.ToLower(m.app.catalog.T("app_projects_enter_hint"))),
		rows, m.cursor, 0, 44, 42,
		func(compactWidth int) []string {
			lines := []string{
				m.renderSelectionBriefCard(compactWidth, m.app.catalog.T("app_projects_brief_title"), m.currentProjectLabel(), m.composeBriefBody(m.projectPreviewLines(compactWidth), m.projectFocusLines(compactWidth)), []string{
					"enter • " + m.app.catalog.T("app_route_scan_review_short"),
					"p • " + m.app.catalog.T("app_action_open_project_picker"),
				}),
			}
			if project.ID != "" {
				lines = append(lines, m.renderPanelCard(compactWidth, project.DisplayName,
					m.renderFactLines(compactWidth,
						factPair{Label: m.app.catalog.T("app_label_target"), Value: trimForSelect(project.LocationHint, max(30, compactWidth-18))},
						factPair{Label: m.app.catalog.T("app_label_stacks"), Value: coalesceString(strings.Join(project.DetectedStacks, ", "), "-")},
						factPair{Label: m.app.catalog.T("app_label_trend"), Value: m.projectTrend(project.ID)},
					)...,
				))
			}
			return lines
		},
		func(rightWidth int) []string {
			if project.ID == "" {
				return []string{
					m.renderSelectionBriefCard(rightWidth, m.app.catalog.T("app_projects_brief_title"), m.currentProjectLabel(), m.composeBriefBody(m.projectPreviewLines(rightWidth), m.projectFocusLines(rightWidth)), []string{
						"enter • " + m.app.catalog.T("app_route_scan_review_short"),
						"p • " + m.app.catalog.T("app_action_open_project_picker"),
					}),
				}
			}
			return []string{
				m.renderSelectionBriefCard(rightWidth, m.app.catalog.T("app_projects_brief_title"), m.currentProjectLabel(), m.composeBriefBody(m.projectPreviewLines(rightWidth), m.projectFocusLines(rightWidth)), []string{
					"enter • " + m.app.catalog.T("app_route_scan_review_short"),
					"p • " + m.app.catalog.T("app_action_open_project_picker"),
				}),
				m.renderPanelCard(rightWidth, project.DisplayName,
					m.renderFactLines(rightWidth,
						factPair{Label: m.app.catalog.T("app_label_target"), Value: trimForSelect(project.LocationHint, max(32, rightWidth-18))},
						factPair{Label: m.app.catalog.T("app_label_stacks"), Value: coalesceString(strings.Join(project.DetectedStacks, ", "), "-")},
						factPair{Label: m.app.catalog.T("app_label_trend"), Value: m.projectTrend(project.ID)},
					)...,
				),
				m.renderPanelCard(rightWidth, m.app.catalog.T("app_project_tree_title"), m.projectTreePreview(project, 2, treeLimit)...),
			}
		},
	)
}

func (m appShellModel) renderScanReviewContent(width int) string {
	project, ok := m.selectedProject()
	if !ok {
		return m.app.tuiTheme().panelStyle(width).Width(width).Render(strings.Join([]string{
			m.renderSection(m.app.catalog.T("app_route_scan_review"),
				m.app.catalog.T("project_select_required"),
				m.app.catalog.T("app_scan_review_pick_project"),
			),
		}, "\n"))
	}

	profile, doctor, ready, blockers := m.scanReviewContext(project)
	laneSummary := m.reviewLaneSummary(project, profile)
	laneHint := "-"
	if len(laneSummary) > 0 {
		laneHint = laneSummary[0]
	}
	leftWidth, rightWidth, _ := splitShellColumns(width, len(m.app.tuiTheme().gap()), 46, 48)
	treeLimit := 10
	laneDetailLimit := 0
	if width < 116 {
		treeLimit = 6
		laneDetailLimit = 18
	}
	hero := m.renderHeroPanel(
		width,
		m.app.catalog.T("app_scan_review_preset"),
		m.reviewPresetLabel(),
		m.scanStartHint(profile, ready),
		m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_project"), Value: project.DisplayName},
			factPair{Label: m.app.catalog.T("app_label_isolation"), Value: strings.ToUpper(string(m.review.Isolation))},
			factPair{Label: m.app.catalog.T("app_label_coverage"), Value: fmt.Sprintf("%d • %s", len(profile.Modules), trimForSelect(laneHint, 42))},
			factPair{Label: m.app.catalog.T("app_label_health"), Value: doctorSummaryLine(m.app, doctor)},
		)...,
	)
	if m.height < 31 {
		controlLines := append(
			m.renderFactLines(width,
				factPair{Label: m.app.catalog.T("app_label_profile"), Value: m.reviewPresetLabel()},
				factPair{Label: m.app.catalog.T("app_label_target"), Value: coalesceString(m.review.DASTTarget, m.app.catalog.T("app_scan_review_target_empty"))},
				factPair{Label: m.app.catalog.T("app_label_health"), Value: ternary(ready, m.app.catalog.T("app_scan_review_ready"), m.app.catalog.T("app_scan_review_start_blocked"))},
			),
			m.app.catalog.T("app_scan_review_lane_summary")+":",
			laneHint,
			m.scanStartHint(profile, ready),
			doctorSummaryLine(m.app, doctor),
		)
		lines := []string{
			m.renderPanelCard(width, m.app.catalog.T("app_scan_review_controls_title"), controlLines...),
			m.renderPanelCard(width, m.app.catalog.T("app_scan_review_lane_summary"), m.reviewLaneSummary(project, profile)...),
		}
		if m.height >= 25 {
			lines = append(lines, m.renderPanelCard(width, m.app.catalog.T("overview_operator_focus"), m.reviewFocusLines(width, project, profile, doctor, ready, blockers)...))
		}
		if len(blockers) > 0 {
			lines = append(lines, m.renderPanelCard(width, m.app.catalog.T("app_scan_review_blockers"), blockers...))
		}
		if m.height >= 26 {
			lines = append(lines, m.renderPanelCard(width, m.app.catalog.T("overview_next_steps"),
				m.app.catalog.T("app_scan_review_enter_hint"),
				m.app.catalog.T("app_scan_review_keys_hint"),
			))
		}
		return strings.Join(lines, "\n\n")
	}

	rows := m.scanReviewRows(project, profile, ready)
	left := strings.Join([]string{
		m.renderPanelCard(leftWidth, m.app.catalog.T("app_scan_review_controls_title"),
			m.renderSelectableList(leftWidth, rows, m.cursor, 0),
			"",
			strings.Join(m.renderFactLines(leftWidth,
				factPair{Label: m.app.catalog.T("app_label_health"), Value: ternary(ready, m.app.catalog.T("app_scan_review_ready"), m.app.catalog.T("app_scan_review_start_blocked"))},
				factPair{Label: m.app.catalog.T("app_label_profile"), Value: m.reviewPresetLabel()},
			), "\n"),
			m.scanStartHint(profile, ready),
			doctorSummaryLine(m.app, doctor),
			m.app.catalog.T("app_scan_review_enter_hint"),
		),
	}, "\n\n")

	rightLines := []string{
		m.renderPanelCard(rightWidth, m.app.catalog.T("app_scan_review_plan_title"),
			m.reviewPlanLines(rightWidth, project, profile)...,
		),
		m.renderSelectionBriefCard(rightWidth, m.app.catalog.T("app_scan_review_brief_title"), m.scanStartHint(profile, ready), m.composeBriefBody(m.reviewPreviewLines(rightWidth, project, profile, doctor, ready, blockers), m.reviewFocusLines(rightWidth, project, profile, doctor, ready, blockers)), []string{
			m.app.catalog.T("app_scan_review_enter_hint"),
			m.app.catalog.T("app_scan_review_keys_hint"),
		}),
	}
	if width >= 150 {
		rightLines = append(rightLines, m.renderPanelCard(rightWidth, m.app.catalog.T("scan_mode_live_scope_title"), m.reviewLaneSectionsForWidth(project, profile, laneDetailLimit)...))
	}
	if width >= 150 {
		rightLines = append(rightLines, m.renderPanelCard(rightWidth, m.app.catalog.T("app_project_tree_title"), m.projectTreePreview(project, 2, treeLimit)...))
	}
	if len(blockers) > 0 {
		rightLines = append(rightLines, m.renderPanelCard(rightWidth, m.app.catalog.T("app_scan_review_blockers"), blockers...))
	}
	right := strings.Join(rightLines, "\n\n")
	return m.renderDeckAndColumns(width, hero, left, right, 46, 48)
}

func (m appShellModel) renderLiveScanContent(width int) string {
	if mission, ok := m.activeScanMissionModel(); ok {
		return m.renderEmbeddedLiveMission(width, mission)
	}
	if m.lastScan == nil {
		lines := append(m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_project"), Value: m.currentProjectValue()},
			factPair{Label: m.app.catalog.T("app_label_health"), Value: m.runtimeSnapshotSummary()},
		), m.app.catalog.T("app_live_scan_empty"))
		return m.renderHeroPanel(width, m.app.catalog.T("app_route_live_scan"), m.app.catalog.T("app_live_scan_empty"), m.app.catalog.T("app_route_live_scan_subtitle"), lines...)
	}
	return m.renderLiveDebriefPanel(*m.lastScan, width)
}

func (m appShellModel) renderEmbeddedLiveMission(width int, mission scanMissionModel) string {
	boardHeight := maxInt(12, minInt(22, m.height-20))
	board := mission.renderMissionBoardWithViewport(width, boardHeight, m.renderDetailViewport)
	sections := []string{
		mission.renderLaunchStrip(width),
		board,
		mission.renderHealthFooter(width),
	}
	if mission.done {
		sections = append(sections, m.renderLiveDebriefPanel(m.currentScanOutcome(), width))
	}
	return strings.Join(sections, "\n\n")
}

func (m appShellModel) renderLiveDebriefPanel(outcome scanMissionOutcome, width int) string {
	theme := m.app.tuiTheme()
	verdict := m.app.catalog.T("scan_outcome_clean")
	nextStep := m.app.catalog.T("app_live_scan_next_runs")
	switch {
	case outcome.requiredErr != nil:
		verdict = m.app.catalog.T("scan_outcome_partial")
		nextStep = m.app.catalog.T("app_live_scan_next_runtime")
	case len(outcome.findings) > 0:
		verdict = m.app.catalog.T("scan_outcome_blocked")
		nextStep = m.app.catalog.T("app_live_scan_next_findings")
	}
	hero := m.renderHeroPanel(
		width,
		m.app.catalog.T("app_route_live_scan"),
		strings.ToUpper(verdict),
		nextStep,
		m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_scope"), Value: outcome.run.ID},
			factPair{Label: m.app.catalog.T("app_label_findings"), Value: fmt.Sprintf("%d", outcome.run.Summary.TotalFindings)},
			factPair{Label: m.app.catalog.T("app_label_tools"), Value: fmt.Sprintf("%d", len(outcome.run.ModuleResults))},
			factPair{Label: m.app.catalog.T("app_label_report"), Value: m.reportDisplayValue(outcome.reportPath)},
			factPair{Label: m.app.catalog.T("app_label_next"), Value: nextStep},
		)...,
	)
	leftWidth, rightWidth, stack := splitShellColumns(width, len(theme.gap()), 42, 42)
	left := []string{
		m.renderPanelCard(leftWidth, m.app.catalog.T("module_execution_title"), m.renderDetailViewport(leftWidth, m.renderLiveRunDigest(outcome.run))),
	}
	briefLines := m.renderFactLines(rightWidth,
		factPair{Label: m.app.catalog.T("app_label_health"), Value: strings.ToUpper(verdict)},
		factPair{Label: m.app.catalog.T("app_label_report"), Value: m.reportDisplayValue(outcome.reportPath)},
		factPair{Label: m.app.catalog.T("app_label_next"), Value: nextStep},
	)
	prioritized := m.app.prioritizedFindings(outcome.findings, 5)
	if len(prioritized) > 0 {
		briefLines = append(briefLines, "", m.app.catalog.T("overview_hot_findings")+":")
		briefLines = append(briefLines, strings.Split(m.renderFindingDigest(prioritized, 5), "\n")...)
	}
	if outcome.requiredErr != nil {
		briefLines = append(briefLines, "", m.app.catalog.T("app_scan_review_blockers")+":", outcome.requiredErr.Error())
	}
	if outcome.scanErr != nil {
		briefLines = append(briefLines, "", m.app.catalog.T("scan_failed")+":", outcome.scanErr.Error())
	}
	if len(prioritized) == 0 && outcome.requiredErr == nil && outcome.scanErr == nil {
		briefLines = append(briefLines, "", m.app.catalog.T("app_live_scan_notice_clean"))
	}
	briefLines = append(briefLines, "", "e • "+m.app.catalog.T("export_title"))
	right := []string{
		m.renderPanelCard(rightWidth, m.app.catalog.T("app_live_scan_brief_title"), briefLines...),
	}
	if stack {
		lines := []string{hero, strings.Join(left, "\n\n"), strings.Join(right, "\n\n")}
		return strings.Join(lines, "\n\n")
	}
	return strings.Join([]string{hero, lipgloss.JoinHorizontal(lipgloss.Top, strings.Join(left, "\n\n"), theme.gap(), strings.Join(right, "\n\n"))}, "\n\n")
}

func (m appShellModel) renderRunsContent(width int) string {
	heroTitle := m.app.catalog.T("runs_title")
	heroBody := m.renderRunQueueSummary()
	heroLines := m.renderFactLines(width,
		factPair{Label: m.app.catalog.T("app_label_sync"), Value: m.snapshotUpdatedClock()},
		factPair{Label: m.app.catalog.T("app_label_trend"), Value: m.app.runTrendLabel(m.snapshot.Portfolio.Runs, 8)},
	)
	if run, ok := m.selectedRun(); ok {
		heroTitle = strings.ToUpper(string(run.Status))
		heroBody = fmt.Sprintf("%s • %s", m.app.projectLabel(run.ProjectID), trimForSelect(run.ID, 42))
		heroLines = append(heroLines, m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_findings"), Value: fmt.Sprintf("%d", run.Summary.TotalFindings)},
			factPair{Label: m.app.catalog.T("campaigns_title"), Value: m.campaignCreateCommandHint(run.ProjectID, run.ID, "")},
		)...)
	}
	content := m.renderMasterDetailRoute(width, nil, 0,
		m.app.catalog.T("runs_ledger_title"),
		m.renderRunQueueSummary(),
		m.runRows(), m.cursor, 0, 42, 48,
		func(compactWidth int) []string {
			return []string{
				m.renderSelectionBriefCard(compactWidth, m.app.catalog.T("app_runs_brief_title"), m.runBriefSummary(), m.composeBriefBody(m.runPreviewLines(compactWidth), m.runFocusLines(compactWidth)), []string{
					"o • " + m.app.catalog.T("app_action_open_run_findings"),
					"c • " + m.app.catalog.T("run_cancel_title"),
					"R • " + m.app.catalog.T("run_retry_title"),
					"e • " + m.app.catalog.T("export_title"),
				}),
				m.renderPanelCard(compactWidth, m.app.catalog.T("app_runs_detail_title"), m.renderRunDetailContent(compactWidth)),
			}
		},
		func(rightWidth int) []string {
			return []string{
				m.renderSelectionBriefCard(rightWidth, m.app.catalog.T("app_runs_brief_title"), m.runBriefSummary(), m.composeBriefBody(m.runPreviewLines(rightWidth), m.runFocusLines(rightWidth)), []string{
					"o • " + m.app.catalog.T("app_action_open_run_findings"),
					"c • " + m.app.catalog.T("run_cancel_title"),
					"R • " + m.app.catalog.T("run_retry_title"),
					"e • " + m.app.catalog.T("export_title"),
				}),
				m.renderPanelCard(rightWidth, m.app.catalog.T("app_runs_detail_title"), m.renderDetailViewport(rightWidth, m.renderRunDetailContent(rightWidth))),
			}
		},
	)
	return strings.Join([]string{m.renderHeroPanel(width, m.app.catalog.T("runs_ledger_title"), heroTitle, heroBody, heroLines...), content}, "\n\n")
}

func (m appShellModel) renderFindingsContent(width int) string {
	findings := m.filteredScopedFindings()
	heroTitle := fmt.Sprintf("%d", len(findings))
	heroBody := m.renderFindingPressureSummary(findings)
	heroLines := m.renderFactLines(width,
		factPair{Label: m.app.catalog.T("findings_filters"), Value: m.currentFindingsSeverityFilterLabel()},
		factPair{Label: m.app.catalog.T("finding_filter_status_label"), Value: m.currentFindingsStatusFilterLabel()},
		factPair{Label: m.app.catalog.T("app_label_sync"), Value: m.snapshotUpdatedClock()},
	)
	if strings.TrimSpace(m.findingsScopeRun) != "" {
		heroLines = append(heroLines, m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_findings_scope_title"), Value: m.findingsScopeLabel()},
		)...)
	}
	if finding, ok := m.selectedFinding(); ok {
		heroTitle = strings.ToUpper(m.app.severityLabel(finding.Severity))
		heroBody = trimForSelect(m.app.displayFindingTitle(finding), 54)
		heroLines = append(heroLines, m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("triage_status"), Value: m.app.findingStatusLabel(m.normalizedFindingStatus(finding.Status))},
			factPair{Label: m.app.catalog.T("campaigns_title"), Value: m.campaignCreateCommandHint(finding.ProjectID, coalesceString(finding.ScanID, m.findingsScopeRun), finding.Fingerprint)},
		)...)
	}
	content := m.renderMasterDetailRoute(width, nil, 0,
		m.app.catalog.T("findings_queue_title"),
		m.renderFindingPressureSummary(findings),
		m.findingRows(findings), m.cursor, 0, 42, 48,
		func(compactWidth int) []string {
			return []string{
				m.renderSelectionBriefCard(compactWidth, m.app.catalog.T("app_findings_brief_title"), m.findingBriefSummary(), m.composeBriefBody(m.findingPreviewLines(compactWidth), m.findingFocusLines(compactWidth)), []string{
					"f • " + m.app.catalog.T("finding_filter_severity_label"),
					"g • " + m.app.catalog.T("finding_filter_status_label"),
					"0 • " + m.app.catalog.T("artifact_filter_all"),
				}),
				m.renderPanelCard(compactWidth, m.app.catalog.T("app_findings_detail_title"), m.renderFindingDetailContent(compactWidth)),
			}
		},
		func(rightWidth int) []string {
			return []string{
				m.renderSelectionBriefCard(rightWidth, m.app.catalog.T("app_findings_brief_title"), m.findingBriefSummary(), m.composeBriefBody(m.findingPreviewLines(rightWidth), m.findingFocusLines(rightWidth)), []string{
					"f • " + m.app.catalog.T("finding_filter_severity_label"),
					"g • " + m.app.catalog.T("finding_filter_status_label"),
					"0 • " + m.app.catalog.T("artifact_filter_all"),
				}),
				m.renderPanelCard(rightWidth, m.app.catalog.T("app_findings_detail_title"), m.renderDetailViewport(rightWidth, m.renderFindingDetailContent(rightWidth))),
			}
		},
	)
	return strings.Join([]string{m.renderHeroPanel(width, m.app.catalog.T("findings_queue_title"), heroTitle, heroBody, heroLines...), content}, "\n\n")
}

func (m appShellModel) renderRuntimeContent(width int) string {
	heroTitle := m.runtimeHealthHeadline()
	heroBody := m.runtimeSnapshotSummary()
	heroLines := m.renderFactLines(width,
		factPair{Label: m.app.catalog.T("app_label_tools"), Value: fmt.Sprintf("%d", len(m.snapshot.Runtime.ScannerBundle))},
		factPair{Label: m.app.catalog.T("app_label_daemon"), Value: m.app.daemonStateLabel(m.snapshot.Runtime.Daemon)},
		factPair{Label: m.app.catalog.T("app_label_sync"), Value: m.snapshotUpdatedClock()},
	)
	if tool, ok := m.selectedRuntimeTool(); ok {
		heroTitle = tool.Name
		heroBody = strings.ToUpper(coalesceString(tool.ActualVersion, tool.ExpectedVersion))
		heroLines = append(heroLines, m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_verify"), Value: strings.ToUpper(tool.Verification.Status())},
		)...)
	}
	content := m.renderMasterDetailRoute(width, nil, 0,
		m.app.catalog.T("runtime_scanners_title"),
		m.runtimeSnapshotSummary(),
		m.runtimeRows(), m.cursor, 0, 42, 48,
		func(compactWidth int) []string {
			lines := []string{}
			if panel := m.renderRuntimeRefreshPanel(compactWidth); panel != "" {
				lines = append(lines, panel)
			}
			lines = append(lines,
				m.renderSelectionBriefCard(compactWidth, m.app.catalog.T("app_runtime_brief_title"), m.runtimeSnapshotSummary(), m.composeBriefBody(m.runtimePreviewLines(compactWidth), m.runtimeFocusLines(compactWidth)), []string{
					"r • " + m.app.catalog.T("app_help_refresh"),
					"/ • " + m.app.catalog.T("app_help_palette"),
				}),
				m.renderPanelCard(compactWidth, m.app.catalog.T("app_runtime_detail_title"), m.renderRuntimeDetailContent(compactWidth)),
			)
			return lines
		},
		func(rightWidth int) []string {
			lines := []string{}
			if panel := m.renderRuntimeRefreshPanel(rightWidth); panel != "" {
				lines = append(lines, panel)
			}
			lines = append(lines,
				m.renderSelectionBriefCard(rightWidth, m.app.catalog.T("app_runtime_brief_title"), m.runtimeSnapshotSummary(), m.composeBriefBody(m.runtimePreviewLines(rightWidth), m.runtimeFocusLines(rightWidth)), []string{
					"r • " + m.app.catalog.T("app_help_refresh"),
					"/ • " + m.app.catalog.T("app_help_palette"),
				}),
				m.renderPanelCard(rightWidth, m.app.catalog.T("app_runtime_detail_title"), m.renderDetailViewport(rightWidth, m.renderRuntimeDetailContent(rightWidth))),
			)
			return lines
		},
	)
	return strings.Join([]string{m.renderHeroPanel(width, m.app.catalog.T("runtime_trust_signal_title"), heroTitle, heroBody, heroLines...), content}, "\n\n")
}
