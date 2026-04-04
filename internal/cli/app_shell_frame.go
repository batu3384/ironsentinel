package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func (m appShellModel) View() string {
	if m.width == 0 || m.height == 0 {
		return "\n  Loading IronSentinel..."
	}

	theme := m.app.tuiTheme()
	mainWidth := m.shellContentWidth()
	header := m.renderShellHeader(mainWidth)
	footer := m.renderHelpBar(mainWidth)
	if strings.TrimSpace(m.notice) != "" {
		footer = lipgloss.JoinVertical(lipgloss.Left, theme.noticeStyle(m.alert).Render(m.notice), footer)
	}
	bodyHeight := maxInt(10, m.height-lipgloss.Height(header)-lipgloss.Height(footer)-2)
	body := fitRenderedBlock(m.renderAppBody(mainWidth), bodyHeight)
	sections := []string{header}
	if strings.TrimSpace(body) != "" {
		sections = append(sections, body)
	}
	sections = append(sections, footer)
	content := lipgloss.JoinVertical(lipgloss.Left, sections...)
	if m.width > mainWidth+2 {
		content = lipgloss.NewStyle().Width(maxInt(mainWidth, m.width-2)).Align(lipgloss.Center).Render(content)
	}
	view := theme.docStyle().Render(content)
	if m.paletteActive {
		return m.renderModalScreen(m.renderPaletteOverlay(minInt(mainWidth, 72)))
	}
	if m.projectPickerActive {
		return m.renderModalScreen(m.renderProjectPickerOverlay(minInt(mainWidth, 80)))
	}
	if m.targetInputActive {
		return m.renderModalScreen(m.renderTargetOverlay(minInt(mainWidth, 72)))
	}
	return view
}

func (m appShellModel) shellContentWidth() int {
	available := m.width - 4
	if available < 60 {
		return maxInt(42, m.width-2)
	}
	maxWidth := 136
	switch m.route {
	case appRouteHome:
		maxWidth = 128
	case appRouteProjects, appRouteScanReview:
		maxWidth = 132
	case appRouteLiveScan:
		maxWidth = 148
	case appRouteRuns, appRouteFindings, appRouteRuntime:
		maxWidth = 136
	}
	return minInt(available, maxWidth)
}

func (m appShellModel) renderShellHeader(width int) string {
	if m.route == appRouteHome {
		if width >= 74 && m.height >= 18 {
			return lipgloss.JoinVertical(
				lipgloss.Left,
				m.app.renderBrandMastheadForRoute(width, m.frame, m.headerSubtitle(), m.route),
				m.renderShellMetaRow(width),
			)
		}
		return lipgloss.JoinVertical(
			lipgloss.Left,
			m.app.renderBrandHeaderCompactForRoute(width, m.frame, m.headerSubtitle(), m.route),
			m.renderShellMetaRow(width),
		)
	}
	if m.route == appRouteLiveScan && width >= 112 && m.height >= 26 {
		return lipgloss.JoinVertical(
			lipgloss.Left,
			m.app.renderBrandConsoleHeaderForRoute(width, m.frame, m.headerSubtitle(), m.route),
			m.renderShellMetaRow(width),
		)
	}
	return lipgloss.JoinVertical(
		lipgloss.Left,
		m.app.renderBrandHeaderCompactForRoute(width, m.frame, m.headerSubtitle(), m.route),
		m.renderShellMetaRow(width),
	)
}

func (m appShellModel) headerSubtitle() string {
	return fmt.Sprintf("%s • %s", m.routeTitle(), m.routeSubtitle())
}

func (m appShellModel) renderShellMetaRow(width int) string {
	theme := m.app.tuiTheme()
	projectChip := m.currentProjectValue()
	if strings.TrimSpace(projectChip) == "" || projectChip == m.app.catalog.T("app_home_selected_project_empty") {
		projectChip = m.currentWorkspaceTitle()
	}
	chips := []string{
		theme.chipStyle(true).Render(strings.ToUpper(m.routeTitle())),
		theme.chipStyle(false).Render(trimForSelect(projectChip, 24)),
		theme.chipStyle(false).Render(trimForSelect(m.runtimeHealthChipLabel(), 18)),
	}
	if m.refreshing && m.refreshTargetRoute() == m.route && (m.manualRefresh || !m.routeHasWarmContent()) {
		chips = append(chips, theme.chipStyle(true).Render(m.app.catalog.T("app_refreshing")))
	} else if !m.snapshotUpdatedAt.IsZero() && width >= 96 {
		chips = append(chips, theme.chipStyle(false).Render(m.metaSyncLabel()))
	}
	divider := theme.mutedStyle().Render(" • ")
	row := strings.Join(chips, divider)
	if width < 112 || m.route == appRouteHome {
		return lipgloss.NewStyle().Width(width).Align(lipgloss.Center).Render(row)
	}
	subtitleStyle := theme.mutedStyle()
	if m.routePulse > 0 {
		subtitleStyle = theme.eyebrowStyle()
	}
	meta := lipgloss.JoinHorizontal(lipgloss.Left, row, "  ", subtitleStyle.Render(trimForSelect(m.routeSubtitle(), maxInt(18, width-lipgloss.Width(row)-4))))
	return lipgloss.NewStyle().Width(width).Align(lipgloss.Center).Render(meta)
}

func (m appShellModel) renderAppBody(width int) string {
	routeBar := m.renderRouteBar(width)
	parts := []string{routeBar}
	if primer := m.renderRoutePrimer(width); strings.TrimSpace(primer) != "" {
		parts = append(parts, primer)
	}
	parts = append(parts, m.renderRouteContent(width))
	return lipgloss.JoinVertical(lipgloss.Left, parts...)
}

func appShellPrimaryRoutes() []appRoute {
	return []appRoute{
		appRouteHome,
		appRouteScanReview,
		appRouteLiveScan,
		appRouteRuns,
		appRouteFindings,
		appRouteRuntime,
	}
}

func (m appShellModel) nextPrimaryRoute(delta int) appRoute {
	routes := appShellPrimaryRoutes()
	index := slices.Index(routes, m.route)
	if index < 0 {
		if m.route == appRouteProjects {
			if delta < 0 {
				return appRouteHome
			}
			return appRouteScanReview
		}
		index = 0
	}
	index = (index + delta + len(routes)) % len(routes)
	return routes[index]
}

func (m appShellModel) renderRouteBar(width int) string {
	theme := m.app.tuiTheme()
	routes := []struct {
		Label string
		Short string
		Route appRoute
		Key   string
	}{
		{m.app.catalog.T("app_route_home"), m.app.catalog.T("app_route_home_short"), appRouteHome, "1"},
		{m.app.catalog.T("app_route_scan_review"), m.app.catalog.T("app_route_scan_review_short"), appRouteScanReview, "2"},
		{m.app.catalog.T("app_route_live_scan"), m.app.catalog.T("app_route_live_scan_short"), appRouteLiveScan, "3"},
		{m.app.catalog.T("runs_title"), m.app.catalog.T("runs_title_short"), appRouteRuns, "4"},
		{m.app.catalog.T("findings_title"), m.app.catalog.T("findings_title_short"), appRouteFindings, "5"},
		{m.app.catalog.T("runtime_command_title"), m.app.catalog.T("runtime_command_title_short"), appRouteRuntime, "6"},
	}
	buildTabs := func(compact int) string {
		tabs := make([]string, 0, len(routes)+1)
		for _, route := range routes {
			label := route.Label
			if compact >= 1 {
				label = route.Short
			}
			token := fmt.Sprintf("%s %s", route.Key, label)
			if compact >= 2 {
				token = route.Key
				if label != "" {
					token = fmt.Sprintf("%s·%s", route.Key, label)
				}
			}
			if m.route == route.Route {
				token = "▸ " + token
				labelText := theme.tabActiveStyle().Render(token)
				if m.routePulse > 0 && !theme.plain() {
					labelText = theme.eyebrowStyle().Render("● ") + labelText
				}
				tabs = append(tabs, labelText)
			} else {
				tabs = append(tabs, theme.tabIdleStyle().Render(token))
			}
		}
		separator := theme.mutedStyle().Render("   ")
		if compact >= 1 {
			separator = theme.mutedStyle().Render("  ")
		}
		if compact >= 2 {
			separator = theme.mutedStyle().Render(" ")
		}
		return strings.Join(tabs, separator)
	}

	bar := buildTabs(0)
	maxWidth := maxInt(24, width-4)
	if lipgloss.Width(bar) > maxWidth {
		bar = buildTabs(1)
	}
	if lipgloss.Width(bar) > maxWidth {
		bar = buildTabs(2)
	}
	return theme.routeRibbonStyle(width).Render(bar)
}

func (m appShellModel) renderRoutePrimer(width int) string {
	if width < 82 {
		return ""
	}
	theme := m.app.tuiTheme()
	text := trimForSelect(m.routePrimerText(), maxInt(18, width-28))
	controlText := trimForSelect(m.routePrimerControls(), maxInt(18, width-len(text)-12))
	controlRow := m.renderActionHintRow(maxInt(26, width/2), m.commandHintActions(m.routePrimerHints()))
	if width < 116 {
		if strings.TrimSpace(controlText) != "" {
			return theme.commandRibbonStyle(width).Render(
				lipgloss.JoinHorizontal(lipgloss.Left, theme.sectionBodyStyle().Render(text), "  ", theme.mutedStyle().Render("•"), "  ", theme.mutedStyle().Render(controlText)),
			)
		}
		return theme.commandRibbonStyle(width).Render(theme.sectionBodyStyle().Render(text))
	}
	return theme.commandRibbonStyle(width).Render(
		lipgloss.JoinHorizontal(
			lipgloss.Left,
			theme.chipStyle(true).Render(strings.ToUpper(m.app.catalog.T("app_route_primer_title"))),
			"  ",
			theme.sectionBodyStyle().Render(text),
			"  ",
			theme.mutedStyle().Render("•"),
			"  ",
			controlRow,
		),
	)
}

func (m appShellModel) routePrimerText() string {
	switch m.route {
	case appRouteScanReview:
		return m.app.catalog.T("app_route_scan_review_primer")
	case appRouteLiveScan:
		return m.app.catalog.T("app_route_live_scan_primer")
	case appRouteRuns:
		return m.app.catalog.T("app_route_runs_primer")
	case appRouteFindings:
		return m.app.catalog.T("app_route_findings_primer")
	case appRouteRuntime:
		return m.app.catalog.T("app_route_runtime_primer")
	default:
		return m.app.catalog.T("app_route_home_primer")
	}
}

func (m appShellModel) routePrimerControls() string {
	hints := m.routePrimerHints()
	if len(hints) == 0 {
		return ""
	}
	parts := make([]string, 0, len(hints))
	for _, hint := range hints {
		parts = append(parts, fmt.Sprintf("%s %s", hint.Key, hint.Label))
	}
	return strings.Join(parts, " • ")
}

func (m appShellModel) routePrimerHints() []commandHint {
	switch m.route {
	case appRouteScanReview:
		return []commandHint{
			{Key: "p", Label: m.app.catalog.T("app_help_preset")},
			{Key: "i", Label: m.app.catalog.T("app_help_isolation")},
			{Key: "enter", Label: m.app.catalog.T("app_action_start_scan")},
		}
	case appRouteLiveScan:
		if m.scanRunning {
			return []commandHint{
				{Key: "pgdn", Label: m.app.catalog.T("app_help_scroll_hint")},
				{Key: "x", Label: m.app.catalog.T("app_help_abort")},
			}
		}
		return []commandHint{
			{Key: "pgdn", Label: m.app.catalog.T("app_help_scroll_hint")},
			{Key: "e", Label: m.app.catalog.T("export_title")},
		}
	case appRouteRuns:
		return []commandHint{
			{Key: "o", Label: m.app.catalog.T("app_action_open_run_findings")},
			{Key: "e", Label: m.app.catalog.T("export_title")},
			{Key: "R", Label: m.app.catalog.T("run_retry_title")},
		}
	case appRouteFindings:
		return []commandHint{
			{Key: "f", Label: m.app.catalog.T("finding_filter_severity_label")},
			{Key: "g", Label: m.app.catalog.T("finding_filter_status_label")},
			{Key: "0", Label: m.app.catalog.T("app_help_filter_reset")},
		}
	case appRouteRuntime:
		return []commandHint{
			{Key: "r", Label: m.app.catalog.T("app_help_refresh")},
			{Key: "/", Label: m.app.catalog.T("app_help_palette")},
			{Key: "q", Label: m.app.catalog.T("app_help_quit")},
		}
	default:
		return []commandHint{
			{Key: "P", Label: m.app.catalog.T("app_action_open_project_picker")},
			{Key: "2", Label: m.app.catalog.T("app_route_scan_review_short")},
			{Key: "enter", Label: m.app.catalog.T("app_help_open")},
		}
	}
}

func (m appShellModel) renderRouteContent(width int) string {
	if m.showRouteSkeleton() {
		return m.renderRouteSkeleton(width)
	}
	switch m.route {
	case appRouteProjects:
		return m.renderProjectsContent(width)
	case appRouteScanReview:
		return m.renderScanReviewContent(width)
	case appRouteLiveScan:
		return m.renderLiveScanContent(width)
	case appRouteRuns:
		return m.renderRunsContent(width)
	case appRouteFindings:
		return m.renderFindingsContent(width)
	case appRouteRuntime:
		return m.renderRuntimeContent(width)
	default:
		return m.renderHomeContent(width)
	}
}

func (m appShellModel) showRouteSkeleton() bool {
	return m.refreshing && m.refreshTargetRoute() == m.route && !m.routeHasWarmContent()
}

func (m appShellModel) routeHasWarmContent() bool {
	switch m.route {
	case appRouteHome, appRouteProjects, appRouteScanReview:
		return len(m.snapshot.Portfolio.Projects) > 0 || !m.snapshotUpdatedAt.IsZero()
	case appRouteRuns:
		return len(m.snapshot.Portfolio.Runs) > 0 || !m.snapshotUpdatedAt.IsZero()
	case appRouteFindings:
		return len(m.filteredScopedFindings()) > 0 || !m.snapshotUpdatedAt.IsZero()
	case appRouteRuntime:
		return len(m.snapshot.Runtime.ScannerBundle) > 0 || !m.snapshotUpdatedAt.IsZero()
	case appRouteLiveScan:
		return m.scanRunning || m.lastScan != nil || !m.snapshotUpdatedAt.IsZero()
	default:
		return !m.snapshotUpdatedAt.IsZero()
	}
}

func (m appShellModel) renderRouteSkeleton(width int) string {
	hero := m.renderHeroPanel(
		width,
		m.routeTitle(),
		m.app.catalog.T("app_loading_title"),
		m.app.catalog.T("app_loading_short"),
		fmt.Sprintf("%s: %s", m.app.catalog.T("status"), m.routeTitle()),
		fmt.Sprintf("%s: %s", m.app.catalog.T("overview_next_steps"), m.routeSubtitle()),
	)
	leftWidth, rightWidth, stack := splitShellColumns(width, len(m.app.tuiTheme().gap()), 42, 42)
	left := m.renderPanelCard(leftWidth, m.routeSkeletonPrimaryTitle(),
		m.routeSkeletonPrimaryLines(leftWidth)...,
	)
	right := m.renderPanelCard(rightWidth, m.routeSkeletonSecondaryTitle(),
		m.routeSkeletonSecondaryLines(rightWidth)...,
	)
	if stack {
		return lipgloss.JoinVertical(lipgloss.Left, hero, "", left, "", right)
	}
	return lipgloss.JoinVertical(lipgloss.Left, hero, "", lipgloss.JoinHorizontal(lipgloss.Top, left, m.app.tuiTheme().gap(), right))
}

func (m appShellModel) skeletonLine(width int) string {
	theme := m.app.tuiTheme()
	if width < 8 {
		width = 8
	}
	patterns := []string{"▒", "░", "▒", "▓"}
	pattern := patterns[m.frame%len(patterns)]
	return theme.mutedStyle().Render(strings.Repeat(pattern, width))
}

func (m appShellModel) routeSkeletonPrimaryTitle() string {
	switch m.route {
	case appRouteScanReview:
		return m.app.catalog.T("app_scan_review_controls_title")
	case appRouteLiveScan:
		return m.app.catalog.T("app_live_scan_brief_title")
	case appRouteRuns:
		return m.app.catalog.T("runs_title")
	case appRouteFindings:
		return m.app.catalog.T("findings_title")
	case appRouteRuntime:
		return m.app.catalog.T("runtime_command_title")
	default:
		return m.app.catalog.T("app_home_actions")
	}
}

func (m appShellModel) routeSkeletonSecondaryTitle() string {
	switch m.route {
	case appRouteScanReview:
		return m.app.catalog.T("app_scan_review_plan_title")
	case appRouteLiveScan:
		return m.app.catalog.T("module_execution_title")
	case appRouteRuns:
		return m.app.catalog.T("app_runs_brief_title")
	case appRouteFindings:
		return m.app.catalog.T("app_findings_brief_title")
	case appRouteRuntime:
		return m.app.catalog.T("app_runtime_brief_title")
	default:
		return m.app.catalog.T("app_home_focus_title")
	}
}

func (m appShellModel) routeSkeletonPrimaryLines(width int) []string {
	lines := []string{
		m.skeletonLine(maxInt(18, width-20)),
		m.skeletonLine(maxInt(14, width-28)),
	}
	switch m.route {
	case appRouteScanReview:
		lines = append(lines,
			"",
			m.skeletonLine(maxInt(26, width-14)),
			m.skeletonLine(maxInt(20, width-18)),
			m.skeletonLine(maxInt(16, width-26)),
		)
	case appRouteLiveScan:
		lines = append(lines,
			"",
			m.skeletonLine(maxInt(24, width-18)),
			m.skeletonLine(maxInt(22, width-16)),
			m.skeletonLine(maxInt(18, width-24)),
		)
	default:
		lines = append(lines,
			"",
			m.skeletonLine(maxInt(24, width-18)),
			m.skeletonLine(maxInt(18, width-24)),
			m.skeletonLine(maxInt(16, width-28)),
		)
	}
	return lines
}

func (m appShellModel) routeSkeletonSecondaryLines(width int) []string {
	lines := []string{
		m.skeletonLine(maxInt(16, width-24)),
		m.skeletonLine(maxInt(24, width-16)),
	}
	switch m.route {
	case appRouteHome:
		lines = append(lines,
			"",
			m.skeletonLine(maxInt(24, width-18)),
			m.skeletonLine(maxInt(20, width-22)),
			m.skeletonLine(maxInt(18, width-28)),
		)
	case appRouteLiveScan:
		lines = append(lines,
			"",
			m.skeletonLine(maxInt(26, width-14)),
			m.skeletonLine(maxInt(14, width-30)),
		)
	default:
		lines = append(lines,
			"",
			m.skeletonLine(maxInt(20, width-22)),
			m.skeletonLine(maxInt(22, width-18)),
			m.skeletonLine(maxInt(14, width-32)),
		)
	}
	return lines
}

func (m appShellModel) renderPaletteOverlay(width int) string {
	theme := m.app.tuiTheme()
	panelWidth := minInt(width, maxInt(56, width/2+8))
	commands := m.filteredPaletteCommands()
	lines := []string{
		theme.sectionTitleStyle().Render(m.app.catalog.T("app_palette_title")),
		theme.mutedStyle().Render(m.app.catalog.T("app_help_move") + " • " + m.app.catalog.T("app_help_open")),
		"",
		m.paletteInput.View(),
		theme.mutedStyle().Render(fmt.Sprintf("%d %s", len(commands), strings.ToLower(m.app.catalog.T("app_palette_selection_title")))),
		"",
	}
	if len(commands) == 0 {
		lines = append(lines, m.app.catalog.T("app_palette_empty"))
	} else {
		lastGroup := ""
		for index, command := range commands[:min(10, len(commands))] {
			if command.Group != "" && command.Group != lastGroup {
				if lastGroup != "" {
					lines = append(lines, "")
				}
				lines = append(lines, theme.sectionTitleStyle().Render(command.Group))
				lastGroup = command.Group
			}
			prefix := "  "
			if index == m.paletteCursor {
				prefix = "› "
			}
			lines = append(lines, theme.rowStyle(index == m.paletteCursor).Render(prefix+command.Label))
			lines = append(lines, theme.mutedStyle().Render("  "+command.Hint))
		}
		selected := commands[min(m.paletteCursor, len(commands)-1)]
		lines = append(lines,
			"",
			theme.sectionTitleStyle().Render(m.app.catalog.T("app_palette_selection_title")),
			theme.panelStyle(panelWidth-2).Width(panelWidth-2).Render(strings.Join([]string{
				theme.titleStyle().Render(selected.Label),
				theme.mutedStyle().Render(selected.Hint),
				theme.eyebrowStyle().Render(selected.Group),
			}, "\n")),
		)
	}
	return theme.panelStyle(panelWidth).Width(panelWidth).Render(strings.Join(lines, "\n"))
}

func (m appShellModel) renderProjectPickerOverlay(width int) string {
	theme := m.app.tuiTheme()
	panelWidth := minInt(width, maxInt(58, width/2+10))
	rows := m.projectRows()
	selected, _ := rows.at(m.projectPickerCursor)
	lines := []string{
		theme.sectionTitleStyle().Render(m.app.catalog.T("app_project_picker_title")),
		theme.mutedStyle().Render(m.app.catalog.T("app_project_picker_subtitle")),
		"",
		m.renderSelectableList(panelWidth, rows, m.projectPickerCursor, 0),
	}
	previewLines := []string{}
	switch selected.Action {
	case appShellActionSelectCurrent:
		previewLines = []string{
			m.app.catalog.T("app_action_select_current_hint"),
			fmt.Sprintf("%s: %s", m.app.catalog.T("app_home_workspace"), m.currentWorkspaceTitle()),
		}
	case appShellActionPickFolder:
		previewLines = []string{
			m.app.catalog.T("app_action_pick_folder_hint"),
			m.app.catalog.T("app_scan_review_pick_project"),
		}
	default:
		if project, ok := m.snapshotProject(selected.Value); ok {
			previewLines = []string{
				fmt.Sprintf("%s: %s", m.app.catalog.T("app_home_selected_project"), project.DisplayName),
				fmt.Sprintf("%s: %s", m.app.catalog.T("scan_target"), trimForSelect(project.LocationHint, max(28, panelWidth-18))),
				fmt.Sprintf("%s: %s", m.app.catalog.T("scan_scope_stacks"), coalesceString(strings.Join(project.DetectedStacks, ", "), "-")),
				m.app.catalog.T("app_home_next_review"),
			}
		}
	}
	if len(previewLines) > 0 {
		lines = append(lines,
			"",
			theme.sectionTitleStyle().Render(m.app.catalog.T("app_palette_selection_title")),
			theme.panelStyle(panelWidth).Width(panelWidth).Render(strings.Join(previewLines, "\n")),
		)
	}
	return theme.panelStyle(panelWidth).Width(panelWidth).Render(strings.Join(lines, "\n"))
}

func (m appShellModel) renderTargetOverlay(width int) string {
	theme := m.app.tuiTheme()
	panelWidth := minInt(width, maxInt(46, width/2))
	lines := []string{
		theme.sectionTitleStyle().Render(m.app.catalog.T("app_target_title")),
		m.targetInput.View(),
		"",
		theme.mutedStyle().Render(m.app.catalog.T("app_target_hint")),
	}
	return theme.panelStyle(panelWidth).Width(panelWidth).Render(strings.Join(lines, "\n"))
}

func (m appShellModel) renderModalScreen(content string) string {
	theme := m.app.tuiTheme()
	canvasWidth := maxInt(m.width, lipgloss.Width(content)+4)
	canvasHeight := maxInt(m.height, lipgloss.Height(content)+4)
	backdrop := lipgloss.NewStyle().Width(canvasWidth).Height(canvasHeight)
	if !theme.plain() {
		backdrop = backdrop.Background(lipgloss.Color("233"))
	}
	centered := lipgloss.Place(canvasWidth, canvasHeight, lipgloss.Center, lipgloss.Center, content)
	return backdrop.Render(centered)
}
