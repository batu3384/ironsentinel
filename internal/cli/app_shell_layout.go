package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/lipgloss"

	"github.com/batu3384/ironsentinel/internal/domain"
)

func (m appShellModel) renderMetricDeck(cards []tuiMetricCard, columns int, width int) string {
	if len(cards) == 0 {
		return ""
	}
	if columns <= 0 {
		columns = 2
	}
	theme := m.app.tuiTheme()
	if width <= 0 {
		width = m.width
	}
	usableWidth := maxInt(40, width-4)
	if usableWidth < 86 {
		columns = 1
	}
	cardWidth := maxInt(28, (usableWidth-(columns-1)*len(theme.gap()))/columns)
	rows := make([]string, 0, (len(cards)+columns-1)/columns)
	for start := 0; start < len(cards); start += columns {
		end := start + columns
		if end > len(cards) {
			end = len(cards)
		}
		rendered := make([]string, 0, end-start)
		for _, card := range cards[start:end] {
			body := strings.Join([]string{
				theme.eyebrowStyle().Render(card.Title),
				theme.titleStyle().Render(card.Value),
				theme.mutedStyle().Render(trimForSelect(card.Hint, maxInt(16, cardWidth-4))),
			}, "\n")
			rendered = append(rendered, theme.metricCardStyle(cardWidth).Width(cardWidth).Render(body))
		}
		rows = append(rows, joinHorizontalWithGap(rendered, theme.gap()))
	}
	return strings.Join(rows, "\n")
}

func (m appShellModel) renderSelectableList(width int, rows selectableRows, cursor int, offset int) string {
	if len(rows) == 0 {
		return m.app.catalog.T("empty_state")
	}
	listWidth := maxInt(24, shellPanelWidth(width)-6)
	items := make([]list.Item, 0, len(rows))
	for _, row := range rows {
		items = append(items, shellListItem{
			title: row.Label,
			desc:  trimForSelect(row.Hint, maxInt(18, listWidth-8)),
		})
	}
	delegate := shellListDelegate{theme: m.app.tuiTheme()}
	listHeight := minInt(maxInt(4, len(rows)*2), m.selectableListHeight())
	l := list.New(items, delegate, listWidth, listHeight)
	l.SetShowTitle(false)
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.SetShowPagination(len(rows)*2 > listHeight)
	l.SetShowHelp(false)
	index := cursor - offset
	if index < 0 {
		index = 0
	}
	if index >= len(rows) {
		index = len(rows) - 1
	}
	l.Select(index)
	return l.View()
}

func (m appShellModel) selectableListHeight() int {
	switch {
	case m.height >= 44:
		return 16
	case m.height >= 36:
		return 14
	case m.height >= 30:
		return 12
	default:
		return 10
	}
}

func (m appShellModel) currentWorkspacePath() string {
	cwd, err := os.Getwd()
	if err != nil {
		return "-"
	}
	return cwd
}

func (m appShellModel) currentWorkspaceTitle() string {
	path := strings.TrimSpace(m.currentWorkspacePath())
	if path == "" || path == "-" {
		return "-"
	}
	base := filepath.Base(path)
	if strings.TrimSpace(base) == "" || base == "." || base == string(filepath.Separator) {
		return path
	}
	return base
}

func (m appShellModel) currentProjectValue() string {
	project, ok := m.selectedProject()
	if !ok {
		return m.app.catalog.T("app_home_selected_project_empty")
	}
	return project.DisplayName
}

func (m appShellModel) runtimeHealthHeadline() string {
	available, drift, missing, failed := runtimeToolHealthCounts(m.snapshot.Runtime)
	switch {
	case missing > 0 || failed > 0:
		return fmt.Sprintf("%d/%d %s", available, available+missing+drift+failed, m.app.catalog.T("runtime_focus_repair"))
	case drift > 0:
		return fmt.Sprintf("%d %s", drift, strings.ToLower(m.app.catalog.T("runtime_doctor_outdated")))
	default:
		return m.app.catalog.T("runtime_focus_ready")
	}
}

func (m appShellModel) runtimeHealthChipLabel() string {
	_, drift, missing, failed := runtimeToolHealthCounts(m.snapshot.Runtime)
	switch {
	case missing > 0 || failed > 0:
		return m.app.catalog.T("runtime_meta_repair")
	case drift > 0:
		return m.app.catalog.T("runtime_meta_drift", drift)
	default:
		return m.app.catalog.T("runtime_meta_ready")
	}
}

func (m appShellModel) renderSection(title string, lines ...string) string {
	trimmed := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimRight(line, "\n")
		if strings.TrimSpace(line) == "" {
			continue
		}
		trimmed = append(trimmed, line)
	}
	if len(trimmed) == 0 {
		trimmed = append(trimmed, "-")
	}
	return m.app.tuiTheme().sectionTitleStyle().Render(title) + "\n" + m.app.tuiTheme().sectionBodyStyle().Render(strings.Join(trimmed, "\n"))
}

func (m appShellModel) renderPanelCard(width int, title string, lines ...string) string {
	panelWidth := shellPanelWidth(width)
	return m.app.tuiTheme().panelStyle(panelWidth).Width(panelWidth).Render(m.renderSection(title, lines...))
}

func (m appShellModel) renderFactLines(width int, facts ...factPair) []string {
	return renderFactRows(m.app.tuiTheme(), width, facts...)
}

func renderFactRows(theme tuiTheme, width int, facts ...factPair) []string {
	if len(facts) == 0 {
		return nil
	}
	labelWidth := 0
	for _, fact := range facts {
		labelWidth = maxInt(labelWidth, utf8.RuneCountInString(strings.TrimSpace(fact.Label)))
	}
	labelWidth = minInt(maxInt(labelWidth, 6), 12)
	lines := make([]string, 0, len(facts))
	for _, fact := range facts {
		label := strings.TrimSpace(fact.Label)
		value := strings.TrimSpace(fact.Value)
		if label == "" && value == "" {
			continue
		}
		padded := trimForSelect(label, labelWidth)
		if diff := labelWidth - utf8.RuneCountInString(padded); diff > 0 {
			padded += strings.Repeat(" ", diff)
		}
		line := theme.mutedStyle().Render(padded)
		if value != "" {
			line += "  " + trimForSelect(value, maxInt(12, width-labelWidth-6))
		}
		lines = append(lines, line)
	}
	return lines
}

func (m appShellModel) renderHeroPanel(width int, eyebrow, title, body string, lines ...string) string {
	panelWidth := shellPanelWidth(width)
	theme := m.app.tuiTheme()
	content := []string{
		theme.eyebrowStyle().Render(trimForSelect(eyebrow, maxInt(18, panelWidth-6))),
		theme.heroTitleStyle().Render(trimForSelect(title, maxInt(18, panelWidth-6))),
	}
	if strings.TrimSpace(body) != "" {
		content = append(content, theme.subtitleStyle().Render(trimForSelect(body, maxInt(18, panelWidth-6))))
	}
	trimmed := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimRight(line, "\n")
		if strings.TrimSpace(line) == "" {
			continue
		}
		trimmed = append(trimmed, trimForSelect(line, maxInt(18, panelWidth-6)))
	}
	if len(trimmed) > 0 {
		content = append(content, "", theme.sectionBodyStyle().Render(strings.Join(trimmed, "\n")))
	}
	return theme.heroPanelStyle(panelWidth).Width(panelWidth).Render(strings.Join(content, "\n"))
}

func (m appShellModel) renderPanelCardWithSummary(width int, title, summary string, lines ...string) string {
	panelWidth := shellPanelWidth(width)
	content := []string{m.app.tuiTheme().sectionTitleStyle().Render(title)}
	if strings.TrimSpace(summary) != "" {
		content = append(content, m.app.tuiTheme().mutedStyle().Render(trimForSelect(summary, maxInt(18, panelWidth-4))))
	}
	body := []string{}
	for _, line := range lines {
		line = strings.TrimRight(line, "\n")
		if strings.TrimSpace(line) == "" {
			continue
		}
		body = append(body, line)
	}
	if len(body) == 0 {
		body = append(body, "-")
	}
	content = append(content, m.app.tuiTheme().sectionBodyStyle().Render(strings.Join(body, "\n")))
	return m.app.tuiTheme().panelStyle(panelWidth).Width(panelWidth).Render(strings.Join(content, "\n"))
}

func (m appShellModel) composeBriefBody(preview, focus []string) []string {
	lines := make([]string, 0, len(preview)+len(focus)+2)
	lines = append(lines, preview...)
	if len(focus) > 0 {
		if len(lines) > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, m.app.catalog.T("overview_operator_focus")+":")
		lines = append(lines, focus...)
	}
	return lines
}

func (m appShellModel) renderSelectionBriefCard(width int, title, summary string, body, actions []string) string {
	panelWidth := shellPanelWidth(width)
	content := []string{m.app.tuiTheme().sectionTitleStyle().Render(title)}
	if strings.TrimSpace(summary) != "" {
		content = append(content, m.app.tuiTheme().mutedStyle().Render(trimForSelect(summary, maxInt(18, panelWidth-4))))
	}

	bodyLines := make([]string, 0, len(body)+2)
	for _, line := range body {
		line = strings.TrimRight(line, "\n")
		if strings.TrimSpace(line) == "" {
			continue
		}
		bodyLines = append(bodyLines, line)
	}
	if len(actions) > 0 {
		if len(bodyLines) > 0 {
			bodyLines = append(bodyLines, "")
		}
		bodyLines = append(bodyLines, m.renderActionHintRow(panelWidth, actions))
	}
	if len(bodyLines) == 0 {
		bodyLines = append(bodyLines, "-")
	}

	content = append(content, m.app.tuiTheme().sectionBodyStyle().Render(strings.Join(bodyLines, "\n")))
	return m.app.tuiTheme().panelStyle(panelWidth).Width(panelWidth).Render(strings.Join(content, "\n"))
}

func (m appShellModel) commandHintActions(hints []commandHint) []string {
	actions := make([]string, 0, len(hints))
	for _, hint := range hints {
		key := strings.TrimSpace(hint.Key)
		label := strings.TrimSpace(hint.Label)
		if key == "" && label == "" {
			continue
		}
		if label == "" {
			actions = append(actions, key)
			continue
		}
		actions = append(actions, fmt.Sprintf("%s • %s", key, label))
	}
	return actions
}

func (m appShellModel) renderActionHintRow(width int, actions []string) string {
	theme := m.app.tuiTheme()
	rendered := make([]string, 0, len(actions))
	for _, action := range actions {
		parts := strings.SplitN(strings.TrimSpace(action), "•", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			label := strings.TrimSpace(parts[1])
			rendered = append(rendered, lipgloss.JoinHorizontal(lipgloss.Left, theme.chipStyle(true).Render(key), " ", theme.mutedStyle().Render(label)))
			continue
		}
		rendered = append(rendered, theme.mutedStyle().Render(strings.TrimSpace(action)))
	}
	row := strings.Join(rendered, "  ")
	if lipgloss.Width(row) <= maxInt(18, width-4) {
		return row
	}
	if len(actions) > 1 {
		return m.renderActionHintRow(width, actions[:len(actions)-1])
	}
	return theme.mutedStyle().Render(strings.TrimSpace(actions[0]))
}

func (m appShellModel) renderDeckAndColumns(width int, deck, left, right string, leftMin, rightMin int) string {
	_, _, stack := splitShellColumns(width, len(m.app.tuiTheme().gap()), leftMin, rightMin)
	gap := m.app.tuiTheme().blockGap()
	base := []string{}
	if strings.TrimSpace(deck) != "" {
		base = append(base, deck)
	}
	if stack {
		if strings.TrimSpace(right) == "" {
			base = append(base, left)
			return strings.Join(base, gap)
		}
		base = append(base, left, right)
		return strings.Join(base, gap)
	}
	if strings.TrimSpace(right) == "" {
		base = append(base, left)
		return strings.Join(base, gap)
	}
	base = append(base, lipgloss.JoinHorizontal(lipgloss.Top, left, m.app.tuiTheme().gap(), right))
	return strings.Join(base, gap)
}

func (m appShellModel) renderMasterDetailRoute(
	width int,
	cards []tuiMetricCard,
	deckColumns int,
	listTitle string,
	listSummary string,
	rows selectableRows,
	cursor int,
	offset int,
	leftMin int,
	rightMin int,
	compactPanels func(int) []string,
	rightPanels func(int) []string,
) string {
	deck := m.renderMetricDeck(cards, deckColumns, width)
	gap := m.app.tuiTheme().blockGap()
	summary := strings.TrimSpace(listSummary)
	if position := m.selectionContextSummary(rows, cursor, offset); position != "" {
		if summary == "" {
			summary = position
		} else {
			summary = summary + " • " + position
		}
	}
	leftContent := m.renderSelectableList(width, rows, cursor, offset)
	if len(rows) == 0 {
		leftContent = strings.Join(m.routeEmptyStateLines(m.route), "\n")
	}
	if width < 118 || m.height < 32 {
		lines := []string{}
		if strings.TrimSpace(deck) != "" {
			lines = append(lines, deck)
		}
		lines = append(lines, m.renderPanelCard(width, listTitle, leftContent))
		if compactPanels != nil {
			lines = append(lines, compactPanels(width)...)
		}
		return strings.Join(lines, gap)
	}

	leftWidth, rightWidth, stack := splitShellColumns(width, len(m.app.tuiTheme().gap()), leftMin, rightMin)
	leftBody := leftContent
	if len(rows) > 0 {
		leftBody = m.renderSelectableList(leftWidth, rows, cursor, offset)
	}
	left := m.renderPanelCardWithSummary(leftWidth, listTitle, summary, leftBody)
	right := ""
	if rightPanels != nil {
		right = strings.Join(rightPanels(rightWidth), "\n\n")
	}
	if stack {
		if strings.TrimSpace(right) == "" {
			if strings.TrimSpace(deck) == "" {
				return left
			}
			return strings.Join([]string{deck, left}, gap)
		}
		if strings.TrimSpace(deck) == "" {
			return strings.Join([]string{left, right}, gap)
		}
		return strings.Join([]string{deck, left, right}, gap)
	}
	if strings.TrimSpace(right) == "" {
		if strings.TrimSpace(deck) == "" {
			return left
		}
		return strings.Join([]string{deck, left}, gap)
	}
	if strings.TrimSpace(deck) == "" {
		return lipgloss.JoinVertical(lipgloss.Left, lipgloss.JoinHorizontal(lipgloss.Top, left, m.app.tuiTheme().gap(), right))
	}
	return strings.Join([]string{deck, lipgloss.JoinHorizontal(lipgloss.Top, left, m.app.tuiTheme().gap(), right)}, gap)
}

func (m appShellModel) selectionSummary(rows selectableRows, cursor int, offset int) string {
	if len(rows) == 0 {
		return ""
	}
	index := cursor - offset
	if index < 0 {
		index = 0
	}
	if index >= len(rows) {
		index = len(rows) - 1
	}
	return m.app.catalog.T("app_selection_position", index+1, len(rows))
}

func (m appShellModel) selectionContextSummary(rows selectableRows, cursor int, offset int) string {
	if len(rows) == 0 {
		return ""
	}
	index := cursor - offset
	if index < 0 {
		index = 0
	}
	if index >= len(rows) {
		index = len(rows) - 1
	}
	position := m.selectionSummary(rows, cursor, offset)
	label := trimForSelect(rows[index].Label, 26)
	if strings.TrimSpace(label) == "" {
		return position
	}
	if strings.TrimSpace(position) == "" {
		return label
	}
	return position + " • " + label
}

func (m appShellModel) routeEmptyStateLines(route appRoute) []string {
	switch route {
	case appRouteProjects:
		return []string{
			m.app.catalog.T("projects_focus_empty"),
			m.app.catalog.T("app_action_select_current_hint"),
			m.app.catalog.T("app_action_pick_folder_hint"),
		}
	case appRouteRuns:
		return []string{
			m.app.catalog.T("runs_focus_empty"),
			m.app.catalog.T("app_live_scan_next_runs"),
			m.app.catalog.T("app_action_start_scan_hint"),
		}
	case appRouteFindings:
		lines := []string{m.app.catalog.T("findings_focus_clean")}
		if strings.TrimSpace(m.findingsScopeRun) != "" {
			lines = append(lines, m.findingsScopeLabel(), m.app.catalog.T("app_action_clear_findings_scope_hint"))
		} else {
			lines = append(lines, m.app.catalog.T("app_action_start_scan_hint"))
		}
		return lines
	case appRouteRuntime:
		return []string{
			m.runtimeFocusMessage(),
			m.runtimeSnapshotSummary(),
			m.app.catalog.T("runtime_doctor_title"),
		}
	default:
		return []string{m.app.catalog.T("empty_state")}
	}
}

func (m appShellModel) detailViewportHeight() int {
	switch {
	case m.height >= 42:
		return 18
	case m.height >= 34:
		return 14
	default:
		return 10
	}
}

func (m appShellModel) renderDetailViewport(width int, content string) string {
	content = strings.TrimSpace(content)
	if content == "" {
		return "-"
	}
	viewWidth := maxInt(24, shellPanelWidth(width)-6)
	v := viewport.New(viewWidth, m.detailViewportHeight())
	v.SetContent(content)
	v.SetYOffset(m.detailScroll)
	lines := []string{v.View()}
	if v.TotalLineCount() > v.Height {
		lines = append(lines, m.app.tuiTheme().mutedStyle().Render(
			fmt.Sprintf("%s • %s %d/%d",
				m.app.catalog.T("app_help_scroll_hint"),
				strings.ToLower(m.app.catalog.T("show_details")),
				v.YOffset+1,
				v.TotalLineCount(),
			),
		))
	}
	return strings.Join(lines, "\n")
}

func (m appShellModel) renderHelpBar(width int) string {
	if width < 72 {
		return m.app.tuiTheme().helpStyle().Render(m.footerText())
	}
	theme := m.app.tuiTheme()
	hints := m.commandHints()
	if width < 118 && len(hints) > 4 {
		hints = hints[:4]
	}
	segments := make([]string, 0, len(hints))
	for _, hint := range hints {
		segments = append(segments, lipgloss.JoinHorizontal(
			lipgloss.Left,
			theme.chipStyle(true).Render(hint.Key),
			" ",
			theme.helpStyle().Render(hint.Label),
		))
	}
	row := strings.Join(segments, theme.mutedStyle().Render("   "))
	return theme.commandRibbonStyle(width).Render(row)
}

func (m appShellModel) commandHints() []commandHint {
	base := []commandHint{
		{Key: "1-6", Label: m.app.catalog.T("app_help_switch")},
		{Key: "↑↓", Label: m.app.catalog.T("app_help_move")},
		{Key: "enter", Label: m.app.catalog.T("app_help_open")},
		{Key: "/", Label: m.app.catalog.T("app_help_palette")},
		{Key: "q", Label: m.app.catalog.T("app_help_quit")},
	}
	switch m.route {
	case appRouteHome:
		base = append(base,
			commandHint{Key: "P", Label: m.app.catalog.T("app_action_open_project_picker")},
		)
	case appRouteProjects:
		base = append(base,
			commandHint{Key: "s", Label: m.app.catalog.T("app_action_select_current")},
			commandHint{Key: "p", Label: m.app.catalog.T("app_action_pick_folder")},
		)
	case appRouteScanReview:
		base = append(base,
			commandHint{Key: "p", Label: m.app.catalog.T("app_help_preset")},
			commandHint{Key: "i", Label: m.app.catalog.T("app_help_isolation")},
			commandHint{Key: "a", Label: m.app.catalog.T("app_help_active")},
			commandHint{Key: "u", Label: m.app.catalog.T("app_help_target")},
		)
	case appRouteLiveScan:
		if m.scanRunning {
			base = append(base, commandHint{Key: "x", Label: m.app.catalog.T("app_help_abort")})
		} else {
			base = append(base, commandHint{Key: "e", Label: m.app.catalog.T("export_title")})
		}
	case appRouteRuns:
		base = append(base,
			commandHint{Key: "o", Label: m.app.catalog.T("app_action_open_run_findings")},
			commandHint{Key: "c", Label: m.app.catalog.T("run_cancel_title")},
			commandHint{Key: "R", Label: m.app.catalog.T("run_retry_title")},
			commandHint{Key: "e", Label: m.app.catalog.T("export_title")},
		)
	case appRouteFindings:
		if strings.TrimSpace(m.findingsScopeRun) != "" {
			base = append(base, commandHint{Key: "⌫", Label: m.app.catalog.T("app_help_scope_clear")})
		}
		base = append(base,
			commandHint{Key: "f", Label: m.app.catalog.T("finding_filter_severity_label")},
			commandHint{Key: "g", Label: m.app.catalog.T("finding_filter_status_label")},
			commandHint{Key: "0", Label: m.app.catalog.T("app_help_filter_reset")},
		)
	}
	return base
}

func fitRenderedBlock(body string, maxHeight int) string {
	if maxHeight <= 0 {
		return ""
	}
	lines := strings.Split(body, "\n")
	if len(lines) <= maxHeight {
		return body
	}
	if maxHeight == 1 {
		return "…"
	}
	if maxHeight == 2 {
		return lines[0] + "\n…"
	}
	clipped := append([]string{}, lines[:maxHeight-1]...)
	clipped = append(clipped, "…")
	return strings.Join(clipped, "\n")
}

func shellPanelWidth(width int) int {
	return maxInt(20, width-2)
}

func joinHorizontalWithGap(items []string, gap string) string {
	if len(items) == 0 {
		return ""
	}
	if len(items) == 1 {
		return items[0]
	}
	parts := make([]string, 0, len(items)*2-1)
	for index, item := range items {
		if index > 0 {
			parts = append(parts, gap)
		}
		parts = append(parts, item)
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, parts...)
}

func nextReviewPreset(current reviewPreset) reviewPreset {
	order := []reviewPreset{reviewPresetFullDeep, reviewPresetQuickSafe, reviewPresetCompliance}
	index := slices.Index(order, current)
	if index < 0 {
		return reviewPresetFullDeep
	}
	return order[(index+1)%len(order)]
}

func nextCompliancePreset(current domain.CompliancePreset) domain.CompliancePreset {
	order := []domain.CompliancePreset{
		domain.CompliancePresetPCIDSS,
		domain.CompliancePresetSOC2,
		domain.CompliancePresetOWASPTop10,
		domain.CompliancePresetSANSTop25,
	}
	index := slices.Index(order, current)
	if index < 0 {
		return order[0]
	}
	return order[(index+1)%len(order)]
}

func nextIsolationMode(current domain.IsolationMode) domain.IsolationMode {
	order := []domain.IsolationMode{domain.IsolationAuto, domain.IsolationLocal, domain.IsolationContainer}
	index := slices.Index(order, current)
	if index < 0 {
		return domain.IsolationAuto
	}
	return order[(index+1)%len(order)]
}

func doctorSummaryLine(app *App, doctor domain.RuntimeDoctor) string {
	summary := app.summarizeDoctorIssues(doctor, 3)
	if strings.TrimSpace(summary) == "" || summary == "-" {
		return app.catalog.T("runtime_focus_ready")
	}
	return summary
}

func splitShellColumns(width, gap, minLeft, minRight int) (left int, right int, stack bool) {
	if width <= 0 {
		return minLeft, minRight, false
	}
	if width < minLeft+minRight+gap+8 {
		return width, width, true
	}
	total := width - gap
	switch {
	case minLeft > minRight:
		left = maxInt(minLeft, total*58/100)
	case minRight > minLeft:
		left = maxInt(minLeft, total*43/100)
	default:
		left = total / 2
	}
	right = total - left
	if left < minLeft || right < minRight {
		return width, width, true
	}
	return left, right, false
}

type selectableRows []appSelectableRow

func (rows selectableRows) at(index int) (appSelectableRow, bool) {
	if index < 0 || index >= len(rows) {
		return appSelectableRow{}, false
	}
	return rows[index], true
}
