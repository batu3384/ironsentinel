package cli

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func (m consoleShellModel) View() string {
	if mission, ok := m.activeMissionModel(); ok {
		return m.renderMissionSurface(mission)
	}
	return m.renderLaunchSurface()
}

func (m consoleShellModel) renderLaunchSurface() string {
	theme := m.app.tuiTheme()
	title := m.app.catalog.T("console_title")
	if m.width == 0 || m.height == 0 {
		return theme.docStyle().Render(title)
	}

	projectLabel := m.launchProjectLabel()
	if projectLabel == "" {
		projectLabel = m.app.catalog.T("console_launch_target_empty")
	}
	lines := []string{
		theme.titleStyle().Render(title),
		theme.subtitleStyle().Render(m.app.catalog.T("console_launch_subtitle")),
		theme.subtitleStyle().Render(fmt.Sprintf("%s: %s", m.app.catalog.T("console_launch_target_label"), projectLabel)),
		theme.subtitleStyle().Render(fmt.Sprintf("%s: %s", m.app.catalog.T("console_launch_readiness_label"), m.launchReadinessLabel())),
		theme.eyebrowStyle().Render(m.app.catalog.T("console_launch_primary_action")),
		theme.subtitleStyle().Render(m.app.catalog.T("console_launch_hint")),
	}
	if strings.TrimSpace(m.launch.Notice) != "" {
		lines = append(lines, theme.noticeStyle(m.launch.Alert).Render(m.launch.Notice))
	}
	return theme.docStyle().Render(lipgloss.JoinVertical(lipgloss.Left, lines...))
}

func (m consoleShellModel) renderMissionSurface(mission scanMissionModel) string {
	theme := m.app.tuiTheme()
	renderMission := mission
	mainWidth := mission.missionContentWidth()
	if m.drawer != consoleDrawerNone {
		drawerWidth := m.drawerWidth()
		renderMission.width = maxInt(72, m.width-drawerWidth-len(theme.gap())-4)
		mainWidth = renderMission.missionContentWidth()
	}

	main := m.renderMissionSurfaceContent(renderMission, mainWidth)
	content := main
	if drawer := m.renderDrawerPanel(m.drawerWidth()); drawer != "" {
		drawer = fitRenderedBlock(drawer, maxInt(1, m.height))
		content = lipgloss.JoinHorizontal(
			lipgloss.Top,
			main,
			theme.gap(),
			drawer,
		)
	}
	if m.width > lipgloss.Width(content)+2 {
		content = lipgloss.NewStyle().Width(maxInt(lipgloss.Width(content), m.width-2)).Align(lipgloss.Center).Render(content)
	}
	return theme.docStyle().Render(content)
}

func (m consoleShellModel) renderMissionSurfaceContent(mission scanMissionModel, width int) string {
	theme := m.app.tuiTheme()

	header := m.app.renderBrandConsoleMissionHeader(width, mission.subtitle())
	launchStrip := mission.renderLaunchStrip(width)
	if m.stage == consoleStageDebrief && mission.height < 34 {
		launchStrip = ""
	}
	decisionStrip := mission.renderMissionDecisionStrip(width)
	footer := theme.helpStyle().Render(m.consoleMissionFooter(mission))
	if strings.TrimSpace(mission.notice) != "" {
		footer = lipgloss.JoinVertical(lipgloss.Left, theme.noticeStyle(mission.alert).Render(mission.notice), footer)
	}

	debriefPanel := ""
	if m.stage == consoleStageDebrief && mission.done {
		debriefPanel = m.renderDebriefPanel(mission, width)
	}
	healthPanel := ""
	if m.shouldRenderMissionHealthPanel(mission) {
		healthPanel = mission.renderHealthFooter(width)
	}

	availableBodyHeight := maxInt(0, mission.height-lipgloss.Height(header)-lipgloss.Height(launchStrip)-lipgloss.Height(decisionStrip)-lipgloss.Height(footer))
	boardHeight, debriefHeight, healthHeight := missionSurfaceSectionHeights(availableBodyHeight, lipgloss.Height(debriefPanel), lipgloss.Height(healthPanel))
	boardPanel := m.renderMissionBodyPanel(mission, width, boardHeight)
	debriefBlock := ""
	if debriefHeight > 0 && strings.TrimSpace(debriefPanel) != "" {
		debriefBlock = fitRenderedBlock(debriefPanel, debriefHeight)
	}
	healthBlock := ""
	if healthHeight > 0 && strings.TrimSpace(healthPanel) != "" {
		healthBlock = fitRenderedBlock(healthPanel, healthHeight)
	}

	if overflow := mission.height - lipgloss.Height(lipgloss.JoinVertical(lipgloss.Left, nonEmptyStrings(header, launchStrip, decisionStrip, boardPanel, debriefBlock, healthBlock, footer)...)); overflow < 0 {
		launchStrip = fitRenderedBlock(launchStrip, maxInt(3, lipgloss.Height(launchStrip)+overflow))
	}
	if overflow := mission.height - lipgloss.Height(lipgloss.JoinVertical(lipgloss.Left, nonEmptyStrings(header, launchStrip, decisionStrip, boardPanel, debriefBlock, healthBlock, footer)...)); overflow < 0 {
		boardPanel = fitRenderedBlock(boardPanel, maxInt(1, lipgloss.Height(boardPanel)+overflow))
	}

	sections := []string{header, launchStrip, decisionStrip}
	if strings.TrimSpace(boardPanel) != "" {
		sections = append(sections, boardPanel)
	}
	if strings.TrimSpace(debriefBlock) != "" {
		sections = append(sections, debriefBlock)
	}
	if strings.TrimSpace(healthBlock) != "" {
		sections = append(sections, healthBlock)
	}
	sections = append(sections, footer)
	return lipgloss.JoinVertical(lipgloss.Left, sections...)
}

func (m consoleShellModel) renderDebriefPanel(mission scanMissionModel, width int) string {
	run := mission.consoleRun()
	findings := mission.findings
	lines := append([]string{m.app.catalog.T("app_label_report") + ":"}, m.app.consoleDebriefReportLines(run, findings, mission.requiredErr)...)
	return renderMissionBox(m.app.catalog.T("scan_debrief_title"), strings.Join(lines, "\n"))
}

func (m consoleShellModel) consoleMissionFooter(mission scanMissionModel) string {
	base := mission.footerText()
	if mission.done {
		return fmt.Sprintf("%s • %s", base, m.drawerHint())
	}
	return base
}

func (m consoleShellModel) shouldRenderMissionHealthPanel(mission scanMissionModel) bool {
	return mission.height >= 28 || (m.stage == consoleStageDebrief && mission.done)
}

func (m consoleShellModel) renderMissionBodyPanel(mission scanMissionModel, width, maxHeight int) string {
	if maxHeight <= 0 {
		return ""
	}
	if m.stage == consoleStageDebrief && mission.done {
		return fitRenderedBlock(mission.renderUltraCompactMissionBoard(width), maxHeight)
	}
	if mission.height < 28 || maxHeight < 14 {
		return mission.renderCompactMissionBoard(width, maxHeight)
	}
	return mission.renderMissionBoard(width, maxHeight)
}

func missionSurfaceSectionHeights(availableBodyHeight, debriefHeight, healthHeight int) (board int, debrief int, health int) {
	if availableBodyHeight <= 0 {
		return 0, 0, 0
	}

	if debriefHeight > 0 {
		board = minInt(maxInt(3, availableBodyHeight/8), 4)
		if availableBodyHeight < 16 {
			board = minInt(availableBodyHeight/4, 3)
		}
		if board < 3 {
			board = minInt(availableBodyHeight, 3)
		}
		health = 0
		debrief = maxInt(0, availableBodyHeight-board-health)
		if debrief < 12 && board > 3 {
			shift := minInt(board-3, 12-debrief)
			board -= shift
			debrief += shift
		}
		if debriefHeight < debrief {
			debrief = debriefHeight
			board = maxInt(1, availableBodyHeight-debrief-health)
		}
		return board, debrief, health
	}

	boardMin := minInt(availableBodyHeight, 8)
	if healthHeight > 0 {
		health = minInt(healthHeight, 3)
	}
	board = boardMin

	overflow := board + debrief + health - availableBodyHeight
	for overflow > 0 && health > 2 {
		health--
		overflow--
	}
	for overflow > 0 && debrief > 4 {
		debrief--
		overflow--
	}
	for overflow > 0 && board > 6 {
		board--
		overflow--
	}
	for overflow > 0 && health > 0 {
		health--
		overflow--
	}
	for overflow > 0 && debrief > 0 {
		debrief--
		overflow--
	}
	for overflow > 0 && board > 1 {
		board--
		overflow--
	}

	remaining := availableBodyHeight - board - debrief - health
	debrief += minInt(remaining, maxInt(0, debriefHeight-debrief))
	remaining = availableBodyHeight - board - debrief - health
	health += minInt(remaining, maxInt(0, healthHeight-health))
	remaining = availableBodyHeight - board - debrief - health
	board += maxInt(0, remaining)

	return board, debrief, health
}

func nonEmptyStrings(items ...string) []string {
	filtered := make([]string, 0, len(items))
	for _, item := range items {
		if strings.TrimSpace(item) == "" {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}
