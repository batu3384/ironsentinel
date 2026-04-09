package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/batu3384/ironsentinel/internal/domain"
)

type scanMissionAction string

const (
	scanMissionActionNone    scanMissionAction = ""
	scanMissionActionReview  scanMissionAction = "review"
	scanMissionActionDetails scanMissionAction = "details"
	scanMissionActionDoctor  scanMissionAction = "doctor"
)

type scanMissionOutcome struct {
	run         domain.ScanRun
	findings    []domain.Finding
	scanErr     error
	requiredErr error
	action      scanMissionAction
	reportPath  string
}

type scanMissionEventMsg struct {
	event domain.StreamEvent
	seq   int
}

type scanMissionDoneMsg struct {
	run      domain.ScanRun
	findings []domain.Finding
	err      error
	seq      int
}

type scanMissionTickMsg time.Time

type scanMissionModel struct {
	app              *App
	project          domain.Project
	profile          domain.ScanProfile
	historicalRuns   []domain.ScanRun
	doctor           domain.RuntimeDoctor
	projectTree      []string
	launchedAt       time.Time
	cpuBaseline      float64
	console          *liveScanConsole
	width            int
	height           int
	detailScroll     int
	done             bool
	aborting         bool
	notice           string
	alert            bool
	run              domain.ScanRun
	findings         []domain.Finding
	scanErr          error
	requiredErr      error
	action           scanMissionAction
	cancel           context.CancelFunc
	eventCh          <-chan domain.StreamEvent
	doneCh           <-chan scanMissionDoneMsg
	seq              int
	missionOnly      bool
	statusOnlyMotion bool
}

func (a *App) runFullscreenScanMode(ctx context.Context, project domain.Project, profile domain.ScanProfile) (scanMissionOutcome, error) {
	console := a.newLiveScanConsole(project, profile)
	if console == nil {
		console = &liveScanConsole{
			project:        project,
			profile:        profile,
			lastEvent:      a.catalog.T("scan_mc_boot"),
			lastStatus:     a.catalog.T("scan_mc_status_booting"),
			telemetry:      []string{a.catalog.T("scan_mc_boot")},
			recentFindings: make([]domain.Finding, 0, 5),
		}
	}

	ctx, cancel := context.WithCancel(commandContext(ctx))
	eventCh := make(chan domain.StreamEvent, 128)
	doneCh := make(chan scanMissionDoneMsg, 1)

	go func() {
		run, findings, err := a.service.Scan(ctx, project.ID, profile, func(event domain.StreamEvent) {
			emitMissionEvent(eventCh, event)
		})
		doneCh <- scanMissionDoneMsg{
			run:      run,
			findings: findings,
			err:      err,
		}
	}()

	model := scanMissionModel{
		app:            a,
		project:        project,
		profile:        profile,
		seq:            1,
		historicalRuns: a.service.ListRuns(),
		doctor:         a.runtimeDoctor(profile, false, false),
		projectTree:    buildProjectTreeSnapshot(project.LocationHint, 3, 18),
		launchedAt:     time.Now(),
		cpuBaseline:    missionCPUSeconds(),
		console:        console,
		cancel:         cancel,
		eventCh:        eventCh,
		doneCh:         doneCh,
	}
	model.width, model.height = initialTerminalViewport()

	finalModel, err := tea.NewProgram(model, tea.WithAltScreen()).Run()
	if err != nil {
		cancel()
		return scanMissionOutcome{}, err
	}

	result, ok := finalModel.(scanMissionModel)
	if !ok {
		cancel()
		return scanMissionOutcome{}, fmt.Errorf("unexpected scan mission model type")
	}

	return scanMissionOutcome{
		run:         result.run,
		findings:    result.findings,
		scanErr:     result.scanErr,
		requiredErr: result.requiredErr,
		action:      result.action,
	}, nil
}

func emitMissionEvent(ch chan<- domain.StreamEvent, event domain.StreamEvent) {
	select {
	case ch <- event:
		return
	default:
	}

	if event.Type == "finding.created" {
		return
	}

	timer := time.NewTimer(150 * time.Millisecond)
	defer timer.Stop()

	select {
	case ch <- event:
	case <-timer.C:
	}
}

func (m scanMissionModel) Init() tea.Cmd {
	return tea.Batch(waitForScanMissionEvent(m.eventCh, m.seq), waitForScanMissionDone(m.doneCh, m.seq), scanMissionTickCmd(m.app))
}

func (m scanMissionModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case scanMissionTickMsg:
		if !m.done && m.console != nil {
			m.console.frame++
		}
		return m, scanMissionTickCmd(m.app)
	case scanMissionEventMsg:
		if msg.seq != 0 && msg.seq != m.seq {
			return m, nil
		}
		if m.console != nil {
			m.console.update(m.app, msg.event)
		}
		m.run = msg.event.Run
		return m, waitForScanMissionEvent(m.eventCh, m.seq)
	case scanMissionDoneMsg:
		if msg.seq != 0 && msg.seq != m.seq {
			return m, nil
		}
		m.done = true
		m.run = msg.run
		m.findings = msg.findings
		m.scanErr = msg.err
		m.requiredErr = m.app.enforceRequiredModuleResults(msg.run, m.profile.Modules)
		if m.console != nil {
			m.console.run = msg.run
			m.console.frame++
		}
		m.setNotice(m.doneNotice(), m.requiredErr != nil || msg.err != nil)
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			if !m.done {
				if m.cancel != nil {
					m.cancel()
				}
				m.aborting = true
				m.setNotice(m.app.catalog.T("scan_mode_live_cancel_requested"), true)
				return m, nil
			}
			m.action = scanMissionActionNone
			return m, tea.Quit
		case "esc":
			if m.done {
				m.action = scanMissionActionNone
				return m, tea.Quit
			}
		case "enter":
			if m.done {
				m.action = m.recommendedAction()
				return m, tea.Quit
			}
		case "d":
			if m.done {
				m.action = scanMissionActionDetails
				return m, tea.Quit
			}
		case "pgdown", "ctrl+d":
			m.detailScroll += maxInt(1, m.detailViewportHeight()/2)
			return m, nil
		case "pgup", "ctrl+u":
			m.detailScroll -= maxInt(1, m.detailViewportHeight()/2)
			if m.detailScroll < 0 {
				m.detailScroll = 0
			}
			return m, nil
		}
	}
	return m, nil
}

func (m scanMissionModel) View() string {
	theme := m.app.tuiTheme()
	contentWidth := m.missionContentWidth()

	frame := 0
	if m.console != nil && !m.statusOnlyMotion {
		frame = m.console.frame
	}
	headerLines := []string{}
	if m.statusOnlyMotion {
		headerLines = append(headerLines, m.app.renderBrandConsoleMissionHeader(contentWidth, m.subtitle()))
	} else {
		headerLines = append(headerLines, m.app.renderBrandConsoleHeaderForRoute(contentWidth, frame, m.subtitle(), appRouteLiveScan))
	}
	launchStrip := m.renderLaunchStrip(contentWidth)
	healthPanel := m.renderHealthFooter(contentWidth)

	footer := theme.helpStyle().Render(m.footerText())
	if strings.TrimSpace(m.notice) != "" {
		footer = lipgloss.JoinVertical(lipgloss.Left, theme.noticeStyle(m.alert).Render(m.notice), footer)
	}

	sections := []string{strings.Join(headerLines, "\n"), launchStrip}
	if m.height < 28 {
		availableBoardHeight := maxInt(8, m.height-lipgloss.Height(strings.Join(headerLines, "\n"))-lipgloss.Height(launchStrip)-lipgloss.Height(footer)-4)
		sections = append(sections, m.renderCompactMissionBoard(contentWidth, availableBoardHeight))
	} else {
		availableBoardHeight := maxInt(8, m.height-lipgloss.Height(strings.Join(headerLines, "\n"))-lipgloss.Height(launchStrip)-lipgloss.Height(healthPanel)-lipgloss.Height(footer)-5)
		sections = append(sections, m.renderMissionBoard(contentWidth, availableBoardHeight), healthPanel)
	}
	sections = append(sections, footer)
	content := lipgloss.JoinVertical(lipgloss.Left, sections...)
	if m.width > contentWidth+2 {
		content = lipgloss.NewStyle().Width(maxInt(contentWidth, m.width-2)).Align(lipgloss.Center).Render(content)
	}
	return theme.docStyle().Render(content)
}

func (m scanMissionModel) missionContentWidth() int {
	available := m.width - 4
	if available < 60 {
		return maxInt(44, m.width-2)
	}
	return minInt(available, 156)
}

func (m scanMissionModel) renderLaunchStrip(width int) string {
	run := m.consoleRun()
	done, total := m.progressCounts()
	_, _, retried := m.app.moduleExecutionCounts(run.ModuleResults)
	elapsed := time.Since(m.launchedAt).Round(time.Second)
	if elapsed < 0 {
		elapsed = 0
	}

	posture := strings.ToUpper(m.app.scanPostureLabel(run))
	if posture == "" {
		posture = strings.ToUpper(m.app.catalog.T("scan_mc_status_booting"))
	}
	activePhase := m.app.catalog.T("scan_phase_general")
	activeModule := "-"
	if m.console != nil {
		activePhase = defaultString(m.console.lastPhase, m.app.catalog.T("scan_phase_general"))
		activeModule = defaultString(m.console.lastModule, "-")
	}
	activeTool := m.missionActiveTool()
	status := m.missionStatusText()
	recentEvent := trimForSelect(defaultString(m.console.lastEvent, m.app.catalog.T("scan_mc_waiting")), maxInt(24, width-24))
	isolation := strings.ToUpper(string(m.profile.Isolation))
	if isolation == "" {
		isolation = strings.ToUpper(string(domain.IsolationAuto))
	}
	preflight := strings.ToUpper(string(domain.RuntimeCheckWarn))
	if m.doctor.Ready {
		preflight = strings.ToUpper(string(domain.RuntimeCheckPass))
	}
	if len(m.doctor.Missing) > 0 || len(m.doctor.FailedVerification) > 0 || len(m.doctor.FailedAssets) > 0 {
		preflight = strings.ToUpper(string(domain.RuntimeCheckFail))
	}
	risk := strings.ToUpper(m.app.liveRiskLabel(
		run.Summary.CountsBySeverity[domain.SeverityCritical],
		run.Summary.CountsBySeverity[domain.SeverityHigh],
		run.Summary.CountsBySeverity[domain.SeverityMedium],
		run.Summary.CountsBySeverity[domain.SeverityLow],
	))
	title := strings.ToUpper(activeModule)
	if strings.TrimSpace(title) == "" || title == "-" {
		title = status
	}
	body := fmt.Sprintf("%s • %s • %d/%d", trimForSelect(activePhase, 24), risk, done, total)
	lines := renderFactRows(m.app.tuiTheme(), width,
		factPair{Label: m.app.catalog.T("status"), Value: status},
		factPair{Label: m.app.catalog.T("app_label_target"), Value: trimForSelect(m.project.LocationHint, maxInt(24, width-22))},
		factPair{Label: m.app.phaseLabel(), Value: trimForSelect(activePhase, maxInt(24, width-22))},
		factPair{Label: m.app.catalog.T("app_label_module"), Value: strings.ToUpper(activeModule)},
		factPair{Label: m.app.toolLabel(), Value: activeTool},
		factPair{Label: m.app.catalog.T("scan_mc_activity"), Value: recentEvent},
		factPair{Label: m.app.catalog.T("app_label_health"), Value: fmt.Sprintf("%s • %s • %s", preflight, strings.ToUpper(isolation), posture)},
		factPair{Label: m.app.catalog.T("app_label_findings"), Value: fmt.Sprintf("%d • %s %d • %s %s", run.Summary.TotalFindings, strings.ToLower(m.app.catalog.T("module_retried_count")), retried, strings.ToLower(m.app.catalog.T("scan_launch_clock")), elapsed.String())},
	)
	return m.renderMissionHeroPanel(width, status, title, body, lines...)
}

func (m *scanMissionModel) setNotice(text string, alert bool) {
	m.notice = strings.TrimSpace(text)
	m.alert = alert
}

func (m scanMissionModel) recommendedAction() scanMissionAction {
	if m.requiredErr != nil {
		return scanMissionActionDoctor
	}
	if len(m.findings) > 0 {
		return scanMissionActionReview
	}
	return scanMissionActionDetails
}

func (m scanMissionModel) subtitle() string {
	if m.missionOnly {
		return m.app.consoleMissionSubtitle(m.done)
	}
	if m.done {
		return m.app.catalog.T("scan_mode_live_subtitle_done")
	}
	return m.app.catalog.T("scan_mode_live_subtitle_running")
}

func (m scanMissionModel) missionStatusText() string {
	switch {
	case m.aborting && !m.done:
		return strings.ToUpper(string(domain.ScanCanceled))
	case m.done:
		return strings.ToUpper(string(m.consoleRun().Status))
	default:
		return strings.ToUpper(string(domain.ScanRunning))
	}
}

func (m scanMissionModel) missionActiveTool() string {
	if m.console != nil {
		if tool := strings.TrimSpace(m.console.lastTool); tool != "" {
			return strings.ToUpper(tool)
		}
		if module := strings.TrimSpace(m.console.lastModule); module != "" {
			return strings.ToUpper(m.app.moduleToolLabel(module))
		}
	}
	return strings.ToUpper(m.app.moduleToolLabel(""))
}

func (m scanMissionModel) doneNotice() string {
	switch m.recommendedAction() {
	case scanMissionActionDoctor:
		return m.app.catalog.T("scan_mode_live_notice_doctor")
	case scanMissionActionReview:
		return m.app.catalog.T("scan_mode_live_notice_review")
	default:
		return m.app.catalog.T("scan_mode_live_notice_details")
	}
}

func (m scanMissionModel) footerText() string {
	if m.missionOnly {
		return m.app.consoleMissionFooter(m.done, m.aborting)
	}
	scrollHint := m.app.catalog.T("app_help_scroll_hint")
	switch {
	case !m.done && m.aborting:
		return fmt.Sprintf("%s • %s", m.app.catalog.T("scan_mode_live_footer_canceling"), scrollHint)
	case !m.done:
		return fmt.Sprintf("%s • %s", m.app.catalog.T("scan_mode_live_footer_running"), scrollHint)
	case m.requiredErr != nil:
		return fmt.Sprintf("%s • %s", m.app.catalog.T("scan_mode_live_footer_doctor"), scrollHint)
	case len(m.findings) > 0:
		return fmt.Sprintf("%s • %s", m.app.catalog.T("scan_mode_live_footer_review"), scrollHint)
	default:
		return fmt.Sprintf("%s • %s", m.app.catalog.T("scan_mode_live_footer_clean"), scrollHint)
	}
}

func (m scanMissionModel) renderCompactMissionBoard(width, maxHeight int) string {
	return m.renderCompactMissionBoardWithViewport(width, maxHeight, m.renderDetailViewport)
}

func (m scanMissionModel) renderCompactMissionBoardWithViewport(width, maxHeight int, renderDetail func(int, string) string) string {
	if maxHeight <= 0 {
		return ""
	}
	if maxHeight < 16 {
		return fitRenderedBlock(m.renderUltraCompactMissionBoard(width), maxHeight)
	}
	briefHeight := maxInt(5, minInt(7, maxHeight/4+1))
	executionHeight := maxInt(5, minInt(8, maxHeight/4+2))
	threatHeight := maxInt(4, minInt(7, maxHeight/4+1))
	remaining := maxHeight - briefHeight - executionHeight - threatHeight - 3
	if remaining < 4 {
		remaining = 4
	}
	sections := []string{
		fitRenderedBlock(m.renderMissionBriefPanel(width), briefHeight),
		fitRenderedBlock(renderDetail(width, m.renderMissionExecutionPanel(width)), executionHeight),
		fitRenderedBlock(renderDetail(width, m.renderMissionThreatPanel(width)), threatHeight),
		fitRenderedBlock(m.renderCompactHealthPanel(width), remaining),
	}
	return strings.Join(sections, "\n\n")
}

func (m scanMissionModel) renderMissionBoard(width, maxHeight int) string {
	return m.renderMissionBoardWithViewport(width, maxHeight, m.renderDetailViewport)
}

func (m scanMissionModel) renderMissionBoardWithViewport(width, maxHeight int, renderDetail func(int, string) string) string {
	theme := m.app.tuiTheme()
	gap := len(theme.gap())
	if maxHeight <= 0 {
		maxHeight = 12
	}
	switch {
	case width < 108:
		briefHeight := maxInt(4, minInt(6, maxHeight/4+1))
		laneHeight := maxInt(5, minInt(8, maxHeight/4+1))
		executionHeight := maxInt(5, minInt(8, maxHeight/4+1))
		threatHeight := maxInt(4, maxHeight-briefHeight-laneHeight-executionHeight-3)
		sections := []string{
			fitRenderedBlock(m.renderMissionBriefPanel(width), briefHeight),
			fitRenderedBlock(renderDetail(width, m.renderMissionLanePanel(width)), laneHeight),
			fitRenderedBlock(renderDetail(width, m.renderMissionExecutionPanel(width)), executionHeight),
			fitRenderedBlock(renderDetail(width, m.renderMissionThreatPanel(width)), threatHeight),
		}
		return strings.Join(sections, "\n\n")
	default:
		leftWidth, rightWidth, stack := splitShellColumns(width, gap, 46, 44)
		briefHeight := maxInt(5, minInt(7, maxHeight/3))
		laneHeight := maxInt(6, minInt(9, maxHeight/3))
		executionHeight := maxInt(6, maxHeight-briefHeight-laneHeight-2)
		leftPanel := strings.Join([]string{
			fitRenderedBlock(m.renderMissionBriefPanel(leftWidth), briefHeight),
			fitRenderedBlock(renderDetail(leftWidth, m.renderMissionLanePanel(leftWidth)), laneHeight),
			fitRenderedBlock(renderDetail(leftWidth, m.renderMissionExecutionPanel(leftWidth)), executionHeight),
		}, "\n\n")
		rightPanel := fitRenderedBlock(renderDetail(rightWidth, m.renderMissionThreatPanel(rightWidth)), maxHeight)
		if stack {
			return strings.Join([]string{leftPanel, rightPanel}, "\n\n")
		}
		return lipgloss.JoinHorizontal(lipgloss.Top, leftPanel, theme.gap(), rightPanel)
	}
}

func (m scanMissionModel) renderCompactHealthPanel(width int) string {
	metrics := m.runtimeMetrics()
	lines := []string{
		fmt.Sprintf("%s: %s", m.app.catalog.T("scan_mode_live_metrics_health"), metrics.HealthLabel),
		trimForSelect(metrics.HealthSummary, maxInt(18, width-12)),
		fmt.Sprintf("%s: %.1f%% • %.1f MiB", m.app.catalog.T("scan_mode_live_metrics_cpu"), metrics.CPUPercent, metrics.MemoryMiB),
		fmt.Sprintf("%s: %.1f/min", m.app.catalog.T("scan_mode_live_metrics_findings"), metrics.FindingPerMin),
	}
	return renderMissionBox(m.app.catalog.T("scan_mode_live_metrics_health"), strings.Join(lines, "\n"))
}

func (m scanMissionModel) renderUltraCompactMissionBoard(width int) string {
	run := m.consoleRun()
	activeLane := strings.ToUpper(defaultString(m.console.lastPhase, m.app.catalog.T("scan_phase_general")))
	activeModule := strings.ToUpper(defaultString(m.console.lastModule, "-"))
	metrics := m.runtimeMetrics()
	lines := []string{
		fmt.Sprintf("%s: %s • %s", m.app.catalog.T("scan_mode_live_brief_title"), trimForSelect(m.project.DisplayName, maxInt(14, width-28)), trimForSelect(activeLane, 22)),
		fmt.Sprintf("%s: %s", m.app.catalog.T("scan_mode_live_execution_title"), trimForSelect(activeModule, maxInt(12, width-24))),
		fmt.Sprintf("%s: %s", m.app.catalog.T("scan_mode_live_threat_title"), strings.ToUpper(m.app.liveRiskLabel(
			run.Summary.CountsBySeverity[domain.SeverityCritical],
			run.Summary.CountsBySeverity[domain.SeverityHigh],
			run.Summary.CountsBySeverity[domain.SeverityMedium],
			run.Summary.CountsBySeverity[domain.SeverityLow],
		))),
		fmt.Sprintf("%s: %s", m.app.catalog.T("scan_mode_live_metrics_health"), metrics.HealthLabel),
	}
	return renderMissionBox(m.app.catalog.T("scan_mode_live_signal_title"), strings.Join(lines, "\n"))
}

func (m scanMissionModel) renderMissionHeroPanel(width int, eyebrow, title, body string, lines ...string) string {
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

func (m scanMissionModel) renderMissionCardGrid(cards [][3]string, width int, maxColumns int) string {
	if len(cards) == 0 {
		return ""
	}
	if maxColumns <= 0 {
		maxColumns = 2
	}
	theme := m.app.tuiTheme()
	usableWidth := maxInt(36, width)
	columns := minInt(maxColumns, len(cards))
	switch {
	case usableWidth < 70:
		columns = 1
	case usableWidth < 116 && columns > 2:
		columns = 2
	}
	cardWidth := maxInt(24, (usableWidth-(columns-1)*len(theme.gap()))/columns)
	rows := make([]string, 0, (len(cards)+columns-1)/columns)
	for start := 0; start < len(cards); start += columns {
		end := start + columns
		if end > len(cards) {
			end = len(cards)
		}
		rendered := make([]string, 0, end-start)
		for _, card := range cards[start:end] {
			body := strings.Join([]string{
				theme.sectionTitleStyle().Render(card[0]),
				theme.titleStyle().Render(card[1]),
				theme.mutedStyle().Render(card[2]),
			}, "\n")
			rendered = append(rendered, theme.metricCardStyle(cardWidth).Width(cardWidth).Render(body))
		}
		rows = append(rows, joinHorizontalWithGap(rendered, theme.gap()))
	}
	return strings.Join(rows, "\n")
}

func (m scanMissionModel) progressCounts() (int, int) {
	total := max(1, m.app.moduleCount(m.profile.Modules))
	done := 0
	for _, module := range m.consoleRun().ModuleResults {
		switch module.Status {
		case domain.ModuleCompleted, domain.ModuleFailed, domain.ModuleSkipped:
			done++
		}
	}
	if done > total {
		done = total
	}
	return done, total
}

func (m scanMissionModel) consoleRun() domain.ScanRun {
	if m.console != nil {
		return m.console.run
	}
	return m.run
}

func (m scanMissionModel) detailViewportHeight() int {
	switch {
	case m.height >= 42:
		return 18
	case m.height >= 34:
		return 14
	default:
		return 10
	}
}

func (m scanMissionModel) renderDetailViewport(width int, content string) string {
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

func waitForScanMissionEvent(ch <-chan domain.StreamEvent, seq int) tea.Cmd {
	return func() tea.Msg {
		event, ok := <-ch
		if !ok {
			return nil
		}
		return scanMissionEventMsg{event: event, seq: seq}
	}
}

func waitForScanMissionDone(ch <-chan scanMissionDoneMsg, seq int) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-ch
		if !ok {
			return nil
		}
		msg.seq = seq
		return msg
	}
}

func scanMissionTickCmd(app *App) tea.Cmd {
	if app != nil && app.reducedMotion() {
		return nil
	}
	return tea.Tick(150*time.Millisecond, func(t time.Time) tea.Msg {
		return scanMissionTickMsg(t)
	})
}
