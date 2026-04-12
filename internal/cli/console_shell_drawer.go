package cli

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/batu3384/ironsentinel/internal/domain"
)

func (m consoleShellModel) drawerWidth() int {
	return minInt(46, maxInt(38, m.width/4))
}

func (m consoleShellModel) drawerTitle() string {
	switch m.drawer {
	case consoleDrawerFindings:
		return m.app.catalog.T("findings_title")
	case consoleDrawerRuntime:
		return m.app.catalog.T("runtime_command_title")
	case consoleDrawerRun:
		return m.app.catalog.T("show_title")
	default:
		return ""
	}
}

func (m consoleShellModel) renderDrawerPanel(width int) string {
	if m.drawer == consoleDrawerNone || !m.mission.done {
		return ""
	}

	theme := m.app.tuiTheme()
	sectionWidth := maxInt(18, width-6)
	sections := []string{
		theme.eyebrowStyle().Render(m.app.displayUpper(m.app.catalog.T("show_details"))),
		theme.titleStyle().Render(m.drawerTitle()),
		theme.mutedStyle().Render(m.drawerHint()),
	}

	for _, section := range m.drawerSections(sectionWidth) {
		if strings.TrimSpace(section) == "" {
			continue
		}
		sections = append(sections, "", section)
	}

	return theme.panelStyle(width).Width(width).Render(strings.Join(sections, "\n"))
}

func (m consoleShellModel) drawerHint() string {
	return m.app.catalog.T("console_drawer_hint")
}

func (m consoleShellModel) drawerSections(width int) []string {
	switch m.drawer {
	case consoleDrawerFindings:
		return m.findingsDrawerSections(width)
	case consoleDrawerRuntime:
		return m.runtimeDrawerSections(width)
	case consoleDrawerRun:
		return m.runDrawerSections(width)
	default:
		return nil
	}
}

func (m consoleShellModel) findingsDrawerSections(width int) []string {
	findings := m.mission.findings
	run := m.mission.run
	overview := []string{
		fmt.Sprintf("%s: %d", m.app.catalog.T("app_label_findings"), run.Summary.TotalFindings),
		fmt.Sprintf("%s: %s", m.app.catalog.T("status"), m.app.displayUpper(m.app.scanPostureLabel(run))),
		m.app.findingTriageSummary(findings),
	}
	if top, ok := m.app.nextReviewFinding(findings); ok {
		overview = append(overview, fmt.Sprintf("%s: %s", m.app.catalog.T("show_details"), trimForSelect(m.app.hottestFindingLine(top, maxInt(18, width-12)), width)))
	}

	queueLines := []string{m.app.catalog.T("empty_state")}
	hot := m.app.prioritizedFindings(findings, 3)
	if len(hot) > 0 {
		queueLines = make([]string, 0, len(hot))
		for _, finding := range hot {
			location := trimForSelect(coalesceString(finding.Location, finding.Module), maxInt(16, width-12))
			queueLines = append(queueLines, fmt.Sprintf("%s\n%s", trimForSelect(m.app.hottestFindingLine(finding, maxInt(18, width-4)), width), location))
		}
	}

	return []string{
		renderConsoleDrawerSection(m.app, width, m.app.catalog.T("summary_total"), overview...),
		renderConsoleDrawerSection(m.app, width, m.app.catalog.T("scan_mc_handoff_title"), queueLines...),
	}
}

func (m consoleShellModel) runtimeDrawerSections(width int) []string {
	doctor := m.mission.doctor
	pass, warn, fail, skip := runtimeDoctorCheckCounts(doctor)

	overview := []string{
		m.runtimeDrawerSummary(doctor),
		fmt.Sprintf("%s: %s", m.app.catalog.T("app_label_health"), m.runtimeDrawerHealthLabel(doctor)),
	}
	health := []string{
		fmt.Sprintf("%s %d • %s %d • %s %d • %s %d",
			strings.ToLower(m.app.runtimeCheckStatusText(domain.RuntimeCheckPass)), pass,
			strings.ToLower(m.app.runtimeCheckStatusText(domain.RuntimeCheckWarn)), warn,
			strings.ToLower(m.app.runtimeCheckStatusText(domain.RuntimeCheckFail)), fail,
			strings.ToLower(m.app.runtimeCheckStatusText(domain.RuntimeCheckSkip)), skip,
		),
		m.app.summarizeDoctorIssues(doctor, 3),
	}

	return []string{
		renderConsoleDrawerSection(m.app, width, m.app.catalog.T("runtime_trust_signal_title"), overview...),
		renderConsoleDrawerSection(m.app, width, m.app.catalog.T("runtime_doctor_title"), health...),
	}
}

func (m consoleShellModel) runDrawerSections(width int) []string {
	run := m.mission.run
	overview := []string{
		fmt.Sprintf("%s: %s", m.app.catalog.T("run_id"), coalesceString(run.ID, "-")),
		fmt.Sprintf("%s: %s", m.app.catalog.T("scan_mode"), m.app.displayUpper(m.app.modeLabel(run.Profile.Mode))),
		fmt.Sprintf("%s: %s", m.app.catalog.T("coverage_profile"), m.app.displayUpper(m.app.coverageLabel(run.Profile.Coverage))),
		fmt.Sprintf("%s: %s", m.app.catalog.T("status"), m.app.displayUpper(m.app.scanStatusLabel(run.Status))),
	}
	moduleLines := []string{
		m.app.consoleDebriefModuleSummary(run),
		fmt.Sprintf("%s: %d", m.app.catalog.T("app_label_findings"), run.Summary.TotalFindings),
	}
	for _, module := range limitModuleResults(run.ModuleResults, 3) {
		moduleLines = append(moduleLines, fmt.Sprintf("%s • %s", m.app.technicalUpper(module.Name), m.app.displayUpper(m.app.moduleStatusLabel(module.Status))))
	}

	return []string{
		renderConsoleDrawerSection(m.app, width, m.app.catalog.T("summary_total"), overview...),
		renderConsoleDrawerSection(m.app, width, m.app.catalog.T("scan_phase_verdicts_title"), moduleLines...),
	}
}

func renderConsoleDrawerSection(app *App, width int, title string, lines ...string) string {
	theme := app.tuiTheme()
	trimmed := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		trimmed = append(trimmed, trimForSelect(line, maxInt(16, width)))
	}
	if len(trimmed) == 0 {
		trimmed = append(trimmed, "-")
	}
	return lipgloss.JoinVertical(
		lipgloss.Left,
		theme.sectionTitleStyle().Render(title),
		theme.sectionBodyStyle().Render(strings.Join(trimmed, "\n")),
	)
}

func limitModuleResults(items []domain.ModuleResult, count int) []domain.ModuleResult {
	if len(items) <= count {
		return items
	}
	return items[:count]
}

func (m consoleShellModel) runtimeDrawerSummary(doctor domain.RuntimeDoctor) string {
	pass, warn, fail, skip := runtimeDoctorCheckCounts(doctor)
	return fmt.Sprintf(
		"%d %s • %d %s • %d %s • %d %s",
		pass,
		strings.ToLower(m.app.runtimeCheckStatusText(domain.RuntimeCheckPass)),
		warn,
		strings.ToLower(m.app.runtimeCheckStatusText(domain.RuntimeCheckWarn)),
		fail,
		strings.ToLower(m.app.runtimeCheckStatusText(domain.RuntimeCheckFail)),
		skip,
		strings.ToLower(m.app.runtimeCheckStatusText(domain.RuntimeCheckSkip)),
	)
}

func (m consoleShellModel) runtimeDrawerHealthLabel(doctor domain.RuntimeDoctor) string {
	if doctor.Ready {
		return m.app.catalog.T("runtime_focus_ready")
	}
	return m.app.catalog.T("runtime_focus_repair")
}
