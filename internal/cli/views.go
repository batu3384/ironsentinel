package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/pterm/pterm"

	"github.com/batu3384/ironsentinel/internal/domain"
	"github.com/batu3384/ironsentinel/internal/i18n"
)

type liveScanTracker struct {
	spinner   *pterm.SpinnerPrinter
	plain     bool
	total     int
	completed int
	failed    int
	skipped   int
	findings  int
	critical  int
	high      int
	medium    int
	low       int
}

type liveScanConsole struct {
	project        domain.Project
	profile        domain.ScanProfile
	run            domain.ScanRun
	eventCount     int
	lastEvent      string
	lastFinding    string
	lastModule     string
	lastTool       string
	lastPhase      string
	lastStatus     string
	recentFindings []domain.Finding
	telemetry      []string
	frame          int
}

func (a *App) renderInitialLanguageOnboarding() {
	pterm.Println()
	pterm.Println(a.renderStaticBrandHero(a.catalog.T("language_onboarding_title")))
	pterm.Println()
	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{
				Data: a.ptermSprintf(
					"%s\n[cyan]%s[-]\n%s\n%s",
					a.catalog.T("app_title"),
					a.catalog.T("language_onboarding_default", a.languageLabel(i18n.Parse(a.cfg.DefaultLanguage))),
					a.catalog.T("language_onboarding_body"),
					a.catalog.T("language_onboarding_scope"),
				),
			},
			{
				Data: a.ptermSprintf(
					"%s\n%s\n%s\n[cyan]%s[-]",
					a.catalog.T("language_onboarding_persistence_title"),
					a.catalog.T("language_onboarding_persistence_body"),
					a.catalog.T("language_onboarding_change_hint"),
					brandPrimaryBinary+" config language",
				),
			},
			{
				Data: a.ptermSprintf(
					"%s\n- [cyan]%s[-]\n- [cyan]%s[-]\n- [cyan]%s[-]",
					a.catalog.T("language_onboarding_next_title"),
					a.commandHint("scan"),
					a.commandHint("overview"),
					a.commandHint("config", "language"),
				),
			},
		},
	}).Render()
	pterm.Println()
}

func (a *App) renderRunWatchFrame(runID string, interval time.Duration) error {
	run, ok := a.service.GetRun(runID)
	if !ok {
		return fmt.Errorf("%s", a.catalog.T("run_not_found", runID))
	}
	snapshot := a.buildPortfolioSnapshot()

	var project *domain.Project
	if value, exists := snapshot.ProjectsByID[run.ProjectID]; exists {
		project = &value
	}
	findings := snapshot.findingsForRun(runID)

	pterm.Info.Println(a.catalog.T("watch_interval", interval.String()))
	a.renderRunSummary(run, project, findings)
	if a.shellSafeSurfaceOutput() {
		return nil
	}
	report, err := a.service.BuildRunReport(runID, "")
	if err != nil {
		return err
	}
	a.renderRunDeltaReport(report)
	a.renderModules(run.ModuleResults)
	return a.renderExecutionTimeline(runID)
}

func (a *App) renderQueueWatchFrame() error {
	runs := a.service.ListRuns()
	counts := a.countRunStatuses(runs)

	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]", a.catalog.T("status_queued"), counts.Queued)},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]", a.catalog.T("status_running"), counts.Running)},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]", a.catalog.T("status_canceled"), counts.Canceled)},
		},
	}).Render()

	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("watch_next_runs"))
	active := a.activeQueueRuns(runs, 8)
	if len(active) == 0 {
		pterm.DefaultBasicText.Println(a.catalog.T("watch_no_active_runs"))
		return nil
	}

	data := pterm.TableData{{a.catalog.T("run_id"), a.catalog.T("status"), a.catalog.T("title"), a.catalog.T("scan_mode"), a.catalog.T("started_at")}}
	for _, run := range active {
		data = append(data, []string{
			run.ID,
			a.statusBadge(string(run.Status)),
			a.projectLabel(run.ProjectID),
			a.modeBadge(run.Profile.Mode),
			run.StartedAt.Local().Format(time.RFC822),
		})
	}
	return pterm.DefaultTable.WithHasHeader().WithData(data).Render()
}

func (a *App) startLiveScanTracker(project domain.Project, profile domain.ScanProfile) *liveScanTracker {
	if a.streamMissionControl {
		return nil
	}
	total := max(1, a.moduleCount(profile.Modules))
	if a.shellSafeSurfaceOutput() {
		pterm.Printf("%s: %d%% • 0/%d • %s\n", a.catalog.T("scan_mc_progress"), 0, total, a.catalog.T("scan_mc_status_booting"))
		return &liveScanTracker{
			plain: true,
			total: total,
		}
	}
	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("scan_live_title"))
	phaseLines := strings.Join(a.scanPhaseLines(profile.Modules), "\n")
	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]", a.catalog.T("title"), project.DisplayName, a.catalog.T("coverage_profile"), a.coverageLabel(profile.Coverage))},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%d[-]", a.catalog.T("scan_mode"), a.modeLabel(profile.Mode), a.catalog.T("scan_modules"), a.moduleCount(profile.Modules))},
			{Data: a.ptermSprintf("%s\n%s", a.catalog.T("scan_live_phases"), phaseLines)},
		},
	}).Render()
	spinner, _ := pterm.DefaultSpinner.Start(a.catalog.T("scan_live_boot", project.DisplayName, a.moduleCount(profile.Modules)))
	return &liveScanTracker{
		spinner: spinner,
		total:   total,
	}
}

func (a *App) updateLiveScanTracker(tracker *liveScanTracker, event domain.StreamEvent) {
	if tracker == nil {
		return
	}
	if tracker.plain {
		a.updatePlainLiveScanTracker(tracker, event)
		return
	}
	if tracker.spinner == nil {
		return
	}

	switch {
	case event.Type == "module.updated" && event.Module != nil:
		module := *event.Module
		switch module.Status {
		case domain.ModuleCompleted:
			tracker.completed++
		case domain.ModuleFailed:
			tracker.failed++
		case domain.ModuleSkipped:
			tracker.skipped++
		}

		progress := a.scanProgressBar(tracker.completed+tracker.failed+tracker.skipped, tracker.total)
		stage := ""
		switch module.Status {
		case domain.ModuleCompleted:
			stage = a.catalog.T("scan_live_stage_completed", a.modulePhaseLabel(module.Name), a.moduleNarrative(module.Name))
		case domain.ModuleFailed:
			stage = a.catalog.T("scan_live_stage_failed", a.modulePhaseLabel(module.Name), a.moduleNarrative(module.Name))
		case domain.ModuleSkipped:
			stage = a.catalog.T("scan_live_stage_skipped", a.modulePhaseLabel(module.Name), a.moduleNarrative(module.Name))
		default:
			stage = a.catalog.T("scan_live_stage_running", a.modulePhaseLabel(module.Name), a.moduleNarrative(module.Name))
		}

		tracker.spinner.UpdateText(a.catalog.T(
			"scan_live_progress",
			progress,
			stage,
			tracker.completed+tracker.failed+tracker.skipped,
			tracker.total,
			tracker.findings,
			a.liveRiskLabel(tracker.critical, tracker.high, tracker.medium, tracker.low),
		))
	case event.Type == "finding.created" && event.Finding != nil:
		tracker.findings++
		switch event.Finding.Severity {
		case domain.SeverityCritical:
			tracker.critical++
		case domain.SeverityHigh:
			tracker.high++
		case domain.SeverityMedium:
			tracker.medium++
		case domain.SeverityLow:
			tracker.low++
		}
		progress := a.scanProgressBar(tracker.completed+tracker.failed+tracker.skipped, tracker.total)
		tracker.spinner.UpdateText(a.catalog.T(
			"scan_live_progress",
			progress,
			a.catalog.T("scan_live_stage_detected", trimForSelect(event.Finding.Title, 48)),
			tracker.completed+tracker.failed+tracker.skipped,
			tracker.total,
			tracker.findings,
			a.liveRiskLabel(tracker.critical, tracker.high, tracker.medium, tracker.low),
		))
	case event.Type == "run.completed":
		tracker.spinner.Success(a.catalog.T("scan_live_done", tracker.completed, tracker.total, tracker.findings))
	case event.Type == "run.failed":
		tracker.spinner.Fail(a.catalog.T("scan_live_failed", tracker.completed, tracker.total, tracker.findings))
	case event.Type == "run.canceled":
		tracker.spinner.Warning(a.catalog.T("scan_live_canceled", tracker.completed, tracker.total, tracker.findings))
	}
}

func (a *App) updatePlainLiveScanTracker(tracker *liveScanTracker, event domain.StreamEvent) {
	switch {
	case event.Type == "module.updated" && event.Module != nil:
		module := *event.Module
		switch module.Status {
		case domain.ModuleCompleted:
			tracker.completed++
		case domain.ModuleFailed:
			tracker.failed++
		case domain.ModuleSkipped:
			tracker.skipped++
		default:
			return
		}
		done := tracker.completed + tracker.failed + tracker.skipped
		percent := 0
		if tracker.total > 0 {
			percent = int(float64(done) / float64(tracker.total) * 100)
		}
		line := fmt.Sprintf(
			"%s: %d%% • %d/%d • %s: %s • %s: %s",
			a.catalog.T("scan_mc_progress"),
			percent,
			done,
			tracker.total,
			a.catalog.T("module"),
			module.Name,
			a.catalog.T("status"),
			a.displayUpper(a.moduleStatusLabel(module.Status)),
		)
		if phase := a.phaseDisplayText("", module.Name); phase != "" {
			line += fmt.Sprintf(" • %s: %s", a.phaseLabel(), phase)
		}
		pterm.Println(line)
	case event.Type == "run.failed":
		pterm.Error.Println(a.catalog.T("scan_failed"))
	case event.Type == "run.canceled":
		pterm.Warning.Println(a.catalog.T("scan_canceled"))
	}
}

func (a *App) newLiveScanConsole(project domain.Project, profile domain.ScanProfile) *liveScanConsole {
	if !a.streamMissionControl {
		return nil
	}
	return &liveScanConsole{
		project:        project,
		profile:        profile,
		lastEvent:      a.catalog.T("scan_mc_boot"),
		lastStatus:     a.catalog.T("scan_mc_status_booting"),
		lastTool:       a.moduleToolLabel(firstModuleName(profile.Modules)),
		telemetry:      []string{a.catalog.T("scan_mc_boot"), a.catalog.T("scan_mc_boot_lane", a.coverageLabel(profile.Coverage))},
		recentFindings: make([]domain.Finding, 0, 5),
	}
}

func (c *liveScanConsole) update(a *App, event domain.StreamEvent) {
	c.run = event.Run
	if a.decorativeMotionEnabled() {
		c.frame++
	}
	c.eventCount++
	if strings.TrimSpace(event.Message) != "" {
		c.lastEvent = a.operatorText(event.Message)
	}
	if event.Module != nil {
		c.lastModule = event.Module.Name
		c.lastTool = a.moduleToolLabel(c.lastModule)
		c.lastPhase = a.modulePhaseLabel(c.lastModule)
		c.lastStatus = string(event.Module.Status)
	}
	if event.Execution != nil {
		c.lastTool = a.executionToolLabel(event.Execution, event.Attempt)
	}
	if event.Attempt != nil && strings.TrimSpace(c.lastTool) == "" {
		c.lastTool = a.executionToolLabel(nil, event.Attempt)
	}
	if event.Finding != nil {
		c.lastFinding = event.Finding.Title
		c.recentFindings = append([]domain.Finding{*event.Finding}, c.recentFindings...)
		if len(c.recentFindings) > 5 {
			c.recentFindings = c.recentFindings[:5]
		}
	}
	switch event.Type {
	case "run.completed":
		c.lastStatus = string(domain.ScanCompleted)
	case "run.failed":
		c.lastStatus = string(domain.ScanFailed)
	case "run.canceled":
		c.lastStatus = string(domain.ScanCanceled)
	}
	c.pushTelemetry(a.missionTelemetryLine(event))
}

func (c *liveScanConsole) render(a *App) {
	a.clearTerminalView()

	done := len(c.run.ModuleResults)
	total := max(1, a.moduleCount(c.profile.Modules))
	if done > total {
		done = total
	}

	critical := c.run.Summary.CountsBySeverity[domain.SeverityCritical]
	high := c.run.Summary.CountsBySeverity[domain.SeverityHigh]
	medium := c.run.Summary.CountsBySeverity[domain.SeverityMedium]
	low := c.run.Summary.CountsBySeverity[domain.SeverityLow]
	risk := a.liveRiskLabel(critical, high, medium, low)
	progress := a.scanProgressBar(done, total)
	postureBadge := a.scanPostureBadge(c.run)
	postureSummary := a.scanPostureSummary(c.run)
	agentState := a.missionAgentStateLabel(c)
	agentFocus := a.missionAgentFocus(c)
	agentThought := a.missionAgentThought(c)
	agentAvatar := a.missionAgentAvatar(c)

	pterm.DefaultHeader.Println(a.catalog.T("scan_mc_title"))
	pterm.Println(postureBadge + " " + postureSummary)
	pterm.Println()
	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]", a.catalog.T("title"), c.project.DisplayName, a.catalog.T("project_path"), c.project.LocationHint)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]", a.catalog.T("scan_mode"), a.modeLabel(c.profile.Mode), a.catalog.T("coverage_profile"), a.coverageLabel(c.profile.Coverage))},
			{Data: a.ptermSprintf("%s\n%s\n%s\n[cyan]%s[-]", a.catalog.T("scan_mc_risk"), risk, a.catalog.T("status"), a.statusBadge(c.lastStatus))},
		},
		{
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]", a.catalog.T("scan_mc_agent_title"), a.catalog.T("scan_mc_agent_name"), a.catalog.T("scan_mc_agent_state"), agentState, a.catalog.T("scan_mc_agent_focus"), trimForSelect(agentFocus, 64))},
			{Data: agentAvatar},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]", a.catalog.T("scan_mc_progress"), progress, a.catalog.T("scan_mc_lane"), a.phaseDisplayText(c.lastPhase, c.lastModule), a.catalog.T("scan_mc_module"), defaultString(c.lastModule, "-"))},
		},
		{
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("scan_mc_activity"), trimForSelect(a.operatorText(c.lastEvent), 96))},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("scan_mc_agent_thought"), trimForSelect(agentThought, 96))},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%d[-]", a.catalog.T("scan_mc_progress"), progress, a.catalog.T("summary_total"), c.run.Summary.TotalFindings)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]", a.catalog.T("scan_mc_last_finding"), defaultString(trimForSelect(c.lastFinding, 72), "-"), a.catalog.T("summary_total"), fmt.Sprintf("%d", c.run.Summary.TotalFindings))},
		},
	}).Render()

	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("scan_mc_schematic_title"))
	a.renderInlineLaneSchematic(c)

	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("scan_mc_matrix_title"))
	a.renderInlineCoverageMatrix(c)

	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("scan_mc_threat_pulse"))
	a.renderInlineThreatPulse(c.run)

	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("scan_phase_verdicts_title"))
	a.renderInlinePhaseVerdicts(c.run)

	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("scan_mc_module_pulse"))
	a.renderInlineModulePulse(c.run)

	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("scan_mc_finding_feed"))
	a.renderInlineFindingFeed(c.recentFindings)

	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("scan_mc_telemetry_title"))
	a.renderInlineTelemetryStream(c, a.missionCodeStreamLines(c))

	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("scan_mc_cards_title"))
	a.renderInlineFindingCards(c.recentFindings, 2)
}

func (c *liveScanConsole) pushTelemetry(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	c.telemetry = append([]string{line}, c.telemetry...)
	if len(c.telemetry) > 8 {
		c.telemetry = c.telemetry[:8]
	}
}

func (a *App) renderInlinePhaseVerdicts(run domain.ScanRun) {
	type phaseStats struct {
		completed int
		failed    int
		skipped   int
	}
	order := a.scanPhaseLines(extractModuleNames(run.ModuleResults))
	stats := make(map[string]*phaseStats, len(order))
	for _, phase := range order {
		stats[phase] = &phaseStats{}
	}
	for _, module := range run.ModuleResults {
		phase := a.modulePhaseLabel(module.Name)
		if _, ok := stats[phase]; !ok {
			stats[phase] = &phaseStats{}
			order = append(order, phase)
		}
		switch module.Status {
		case domain.ModuleCompleted:
			stats[phase].completed++
		case domain.ModuleFailed:
			stats[phase].failed++
		case domain.ModuleSkipped:
			stats[phase].skipped++
		}
	}
	data := pterm.TableData{{a.catalog.T("title"), a.catalog.T("status"), a.catalog.T("scan_modules_completed"), a.catalog.T("scan_modules_failed"), a.catalog.T("scan_modules_skipped")}}
	for _, phase := range order {
		row := stats[phase]
		status := a.statusBadge("queued")
		if row.completed > 0 && row.failed == 0 {
			status = a.statusBadge("available")
		}
		if row.failed > 0 {
			status = a.statusBadge("failed")
		}
		if row.completed == 0 && row.failed == 0 && row.skipped > 0 {
			status = a.statusBadge("skipped")
		}
		data = append(data, []string{phase, status, fmt.Sprintf("%d", row.completed), fmt.Sprintf("%d", row.failed), fmt.Sprintf("%d", row.skipped)})
	}
	_ = pterm.DefaultTable.WithHasHeader().WithData(data).Render()
}

func (a *App) renderInlineModulePulse(run domain.ScanRun) {
	queued, running, completed, failed, skipped := a.moduleStatusCounts(run.ModuleResults)
	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]", a.catalog.T("module_queued_count"), queued)},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]", a.catalog.T("module_running_count"), running)},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]", a.catalog.T("module_completed_count"), completed)},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]", a.catalog.T("module_failed_count"), failed)},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]", a.catalog.T("module_skipped_count"), skipped)},
		},
	}).Render()

	lines := make([]string, 0, 8)
	for _, module := range run.ModuleResults {
		lines = append(lines, fmt.Sprintf("%s | %s | %s", module.Name, a.displayUpper(a.moduleStatusLabel(module.Status)), trimForSelect(a.operatorText(coalesceString(module.Summary, "-")), 72)))
		if len(lines) >= 8 {
			break
		}
	}
	if len(lines) == 0 {
		pterm.Println(a.catalog.T("scan_mc_waiting"))
		return
	}
	for _, line := range lines {
		pterm.Println(" - " + line)
	}
}

func (a *App) renderInlineThreatPulse(run domain.ScanRun) {
	critical := run.Summary.CountsBySeverity[domain.SeverityCritical]
	high := run.Summary.CountsBySeverity[domain.SeverityHigh]
	medium := run.Summary.CountsBySeverity[domain.SeverityMedium]
	low := run.Summary.CountsBySeverity[domain.SeverityLow]
	total := max(1, critical+high+medium+low)

	data := pterm.TableData{{a.catalog.T("summary_critical"), a.catalog.T("summary_high"), a.catalog.T("summary_medium"), a.catalog.T("summary_low"), a.catalog.T("scan_mc_risk")}}
	data = append(data, []string{
		a.severityBadgeCount(domain.SeverityCritical, critical),
		a.severityBadgeCount(domain.SeverityHigh, high),
		a.severityBadgeCount(domain.SeverityMedium, medium),
		a.severityBadgeCount(domain.SeverityLow, low),
		a.displayUpper(a.liveRiskLabel(critical, high, medium, low)),
	})
	_ = pterm.DefaultTable.WithHasHeader().WithData(data).Render()

	pterm.Println(a.catalog.T("scan_mc_pressure"))
	pterm.Println(" - " + a.catalog.T("summary_critical") + " " + a.scanProgressBar(critical, total))
	pterm.Println(" - " + a.catalog.T("summary_high") + " " + a.scanProgressBar(high, total))
	pterm.Println(" - " + a.catalog.T("summary_medium") + " " + a.scanProgressBar(medium, total))
	pterm.Println(" - " + a.catalog.T("summary_low") + " " + a.scanProgressBar(low, total))
}

func (a *App) renderInlineFindingFeed(findings []domain.Finding) {
	if len(findings) == 0 {
		pterm.Println(a.catalog.T("scan_mc_no_findings_yet"))
		return
	}
	for _, finding := range findings {
		pterm.Println(fmt.Sprintf(
			" - %s | %s | %s | %s",
			a.severityBadge(finding.Severity),
			a.categoryLabel(finding.Category),
			trimForSelect(finding.Title, 44),
			trimForSelect(coalesceString(finding.Location, "-"), 36),
		))
	}
}

func (a *App) renderInlineTelemetryStream(c *liveScanConsole, lines []string) {
	if len(lines) == 0 {
		pterm.Println(a.catalog.T("scan_mc_waiting"))
		return
	}
	for index, line := range lines {
		phase := a.phaseDisplayText(c.lastPhase, c.lastModule)
		if index < len(c.telemetry) {
			pterm.Println(fmt.Sprintf(" %02d | %s | %s", index+1, trimForSelect(phase, 24), line))
			continue
		}
		pterm.Println(fmt.Sprintf(" %02d | %s", index+1, line))
	}
}

func (a *App) renderInlineCoverageMatrix(c *liveScanConsole) {
	lines := a.missionCoverageMatrixLines(c)
	for _, line := range lines {
		pterm.Println(" - " + line)
	}
}

func (a *App) renderInlineLaneSchematic(c *liveScanConsole) {
	for _, line := range a.missionLaneSchematicLines(c) {
		pterm.Println(" " + line)
	}
}

func (a *App) missionAgentAvatar(c *liveScanConsole) string {
	posture := a.scanPostureLabel(c.run)
	frames := []string{
		"         .-^^^^-.\n       .'  HHHH  '.\n      /   .----.   \\\n     |   | OO | |   |\n     |   | MM | |   |\n     |   | '--' |   |\n      \\   '----'   /\n       '._/____\\_.'\n          /_||_\\\\",
		"         .-====-.\n       .'  HHHH  '.\n      /   .----.   \\\n     |   | OO | |   |\n     |   | MM | |   |\n     |   | '--' |   |\n      \\   '----'   /\n       '._/____\\_.'\n          /_||_\\\\",
		"         .-^^^^-.\n       .'  HHHH  '.\n      /   .-__-.   \\\n     |   | OO | |   |\n     |   | MM | |   |\n     |   | '--' |   |\n      \\   '----'   /\n       '._/____\\_.'\n          /_||_\\\\",
		"         .-====-.\n       .'  HHHH  '.\n      /   .-__-.   \\\n     |   | OO | |   |\n     |   | MM | |   |\n     |   | '--' |   |\n      \\   '----'   /\n       '._/____\\_.'\n          /_||_\\\\",
	}

	eyes := "[]"
	mouth := "=="
	head := "||"
	switch posture {
	case a.catalog.T("scan_posture_warning"):
		eyes = "<>"
		mouth = "=="
		head = "##"
	case a.catalog.T("scan_posture_breach"):
		eyes = "!!"
		mouth = "/\\"
		head = "!!"
	case a.catalog.T("scan_posture_degraded"):
		eyes = "??"
		mouth = "~~"
		head = "::"
	}

	frameIndex := 0
	if a.decorativeMotionEnabled() {
		frameIndex = c.frame % len(frames)
	}
	frame := frames[frameIndex]
	frame = strings.ReplaceAll(frame, "EE", eyes)
	frame = strings.ReplaceAll(frame, "MM", mouth)
	frame = strings.ReplaceAll(frame, "HH", head)
	return frame
}

func (a *App) missionAgentStateLabel(c *liveScanConsole) string {
	failed, _, _ := a.moduleExecutionCounts(c.run.ModuleResults)
	switch {
	case c.run.Status == domain.ScanCompleted || c.run.Status == domain.ScanCanceled:
		return a.catalog.T("scan_mc_state_complete")
	case failed > 0 || c.run.Status == domain.ScanFailed:
		return a.catalog.T("scan_mc_state_degraded")
	case strings.TrimSpace(c.lastFinding) != "":
		return a.catalog.T("scan_mc_state_alert")
	case strings.Contains(strings.ToLower(a.phaseDisplayText(c.lastPhase, c.lastModule)), strings.ToLower(a.catalog.T("scan_phase_attack_surface"))):
		return a.catalog.T("scan_mc_state_mapping")
	case strings.TrimSpace(c.lastModule) != "":
		return a.catalog.T("scan_mc_state_correlating")
	default:
		return a.catalog.T("scan_mc_status_booting")
	}
}

func (a *App) missionAgentFocus(c *liveScanConsole) string {
	switch {
	case strings.TrimSpace(c.lastModule) != "":
		return a.moduleNarrative(c.lastModule)
	case strings.TrimSpace(c.lastPhase) != "":
		return a.phaseDisplayText(c.lastPhase, "")
	default:
		return a.catalog.T("scan_mc_focus_default")
	}
}

func (a *App) missionAgentThought(c *liveScanConsole) string {
	failed, _, _ := a.moduleExecutionCounts(c.run.ModuleResults)
	switch {
	case c.run.Status == domain.ScanCompleted && c.run.Summary.TotalFindings == 0:
		return a.catalog.T("scan_mc_thought_complete_clean")
	case c.run.Status == domain.ScanCompleted:
		return a.catalog.T("scan_mc_thought_complete_findings", c.run.Summary.TotalFindings)
	case failed > 0 || c.run.Status == domain.ScanFailed:
		return a.catalog.T("scan_mc_thought_degraded", defaultString(c.lastModule, a.catalog.T("scan_phase_general")))
	case strings.TrimSpace(c.lastFinding) != "":
		return a.catalog.T("scan_mc_thought_alert", trimForSelect(c.lastFinding, 56))
	case strings.TrimSpace(c.lastModule) != "":
		return a.catalog.T("scan_mc_thought_working", trimForSelect(a.moduleNarrative(c.lastModule), 64))
	default:
		return a.catalog.T("scan_mc_thought_boot")
	}
}

func (a *App) missionTelemetryLine(event domain.StreamEvent) string {
	switch {
	case event.Type == "run.updated":
		return fmt.Sprintf("[boot ] %s", trimForSelect(a.operatorText(coalesceString(event.Message, a.catalog.T("scan_mc_waiting"))), 88))
	case event.Type == "module.updated" && event.Module != nil:
		module := event.Module
		switch module.Status {
		case domain.ModuleQueued:
			return fmt.Sprintf("[queue] %s -> %s", module.Name, trimForSelect(a.modulePhaseLabel(module.Name), 56))
		case domain.ModuleRunning:
			return fmt.Sprintf("[exec ] %s -> %s", module.Name, trimForSelect(a.moduleNarrative(module.Name), 72))
		case domain.ModuleCompleted:
			return fmt.Sprintf("[done ] %s -> %s", module.Name, trimForSelect(a.moduleSummaryText(*module), 72))
		case domain.ModuleFailed:
			return fmt.Sprintf("[fail ] %s -> %s", module.Name, trimForSelect(a.moduleSummaryText(*module), 72))
		case domain.ModuleSkipped:
			return fmt.Sprintf("[skip ] %s -> %s", module.Name, trimForSelect(a.moduleSummaryText(*module), 72))
		}
	case event.Type == "module.execution" && event.Execution != nil:
		execution := event.Execution
		lastAttempt := execution.AttemptsUsed
		if event.Attempt != nil && event.Attempt.Attempt > 0 {
			lastAttempt = event.Attempt.Attempt
		}
		attemptLabel := "attempts"
		statusLabel := "status"
		if a.lang == "tr" {
			attemptLabel = "deneme"
			statusLabel = "durum"
		}
		return fmt.Sprintf("[trace] %s -> %d/%d %s, %s %s", execution.Module, lastAttempt, execution.MaxAttempts, attemptLabel, statusLabel, a.displayUpper(a.moduleStatusLabel(execution.Status)))
	case event.Type == "finding.created" && event.Finding != nil:
		return fmt.Sprintf("[alert] %s %s @ %s", a.displayUpper(a.severityLabel(event.Finding.Severity)), trimForSelect(event.Finding.Title, 44), trimForSelect(coalesceString(event.Finding.Location, "-"), 24))
	case event.Type == "run.completed":
		return fmt.Sprintf("[seal ] %s", trimForSelect(a.operatorText(coalesceString(event.Message, a.catalog.T("scan_completed"))), 88))
	case event.Type == "run.failed":
		return fmt.Sprintf("[halt ] %s", trimForSelect(a.operatorText(coalesceString(event.Message, a.catalog.T("scan_failed"))), 88))
	case event.Type == "run.canceled":
		return fmt.Sprintf("[halt ] %s", trimForSelect(a.operatorText(coalesceString(event.Message, a.catalog.T("scan_canceled"))), 88))
	}
	return fmt.Sprintf("[info ] %s", trimForSelect(a.operatorText(coalesceString(event.Message, a.catalog.T("scan_mc_waiting"))), 88))
}

func (a *App) missionCodeStreamLines(c *liveScanConsole) []string {
	lines := []string{
		fmt.Sprintf("agent.bind(project=%q, mode=%q, coverage=%q)", c.project.DisplayName, c.profile.Mode, a.coverageLabel(c.profile.Coverage)),
		fmt.Sprintf("agent.focus(lane=%q, module=%q)", a.phaseDisplayText(c.lastPhase, c.lastModule), defaultString(c.lastModule, "-")),
		fmt.Sprintf("risk.snapshot(level=%q, findings=%d)", a.liveRiskLabel(
			c.run.Summary.CountsBySeverity[domain.SeverityCritical],
			c.run.Summary.CountsBySeverity[domain.SeverityHigh],
			c.run.Summary.CountsBySeverity[domain.SeverityMedium],
			c.run.Summary.CountsBySeverity[domain.SeverityLow],
		), c.run.Summary.TotalFindings),
	}
	if c.lastFinding != "" {
		lines = append(lines, fmt.Sprintf("finding.cache(latest=%q)", trimForSelect(c.lastFinding, 56)))
	}
	for _, line := range c.telemetry {
		lines = append(lines, fmt.Sprintf("stream.push(%q)", trimForSelect(line, 84)))
	}
	if len(lines) > 8 {
		lines = lines[:8]
	}
	return lines
}

func (a *App) missionCoverageMatrixLines(c *liveScanConsole) []string {
	type phaseStats struct {
		completed int
		failed    int
		skipped   int
	}

	order := a.scanPhaseLines(c.profile.Modules)
	if len(order) == 0 {
		order = []string{a.catalog.T("scan_phase_general")}
	}
	stats := make(map[string]*phaseStats, len(order))
	for _, phase := range order {
		stats[phase] = &phaseStats{}
	}
	for _, module := range c.run.ModuleResults {
		phase := a.modulePhaseLabel(module.Name)
		if _, ok := stats[phase]; !ok {
			stats[phase] = &phaseStats{}
			order = append(order, phase)
		}
		switch module.Status {
		case domain.ModuleCompleted:
			stats[phase].completed++
		case domain.ModuleFailed:
			stats[phase].failed++
		case domain.ModuleSkipped:
			stats[phase].skipped++
		}
	}

	lines := make([]string, 0, len(order))
	for _, phase := range order {
		state := a.catalog.T("scan_mc_matrix_wait")
		if phase == c.lastPhase && !a.isTerminalRunStatus(c.run.Status) {
			state = a.catalog.T("scan_mc_matrix_active")
		}
		if stats[phase].failed > 0 {
			state = a.catalog.T("scan_mc_matrix_failed")
		} else if stats[phase].completed > 0 && stats[phase].skipped > 0 {
			state = a.catalog.T("scan_mc_matrix_partial")
		} else if stats[phase].completed > 0 {
			state = a.catalog.T("scan_mc_matrix_done")
		}
		lines = append(lines, fmt.Sprintf("%s | %s | c:%d f:%d s:%d", a.displayUpper(state), phase, stats[phase].completed, stats[phase].failed, stats[phase].skipped))
	}
	return lines
}

func (a *App) missionLaneSchematicLines(c *liveScanConsole) []string {
	lanes := a.scanLaneDescriptors(c.profile.Modules)
	if len(lanes) == 0 {
		lanes = []scanLaneDescriptor{a.scanLaneDescriptor("general")}
	}
	lines := make([]string, 0, len(lanes))
	activeLaneKey := a.moduleLaneKey(c.lastModule)
	for index, lane := range lanes {
		state := a.catalog.T("scan_mc_matrix_wait")
		for _, module := range c.run.ModuleResults {
			if a.moduleLaneKey(module.Name) != lane.Key {
				continue
			}
			switch module.Status {
			case domain.ModuleFailed:
				state = a.catalog.T("scan_mc_matrix_failed")
			case domain.ModuleRunning:
				state = a.catalog.T("scan_mc_matrix_active")
			case domain.ModuleCompleted:
				if state != a.catalog.T("scan_mc_matrix_failed") {
					state = a.catalog.T("scan_mc_matrix_done")
				}
			case domain.ModuleSkipped:
				if state == a.catalog.T("scan_mc_matrix_wait") {
					state = a.catalog.T("scan_mc_matrix_partial")
				}
			}
		}
		indicator := "   "
		if lane.Key == activeLaneKey && !a.isTerminalRunStatus(c.run.Status) {
			indicator = " > "
		}
		line := fmt.Sprintf("%s[%s] %s", indicator, a.displayUpper(state), lane.Title)
		if index < len(lanes)-1 {
			line += "  --->"
		}
		lines = append(lines, line)
	}
	return lines
}

func (a *App) renderInlineFindingCards(findings []domain.Finding, limit int) {
	if len(findings) == 0 {
		pterm.Println(a.catalog.T("scan_mc_no_findings_yet"))
		return
	}
	if limit <= 0 || limit > len(findings) {
		limit = len(findings)
	}
	for _, finding := range findings[:limit] {
		_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
			{
				{Data: a.ptermSprintf("%s\n%s\n%s\n[cyan]%s[-]", a.catalog.T("severity"), a.severityBadge(finding.Severity), a.catalog.T("category"), a.categoryLabel(finding.Category))},
				{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]", a.catalog.T("title"), trimForSelect(finding.Title, 52), a.catalog.T("location"), defaultString(trimForSelect(finding.Location, 36), "-"))},
				{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]", a.catalog.T("module"), finding.Module, a.catalog.T("rule"), defaultString(finding.RuleID, "-"))},
			},
		}).Render()
	}
}

func renderPlainStage(title string, lines ...string) string {
	stageLines := []string{strings.TrimSpace(title) + ":"}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		stageLines = append(stageLines, "- "+line)
	}
	return strings.Join(stageLines, "\n")
}

func renderPlainReportStage(title string, lines ...string) string {
	stageLines := []string{strings.TrimSpace(title) + ":"}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		stageLines = append(stageLines, line)
	}
	return strings.Join(stageLines, "\n")
}

func (a *App) renderProjects(projects []domain.Project) error {
	pterm.Println(a.renderStaticBrandHero(a.catalog.T("projects_title")))
	pterm.Println()
	if len(projects) == 0 {
		pterm.DefaultBasicText.Println(a.catalog.T("no_projects"))
		return nil
	}
	attachedPolicies := 0
	stackAware := 0
	for _, project := range projects {
		if strings.TrimSpace(project.PolicyID) != "" {
			attachedPolicies++
		}
		if len(project.DetectedStacks) > 0 {
			stackAware++
		}
	}
	latest := latestProject(projects)
	latestLabel := a.catalog.T("projects_focus_empty")
	if latest != nil {
		latestLabel = fmt.Sprintf("%s | %s", latest.DisplayName, trimForSelect(latest.LocationHint, 48))
	}
	stackSignal := topProjectStacks(projects, 4)
	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]",
				a.catalog.T("projects_registered_total"),
				len(projects),
				a.catalog.T("project_stacks"),
				distinctProjectStacks(projects),
				a.catalog.T("policy_id"),
				attachedPolicies,
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%d[-]",
				a.catalog.T("overview_operator_focus"),
				latestLabel,
				a.catalog.T("scan_modules"),
				stackAware,
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]",
				a.catalog.T("overview_portfolio"),
				stackSignal,
				a.catalog.T("overview_next_steps"),
				a.commandHint("scan"),
				a.catalog.T("runs_title"),
				a.commandHint("runs", "list"),
			)},
		},
	}).Render()
	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("projects_roster_title"))
	data := pterm.TableData{{a.catalog.T("project_id"), a.catalog.T("title"), a.catalog.T("project_path"), a.catalog.T("project_stacks"), a.catalog.T("policy_id")}}
	for _, project := range projects {
		data = append(data, []string{
			project.ID,
			project.DisplayName,
			project.LocationHint,
			coalesceString(strings.Join(project.DetectedStacks, ", "), "-"),
			coalesceString(project.PolicyID, "-"),
		})
	}
	return pterm.DefaultTable.WithHasHeader().WithData(data).Render()
}

func (a *App) renderRuns(runs []domain.ScanRun) error {
	pterm.Println(a.renderStaticBrandHero(a.catalog.T("runs_title")))
	pterm.Println()
	if len(runs) == 0 {
		pterm.DefaultBasicText.Println(a.catalog.T("no_runs"))
		return nil
	}
	snapshot := a.buildPortfolioSnapshot()
	counts := a.countRunStatuses(runs)
	trendline := a.runTrendLabel(runs, 8)
	latest := latestRun(runs)
	queueBrief := a.renderQueueHeadlineFromSnapshot(snapshot, runs)
	operatorFocus := a.catalog.T("runs_focus_empty")
	hotFindingSummary := a.catalog.T("overview_no_findings")
	if latest != nil {
		operatorFocus = fmt.Sprintf("%s | %s | %s", snapshot.projectLabel(latest.ProjectID), strings.ToUpper(string(latest.Status)), latest.StartedAt.Local().Format(time.RFC822))
		if hot := a.prioritizedFindings(snapshot.findingsForRun(latest.ID), 1); len(hot) > 0 {
			hotFindingSummary = a.hottestFindingLine(hot[0], 60)
		}
	}
	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]\n%s\n[cyan]%s[-]",
				a.catalog.T("runs_total"),
				len(runs),
				a.catalog.T("overview_trendline"),
				trendline,
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]",
				a.catalog.T("status_queued"),
				counts.Queued,
				a.catalog.T("status_running"),
				counts.Running,
				a.catalog.T("status_failed"),
				counts.Failed,
				a.catalog.T("status_canceled"),
				counts.Canceled,
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]",
				a.catalog.T("overview_operator_focus"),
				operatorFocus,
				a.catalog.T("overview_queue_brief"),
				queueBrief,
				a.catalog.T("finding_hotlist_title"),
				hotFindingSummary,
			)},
		},
	}).Render()
	pterm.Println()
	if latest != nil {
		hotFindings := a.prioritizedFindings(snapshot.findingsForRun(latest.ID), 2)
		if len(hotFindings) > 0 {
			pterm.DefaultSection.Println(a.catalog.T("overview_hot_findings"))
			a.renderInlineFindingCards(hotFindings, 2)
			pterm.Println()
		}
	}

	pterm.DefaultSection.Println(a.catalog.T("runs_ledger_title"))
	data := pterm.TableData{{a.catalog.T("title"), a.catalog.T("run_id"), a.catalog.T("status"), a.catalog.T("scan_findings"), a.catalog.T("scan_blocked"), a.catalog.T("scan_mode"), a.catalog.T("started_at"), a.catalog.T("finished_at"), a.catalog.T("finding_priority")}}
	for _, run := range runs {
		finished := "-"
		if run.FinishedAt != nil {
			finished = run.FinishedAt.Local().Format(time.RFC822)
		}
		findings := snapshot.findingsForRun(run.ID)
		data = append(data, []string{
			snapshot.projectLabel(run.ProjectID),
			run.ID,
			a.statusBadge(string(run.Status)),
			fmt.Sprintf("%d", run.Summary.TotalFindings),
			ternary(run.Summary.Blocked, a.catalog.T("scan_blocked_yes"), a.catalog.T("scan_blocked_no")),
			a.modeBadge(run.Profile.Mode),
			run.StartedAt.Local().Format(time.RFC822),
			finished,
			fmt.Sprintf("%.1f", averagePriority(findings)),
		})
	}
	return pterm.DefaultTable.WithHasHeader().WithData(data).Render()
}

func (a *App) renderRunDetails(runID string) error {
	run, ok := a.service.GetRun(runID)
	if !ok {
		return fmt.Errorf("%s", a.catalog.T("run_not_found", runID))
	}
	snapshot := a.buildPortfolioSnapshot()

	var project *domain.Project
	if value, exists := snapshot.ProjectsByID[run.ProjectID]; exists {
		project = &value
	}
	findings := snapshot.findingsForRun(runID)

	pterm.Println(a.renderStaticBrandHero(a.catalog.T("show_title")))
	pterm.Println()
	a.renderRunSummary(run, project, findings)
	if a.shellSafeSurfaceOutput() {
		return nil
	}
	report, err := a.service.BuildRunReport(runID, "")
	if err != nil {
		return err
	}
	a.renderRunDeltaReport(report)
	a.renderModules(run.ModuleResults)
	if err := a.renderExecutionTimeline(run.ID); err != nil {
		return err
	}
	if err := a.renderArtifacts(run.ArtifactRefs); err != nil {
		return err
	}
	a.renderFindings(findings)
	return nil
}

func (a *App) renderRunSummary(run domain.ScanRun, project *domain.Project, findings []domain.Finding) {
	if a.shellSafeSurfaceOutput() {
		fmt.Print(a.renderPlainRunSummary(run, project, findings))
		return
	}

	finished := "-"
	if run.FinishedAt != nil {
		finished = run.FinishedAt.Local().Format(time.RFC822)
	}
	failedModules, skippedModules, retriedModules := a.moduleExecutionCounts(run.ModuleResults)
	queuedModules, runningModules, completedModules, _, _ := a.moduleStatusCounts(run.ModuleResults)
	contract := a.isolationContract(run.Profile)
	hotFindings := a.prioritizedFindings(findings, 2)
	hotFindingSummary := "-"
	if len(hotFindings) > 0 {
		hotFindingSummary = a.hottestFindingLine(hotFindings[0], 64)
	}
	postureBadge := a.scanPostureBadge(run)
	postureSummary := a.scanPostureSummary(run)

	projectName := run.ProjectID
	projectPath := "-"
	if project != nil {
		projectName = project.DisplayName
		projectPath = project.LocationHint
	}
	operatorFocus := a.commandHint("findings", "--run", run.ID)
	if run.Summary.TotalFindings == 0 && !run.Summary.Blocked {
		operatorFocus = a.commandHint("runs", "diff", run.ID)
	}

	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n%s\n%s\n[cyan]%s[-]",
				a.catalog.T("run_id"),
				run.ID,
				a.catalog.T("status"),
				a.statusBadge(string(run.Status)),
				a.catalog.T("title"),
				projectName,
			)},
			{Data: a.ptermSprintf("%s\n%s\n%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]",
				a.catalog.T("overview_live_pressure"),
				postureBadge,
				a.catalog.T("summary_title"),
				trimForSelect(postureSummary, 72),
				a.catalog.T("overview_operator_focus"),
				operatorFocus,
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]",
				a.catalog.T("started_at"),
				run.StartedAt.Local().Format(time.RFC822),
				a.catalog.T("finished_at"),
				finished,
				a.catalog.T("project_path"),
				projectPath,
			)},
		},
		{
			{Data: a.ptermSprintf("%s\n%s\n%s\n%s\n%s\n[cyan]%s[-]",
				a.catalog.T("scan_mode"),
				a.modeBadge(run.Profile.Mode),
				a.catalog.T("scan_gate"),
				a.severityBadge(run.Profile.SeverityGate),
				a.catalog.T("runtime_preferred_mode"),
				strings.ToUpper(string(run.Profile.Isolation)),
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]\n%s\n[cyan]%s[-]",
				a.catalog.T("scan_modules"),
				len(run.ModuleResults),
				a.catalog.T("scan_findings"),
				run.Summary.TotalFindings,
				a.catalog.T("scan_blocked"),
				ternary(run.Summary.Blocked, a.catalog.T("scan_blocked_yes"), a.catalog.T("scan_blocked_no")),
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]",
				a.catalog.T("module_queued_count"),
				queuedModules,
				a.catalog.T("module_running_count"),
				runningModules,
				a.catalog.T("module_completed_count"),
				completedModules,
				a.catalog.T("artifact_count"),
				len(run.ArtifactRefs),
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]",
				a.catalog.T("finding_hotlist_title"),
				hotFindingSummary,
				a.catalog.T("finding_exposure_title"),
				a.findingTriageSummary(findings),
			)},
		},
	}).Render()

	pterm.Println()
	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n%s\n%s\n%s\n%s\n%s",
				a.catalog.T("summary_total"),
				pterm.Cyan(fmt.Sprintf("%d", run.Summary.TotalFindings)),
				a.catalog.T("summary_critical"),
				a.severityBadgeCount(domain.SeverityCritical, run.Summary.CountsBySeverity[domain.SeverityCritical]),
				a.catalog.T("summary_high"),
				a.severityBadgeCount(domain.SeverityHigh, run.Summary.CountsBySeverity[domain.SeverityHigh]),
			)},
			{Data: a.ptermSprintf("%s\n%s\n%s\n%s\n%s\n%s",
				a.catalog.T("summary_medium"),
				a.severityBadgeCount(domain.SeverityMedium, run.Summary.CountsBySeverity[domain.SeverityMedium]),
				a.catalog.T("summary_low"),
				a.severityBadgeCount(domain.SeverityLow, run.Summary.CountsBySeverity[domain.SeverityLow]),
				a.catalog.T("summary_info"),
				a.severityBadgeCount(domain.SeverityInfo, run.Summary.CountsBySeverity[domain.SeverityInfo]),
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]",
				a.catalog.T("triage_open"),
				run.Summary.CountsByStatus[domain.FindingOpen],
				a.catalog.T("triage_investigating"),
				run.Summary.CountsByStatus[domain.FindingInvestigating],
				a.catalog.T("triage_accepted_risk"),
				run.Summary.CountsByStatus[domain.FindingAcceptedRisk],
				a.catalog.T("triage_false_positive"),
				run.Summary.CountsByStatus[domain.FindingFalsePositive],
				a.catalog.T("triage_fixed"),
				run.Summary.CountsByStatus[domain.FindingFixed],
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]",
				a.catalog.T("module_failed_count"),
				failedModules,
				a.catalog.T("module_skipped_count"),
				skippedModules,
				a.catalog.T("module_retried_count"),
				retriedModules,
			)},
		},
	}).Render()

	if len(hotFindings) > 0 {
		pterm.Println()
		pterm.DefaultSection.Println(a.catalog.T("overview_hot_findings"))
		a.renderInlineFindingCards(hotFindings, 2)
	}

	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("runtime_isolation_contract_title"))
	contractData := pterm.TableData{{a.catalog.T("title"), a.catalog.T("status")}}
	for _, row := range a.isolationContractRows(contract) {
		contractData = append(contractData, row)
	}
	_ = pterm.DefaultTable.WithHasHeader().WithData(contractData).Render()

	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("module_execution_title"))
	executionData := pterm.TableData{{a.catalog.T("module_failed_count"), a.catalog.T("module_skipped_count"), a.catalog.T("module_retried_count")}}
	executionData = append(executionData, []string{
		fmt.Sprintf("%d", failedModules),
		fmt.Sprintf("%d", skippedModules),
		fmt.Sprintf("%d", retriedModules),
	})
	_ = pterm.DefaultTable.WithHasHeader().WithData(executionData).Render()
}

func (a *App) renderScanOutcome(run domain.ScanRun, findings []domain.Finding, requiredErr error) {
	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("scan_outcome_title"))

	completed := 0
	failed := 0
	skipped := 0
	for _, module := range run.ModuleResults {
		switch module.Status {
		case domain.ModuleCompleted:
			completed++
		case domain.ModuleFailed:
			failed++
		case domain.ModuleSkipped:
			skipped++
		}
	}

	verdict := a.catalog.T("scan_outcome_clean")
	if requiredErr != nil {
		verdict = a.catalog.T("scan_outcome_partial")
	} else if run.Summary.TotalFindings > 0 {
		verdict = a.catalog.T("scan_outcome_findings")
	}

	confidence := a.catalog.T("scan_confidence_full")
	if requiredErr != nil {
		confidence = a.catalog.T("scan_confidence_partial")
	}

	panel := pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("scan_outcome_verdict"), verdict)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("scan_outcome_confidence"), confidence)},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]", a.catalog.T("scan_modules_completed"), completed)},
		},
		{
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]", a.catalog.T("scan_modules_failed"), failed)},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]", a.catalog.T("scan_modules_skipped"), skipped)},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]", a.catalog.T("summary_total"), len(findings))},
		},
	}
	_ = pterm.DefaultPanel.WithPanels(panel).Render()

	if requiredErr != nil {
		pterm.Error.Println(a.catalog.T("scan_outcome_partial_explainer"))
	} else if len(findings) == 0 {
		pterm.Success.Println(a.catalog.T("scan_outcome_clean_explainer"))
	} else {
		pterm.Warning.Printf("%s\n", a.catalog.T(
			"scan_outcome_findings_explainer",
			run.Summary.CountsBySeverity[domain.SeverityCritical],
			run.Summary.CountsBySeverity[domain.SeverityHigh],
			run.Summary.CountsBySeverity[domain.SeverityMedium],
			run.Summary.CountsBySeverity[domain.SeverityLow],
		))
	}

	failedModules := make([]string, 0)
	for _, module := range run.ModuleResults {
		if module.Status != domain.ModuleFailed && module.Status != domain.ModuleSkipped {
			continue
		}
		failedModules = append(failedModules, fmt.Sprintf("%s (%s)", module.Name, a.moduleFailureLabel(module.FailureKind)))
	}
	if len(failedModules) > 0 {
		pterm.Println()
		pterm.Warning.Println(a.catalog.T("scan_outcome_failed_modules"))
		for _, line := range failedModules {
			pterm.Println(" - " + line)
		}
	}

	pterm.Println()
	pterm.Info.Println(a.catalog.T("scan_outcome_next_steps"))
	if requiredErr != nil {
		pterm.Println(" - " + a.catalog.T("scan_outcome_next_steps_partial"))
		pterm.Println(" - " + a.catalog.T("scan_outcome_next_steps_doctor"))
		pterm.Println(" - " + a.catalog.T("scan_outcome_next_steps_rescan"))
		return
	}
	if len(findings) > 0 {
		pterm.Println(" - " + a.catalog.T("scan_outcome_next_steps_review"))
		pterm.Println(" - " + a.catalog.T("scan_outcome_next_steps_details"))
		pterm.Println(" - " + a.catalog.T("scan_outcome_next_steps_export"))
		return
	}
	pterm.Println(" - " + a.catalog.T("scan_outcome_next_steps_clean"))
}

func (a *App) renderScanPhaseVerdicts(run domain.ScanRun) {
	type phaseStats struct {
		completed int
		failed    int
		skipped   int
	}

	order := a.scanPhaseLines(extractModuleNames(run.ModuleResults))
	stats := make(map[string]*phaseStats, len(order))
	for _, phase := range order {
		stats[phase] = &phaseStats{}
	}
	for _, module := range run.ModuleResults {
		phase := a.modulePhaseLabel(module.Name)
		if _, ok := stats[phase]; !ok {
			stats[phase] = &phaseStats{}
			order = append(order, phase)
		}
		switch module.Status {
		case domain.ModuleCompleted:
			stats[phase].completed++
		case domain.ModuleFailed:
			stats[phase].failed++
		case domain.ModuleSkipped:
			stats[phase].skipped++
		}
	}

	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("scan_phase_verdicts_title"))
	data := pterm.TableData{{a.catalog.T("title"), a.catalog.T("status"), a.catalog.T("scan_modules_completed"), a.catalog.T("scan_modules_failed"), a.catalog.T("scan_modules_skipped")}}
	for _, phase := range order {
		row := stats[phase]
		status := a.statusBadge("available")
		if row.failed > 0 {
			status = a.statusBadge("failed")
		} else if row.completed == 0 && row.skipped > 0 {
			status = a.statusBadge("skipped")
		}
		data = append(data, []string{
			phase,
			status,
			fmt.Sprintf("%d", row.completed),
			fmt.Sprintf("%d", row.failed),
			fmt.Sprintf("%d", row.skipped),
		})
	}
	_ = pterm.DefaultTable.WithHasHeader().WithData(data).Render()
}

func (a *App) renderFindingSpotlight(findings []domain.Finding, limit int) {
	if len(findings) == 0 {
		return
	}
	if limit <= 0 {
		limit = 3
	}
	if len(findings) < limit {
		limit = len(findings)
	}

	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("scan_spotlight_title"))
	for _, finding := range findings[:limit] {
		_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
			{
				{Data: a.ptermSprintf("%s\n%s\n%s\n[cyan]%s[-]", a.catalog.T("severity"), a.severityBadge(finding.Severity), a.catalog.T("category"), a.categoryLabel(finding.Category))},
				{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]", a.catalog.T("module"), finding.Module, a.catalog.T("location"), coalesceString(finding.Location, "-"))},
				{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]", a.catalog.T("title"), trimForSelect(finding.Title, 70), a.catalog.T("rule"), defaultString(finding.RuleID, "-"))},
			},
		}).Render()
	}
}

func (a *App) renderAnalystHandoff(run domain.ScanRun, findings []domain.Finding, requiredErr error) {
	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("scan_mc_handoff_title"))

	primaryAction := a.catalog.T("scan_mc_handoff_hold")
	secondaryAction := a.catalog.T("scan_mc_handoff_clean")
	if requiredErr != nil {
		primaryAction = a.catalog.T("scan_mc_handoff_doctor")
		secondaryAction = a.catalog.T("scan_mc_handoff_partial")
	} else if len(findings) > 0 {
		primaryAction = a.catalog.T("scan_mc_handoff_review")
		secondaryAction = a.catalog.T("scan_mc_handoff_findings", len(findings))
	}

	topFinding := "-"
	if finding, ok := a.nextReviewFinding(findings); ok {
		topFinding = fmt.Sprintf("%s | %s", a.severityLabel(finding.Severity), trimForSelect(finding.Title, 44))
	}

	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("scan_mc_handoff_primary"), primaryAction)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("scan_mc_handoff_secondary"), secondaryAction)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("scan_mc_handoff_top_finding"), topFinding)},
		},
	}).Render()
}

func (a *App) renderPlainScanLaunchSummary(project domain.Project, profile domain.ScanProfile) string {
	lines := []string{
		renderPlainStage(a.catalog.T("console_stage_launch"),
			fmt.Sprintf("%s: %s", a.catalog.T("title"), project.DisplayName),
			fmt.Sprintf("%s: %s", a.catalog.T("scan_target"), project.LocationHint),
			fmt.Sprintf("%s: %s", a.catalog.T("scan_mode"), a.modeLabel(profile.Mode)),
			fmt.Sprintf("%s: %s", a.catalog.T("runtime_preferred_mode"), a.displayUpper(a.isolationModeLabel(profile.Isolation))),
		),
		"",
		renderPlainStage(a.catalog.T("console_stage_mission"),
			fmt.Sprintf("%s: %s", a.catalog.T("coverage_profile"), a.coverageLabel(profile.Coverage)),
			fmt.Sprintf("%s: %d", a.catalog.T("scan_modules"), a.moduleCount(profile.Modules)),
			fmt.Sprintf("%s: %s", a.catalog.T("scan_live_phases"), strings.Join(a.scanPhaseLines(profile.Modules), " • ")),
		),
		"",
	}
	return strings.Join(lines, "\n")
}

func (a *App) renderPlainRunSummary(run domain.ScanRun, project *domain.Project, findings []domain.Finding) string {
	projectName := run.ProjectID
	projectPath := "-"
	if project != nil {
		projectName = project.DisplayName
		projectPath = project.LocationHint
	}
	finished := "-"
	if run.FinishedAt != nil {
		finished = run.FinishedAt.Local().Format(time.RFC822)
	}

	requiredErr := error(nil)
	if run.Status == domain.ScanCompleted {
		requiredErr = a.enforceRequiredModuleResults(run, run.Profile.Modules)
	}
	var debriefLines []string
	if run.Status == domain.ScanQueued || run.Status == domain.ScanRunning {
		debriefLines = []string{
			fmt.Sprintf("%s: %s", a.catalog.T("overview_live_pressure"), a.scanPostureSummary(run)),
			fmt.Sprintf("%s: %s", a.catalog.T("severity"), a.debriefSeverityBreakdown(run)),
			fmt.Sprintf("%s: %s", a.catalog.T("scan_modules"), a.failedOrSkippedModuleSummary(run.ModuleResults)),
			fmt.Sprintf("%s: %s", a.catalog.T("overview_hot_findings"), a.hotFindingSummary(findings, 2, 56)),
			fmt.Sprintf("%s: %s", a.catalog.T("overview_next_steps"), a.plainNextAction(run, findings, requiredErr)),
		}
	} else {
		debriefLines = append([]string{a.catalog.T("app_label_report") + ":"}, a.consoleDebriefReportLines(run, findings, requiredErr)...)
	}

	lines := []string{
		renderPlainStage(a.catalog.T("console_stage_launch"),
			fmt.Sprintf("%s: %s", a.catalog.T("title"), projectName),
			fmt.Sprintf("%s: %s", a.catalog.T("project_path"), projectPath),
			fmt.Sprintf("%s: %s", a.catalog.T("status"), a.displayUpper(a.scanStatusLabel(run.Status))),
			fmt.Sprintf("%s: %s", a.catalog.T("scan_mode"), a.modeLabel(run.Profile.Mode)),
		),
		"",
		renderPlainStage(a.catalog.T("console_stage_mission"),
			fmt.Sprintf("%s: %s", a.catalog.T("run_id"), run.ID),
			fmt.Sprintf("%s: %s", a.catalog.T("started_at"), run.StartedAt.Local().Format(time.RFC822)),
			fmt.Sprintf("%s: %s", a.catalog.T("finished_at"), finished),
			fmt.Sprintf("%s: %d", a.catalog.T("scan_modules"), len(run.ModuleResults)),
			fmt.Sprintf("%s: %d", a.catalog.T("scan_findings"), len(findings)),
			fmt.Sprintf("%s: %s", a.catalog.T("scan_blocked"), ternary(run.Summary.Blocked, a.catalog.T("scan_blocked_yes"), a.catalog.T("scan_blocked_no"))),
		),
		"",
		renderPlainReportStage(a.catalog.T("console_stage_debrief"), debriefLines...),
		"",
	}
	return strings.Join(lines, "\n")
}

func (a *App) plainNextAction(run domain.ScanRun, findings []domain.Finding, requiredErr error) string {
	switch {
	case run.Status == domain.ScanQueued || run.Status == domain.ScanRunning:
		return a.commandHint("runs", "watch", run.ID)
	case run.Status == domain.ScanFailed || run.Status == domain.ScanCanceled:
		return a.catalog.T("scan_debrief_action_show", run.ID)
	case requiredErr != nil:
		return a.catalog.T("scan_debrief_action_doctor")
	case len(findings) > 0:
		return a.catalog.T("scan_debrief_action_review")
	default:
		return a.catalog.T("scan_debrief_action_watch")
	}
}

func (a *App) renderMissionDebrief(project domain.Project, run domain.ScanRun, findings []domain.Finding, requiredErr error) {
	a.clearTerminalView()

	postureBadge := a.scanPostureBadge(run)
	postureSummary := a.scanPostureSummary(run)
	coverage := a.catalog.T("scan_confidence_full")
	if requiredErr != nil {
		coverage = a.catalog.T("scan_confidence_partial")
	}
	failed, skipped, retried := a.moduleExecutionCounts(run.ModuleResults)
	topFinding := "-"
	if finding, ok := a.nextReviewFinding(findings); ok {
		topFinding = fmt.Sprintf("%s | %s", a.severityLabel(finding.Severity), trimForSelect(finding.Title, 44))
	}

	pterm.DefaultHeader.Println(a.catalog.T("scan_debrief_title"))
	pterm.Println(postureBadge + " " + postureSummary)
	pterm.Println()
	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n%s", a.catalog.T("title"), project.DisplayName, a.catalog.T("status"), a.statusBadge(string(run.Status)))},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]", a.catalog.T("scan_mode"), a.modeLabel(run.Profile.Mode), a.catalog.T("coverage_profile"), a.coverageLabel(run.Profile.Coverage))},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%d[-]", a.catalog.T("scan_outcome_confidence"), coverage, a.catalog.T("summary_total"), run.Summary.TotalFindings)},
		},
		{
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]", a.catalog.T("scan_modules_completed"), len(run.ModuleResults)-failed-skipped, a.catalog.T("module_failed_count"), failed)},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]", a.catalog.T("module_skipped_count"), skipped, a.catalog.T("module_retried_count"), retried)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("scan_mc_handoff_top_finding"), topFinding)},
		},
	}).Render()

	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("scan_mc_cards_title"))
	a.renderInlineFindingCards(findings, 3)

	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("scan_phase_verdicts_title"))
	a.renderInlinePhaseVerdicts(run)

	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("scan_mc_handoff_title"))
	lines := a.scanDebriefActionLines(run, findings, requiredErr)
	for _, line := range lines {
		pterm.Println(" - " + line)
	}
}

func (a *App) scanDebriefActionLines(run domain.ScanRun, findings []domain.Finding, requiredErr error) []string {
	lines := make([]string, 0, 5)
	switch {
	case requiredErr != nil:
		lines = append(lines, a.catalog.T("scan_mc_handoff_doctor"))
		lines = append(lines, a.catalog.T("scan_debrief_action_doctor"))
		lines = append(lines, a.catalog.T("scan_debrief_action_rescan"))
	case len(findings) > 0:
		lines = append(lines, a.catalog.T("scan_mc_handoff_review"))
		lines = append(lines, a.catalog.T("scan_debrief_action_review"))
		lines = append(lines, a.catalog.T("scan_debrief_action_export"))
	default:
		lines = append(lines, a.catalog.T("scan_mc_handoff_clean"))
		lines = append(lines, a.catalog.T("scan_debrief_action_watch"))
	}
	lines = append(lines, a.catalog.T("scan_debrief_action_show", run.ID))
	return lines
}

func (a *App) consoleDebriefActionSummary(run domain.ScanRun, findings []domain.Finding, requiredErr error) string {
	lines := a.scanDebriefActionLines(run, findings, requiredErr)
	if len(lines) == 0 {
		return "-"
	}
	lines = limitStringSlice(lines, 2)
	return strings.Join(lines, " • ")
}

func (a *App) consoleDebriefModuleSummary(run domain.ScanRun) string {
	_, _, completed, failed, skipped := a.moduleStatusCounts(run.ModuleResults)
	return fmt.Sprintf(
		"%s %d • %s %d • %s %d",
		a.catalog.T("module_completed_count"),
		completed,
		a.catalog.T("module_failed_count"),
		failed,
		a.catalog.T("module_skipped_count"),
		skipped,
	)
}

func (a *App) consoleDebriefBlockerLines(run domain.ScanRun, requiredErr error) []string {
	lines := make([]string, 0, 4)
	if requiredErr != nil {
		lines = append(lines, a.catalog.T("scan_outcome_partial_explainer"))
	}
	for _, module := range run.ModuleResults {
		if module.Status != domain.ModuleFailed && module.Status != domain.ModuleSkipped {
			continue
		}
		lines = append(lines, fmt.Sprintf("- %s • %s", a.technicalUpper(module.Name), trimForSelect(a.moduleSummaryText(module), 72)))
		if len(lines) >= 3 {
			break
		}
	}
	if len(lines) == 0 {
		lines = append(lines, a.catalog.T("scan_report_blockers_clear"))
	}
	return lines
}

func (a *App) consoleDebriefFixPlanLines(run domain.ScanRun, findings []domain.Finding, requiredErr error) []string {
	steps := make([]string, 0, 4)
	if requiredErr != nil {
		steps = append(steps,
			fmt.Sprintf("1. %s", a.catalog.T("scan_debrief_action_doctor")),
			fmt.Sprintf("2. %s", a.catalog.T("scan_debrief_action_rescan")),
		)
		if len(findings) > 0 {
			steps = append(steps, fmt.Sprintf("3. %s", a.catalog.T("scan_debrief_action_review")))
		}
		return steps
	}
	if len(findings) > 0 {
		steps = append(steps,
			fmt.Sprintf("1. %s", a.catalog.T("scan_debrief_action_review")),
			fmt.Sprintf("2. %s", a.catalog.T("scan_debrief_action_show", run.ID)),
			fmt.Sprintf("3. %s", a.catalog.T("scan_debrief_action_export")),
		)
		return steps
	}
	return []string{
		fmt.Sprintf("1. %s", a.catalog.T("scan_debrief_action_watch")),
		fmt.Sprintf("2. %s", a.catalog.T("scan_debrief_action_show", run.ID)),
	}
}

func (a *App) consoleDebriefReportLines(run domain.ScanRun, findings []domain.Finding, requiredErr error) []string {
	totalModules := max(1, len(run.ModuleResults))
	_, _, completed, failed, skipped := a.moduleStatusCounts(run.ModuleResults)
	doneModules := min(totalModules, completed+failed+skipped)
	coverage := a.catalog.T("scan_confidence_full")
	verdict := a.catalog.T("scan_outcome_clean")
	switch {
	case requiredErr != nil:
		coverage = a.catalog.T("scan_confidence_partial")
		verdict = a.catalog.T("scan_outcome_partial")
	case len(findings) > 0:
		verdict = a.catalog.T("scan_outcome_findings")
	}
	lines := []string{
		a.catalog.T("scan_outcome_title") + ":",
		fmt.Sprintf("- %s: %s • %s", a.catalog.T("scan_outcome_verdict"), verdict, coverage),
		fmt.Sprintf("- %s: %s", a.catalog.T("scan_mc_progress"), a.missionProgressSummary(doneModules, totalModules)),
		fmt.Sprintf("- %s: %s", a.catalog.T("scan_phase_verdicts_title"), a.consoleDebriefModuleSummary(run)),
		fmt.Sprintf("- %s: %s • %s", a.catalog.T("status"), a.displayUpper(a.scanStatusLabel(run.Status)), a.displayUpper(a.scanPostureLabel(run))),
		fmt.Sprintf("- %s: %s", a.catalog.T("app_label_findings"), a.debriefSeverityBreakdown(run)),
		fmt.Sprintf("- %s: %s", a.catalog.T("scan_mc_handoff_title"), a.consoleDebriefActionSummary(run, findings, requiredErr)),
	}

	lines = append(lines, a.catalog.T("scan_report_blockers_title")+":")
	lines = append(lines, a.consoleDebriefBlockerLines(run, requiredErr)...)

	lines = append(lines, a.catalog.T("scan_report_fix_plan_title")+":", a.catalog.T("scan_report_first_step_title")+":")
	lines = append(lines, a.consoleDebriefFixPlanLines(run, findings, requiredErr)...)

	prioritized := a.prioritizedFindings(findings, 2)
	if len(prioritized) > 0 {
		lines = append(lines, a.catalog.T("scan_spotlight_title")+":")
		for _, finding := range prioritized {
			lines = append(lines, fmt.Sprintf("- %s", a.hottestFindingLine(finding, 64)))
		}
	}

	return lines
}

func extractModuleNames(modules []domain.ModuleResult) []string {
	names := make([]string, 0, len(modules))
	for _, module := range modules {
		names = append(names, module.Name)
	}
	return names
}

func limitStringSlice(items []string, count int) []string {
	if len(items) <= count {
		return items
	}
	return items[:count]
}

func (a *App) renderRunDeltaView(runID, baselineRunID string) error {
	report, err := a.service.BuildRunReport(runID, baselineRunID)
	if err != nil {
		return err
	}

	pterm.DefaultHeader.Println(a.catalog.T("diff_title"))
	a.renderRunDeltaReport(report)
	return nil
}

func (a *App) runRegressionGate(runID, baselineRunID string, threshold domain.Severity) error {
	return a.runRegressionGateWithVEX(runID, baselineRunID, threshold, "")
}

func (a *App) runRegressionGateWithVEX(runID, baselineRunID string, threshold domain.Severity, vexPath string) error {
	delta, current, baseline, blocking, err := a.service.EvaluateGateWithVEX(runID, baselineRunID, threshold, vexPath)
	if err != nil {
		return err
	}

	pterm.DefaultHeader.Println(a.catalog.T("gate_title"))
	baselineLabel := a.catalog.T("diff_no_baseline")
	if baseline != nil {
		baselineLabel = baseline.ID
	}

	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("run_id"), current.ID)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("diff_baseline"), baselineLabel)},
			{Data: a.ptermSprintf("%s\n%s", a.catalog.T("gate_threshold"), a.severityBadge(threshold))},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]", a.catalog.T("gate_blocking_count"), len(blocking))},
		},
	}).Render()

	if len(blocking) == 0 {
		pterm.Success.Println(a.catalog.T("gate_passed"))
		return nil
	}

	a.renderDeltaSection(a.catalog.T("gate_blocking_findings"), blocking)
	return fmt.Errorf("%s", a.catalog.T("gate_failed", len(blocking), strings.ToUpper(string(threshold)), delta.CountsByChange[domain.FindingNew]))
}

func (a *App) runPolicyEvaluation(runID, baselineRunID, policyID string) error {
	return a.runPolicyEvaluationWithVEX(runID, baselineRunID, policyID, "")
}

func (a *App) runPolicyEvaluationWithVEX(runID, baselineRunID, policyID, vexPath string) error {
	evaluation, current, baseline, err := a.service.EvaluatePolicyWithVEX(runID, baselineRunID, policyID, vexPath)
	if err != nil {
		return err
	}
	a.renderPolicyEvaluation(current, baseline, evaluation)
	if evaluation.Passed {
		pterm.Success.Println(a.catalog.T("policy_passed"))
		return nil
	}
	return fmt.Errorf("%s", a.catalog.T("policy_failed", evaluation.PolicyID))
}

func (a *App) renderPolicyEvaluation(current domain.ScanRun, baseline *domain.ScanRun, evaluation domain.PolicyEvaluation) {
	baselineLabel := a.catalog.T("diff_no_baseline")
	if baseline != nil {
		baselineLabel = baseline.ID
	}

	pterm.DefaultHeader.Println(a.catalog.T("policy_title"))
	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("run_id"), current.ID)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("diff_baseline"), baselineLabel)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("policy_id"), evaluation.PolicyID)},
			{Data: a.ptermSprintf("%s\n%s", a.catalog.T("status"), ternary(evaluation.Passed, a.statusBadge("available"), a.statusBadge("failed")))},
		},
	}).Render()

	data := pterm.TableData{{a.catalog.T("rule"), a.catalog.T("status"), a.catalog.T("scan_findings"), a.catalog.T("summary_title")}}
	for _, result := range evaluation.Results {
		status := a.statusBadge(string(result.Outcome))
		if result.Outcome == domain.PolicyOutcomePass {
			status = a.statusBadge("available")
		}
		data = append(data, []string{
			result.Rule.Title,
			status,
			fmt.Sprintf("%d", result.MatchedCount),
			result.Rule.Description,
		})
	}
	_ = pterm.DefaultTable.WithHasHeader().WithData(data).Render()
}

func (a *App) renderRunDelta(current domain.ScanRun, delta domain.RunDelta, baseline *domain.ScanRun) {
	baselineLabel := a.catalog.T("diff_no_baseline")
	if baseline != nil {
		baselineLabel = baseline.ID
	}
	newSummary := "-"
	if len(delta.NewFindings) > 0 {
		newSummary = a.hottestFindingLine(a.prioritizedFindings(delta.NewFindings, 1)[0], 56)
	}
	resolvedSummary := "-"
	if len(delta.ResolvedFindings) > 0 {
		resolvedSummary = a.hottestFindingLine(a.prioritizedFindings(delta.ResolvedFindings, 1)[0], 56)
	}

	pterm.Println()
	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("diff_current"), current.ID)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("diff_baseline"), baselineLabel)},
		},
		{
			{Data: a.ptermSprintf("%s\n%s", a.catalog.T("diff_new"), pterm.LightRed(fmt.Sprintf("%d", delta.CountsByChange[domain.FindingNew])))},
			{Data: a.ptermSprintf("%s\n%s", a.catalog.T("diff_existing"), pterm.LightYellow(fmt.Sprintf("%d", delta.CountsByChange[domain.FindingExisting])))},
			{Data: a.ptermSprintf("%s\n%s", a.catalog.T("diff_resolved"), pterm.LightGreen(fmt.Sprintf("%d", delta.CountsByChange[domain.FindingResolved])))},
		},
		{
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("finding_hotlist_title"), newSummary)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("scan_mc_handoff_top_finding"), resolvedSummary)},
		},
	}).Render()

	a.renderDeltaSection(a.catalog.T("diff_section_new"), delta.NewFindings)
	a.renderDeltaSection(a.catalog.T("diff_section_existing"), delta.ExistingFindings)
	a.renderDeltaSection(a.catalog.T("diff_section_resolved"), delta.ResolvedFindings)
}

func (a *App) renderRunDeltaReport(report domain.RunReport) {
	a.renderRunDelta(report.Run, report.Delta, report.Baseline)
}

func (a *App) renderDeltaSection(title string, findings []domain.Finding) {
	pterm.Println()
	pterm.DefaultSection.Println(title)
	if len(findings) == 0 {
		pterm.DefaultBasicText.Println("-")
		return
	}

	data := pterm.TableData{{a.catalog.T("severity"), a.catalog.T("triage_status"), a.catalog.T("finding_priority"), a.catalog.T("finding_exposure_title"), a.catalog.T("title"), a.catalog.T("location")}}
	for _, finding := range a.prioritizedFindings(findings, len(findings)) {
		data = append(data, []string{
			a.severityBadge(finding.Severity),
			a.findingStatusBadge(finding.Status),
			fmt.Sprintf("%.1f", finding.Priority),
			trimForSelect(a.findingExposureSummary(finding), 28),
			finding.Title,
			finding.Location,
		})
		if len(data) > 8 {
			break
		}
	}
	_ = pterm.DefaultTable.WithHasHeader().WithData(data).Render()
}

func (a *App) renderModules(modules []domain.ModuleResult) {
	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("scan_modules"))
	if len(modules) == 0 {
		pterm.DefaultBasicText.Println("-")
		return
	}
	queued, running, completed, failed, skipped := a.moduleStatusCounts(modules)
	_, _, retried := a.moduleExecutionCounts(modules)
	focusSummary := "-"
	for _, module := range modules {
		if module.Status == domain.ModuleRunning || module.Status == domain.ModuleFailed {
			focusSummary = fmt.Sprintf("%s | %s", module.Name, trimForSelect(a.moduleNarrative(module.Name), 52))
			break
		}
	}
	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]", a.catalog.T("module_queued_count"), queued, a.catalog.T("module_running_count"), running)},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]", a.catalog.T("module_completed_count"), completed, a.catalog.T("module_failed_count"), failed)},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]", a.catalog.T("module_skipped_count"), skipped, a.catalog.T("module_retried_count"), retried)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("overview_operator_focus"), focusSummary)},
		},
	}).Render()
	pterm.Println()

	data := pterm.TableData{{
		a.catalog.T("module"),
		a.catalog.T("scan_mc_lane"),
		a.catalog.T("category"),
		a.catalog.T("status"),
		a.catalog.T("module_attempts"),
		a.catalog.T("module_duration"),
		a.catalog.T("module_failure_kind"),
		a.catalog.T("module_timed_out"),
		a.catalog.T("scan_findings"),
		a.catalog.T("summary_title"),
	}}
	for _, module := range modules {
		data = append(data, []string{
			module.Name,
			a.modulePhaseLabel(module.Name),
			a.categoryLabel(module.Category),
			a.moduleStatusBadge(module.Status),
			fmt.Sprintf("%d", a.maxModuleAttempts(module)),
			a.formatModuleDuration(module.DurationMs),
			a.moduleFailureLabel(module.FailureKind),
			ternary(module.TimedOut, a.yesText(), a.noText()),
			fmt.Sprintf("%d", module.FindingCount),
			module.Summary,
		})
	}
	_ = pterm.DefaultTable.WithHasHeader().WithData(data).Render()
}

func (a *App) renderArtifacts(artifacts []domain.ArtifactRef) error {
	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("artifacts_title"))
	if len(artifacts) == 0 {
		pterm.DefaultBasicText.Println(a.catalog.T("no_artifacts"))
		return nil
	}
	redacted, encrypted := artifactProtectionCounts(artifacts)
	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]", a.catalog.T("artifact_count"), len(artifacts))},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]", a.catalog.T("artifact_redaction"), redacted, a.catalog.T("artifact_encryption"), encrypted)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("kind"), topArtifactKinds(artifacts, 3))},
		},
	}).Render()
	pterm.Println()

	data := pterm.TableData{{a.catalog.T("artifact_kind"), a.catalog.T("artifact_label"), a.catalog.T("artifact_protection"), a.catalog.T("artifact_expires_at"), a.catalog.T("artifact_uri")}}
	for _, artifact := range artifacts {
		data = append(data, []string{
			artifact.Kind,
			artifact.Label,
			a.artifactProtectionLabel(artifact),
			a.artifactExpiryLabel(artifact),
			artifact.URI,
		})
	}
	return pterm.DefaultTable.WithHasHeader().WithData(data).Render()
}

func (a *App) renderExecutionTimeline(runID string) error {
	traces, err := a.service.GetRunExecutionTraces(runID)
	if err != nil {
		return err
	}

	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("execution_timeline_title"))
	if len(traces) == 0 {
		pterm.DefaultBasicText.Println(a.catalog.T("no_execution_traces"))
		return nil
	}
	failed := 0
	retried := 0
	active := 0
	for _, trace := range traces {
		if trace.Status == domain.ModuleFailed {
			failed++
		}
		if trace.AttemptsUsed > 1 {
			retried++
		}
		if trace.Status == domain.ModuleRunning || trace.Status == domain.ModuleQueued {
			active++
		}
	}
	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]", a.catalog.T("module_execution_title"), len(traces))},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]", a.catalog.T("module_failed_count"), failed, a.catalog.T("module_retried_count"), retried)},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]", a.catalog.T("module_running_count"), active)},
		},
	}).Render()
	pterm.Println()

	data := pterm.TableData{{
		a.catalog.T("module"),
		a.catalog.T("status"),
		a.catalog.T("module_attempts"),
		a.catalog.T("module_duration"),
		a.catalog.T("module_failure_kind"),
		a.catalog.T("module_last_attempt"),
	}}
	for _, trace := range traces {
		data = append(data, []string{
			trace.Module,
			a.moduleStatusBadge(trace.Status),
			fmt.Sprintf("%d/%d", trace.AttemptsUsed, maxInt(trace.MaxAttempts, trace.AttemptsUsed)),
			a.formatModuleDuration(trace.DurationMs),
			a.moduleFailureLabel(trace.FailureKind),
			a.traceLastAttemptLabel(trace),
		})
	}
	return pterm.DefaultTable.WithHasHeader().WithData(data).Render()
}

func (a *App) renderFindingsView(runID, severity, category, status, change string, limit int) error {
	snapshot := a.buildPortfolioSnapshot()
	findings := findingsViewSource(snapshot, runID)
	if strings.TrimSpace(change) != "" && strings.TrimSpace(runID) == "" {
		return fmt.Errorf("%s", a.catalog.T("change_filter_requires_run"))
	}

	filtered := findings
	if strings.TrimSpace(change) != "" {
		report, err := a.service.BuildRunReport(runID, "")
		if err != nil {
			return err
		}
		filtered = filterFindingsByReportChange(report, change)
	}
	filtered = filterFindings(filtered, severity, category, status, limit)

	scope := a.catalog.T("findings_scope_all")
	if runID != "" {
		scope = a.catalog.T("findings_scope_run", runID)
	}
	filterSummary := a.catalog.T("filters_none")
	applied := make([]string, 0, 3)
	if severity != "" {
		applied = append(applied, a.catalog.T("severity")+": "+severity)
	}
	if category != "" {
		applied = append(applied, a.catalog.T("category")+": "+category)
	}
	if status != "" {
		applied = append(applied, a.catalog.T("triage_status")+": "+status)
	}
	if change != "" {
		applied = append(applied, a.catalog.T("change")+": "+change)
	}
	if len(applied) > 0 {
		filterSummary = strings.Join(applied, " | ")
	}
	counts := severityCounts(filtered)
	hotFindings := a.prioritizedFindings(filtered, 3)
	hotFindingSummary := a.catalog.T("overview_no_findings")
	if len(hotFindings) > 0 {
		lines := make([]string, 0, len(hotFindings))
		for _, finding := range hotFindings {
			lines = append(lines, a.hottestFindingLine(finding, 64))
		}
		hotFindingSummary = strings.Join(lines, "\n")
	}
	operatorFocus := a.catalog.T("findings_focus_clean")
	if len(filtered) > 0 {
		operatorFocus = a.findingTriageSummary(filtered)
	}

	pterm.Println(a.renderStaticBrandHero(a.catalog.T("findings_title")))
	pterm.Println()
	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]\n%s\n[cyan]%d[-]",
				a.catalog.T("findings_scope"),
				scope,
				a.catalog.T("findings_filters"),
				filterSummary,
				a.catalog.T("findings_limit"),
				limit,
			)},
			{Data: a.ptermSprintf("%s\n%s\n%s\n%s\n%s\n%s",
				a.catalog.T("findings_exposure_title"),
				a.severityBadgeCount(domain.SeverityCritical, counts[domain.SeverityCritical]),
				a.severityBadgeCount(domain.SeverityHigh, counts[domain.SeverityHigh]),
				a.severityBadgeCount(domain.SeverityMedium, counts[domain.SeverityMedium]),
				a.severityBadgeCount(domain.SeverityLow, counts[domain.SeverityLow]),
				a.severityBadgeCount(domain.SeverityInfo, counts[domain.SeverityInfo]),
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]\n%s\n[cyan]%.1f[-]",
				a.catalog.T("finding_kev_title"),
				countKEVFindings(filtered),
				a.catalog.T("finding_compliance_title"),
				countComplianceSignals(filtered),
				a.catalog.T("finding_attack_chain_title"),
				countAttackChains(filtered),
				a.catalog.T("finding_priority"),
				averagePriority(filtered),
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n%s",
				a.catalog.T("overview_operator_focus"),
				operatorFocus,
				a.catalog.T("finding_hotlist_title"),
				hotFindingSummary,
			)},
		},
	}).Render()

	if len(filtered) == 0 {
		pterm.Warning.Println(a.catalog.T("no_matching_findings"))
		return nil
	}

	a.renderFindings(filtered)
	return nil
}

func findingsViewSource(snapshot portfolioSnapshot, runID string) []domain.Finding {
	if strings.TrimSpace(runID) == "" {
		return snapshot.Findings
	}
	return snapshot.findingsForRun(runID)
}

func (a *App) renderFindings(findings []domain.Finding) {
	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("findings_queue_title"))
	if len(findings) == 0 {
		pterm.DefaultBasicText.Println(a.catalog.T("no_findings"))
		return
	}

	counts := make(map[domain.Severity]int, len(domain.AllSeverities()))
	for _, finding := range findings {
		counts[finding.Severity]++
	}

	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n%s\n%s\n%s\n%s\n%s",
				a.catalog.T("summary_total"),
				pterm.Cyan(fmt.Sprintf("%d", len(findings))),
				a.catalog.T("summary_critical"),
				a.severityBadgeCount(domain.SeverityCritical, counts[domain.SeverityCritical]),
				a.catalog.T("summary_high"),
				a.severityBadgeCount(domain.SeverityHigh, counts[domain.SeverityHigh]),
			)},
			{Data: a.ptermSprintf("%s\n%s\n%s\n%s\n%s\n%s",
				a.catalog.T("summary_medium"),
				a.severityBadgeCount(domain.SeverityMedium, counts[domain.SeverityMedium]),
				a.catalog.T("summary_low"),
				a.severityBadgeCount(domain.SeverityLow, counts[domain.SeverityLow]),
				a.catalog.T("summary_info"),
				a.severityBadgeCount(domain.SeverityInfo, counts[domain.SeverityInfo]),
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]",
				a.catalog.T("triage_open"),
				countFindingStatus(findings, domain.FindingOpen),
				a.catalog.T("triage_investigating"),
				countFindingStatus(findings, domain.FindingInvestigating),
				a.catalog.T("triage_accepted_risk"),
				countFindingStatus(findings, domain.FindingAcceptedRisk),
				a.catalog.T("triage_false_positive"),
				countFindingStatus(findings, domain.FindingFalsePositive),
				a.catalog.T("triage_fixed"),
				countFindingStatus(findings, domain.FindingFixed),
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]\n%s\n[cyan]%.1f[-]\n%s\n[cyan]%s[-]",
				a.catalog.T("finding_kev_title"),
				countKEVFindings(findings),
				a.catalog.T("finding_compliance_title"),
				countComplianceSignals(findings),
				a.catalog.T("finding_attack_chain_title"),
				countAttackChains(findings),
				a.catalog.T("finding_priority"),
				averagePriority(findings),
				a.catalog.T("overview_trendline"),
				asciiSparkline([]int{
					counts[domain.SeverityCritical],
					counts[domain.SeverityHigh],
					counts[domain.SeverityMedium],
					counts[domain.SeverityLow],
					counts[domain.SeverityInfo],
				}),
			)},
		},
	}).Render()

	a.renderInlineFindingCards(a.prioritizedFindings(findings, 2), 2)

	data := pterm.TableData{{a.catalog.T("severity"), a.catalog.T("triage_status"), a.catalog.T("title"), a.catalog.T("finding_priority"), a.catalog.T("finding_exposure_title"), a.catalog.T("module"), a.catalog.T("location")}}
	for _, finding := range a.prioritizedFindings(findings, len(findings)) {
		data = append(data, []string{
			a.severityBadge(finding.Severity),
			a.findingStatusBadge(finding.Status),
			finding.Title,
			fmt.Sprintf("%.1f", finding.Priority),
			trimForSelect(a.findingExposureSummary(finding), 32),
			coalesceString(finding.Module, a.categoryLabel(finding.Category)),
			finding.Location,
		})
	}
	_ = pterm.DefaultTable.WithHasHeader().WithData(data).Render()
}

func (a *App) renderFindingDetails(finding domain.Finding) error {
	pterm.Println(a.renderStaticBrandHero(a.catalog.T("finding_details_title")))
	pterm.Println()
	vexStatus := defaultString(a.findingVEXStatusLabel(finding.VEXStatus), "-")
	vexReason := defaultString(a.findingVEXJustificationLabel(finding.VEXJustification), "-")
	vexSource := defaultString(finding.VEXStatementSource, "-")
	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n%s\n%s\n[cyan]%s[-]", a.catalog.T("severity"), a.severityBadge(finding.Severity), a.catalog.T("category"), a.categoryLabel(finding.Category))},
			{Data: a.ptermSprintf("%s\n%s\n%s\n[cyan]%s[-]", a.catalog.T("triage_status"), a.findingStatusBadge(finding.Status), a.catalog.T("rule"), coalesceString(finding.RuleID, "-"))},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]\n%s\n[cyan]%.1f[-]", a.catalog.T("module"), finding.Module, a.catalog.T("location"), coalesceString(finding.Location, "-"), a.catalog.T("finding_priority"), finding.Priority)},
		},
		{
			{Data: a.ptermSprintf("%s\n[cyan]%.1f[-]\n%s\n[cyan]%.1f%%[-]\n%s\n%s", a.catalog.T("finding_cvss31"), finding.CVSS31, a.catalog.T("finding_epss"), finding.EPSSPercent, a.catalog.T("finding_kev_title"), ternary(finding.KEV, a.statusBadge("breach"), a.statusBadge("clean")))},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]", a.catalog.T("finding_cwes"), coalesceString(strings.Join(finding.CWEs, ", "), "-"), a.catalog.T("finding_compliance_title"), coalesceString(strings.Join(finding.Compliance, ", "), "-"))},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]", a.catalog.T("finding_attack_chain_title"), a.findingAttackChainSummary(finding), a.catalog.T("owner"), defaultString(finding.Owner, "-"))},
		},
		{
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%.2f[-]\n%s\n[cyan]%s[-]", a.catalog.T("title"), finding.Title, a.catalog.T("confidence"), finding.Confidence, a.catalog.T("reachability"), coalesceString(finding.Reachability.String(), "-"))},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%.1f[-]\nVEX\n[cyan]%s[-]", a.catalog.T("fingerprint"), finding.Fingerprint, a.catalog.T("finding_asset_value"), finding.AssetValue, vexStatus)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]", a.catalog.T("finding_exposure_title"), a.findingExposureSummary(finding), a.catalog.T("reason"), vexReason)},
		},
	}).Render()

	pterm.Println()
	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]",
				a.catalog.T("overview_operator_focus"),
				a.findingPriorityLabel(finding),
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]",
				a.catalog.T("finding_hotlist_title"),
				a.findingOwnershipSummary(finding),
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]",
				a.catalog.T("overview_next_steps"),
				a.commandHint("review", finding.Fingerprint, "--run", finding.ScanID),
				a.catalog.T("triage_title"),
				a.commandHint("triage", "set", finding.Fingerprint, "--run", finding.ScanID),
				a.catalog.T("artifact_uri"),
				vexSource,
			)},
		},
	}).Render()

	pterm.Println()
	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]",
				a.catalog.T("tags"),
				coalesceString(strings.Join(finding.Tags, ", "), "-"),
				a.catalog.T("note"),
				coalesceString(finding.Note, "-"),
			)},
			{Data: a.ptermSprintf("%s\n%s",
				a.catalog.T("remediation"),
				trimForSelect(coalesceString(finding.Remediation, "-"), 140),
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]",
				a.catalog.T("finding_operator_context_title"),
				a.findingOwnershipSummary(finding),
				a.catalog.T("evidence_ref"),
				coalesceString(finding.EvidenceRef, "-"),
			)},
		},
	}).Render()

	if len(finding.Related) > 0 {
		pterm.Println()
		pterm.DefaultSection.Println(a.catalog.T("finding_related_title"))
		pterm.Println(strings.Join(finding.Related, "\n"))
	}
	return nil
}

func (a *App) renderTriage(status string) error {
	items := a.service.ListTriage()
	filtered := make([]domain.FindingTriage, 0, len(items))
	for _, item := range items {
		if status != "" && string(item.Status) != status {
			continue
		}
		filtered = append(filtered, item)
	}

	pterm.Println(a.renderStaticBrandHero(a.catalog.T("triage_list_title")))
	pterm.Println()
	if len(filtered) == 0 {
		pterm.DefaultBasicText.Println(a.catalog.T("no_triage"))
		return nil
	}
	latestUpdate := "-"
	if value := latestTriageUpdate(filtered); value != nil {
		latestUpdate = value.Local().Format(time.RFC822)
	}
	operatorFocus := a.catalog.T("triage_focus_empty")
	if value := latestTriageUpdate(filtered); value != nil {
		operatorFocus = fmt.Sprintf("%s | %s", latestUpdate, a.commandHint("triage", "set"))
	}
	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]",
				a.catalog.T("triage_records"),
				len(filtered),
				a.catalog.T("owner"),
				triageOwnerCount(filtered),
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]",
				a.catalog.T("triage_open"),
				countTriageStatus(filtered, domain.FindingOpen),
				a.catalog.T("triage_investigating"),
				countTriageStatus(filtered, domain.FindingInvestigating),
				a.catalog.T("triage_fixed"),
				countTriageStatus(filtered, domain.FindingFixed),
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]",
				a.catalog.T("overview_operator_focus"),
				operatorFocus,
				a.catalog.T("overview_next_steps"),
				a.commandHint("triage", "clear", "<fingerprint>"),
			)},
		},
	}).Render()
	pterm.Println()

	pterm.DefaultSection.Println(a.catalog.T("triage_queue_title"))
	data := pterm.TableData{{a.catalog.T("fingerprint"), a.catalog.T("triage_status"), a.catalog.T("owner"), a.catalog.T("tags"), a.catalog.T("note"), a.catalog.T("updated_at")}}
	for _, item := range filtered {
		data = append(data, []string{
			item.Fingerprint,
			a.findingStatusBadge(item.Status),
			item.Owner,
			strings.Join(item.Tags, ","),
			trimForSelect(coalesceString(item.Note, "-"), 40),
			item.UpdatedAt.Local().Format(time.RFC822),
		})
	}
	return pterm.DefaultTable.WithHasHeader().WithData(data).Render()
}

func filterFindingsByReportChange(report domain.RunReport, change string) []domain.Finding {
	normalized := strings.TrimSpace(strings.ToLower(change))
	if normalized == "" {
		return findingsFromReport(report)
	}
	if normalized == strings.ToLower(string(domain.FindingResolved)) {
		return append([]domain.Finding(nil), report.Delta.ResolvedFindings...)
	}

	filtered := make([]domain.Finding, 0, len(report.Findings))
	for _, item := range report.Findings {
		itemChange := item.Change
		if itemChange == "" {
			itemChange = domain.FindingNew
		}
		if strings.EqualFold(string(itemChange), normalized) {
			filtered = append(filtered, item.Finding)
		}
	}
	return filtered
}

func findingsFromReport(report domain.RunReport) []domain.Finding {
	findings := make([]domain.Finding, 0, len(report.Findings))
	for _, item := range report.Findings {
		findings = append(findings, item.Finding)
	}
	return findings
}

func (a *App) renderSuppressions() error {
	suppressions := a.service.ListSuppressions()
	pterm.Println(a.renderStaticBrandHero(a.catalog.T("suppress_list_title")))
	pterm.Println()
	if len(suppressions) == 0 {
		pterm.DefaultBasicText.Println(a.catalog.T("no_suppressions"))
		return nil
	}
	nextExpiry := "-"
	expiringSoon := suppressionExpiringCount(suppressions, 7*24*time.Hour)
	if len(suppressions) > 0 {
		soonest := suppressions[0].ExpiresAt
		for _, suppression := range suppressions[1:] {
			if suppression.ExpiresAt.Before(soonest) {
				soonest = suppression.ExpiresAt
			}
		}
		nextExpiry = soonest.Local().Format(time.RFC822)
	}
	operatorFocus := fmt.Sprintf("%s | %s", nextExpiry, a.commandHint("suppress", "renew", "<fingerprint>"))
	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]",
				a.catalog.T("suppression_records"),
				len(suppressions),
				a.catalog.T("owner"),
				suppressionOwnerCount(suppressions),
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]\n%s\n[cyan]%s[-]",
				a.catalog.T("suppression_expiring_soon"),
				expiringSoon,
				a.catalog.T("next_expiry"),
				nextExpiry,
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]",
				a.catalog.T("overview_operator_focus"),
				operatorFocus,
				a.catalog.T("overview_next_steps"),
				a.commandHint("suppress", "remove", "<fingerprint>"),
			)},
		},
	}).Render()
	pterm.Println()

	pterm.DefaultSection.Println(a.catalog.T("suppress_queue_title"))
	data := pterm.TableData{{a.catalog.T("fingerprint"), a.catalog.T("owner"), a.catalog.T("reason"), a.catalog.T("expires_at"), a.catalog.T("ticket")}}
	for _, suppression := range suppressions {
		data = append(data, []string{
			suppression.Fingerprint,
			suppression.Owner,
			trimForSelect(suppression.Reason, 42),
			suppression.ExpiresAt.Local().Format(time.RFC822),
			suppression.TicketRef,
		})
	}
	return pterm.DefaultTable.WithHasHeader().WithData(data).Render()
}

func (a *App) renderDASTPlan(plan domain.DastPlan, targets []domain.DastTarget) error {
	pterm.DefaultHeader.Println(a.catalog.T("dast_title"))

	targetSummary := a.catalog.T("filters_none")
	if len(targets) > 0 {
		items := make([]string, 0, len(targets))
		for _, target := range targets {
			summary := fmt.Sprintf("%s=%s", target.Name, target.URL)
			if target.AuthProfile != "" {
				summary += fmt.Sprintf(" [%s:%s]", target.AuthType.String(), target.AuthProfile)
			}
			items = append(items, summary)
		}
		targetSummary = strings.Join(items, "\n")
	}

	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("project_id"), plan.ProjectID)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("dast_policy"), strings.ToUpper(plan.Policy))},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("scan_target"), targetSummary)},
		},
	}).Render()

	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("dast_steps"))
	for index, step := range plan.Steps {
		pterm.Printf("%d. %s\n", index+1, step)
	}
	return nil
}

func (a *App) renderStreamEvent(event domain.StreamEvent) {
	if a.streamMissionControl {
		return
	}
	if !a.streamVerbose {
		switch {
		case event.Type == "finding.created" && event.Finding != nil:
			pterm.Warning.Printf("%s\n", a.catalog.T("finding_detected", event.Finding.Title))
		case event.Type == "run.failed":
			pterm.Error.Println(a.catalog.T("scan_failed"))
		case event.Type == "run.canceled":
			pterm.Warning.Println(a.catalog.T("scan_canceled"))
		}
		return
	}

	switch {
	case event.Type == "module.updated" && event.Module != nil:
		label := a.moduleEventLabel(*event.Module)
		switch event.Module.Status {
		case domain.ModuleQueued:
			pterm.Info.Printf("%s\n", a.catalog.T("module_queued", label))
		case domain.ModuleRunning:
			pterm.Info.Printf("%s\n", a.catalog.T("module_started", label))
		case domain.ModuleCompleted:
			pterm.Success.Printf("%s\n", a.catalog.T("module_completed", label))
		case domain.ModuleSkipped:
			pterm.Warning.Printf("%s\n", a.catalog.T("module_skipped", label))
		case domain.ModuleFailed:
			pterm.Error.Printf("%s\n", a.catalog.T("module_failed", label))
		}
	case event.Type == "module.execution" && event.Execution != nil:
		a.renderModuleExecutionEvent(*event.Execution, event.Attempt)
	case event.Type == "finding.created" && event.Finding != nil:
		pterm.Warning.Printf("%s\n", a.catalog.T("finding_detected", event.Finding.Title))
	case event.Type == "run.completed":
		pterm.Success.Println(a.catalog.T("scan_completed"))
	case event.Type == "run.canceled":
		pterm.Warning.Println(a.catalog.T("scan_canceled"))
	case event.Type == "run.failed":
		pterm.Error.Println(a.catalog.T("scan_failed"))
	}
}
