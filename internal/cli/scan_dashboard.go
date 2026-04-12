package cli

import (
	"fmt"
	"os"
	"path/filepath"
	runtimemetrics "runtime/metrics"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/pterm/pterm"

	"github.com/batu3384/ironsentinel/internal/domain"
)

type missionRuntimeMetrics struct {
	CPUPercent     float64
	MemoryMiB      float64
	Goroutines     uint64
	ModulePerMin   float64
	FindingPerMin  float64
	EventPerMin    float64
	HealthLabel    string
	HealthSummary  string
	CompletedCount int
	QueueDepth     int
	ArtifactCount  int
	Elapsed        time.Duration
}

var missionRuntimeMetricsReader = readMissionRuntimeMetrics

var scanTreeIgnoredDirs = map[string]struct{}{
	".git":         {},
	".next":        {},
	"node_modules": {},
	"dist":         {},
	"build":        {},
	"coverage":     {},
	".venv":        {},
	"venv":         {},
}

func (m scanMissionModel) renderMissionBriefPanel(width int) string {
	stacks := strings.Join(m.project.DetectedStacks, ", ")
	if strings.TrimSpace(stacks) == "" {
		stacks = m.app.catalog.T("scan_scope_pending")
	}
	run := m.consoleRun()
	activeModule := defaultString(m.console.lastModule, "-")
	done, total := m.progressCounts()
	queued, running, completed, failed, skipped := m.app.moduleStatusCounts(run.ModuleResults)
	rail := fmt.Sprintf(
		"%s  %s • %s %d • %s %d",
		m.app.scanProgressRail(done, total, min(20, max(10, width/5))),
		m.app.missionProgressSummary(done, total),
		strings.ToLower(m.app.catalog.T("module_running_count")),
		running,
		strings.ToLower(m.app.catalog.T("module_queued_count")),
		queued,
	)
	lines := []string{rail, ""}
	lines = append(lines, renderFactRows(m.app.tuiTheme(), width,
		factPair{Label: m.app.catalog.T("app_label_project"), Value: m.project.DisplayName},
		factPair{Label: m.app.catalog.T("app_label_target"), Value: trimForSelect(m.project.LocationHint, max(24, width-18))},
		factPair{Label: m.app.catalog.T("app_label_stacks"), Value: trimForSelect(stacks, max(18, width-18))},
		factPair{Label: m.app.catalog.T("app_label_module"), Value: m.app.technicalUpper(activeModule)},
		factPair{Label: m.app.catalog.T("app_label_scope"), Value: fmt.Sprintf("%d/%d • %s %d • %s %d", done, total, strings.ToLower(m.app.catalog.T("module_completed_count")), completed, strings.ToLower(m.app.catalog.T("module_failed_count")), failed)},
		factPair{Label: m.app.catalog.T("app_label_findings"), Value: fmt.Sprintf("%d • %s %d • %s %d • %s %d", run.Summary.TotalFindings, strings.ToLower(m.app.catalog.T("module_completed_count")), completed, strings.ToLower(m.app.catalog.T("module_failed_count")), failed, strings.ToLower(m.app.catalog.T("module_skipped_count")), skipped)},
		factPair{Label: m.app.catalog.T("app_label_isolation"), Value: m.app.displayUpper(m.app.isolationModeLabel(m.profile.Isolation))},
		factPair{Label: m.app.catalog.T("app_label_health"), Value: m.app.displayUpper(m.app.scanPostureLabel(run))},
	)...)
	return renderMissionBox(m.app.catalog.T("scan_mode_live_brief_title"), strings.Join(lines, "\n"))
}

func (m scanMissionModel) renderMissionLanePanel(width int) string {
	run := m.consoleRun()
	done, total := m.progressCounts()
	currentLane, nextLane, deferredLane := m.missionLaneFlow()
	activeLaneDescriptor := m.missionCurrentLaneDescriptor()
	activeLane := m.app.displayUpper(m.app.phaseDisplayText(m.console.lastPhase, m.console.lastModule))
	activeModule := m.app.technicalUpper(defaultString(m.console.lastModule, "-"))
	state := m.app.displayUpper(m.app.moduleStatusLabel(domain.ModuleQueued))
	if raw := strings.TrimSpace(m.console.lastStatus); raw != "" {
		state = m.app.displayUpper(m.app.statusText(raw))
	}
	queued, running, completed, failed, skipped := m.app.moduleStatusCounts(run.ModuleResults)

	lines := []string{
		fmt.Sprintf("%s: %s", m.app.catalog.T("app_label_current"), currentLane),
		fmt.Sprintf("%s: %s", m.app.catalog.T("app_label_next"), nextLane),
		fmt.Sprintf("%s: %s", m.app.catalog.T("app_label_deferred"), trimForSelect(deferredLane, max(12, width-18))),
		"",
		fmt.Sprintf("%s: %s", m.app.catalog.T("scan_mc_lane"), activeLane),
		fmt.Sprintf("%s: %s", m.app.catalog.T("app_label_type"), activeLaneDescriptor.Kind),
		fmt.Sprintf("%s: %s", m.app.catalog.T("app_label_eta"), activeLaneDescriptor.ETA),
		fmt.Sprintf("%s: %s", m.app.catalog.T("scan_mc_module"), activeModule),
		fmt.Sprintf("%s: %s", m.app.catalog.T("scan_agent_module_state"), state),
		fmt.Sprintf("%s: %d/%d", m.app.catalog.T("scan_scope_modules"), done, total),
		fmt.Sprintf("%s: %d • %s: %d • %s: %d • %s: %d", m.app.catalog.T("module_running_count"), running, m.app.catalog.T("module_queued_count"), queued, m.app.catalog.T("module_completed_count"), completed, m.app.catalog.T("module_failed_count"), failed),
	}
	if skipped > 0 {
		lines = append(lines, fmt.Sprintf("%s: %d", m.app.catalog.T("module_skipped_count"), skipped))
	}
	lines = append(lines, "")
	lines = append(lines, m.renderMissionLaneChipRows(width)...)
	lines = append(lines, "")
	lines = append(lines, m.app.missionLaneSchematicLines(m.console)...)
	return renderMissionBox(m.app.catalog.T("scan_mode_live_queue_title"), strings.Join(lines, "\n"))
}

func (m scanMissionModel) missionLaneFlow() (string, string, string) {
	order := m.app.scanLaneDescriptorsForProject(m.project, m.profile.Modules, m.historicalRuns)
	if len(order) == 0 {
		return "-", "-", "-"
	}
	currentIndex := 0
	active := defaultString(m.console.lastPhase, "")
	if active != "" && !m.app.isTerminalRunStatus(m.consoleRun().Status) {
		activeKey := m.app.moduleLaneKey(m.console.lastModule)
		for index, lane := range order {
			if lane.Key == activeKey || lane.Title == active {
				currentIndex = index
				break
			}
		}
	} else {
		for index, lane := range order {
			state := m.missionLaneStateLabel(lane.Key)
			if state == m.app.catalog.T("scan_mc_matrix_done") {
				continue
			}
			currentIndex = index
			break
		}
	}
	current := m.app.formatLaneDescriptor(order[currentIndex], 52)
	next := "-"
	if currentIndex+1 < len(order) {
		next = m.app.formatLaneDescriptor(order[currentIndex+1], 52)
	}
	deferred := "-"
	if currentIndex+2 < len(order) {
		deferredTitles := make([]string, 0, len(order)-currentIndex-2)
		for _, lane := range order[currentIndex+2:] {
			deferredTitles = append(deferredTitles, lane.Title)
		}
		deferred = strings.Join(deferredTitles, ", ")
	}
	return current, next, deferred
}

func (m scanMissionModel) missionCurrentLaneDescriptor() scanLaneDescriptor {
	if module := strings.TrimSpace(m.console.lastModule); module != "" {
		return m.app.scanLaneDescriptor(m.app.moduleLaneKey(module))
	}
	descriptors := m.app.scanLaneDescriptorsForProject(m.project, m.profile.Modules, m.historicalRuns)
	if len(descriptors) == 0 {
		return m.app.scanLaneDescriptor("general")
	}
	return descriptors[0]
}

func (m scanMissionModel) renderMissionLaneChipRows(width int) []string {
	theme := m.app.tuiTheme()
	lanes := m.app.scanLaneDescriptorsForProject(m.project, m.profile.Modules, m.historicalRuns)
	if len(lanes) == 0 {
		lanes = []scanLaneDescriptor{m.app.scanLaneDescriptor("general")}
	}
	chips := make([]string, 0, len(lanes))
	activeLaneKey := m.app.moduleLaneKey(m.console.lastModule)
	for _, lane := range lanes {
		state := m.missionLaneStateLabel(lane.Key)
		label := trimForSelect(lane.Title, max(12, width/4))
		active := lane.Key == activeLaneKey && !m.app.isTerminalRunStatus(m.consoleRun().Status)
		chips = append(chips, theme.chipStyle(active).Render(m.app.displayUpper(state)+" "+label))
	}
	if len(chips) == 0 {
		return nil
	}
	maxWidth := max(24, width-4)
	rows := []string{}
	current := ""
	for _, chip := range chips {
		if current == "" {
			current = chip
			continue
		}
		candidate := current + theme.gap() + chip
		if lipgloss.Width(candidate) > maxWidth {
			rows = append(rows, current)
			current = chip
			continue
		}
		current = candidate
	}
	if strings.TrimSpace(current) != "" {
		rows = append(rows, current)
	}
	return rows
}

func (m scanMissionModel) missionLaneStateLabel(laneKey string) string {
	state := m.app.catalog.T("scan_mc_matrix_wait")
	for _, module := range m.consoleRun().ModuleResults {
		if m.app.moduleLaneKey(module.Name) != laneKey {
			continue
		}
		switch module.Status {
		case domain.ModuleFailed:
			state = m.app.catalog.T("scan_mc_matrix_failed")
		case domain.ModuleRunning:
			state = m.app.catalog.T("scan_mc_matrix_active")
		case domain.ModuleCompleted:
			if state != m.app.catalog.T("scan_mc_matrix_failed") {
				state = m.app.catalog.T("scan_mc_matrix_done")
			}
		case domain.ModuleSkipped:
			if state == m.app.catalog.T("scan_mc_matrix_wait") {
				state = m.app.catalog.T("scan_mc_matrix_partial")
			}
		}
	}
	return state
}

func (m scanMissionModel) renderMissionExecutionPanel(width int) string {
	done, total := m.progressCounts()
	run := m.consoleRun()
	queued, running, completed, failed, _ := m.app.moduleStatusCounts(run.ModuleResults)
	lines := []string{
		fmt.Sprintf("%s: %s", m.app.catalog.T("scan_mc_activity"), trimForSelect(m.app.operatorText(defaultString(m.console.lastEvent, m.app.catalog.T("scan_mc_waiting"))), max(18, width-18))),
		fmt.Sprintf("%s: %s", m.app.toolLabel(), m.missionActiveTool()),
		fmt.Sprintf("%s: %d/%d • %s %d • %s %d • %s %d • %s %d", m.app.catalog.T("scan_scope_modules"), done, total, strings.ToLower(m.app.catalog.T("module_running_count")), running, strings.ToLower(m.app.catalog.T("module_queued_count")), queued, strings.ToLower(m.app.catalog.T("module_completed_count")), completed, strings.ToLower(m.app.catalog.T("module_failed_count")), failed),
		"",
	}
	lines = append(lines, m.moduleFlowRows(max(36, width-6))...)
	stream := m.app.missionCodeStreamLines(m.console)
	if len(stream) > 0 {
		lines = append(lines, "", m.app.catalog.T("scan_mode_live_telemetry_title")+":")
		for index, line := range stream[:min(2, len(stream))] {
			lines = append(lines, fmt.Sprintf("%02d | %s", index+1, trimForSelect(m.app.operatorText(line), max(18, width-10))))
		}
	}
	return renderMissionBox(m.app.catalog.T("scan_mode_live_execution_title"), strings.Join(lines, "\n"))
}

func (m scanMissionModel) renderMissionThreatPanel(width int) string {
	doctor := m.doctor
	preflight := m.app.catalog.T("scan_preflight_ready")
	if !doctor.Ready {
		preflight = m.app.catalog.T("scan_preflight_not_ready")
	}
	run := m.consoleRun()
	source := m.console.recentFindings
	if m.done && len(m.findings) > 0 {
		source = m.findings
	}
	hot := m.app.prioritizedFindings(source, 2)
	lines := []string{
		fmt.Sprintf("%s: %s", m.app.catalog.T("scan_mc_risk"), m.app.displayUpper(m.app.liveRiskLabel(
			run.Summary.CountsBySeverity[domain.SeverityCritical],
			run.Summary.CountsBySeverity[domain.SeverityHigh],
			run.Summary.CountsBySeverity[domain.SeverityMedium],
			run.Summary.CountsBySeverity[domain.SeverityLow],
		))),
		fmt.Sprintf("%s: %s", m.app.catalog.T("status"), m.app.displayUpper(m.app.scanPostureLabel(run))),
		fmt.Sprintf("%s: %d", m.app.catalog.T("app_label_findings"), run.Summary.TotalFindings),
		fmt.Sprintf("%s: %s", m.app.catalog.T("scan_mode_live_preflight_title"), preflight),
	}
	if len(doctor.Missing) > 0 || len(doctor.Outdated) > 0 {
		lines = append(lines, fmt.Sprintf("%s: %d • %s: %d", m.app.catalog.T("runtime_missing"), len(doctor.Missing), m.app.catalog.T("runtime_doctor_outdated"), len(doctor.Outdated)))
	}
	if len(hot) > 0 {
		top := hot[0]
		lines = append(lines,
			"",
			fmt.Sprintf("%s: %s", m.app.catalog.T("scan_mode_live_findings_title"), m.app.displayUpper(m.app.severityLabel(top.Severity))),
			trimForSelect(m.app.displayFindingTitle(top), max(18, width-8)),
			fmt.Sprintf("%s • %s", m.app.categoryLabel(top.Category), trimForSelect(coalesceString(top.Location, top.Module), max(16, width-12))),
		)
		if len(hot) > 1 {
			lines = append(lines, fmt.Sprintf("+1 %s", trimForSelect(m.app.displayFindingTitle(hot[1]), max(16, width-8))))
		}
	}
	severityRows := []string{}
	for _, item := range []struct {
		label    string
		severity domain.Severity
		count    int
	}{
		{m.app.catalog.T("summary_critical"), domain.SeverityCritical, run.Summary.CountsBySeverity[domain.SeverityCritical]},
		{m.app.catalog.T("summary_high"), domain.SeverityHigh, run.Summary.CountsBySeverity[domain.SeverityHigh]},
		{m.app.catalog.T("summary_medium"), domain.SeverityMedium, run.Summary.CountsBySeverity[domain.SeverityMedium]},
		{m.app.catalog.T("summary_low"), domain.SeverityLow, run.Summary.CountsBySeverity[domain.SeverityLow]},
	} {
		if item.count == 0 {
			continue
		}
		severityRows = append(severityRows, m.renderSeverityRow(item.label, item.count, item.severity, width))
	}
	if len(severityRows) == 0 {
		severityRows = append(severityRows, m.renderSeverityRow(m.app.catalog.T("summary_low"), 0, domain.SeverityLow, width))
	}
	lines = append(lines,
		"",
		strings.Join(severityRows, "\n"),
	)
	return renderMissionBox(m.app.catalog.T("scan_mode_live_threat_title"), strings.Join(lines, "\n"))
}

func (m scanMissionModel) renderHealthFooter(width int) string {
	metrics := m.runtimeMetrics()
	cards := [][3]string{
		{m.app.catalog.T("scan_mode_live_metrics_health"), metrics.HealthLabel, metrics.HealthSummary},
		{m.app.catalog.T("scan_mode_live_metrics_cpu"), fmt.Sprintf("%.1f%% • %.1f MiB", metrics.CPUPercent, metrics.MemoryMiB), fmt.Sprintf("%s %d", m.app.catalog.T("scan_mode_live_metrics_goroutines"), metrics.Goroutines)},
		{m.app.catalog.T("scan_mode_live_metrics_throughput"), fmt.Sprintf("%.1f mod/min", metrics.ModulePerMin), fmt.Sprintf("%s %.1f/min • %s %s", m.app.catalog.T("scan_mode_live_metrics_findings"), metrics.FindingPerMin, m.app.catalog.T("scan_launch_clock"), metrics.Elapsed.Round(time.Second).String())},
	}
	return m.renderMissionCardGrid(cards, width, 3)
}

func (m scanMissionModel) moduleFlowRows(width int) []string {
	index := make(map[string]domain.ModuleResult, len(m.consoleRun().ModuleResults))
	for _, module := range m.consoleRun().ModuleResults {
		index[module.Name] = module
	}
	modules := m.profile.Modules
	if len(modules) == 0 {
		modules = extractModuleNames(m.consoleRun().ModuleResults)
	}
	if len(modules) == 0 {
		return []string{m.app.catalog.T("scan_mc_waiting")}
	}

	lines := make([]string, 0, len(modules))
	nameWidth := 16
	if width < 56 {
		nameWidth = 12
	}
	statusWidth := 11
	for _, name := range modules {
		module, ok := index[name]
		status := domain.ModuleQueued
		if ok {
			status = module.Status
		}
		icon := m.moduleStateIcon(status)
		if m.statusOnlyMotion {
			icon = m.moduleStateStatusIcon(status)
		}
		summaryWidth := max(14, width-nameWidth-statusWidth-8)
		summary := trimForSelect(m.moduleStateSummary(name, module, status), summaryWidth)
		lines = append(lines, fmt.Sprintf("%s %-*s %-*s %s", icon, nameWidth, trimForSelect(name, nameWidth), statusWidth, m.app.displayUpper(m.app.moduleStatusLabel(status)), summary))
	}
	return lines
}

func (m scanMissionModel) moduleStateStatusIcon(status domain.ModuleStatus) string {
	switch status {
	case domain.ModuleCompleted:
		return "[✓]"
	case domain.ModuleFailed:
		return "[!]"
	case domain.ModuleSkipped:
		return "[-]"
	case domain.ModuleRunning:
		return "[>]"
	default:
		return "[ ]"
	}
}

func (m scanMissionModel) moduleStateIcon(status domain.ModuleStatus) string {
	frame := m.console.frame
	spinner := []string{"|", "/", "-", `\`}
	switch status {
	case domain.ModuleCompleted:
		if frame%4 == 0 {
			return "[+]"
		}
		return "[✓]"
	case domain.ModuleFailed:
		return "[!]"
	case domain.ModuleSkipped:
		return "[-]"
	case domain.ModuleRunning:
		return "[" + spinner[frame%len(spinner)] + "]"
	default:
		return "[ ]"
	}
}

func (m scanMissionModel) moduleStateSummary(name string, module domain.ModuleResult, status domain.ModuleStatus) string {
	switch status {
	case domain.ModuleCompleted, domain.ModuleFailed, domain.ModuleSkipped:
		return m.app.moduleSummaryText(module)
	case domain.ModuleRunning:
		return m.app.moduleNarrative(name)
	default:
		return m.app.catalog.T("scan_mode_live_status_queued", m.app.modulePhaseLabel(name))
	}
}

func (m scanMissionModel) renderSeverityRow(label string, count int, severity domain.Severity, width int) string {
	maxCount := 1
	run := m.consoleRun()
	for _, item := range []int{
		run.Summary.CountsBySeverity[domain.SeverityCritical],
		run.Summary.CountsBySeverity[domain.SeverityHigh],
		run.Summary.CountsBySeverity[domain.SeverityMedium],
		run.Summary.CountsBySeverity[domain.SeverityLow],
	} {
		if item > maxCount {
			maxCount = item
		}
	}
	barWidth := min(18, max(10, width-16))
	fill := int((float64(count) / float64(maxCount)) * float64(barWidth))
	if count > 0 && fill == 0 {
		fill = 1
	}
	color := lipgloss.Color("#5EEAD4")
	switch severity {
	case domain.SeverityCritical:
		color = lipgloss.Color("#FF4D6D")
	case domain.SeverityHigh:
		color = lipgloss.Color("#FF8C42")
	case domain.SeverityMedium:
		color = lipgloss.Color("#FFD166")
	case domain.SeverityLow:
		color = lipgloss.Color("#5EEAD4")
	}
	bar := lipgloss.NewStyle().Foreground(color).Render(strings.Repeat("█", fill))
	return fmt.Sprintf("%-9s %s%s %3d", label, bar, strings.Repeat("·", max(0, barWidth-fill)), count)
}

func (m scanMissionModel) runtimeMetrics() missionRuntimeMetrics {
	return missionRuntimeMetricsReader(m)
}

func readMissionRuntimeMetrics(m scanMissionModel) missionRuntimeMetrics {
	cpuSeconds, memoryMiB, goroutines := missionProcessMetrics()
	elapsed := time.Since(m.launchedAt)
	if elapsed < time.Second {
		elapsed = time.Second
	}
	completed, failed, skipped := m.completedModuleCount()
	modulesDone := completed + failed + skipped
	moduleRate := float64(modulesDone) / elapsed.Minutes()
	findingRate := float64(m.consoleRun().Summary.TotalFindings) / elapsed.Minutes()
	eventRate := 0.0
	if elapsed.Minutes() > 0 {
		eventRate = float64(m.missionEventCount()) / elapsed.Minutes()
	}
	health := m.app.catalog.T("scan_mode_live_health_good")
	summary := m.app.catalog.T("scan_mode_live_health_flowing")
	if failed > 0 {
		health = m.app.catalog.T("scan_mode_live_health_degraded")
		summary = m.app.catalog.T("scan_mode_live_health_failed_modules", failed)
	} else if m.consoleRun().Summary.CountsBySeverity[domain.SeverityCritical] > 0 {
		health = m.app.catalog.T("scan_mode_live_health_breach")
		summary = m.app.catalog.T("scan_mode_live_health_critical_findings", m.consoleRun().Summary.CountsBySeverity[domain.SeverityCritical])
	} else if m.consoleRun().Summary.TotalFindings > 0 {
		health = m.app.catalog.T("scan_mode_live_health_warning")
		summary = m.app.catalog.T("scan_mode_live_health_findings", m.consoleRun().Summary.TotalFindings)
	}
	return missionRuntimeMetrics{
		CPUPercent:     missionCPUPercent(cpuSeconds, m.cpuBaseline, elapsed),
		MemoryMiB:      memoryMiB,
		Goroutines:     goroutines,
		ModulePerMin:   moduleRate,
		FindingPerMin:  findingRate,
		EventPerMin:    eventRate,
		HealthLabel:    health,
		HealthSummary:  summary,
		CompletedCount: modulesDone,
		QueueDepth:     max(0, m.app.moduleCount(m.profile.Modules)-modulesDone),
		ArtifactCount:  len(m.consoleRun().ArtifactRefs),
		Elapsed:        elapsed,
	}
}

func (m scanMissionModel) missionEventCount() int {
	if m.console == nil {
		return 0
	}
	return max(0, m.console.eventCount)
}

func missionCPUPercent(current, baseline float64, elapsed time.Duration) float64 {
	if elapsed <= 0 {
		return 0
	}
	delta := current - baseline
	if delta < 0 {
		delta = 0
	}
	return (delta / elapsed.Seconds()) * 100
}

func missionCPUSeconds() float64 {
	cpuSeconds, _, _ := missionProcessMetrics()
	return cpuSeconds
}

func missionProcessMetrics() (cpuSeconds, memoryMiB float64, goroutines uint64) {
	samples := []runtimemetrics.Sample{
		{Name: "/cpu/classes/total:cpu-seconds"},
		{Name: "/memory/classes/heap/objects:bytes"},
		{Name: "/sched/goroutines:goroutines"},
	}
	runtimemetrics.Read(samples)
	return samples[0].Value.Float64(), float64(samples[1].Value.Uint64()) / 1024 / 1024, samples[2].Value.Uint64()
}

func (m scanMissionModel) completedModuleCount() (completed, failed, skipped int) {
	for _, module := range m.consoleRun().ModuleResults {
		switch module.Status {
		case domain.ModuleCompleted:
			completed++
		case domain.ModuleFailed:
			failed++
		case domain.ModuleSkipped:
			skipped++
		}
	}
	return completed, failed, skipped
}

func buildProjectTreeSnapshot(root string, depth, limit int) []string {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil
	}
	lines := make([]string, 0, limit)
	root = filepath.Clean(root)
	lines = append(lines, filepath.Base(root))
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || path == root || len(lines) >= limit {
			return nil
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		level := strings.Count(relative, string(os.PathSeparator))
		if entry.IsDir() {
			if _, ignored := scanTreeIgnoredDirs[entry.Name()]; ignored {
				return filepath.SkipDir
			}
			if level >= depth {
				return filepath.SkipDir
			}
			lines = append(lines, strings.Repeat("  ", level+1)+"├─ "+entry.Name()+"/")
			return nil
		}
		if level > depth {
			return nil
		}
		lines = append(lines, strings.Repeat("  ", level+1)+"└─ "+entry.Name())
		return nil
	})
	return lines[:min(limit, len(lines))]
}

func renderMissionBox(title, body string) string {
	return pterm.DefaultBox.
		WithTitle(" "+title+" ").
		WithTitleTopLeft(true).
		WithRightPadding(1).
		WithLeftPadding(1).
		Sprintf("%s", body)
}
