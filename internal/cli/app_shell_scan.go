package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/batu3384/ironsentinel/internal/domain"
)

func (m appShellModel) liveDebriefNotice(outcome scanMissionOutcome) string {
	switch {
	case outcome.requiredErr != nil:
		return m.app.catalog.T("app_live_scan_notice_runtime")
	case len(outcome.findings) > 0:
		return m.app.catalog.T("app_live_scan_notice_findings")
	default:
		return m.app.catalog.T("app_live_scan_notice_clean")
	}
}

func (m appShellModel) renderLiveRunDigest(run domain.ScanRun) string {
	if len(run.ModuleResults) == 0 {
		return m.app.catalog.T("watch_no_active_runs")
	}
	lines := make([]string, 0, min(8, len(run.ModuleResults)))
	for _, result := range run.ModuleResults[:min(8, len(run.ModuleResults))] {
		lines = append(lines, fmt.Sprintf("%s • %s • %s", result.Name, strings.ToUpper(string(result.Status)), trimForSelect(result.Summary, 56)))
	}
	return strings.Join(lines, "\n")
}

func (m appShellModel) renderFindingDigest(findings []domain.Finding, limit int) string {
	if len(findings) == 0 {
		return m.app.catalog.T("overview_no_findings")
	}
	if limit <= 0 || limit > len(findings) {
		limit = len(findings)
	}
	lines := make([]string, 0, limit)
	for _, finding := range findings[:limit] {
		lines = append(lines, fmt.Sprintf("%s | %s | %s", strings.ToUpper(m.app.severityLabel(finding.Severity)), m.app.findingPriorityLabel(finding), trimForSelect(m.app.displayFindingTitle(finding), 54)))
	}
	return strings.Join(lines, "\n")
}

func (m appShellModel) beginLiveScan(project domain.Project, profile domain.ScanProfile, doctor domain.RuntimeDoctor) (tea.Model, tea.Cmd) {
	if m.scanRunning && m.scanCancel != nil {
		m.scanCancel()
	}
	console := m.app.newLiveScanConsole(project, profile)
	if console == nil {
		console = &liveScanConsole{
			project:        project,
			profile:        profile,
			lastEvent:      m.app.catalog.T("scan_mc_boot"),
			lastStatus:     m.app.catalog.T("scan_mc_status_booting"),
			telemetry:      []string{m.app.catalog.T("scan_mc_boot")},
			recentFindings: make([]domain.Finding, 0, 5),
		}
	}
	ctx, cancel := context.WithCancel(commandContext(m.baseCtx))
	m.scanSeq++
	scanSeq := m.scanSeq
	eventCh := make(chan domain.StreamEvent, 128)
	doneCh := make(chan scanMissionDoneMsg, 1)
	go func() {
		run, findings, err := m.app.service.Scan(ctx, project.ID, profile, func(event domain.StreamEvent) {
			emitMissionEvent(eventCh, event)
		})
		doneCh <- scanMissionDoneMsg{run: run, findings: findings, err: err, seq: scanSeq}
	}()

	m.setRouteFresh(appRouteLiveScan)
	m.scanRunning = true
	m.scanDone = false
	m.scanAborting = false
	m.scanProject = project
	m.scanProfile = profile
	m.scanDoctor = doctor
	m.scanProjectTree = buildProjectTreeSnapshot(project.LocationHint, 3, 18)
	m.scanLaunchedAt = time.Now()
	m.scanCPUBaseline = missionCPUSeconds()
	m.scanConsole = console
	m.scanRun = domain.ScanRun{}
	m.scanFindings = nil
	m.scanErr = nil
	m.scanRequiredErr = nil
	m.scanCancel = cancel
	m.scanEventCh = eventCh
	m.scanDoneCh = doneCh
	m.lastScan = nil
	m.notice = doctorSummaryLine(m.app, doctor)
	m.alert = false
	return m, tea.Batch(waitForScanMissionEvent(eventCh, scanSeq), waitForScanMissionDone(doneCh, scanSeq))
}

func (m appShellModel) activeScanMissionModel() (scanMissionModel, bool) {
	if !m.scanRunning && !m.scanDone {
		return scanMissionModel{}, false
	}
	return scanMissionModel{
		app:         m.app,
		project:     m.scanProject,
		profile:     m.scanProfile,
		doctor:      m.scanDoctor,
		projectTree: m.scanProjectTree,
		launchedAt:  m.scanLaunchedAt,
		cpuBaseline: m.scanCPUBaseline,
		console:     m.scanConsole,
		width:       m.width,
		height:      m.height,
		done:        m.scanDone,
		aborting:    m.scanAborting,
		notice:      m.notice,
		alert:       m.alert,
		run:         m.scanRun,
		findings:    m.scanFindings,
		scanErr:     m.scanErr,
		requiredErr: m.scanRequiredErr,
	}, true
}

func (m appShellModel) currentScanOutcome() scanMissionOutcome {
	if m.lastScan != nil {
		return *m.lastScan
	}
	return scanMissionOutcome{
		run:         m.scanRun,
		findings:    m.scanFindings,
		scanErr:     m.scanErr,
		requiredErr: m.scanRequiredErr,
	}
}

func (m appShellModel) reportDisplayValue(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return m.app.catalog.T("app_report_export_hint")
	}
	return trimForSelect(path, 56)
}

func (m appShellModel) exportCurrentScanReport() (tea.Model, tea.Cmd) {
	outcome := m.currentScanOutcome()
	if strings.TrimSpace(outcome.run.ID) == "" {
		m.notice = m.app.catalog.T("app_report_export_unavailable")
		m.alert = true
		return m, nil
	}
	reportPath, err := m.app.writeRunExport(outcome.run.ID, "html", "", "")
	if err != nil {
		m.notice = err.Error()
		m.alert = true
		return m, nil
	}
	if m.lastScan != nil {
		m.lastScan.reportPath = reportPath
	}
	m.notice = m.app.catalog.T("report_saved", reportPath)
	m.alert = false
	return m, nil
}

func (m appShellModel) currentScanRequiredErr() error {
	if m.scanDone || m.scanRunning {
		return m.scanRequiredErr
	}
	if m.lastScan != nil {
		return m.lastScan.requiredErr
	}
	return nil
}

func (m appShellModel) currentScanFindings() []domain.Finding {
	if m.scanDone || m.scanRunning {
		return m.scanFindings
	}
	if m.lastScan != nil {
		return m.lastScan.findings
	}
	return nil
}
