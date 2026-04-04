package cli

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func (m appShellModel) handleRefreshMsg() (tea.Model, tea.Cmd) {
	if m.refreshing {
		return m, appShellRefreshCmd(m.autoRefreshInterval())
	}
	if m.paletteActive || m.projectPickerActive || m.targetInputActive {
		return m, appShellRefreshCmd(m.autoRefreshInterval())
	}
	if m.scanRunning && m.route == appRouteLiveScan {
		return m, appShellRefreshCmd(m.autoRefreshInterval())
	}
	m.refreshing = true
	m.refreshingRoute = m.route
	m.refreshSeq++
	m.manualRefresh = false
	if m.route != appRouteHome && m.route != appRouteLiveScan {
		m.routePulse = maxInt(m.routePulse, 3)
	}
	return m, tea.Batch(loadAppShellSnapshotCmd(m.app, m.route, false, m.refreshSeq), appShellRefreshCmd(m.autoRefreshInterval()))
}

func (m appShellModel) handleSnapshotLoadedMsg(msg appShellSnapshotLoadedMsg) (tea.Model, tea.Cmd) {
	if msg.seq != 0 && msg.seq != m.refreshSeq {
		return m, nil
	}
	m.snapshot = msg.snapshot
	m.snapshotUpdatedAt = msg.at
	m.invalidateCachesForRoutes(m.route, msg.route)
	m.reconcileSnapshotState(m.route)
	m.refreshing = false
	m.refreshingRoute = appRouteHome
	m.manualRefresh = false
	m.clampCursor()
	m.refreshReviewContext()
	return m, m.scheduleBackgroundLoads()
}

func (m appShellModel) handleProjectResolvedMsg(msg appShellProjectResolvedMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		m.notice = msg.err.Error()
		m.alert = true
		return m, nil
	}
	m.snapshot = m.app.buildTUISnapshot()
	m.snapshotUpdatedAt = time.Now()
	m.selectedProjectID = msg.project.ID
	m.invalidateCachesForRoutes(appRouteHome, appRouteProjects, appRouteScanReview)
	m.reconcileSnapshotState(appRouteScanReview)
	m.setRouteFresh(appRouteScanReview)
	m.refreshReviewContext()
	if msg.existed {
		m.notice = m.app.catalog.T("project_existing", msg.project.DisplayName)
	} else {
		m.notice = m.app.catalog.T("project_registered", msg.project.DisplayName)
	}
	m.alert = false
	return m, m.scheduleBackgroundLoads()
}

func (m appShellModel) handleFrameTickMsg() (tea.Model, tea.Cmd) {
	if !m.shouldAnimate() {
		return m, nil
	}
	m.frame++
	if m.routePulse > 0 {
		m.routePulse--
	}
	if m.scanRunning && m.scanConsole != nil {
		m.scanConsole.frame++
	}
	return m, m.animationCmd()
}

func (m appShellModel) handleScanMissionEventMsg(msg scanMissionEventMsg) (tea.Model, tea.Cmd) {
	if msg.seq != 0 && msg.seq != m.scanSeq {
		return m, nil
	}
	if m.scanConsole != nil {
		m.scanConsole.update(m.app, msg.event)
	}
	m.scanRun = msg.event.Run
	return m, waitForScanMissionEvent(m.scanEventCh, m.scanSeq)
}

func (m appShellModel) handleScanMissionDoneMsg(msg scanMissionDoneMsg) (tea.Model, tea.Cmd) {
	if msg.seq != 0 && msg.seq != m.scanSeq {
		return m, nil
	}
	m.scanRunning = false
	m.scanDone = true
	m.scanRun = msg.run
	m.scanFindings = msg.findings
	m.scanErr = msg.err
	m.scanRequiredErr = m.app.enforceRequiredModuleResults(msg.run, m.scanProfile.Modules)
	if m.scanConsole != nil {
		m.scanConsole.run = msg.run
		m.scanConsole.frame++
	}
	outcome := scanMissionOutcome{
		run:         msg.run,
		findings:    msg.findings,
		scanErr:     msg.err,
		requiredErr: m.scanRequiredErr,
	}
	if strings.TrimSpace(msg.run.ID) != "" {
		if reportPath, reportErr := m.app.writeRunExport(msg.run.ID, "html", "", ""); reportErr == nil {
			outcome.reportPath = reportPath
		}
	}
	m.lastScan = &outcome
	m.setRouteFresh(appRouteLiveScan)
	m.notice = m.liveDebriefNotice(outcome)
	if strings.TrimSpace(outcome.reportPath) != "" {
		m.notice = fmt.Sprintf("%s • %s", m.notice, m.app.catalog.T("app_report_ready"))
	}
	m.alert = outcome.scanErr != nil || outcome.requiredErr != nil
	return m, nil
}

func (m appShellModel) handleRunDetailLoadedMsg(msg appShellRunDetailLoadedMsg) (tea.Model, tea.Cmd) {
	if msg.seq != 0 && msg.seq != m.runDetailSeq {
		return m, nil
	}
	m.runDetailPendingID = ""
	if strings.TrimSpace(msg.runID) == "" {
		return m, nil
	}
	m.runDetailCache[msg.runID] = msg.entry
	return m, nil
}

func (m appShellModel) handleProjectTreeLoadedMsg(msg appShellProjectTreeLoadedMsg) (tea.Model, tea.Cmd) {
	if msg.seq != 0 && msg.seq != m.projectTreeSeq {
		return m, nil
	}
	m.projectTreePending = ""
	if strings.TrimSpace(msg.projectID) == "" {
		return m, nil
	}
	m.projectTreeCache[m.projectTreeCacheKey(msg.projectID)] = msg.lines
	return m, nil
}

func (m appShellModel) handleKeyMsg(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.targetInputActive {
		return m.updateTargetInput(msg)
	}
	if m.paletteActive {
		return m.updatePalette(msg)
	}
	if m.projectPickerActive {
		return m.updateProjectPicker(msg)
	}
	switch msg.String() {
	case "ctrl+c", "q":
		if m.scanRunning && m.scanCancel != nil {
			m.scanCancel()
		}
		m.outcomeAction = appShellActionQuit
		return m, tea.Quit
	case "/", ":":
		return m.openPalette(), nil
	case "r":
		if m.refreshing {
			return m, nil
		}
		m.refreshing = true
		m.refreshingRoute = m.route
		m.refreshSeq++
		m.manualRefresh = true
		if m.route != appRouteHome && m.route != appRouteLiveScan {
			m.routePulse = maxInt(m.routePulse, 3)
		}
		return m, loadAppShellSnapshotCmd(m.app, m.route, true, m.refreshSeq)
	case "tab", "right", "l":
		m.setRoutePreservingState(m.nextPrimaryRoute(1))
		return m, tea.Batch(m.animationCmd(), m.scheduleBackgroundLoads())
	case "shift+tab", "left", "h":
		m.setRoutePreservingState(m.nextPrimaryRoute(-1))
		return m, tea.Batch(m.animationCmd(), m.scheduleBackgroundLoads())
	case "1":
		m.setRoutePreservingState(appRouteHome)
		return m, tea.Batch(m.animationCmd(), m.scheduleBackgroundLoads())
	case "2":
		m.setRoutePreservingState(appRouteScanReview)
		return m, tea.Batch(m.animationCmd(), m.scheduleBackgroundLoads())
	case "3":
		m.setRoutePreservingState(appRouteLiveScan)
		return m, tea.Batch(m.animationCmd(), m.scheduleBackgroundLoads())
	case "4":
		m.setRoutePreservingState(appRouteRuns)
		return m, tea.Batch(m.animationCmd(), m.scheduleBackgroundLoads())
	case "5":
		m.setRoutePreservingState(appRouteFindings)
		return m, tea.Batch(m.animationCmd(), m.scheduleBackgroundLoads())
	case "6":
		m.setRoutePreservingState(appRouteRuntime)
		return m, tea.Batch(m.animationCmd(), m.scheduleBackgroundLoads())
	case "s":
		if m.route == appRouteHome {
			if _, ok := m.selectedProject(); ok {
				m.setRouteFresh(appRouteScanReview)
			} else {
				return m.openProjectPicker(), nil
			}
			return m, m.animationCmd()
		}
		if m.route == appRouteProjects {
			return m.activateRow(appSelectableRow{Action: appShellActionSelectCurrent})
		}
	case "P":
		return m.openProjectPicker(), nil
	case "o":
		if m.route == appRouteRuns {
			run, ok := m.selectedRun()
			if !ok {
				return m, nil
			}
			m.findingsScopeRun = run.ID
			m.setRouteFresh(appRouteFindings)
			m.notice = m.app.catalog.T("app_findings_scope_set", m.app.projectLabel(run.ProjectID))
			m.alert = false
			return m, nil
		}
	case "e":
		if m.route == appRouteRuns {
			return m.exportSelectedRunReport()
		}
		if m.route == appRouteLiveScan && !m.scanRunning {
			return m.exportCurrentScanReport()
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
	case "j", "down":
		m.moveCursor(1)
		return m, m.scheduleBackgroundLoads()
	case "k", "up":
		m.moveCursor(-1)
		return m, m.scheduleBackgroundLoads()
	case "enter":
		return m.activateSelection()
	case "backspace":
		if m.route == appRouteFindings && strings.TrimSpace(m.findingsScopeRun) != "" {
			m.findingsScopeRun = ""
			m.resetRouteState(appRouteFindings)
			m.cursor = 0
			m.detailScroll = 0
			m.notice = m.app.catalog.T("app_findings_scope_cleared")
			m.alert = false
			return m, nil
		}
	case "f":
		if m.route == appRouteFindings {
			m.findingsSeverityIdx = (m.findingsSeverityIdx + 1) % len(runFindingSeverityFilters)
			m.cursor = 0
			m.detailScroll = 0
			m.clampCursor()
			m.notice = m.app.catalog.T("finding_filter_notice", m.currentFindingsSeverityFilterLabel(), m.currentFindingsStatusFilterLabel())
			m.alert = false
			return m, nil
		}
	case "g":
		if m.route == appRouteFindings {
			m.findingsStatusIdx = (m.findingsStatusIdx + 1) % len(runFindingStatusFilters)
			m.cursor = 0
			m.detailScroll = 0
			m.clampCursor()
			m.notice = m.app.catalog.T("finding_filter_notice", m.currentFindingsSeverityFilterLabel(), m.currentFindingsStatusFilterLabel())
			m.alert = false
			return m, nil
		}
	case "a":
		if m.route == appRouteScanReview {
			m.review.ActiveValidation = !m.review.ActiveValidation
			if !m.review.ActiveValidation {
				m.review.DASTTarget = ""
				m.targetInput.SetValue("")
			}
			m.refreshReviewContext()
			return m, nil
		}
	case "p":
		if m.route == appRouteProjects {
			return m.activateRow(appSelectableRow{Action: appShellActionPickFolder})
		}
		if m.route == appRouteScanReview {
			m.review.Preset = nextReviewPreset(m.review.Preset)
			m.refreshReviewContext()
			return m, nil
		}
	case "c":
		if m.route == appRouteRuns {
			return m.cancelSelectedRun()
		}
		if m.route == appRouteScanReview && m.review.Preset == reviewPresetCompliance {
			m.review.CompliancePreset = nextCompliancePreset(m.review.CompliancePreset)
			m.refreshReviewContext()
			return m, nil
		}
	case "i":
		if m.route == appRouteScanReview {
			m.review.Isolation = nextIsolationMode(m.review.Isolation)
			m.refreshReviewContext()
			return m, nil
		}
	case "u":
		if m.route == appRouteScanReview {
			m.targetInputActive = true
			m.targetInput.Focus()
			m.targetInput.SetValue(strings.TrimSpace(m.review.DASTTarget))
			return m, nil
		}
	case "x":
		if m.route == appRouteLiveScan && m.scanRunning && m.scanCancel != nil {
			m.scanCancel()
			m.scanAborting = true
			m.notice = m.app.catalog.T("scan_mode_live_cancel_requested")
			m.alert = true
			return m, nil
		}
	case "0":
		if m.route == appRouteFindings {
			m.findingsSeverityIdx = 0
			m.findingsStatusIdx = 0
			m.cursor = 0
			m.detailScroll = 0
			m.clampCursor()
			m.notice = m.app.catalog.T("finding_filter_notice", m.currentFindingsSeverityFilterLabel(), m.currentFindingsStatusFilterLabel())
			m.alert = false
			return m, nil
		}
	case "R":
		if m.route == appRouteRuns {
			return m.retrySelectedRun()
		}
	}
	return m, nil
}
