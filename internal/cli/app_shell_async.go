package cli

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/batu3384/ironsentinel/internal/domain"
)

func (m *appShellModel) saveRouteState(route appRoute) {
	if m.routeState == nil {
		m.routeState = make(map[appRoute]routeViewState)
	}
	m.routeState[route] = routeViewState{
		Cursor:              m.cursor,
		DetailScroll:        maxInt(0, m.detailScroll),
		FindingsSeverityIdx: m.findingsSeverityIdx,
		FindingsStatusIdx:   m.findingsStatusIdx,
	}
}

func (m *appShellModel) resetRouteState(route appRoute) {
	if m.routeState == nil {
		m.routeState = make(map[appRoute]routeViewState)
	}
	m.routeState[route] = routeViewState{}
}

func (m *appShellModel) setRoutePreservingState(route appRoute) {
	if route == appRouteProjects {
		route = appRouteHome
	}
	if route == m.route {
		m.clampCursor()
		m.routePulse = 4
		return
	}
	m.saveRouteState(m.route)
	m.route = route
	if state, ok := m.routeState[route]; ok {
		m.cursor = state.Cursor
		m.detailScroll = maxInt(0, state.DetailScroll)
		m.findingsSeverityIdx = state.FindingsSeverityIdx
		m.findingsStatusIdx = state.FindingsStatusIdx
	} else {
		m.cursor = 0
		m.detailScroll = 0
		m.findingsSeverityIdx = 0
		m.findingsStatusIdx = 0
	}
	m.clampCursor()
	m.routePulse = 4
}

func (m *appShellModel) setRouteFresh(route appRoute) {
	if route == appRouteProjects {
		route = appRouteHome
	}
	if route != m.route {
		m.saveRouteState(m.route)
	}
	m.route = route
	m.resetRouteState(route)
	m.cursor = 0
	m.detailScroll = 0
	m.findingsSeverityIdx = 0
	m.findingsStatusIdx = 0
	m.clampCursor()
	m.routePulse = 4
}

func (m *appShellModel) scheduleBackgroundLoads() tea.Cmd {
	return tea.Batch(m.scheduleSelectedRunDetailLoad(), m.scheduleSelectedProjectTreeLoad())
}

func (m *appShellModel) scheduleSelectedRunDetailLoad() tea.Cmd {
	if m.route != appRouteRuns {
		return nil
	}
	run, ok := m.selectedRun()
	if !ok {
		m.runDetailPendingID = ""
		return nil
	}
	if _, ok := m.runDetailCache[run.ID]; ok {
		m.runDetailPendingID = ""
		return nil
	}
	if m.runDetailPendingID == run.ID {
		return nil
	}
	m.runDetailPendingID = run.ID
	m.runDetailSeq++
	return loadAppShellRunDetailCmd(m.app, run.ID, m.runDetailSeq)
}

func (m *appShellModel) scheduleSelectedProjectTreeLoad() tea.Cmd {
	if m.route != appRouteHome && m.route != appRouteProjects && m.route != appRouteScanReview {
		m.projectTreePending = ""
		return nil
	}
	project, ok := m.selectedProject()
	if !ok {
		m.projectTreePending = ""
		return nil
	}
	key := m.projectTreeCacheKey(project.ID)
	if _, ok := m.projectTreeCache[key]; ok {
		m.projectTreePending = ""
		return nil
	}
	if m.projectTreePending == project.ID {
		return nil
	}
	m.projectTreePending = project.ID
	m.projectTreeSeq++
	return loadAppShellProjectTreeCmd(project.ID, project.LocationHint, 2, 12, m.projectTreeSeq)
}

func (m *appShellModel) refreshShellSnapshot(route appRoute) {
	m.snapshot = m.app.buildTUISnapshot()
	m.snapshotUpdatedAt = time.Now()
	m.invalidateCachesForRoutes(route)
	m.reconcileSnapshotState(route)
	m.clampCursor()
	m.refreshReviewContext()
}

func (m *appShellModel) focusRun(runID string) {
	for index, run := range m.snapshot.Portfolio.Runs {
		if run.ID == runID {
			m.cursor = index
			m.detailScroll = 0
			return
		}
	}
}

func (m appShellModel) selectedRun() (domain.ScanRun, bool) {
	if len(m.snapshot.Portfolio.Runs) == 0 || m.cursor < 0 || m.cursor >= len(m.snapshot.Portfolio.Runs) {
		return domain.ScanRun{}, false
	}
	return m.snapshot.Portfolio.Runs[m.cursor], true
}

func (m appShellModel) selectedFinding() (domain.Finding, bool) {
	findings := m.filteredScopedFindings()
	if len(findings) == 0 || m.cursor < 0 || m.cursor >= len(findings) {
		return domain.Finding{}, false
	}
	return findings[m.cursor], true
}

func (m appShellModel) selectedRuntimeTool() (domain.RuntimeTool, bool) {
	if len(m.snapshot.Runtime.ScannerBundle) == 0 || m.cursor < 0 || m.cursor >= len(m.snapshot.Runtime.ScannerBundle) {
		return domain.RuntimeTool{}, false
	}
	return m.snapshot.Runtime.ScannerBundle[m.cursor], true
}

func appShellRefreshCmd(interval time.Duration) tea.Cmd {
	if interval <= 0 {
		interval = 8 * time.Second
	}
	return tea.Tick(interval, func(time.Time) tea.Msg {
		return appShellRefreshMsg{}
	})
}

func loadAppShellSnapshotCmd(app *App, route appRoute, invalidateRuntime bool, seq int) tea.Cmd {
	return func() tea.Msg {
		if invalidateRuntime {
			app.invalidateRuntimeCache()
		}
		return appShellSnapshotLoadedMsg{
			snapshot: app.buildTUISnapshot(),
			route:    route,
			at:       time.Now(),
			seq:      seq,
		}
	}
}

func loadAppShellRunDetailCmd(app *App, runID string, seq int) tea.Cmd {
	return func() tea.Msg {
		entry := runDetailCacheEntry{}
		report, err := app.service.BuildRunReport(runID, "")
		if err != nil {
			entry.err = err.Error()
			return appShellRunDetailLoadedMsg{
				runID: runID,
				entry: entry,
				seq:   seq,
			}
		}
		entry.delta = report.Delta
		entry.baselineLabel = app.catalog.T("diff_no_baseline")
		if report.Baseline != nil {
			entry.baselineLabel = report.Baseline.ID
		}
		if traces, err := app.service.GetRunExecutionTraces(runID); err == nil && len(traces) > 0 {
			traceLines := make([]string, 0, min(4, len(traces)))
			for _, trace := range traces[:min(4, len(traces))] {
				traceLines = append(traceLines, fmt.Sprintf("%s | %s | %s", trace.Module, strings.ToUpper(string(trace.Status)), app.traceLastAttemptLabel(trace)))
			}
			entry.traceLines = traceLines
		}
		return appShellRunDetailLoadedMsg{
			runID: runID,
			entry: entry,
			seq:   seq,
		}
	}
}

func loadAppShellProjectTreeCmd(projectID, root string, depth, limit, seq int) tea.Cmd {
	return func() tea.Msg {
		lines := buildProjectTreeSnapshot(root, depth, limit)
		return appShellProjectTreeLoadedMsg{
			projectID: projectID,
			lines:     lines,
			seq:       seq,
		}
	}
}

func (m appShellModel) shouldAnimate() bool {
	if m.app.reducedMotion() {
		return false
	}
	return m.route == appRouteLiveScan || m.scanRunning || m.routePulse > 0
}

func (m appShellModel) autoRefreshInterval() time.Duration {
	switch {
	case m.paletteActive || m.projectPickerActive || m.targetInputActive:
		return 15 * time.Second
	case m.scanRunning && m.route == appRouteLiveScan:
		return 12 * time.Second
	case m.route == appRouteRuntime:
		return 4 * time.Second
	case m.route == appRouteRuns || m.route == appRouteFindings:
		return 6 * time.Second
	default:
		return 12 * time.Second
	}
}

func (m appShellModel) animationCmd() tea.Cmd {
	if !m.shouldAnimate() {
		return nil
	}
	return appShellFrameCmd()
}

func appShellFrameCmd() tea.Cmd {
	return tea.Tick(420*time.Millisecond, func(t time.Time) tea.Msg {
		return appShellFrameTickMsg(t)
	})
}
