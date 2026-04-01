package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/batu3384/ironsentinel/internal/domain"
)

type appRoute int

const (
	appRouteHome appRoute = iota
	appRouteProjects
	appRouteScanReview
	appRouteLiveScan
	appRouteRuns
	appRouteFindings
	appRouteRuntime
)

type reviewPreset string

const (
	reviewPresetFullDeep   reviewPreset = "full_deep"
	reviewPresetQuickSafe  reviewPreset = "quick_safe"
	reviewPresetCompliance reviewPreset = "compliance"
)

type appShellAction string

const (
	appShellActionNone              appShellAction = ""
	appShellActionQuit              appShellAction = "quit"
	appShellActionSelectCurrent     appShellAction = "select_current"
	appShellActionPickFolder        appShellAction = "pick_folder"
	appShellActionOpenProjectPicker appShellAction = "open_project_picker"
	appShellActionStartScan         appShellAction = "start_scan"
	appShellActionAbortScan         appShellAction = "abort_scan"
	appShellActionOpenRunFinds      appShellAction = "open_run_findings"
	appShellActionClearFinds        appShellAction = "clear_findings_scope"
	appShellActionExportReport      appShellAction = "export_report"
)

type appShellLaunchState struct {
	Route             appRoute
	SelectedProjectID string
	FindingsScopeRun  string
	Review            scanReviewState
	Notice            string
	Alert             bool
	LastScan          *scanMissionOutcome
}

type scanReviewState struct {
	Preset           reviewPreset
	CompliancePreset domain.CompliancePreset
	Isolation        domain.IsolationMode
	ActiveValidation bool
	DASTTarget       string
	StrictVersions   bool
	RequireIntegrity bool
}

type paletteCommand struct {
	ID     string
	Group  string
	Label  string
	Hint   string
	Route  appRoute
	Action appShellAction
}

type appShellModel struct {
	app                 *App
	width               int
	height              int
	frame               int
	routePulse          int
	snapshot            tuiSnapshot
	snapshotUpdatedAt   time.Time
	refreshing          bool
	refreshingRoute     appRoute
	refreshSeq          int
	manualRefresh       bool
	route               appRoute
	cursor              int
	detailScroll        int
	findingsSeverityIdx int
	findingsStatusIdx   int
	selectedProjectID   string
	findingsScopeRun    string
	review              scanReviewState
	notice              string
	alert               bool
	paletteActive       bool
	paletteInput        textinput.Model
	paletteCursor       int
	projectPickerActive bool
	projectPickerCursor int
	targetInputActive   bool
	targetInput         textinput.Model
	baseCtx             context.Context
	outcomeAction       appShellAction
	lastScan            *scanMissionOutcome
	scanRunning         bool
	scanDone            bool
	scanAborting        bool
	scanProject         domain.Project
	scanProfile         domain.ScanProfile
	scanDoctor          domain.RuntimeDoctor
	scanProjectTree     []string
	scanSeq             int
	scanLaunchedAt      time.Time
	scanCPUBaseline     float64
	scanConsole         *liveScanConsole
	scanRun             domain.ScanRun
	scanFindings        []domain.Finding
	scanErr             error
	scanRequiredErr     error
	scanCancel          context.CancelFunc
	scanEventCh         <-chan domain.StreamEvent
	scanDoneCh          <-chan scanMissionDoneMsg
	projectTreeCache    map[string][]string
	projectTreePending  string
	projectTreeSeq      int
	runDetailCache      map[string]runDetailCacheEntry
	runDetailPendingID  string
	runDetailSeq        int
	scopedFindingsMap   map[string][]domain.Finding
	routeState          map[appRoute]routeViewState
	reviewContext       reviewContextCacheEntry
}

type runDetailCacheEntry struct {
	delta         domain.RunDelta
	baselineLabel string
	traceLines    []string
	err           string
}

type reviewContextCacheEntry struct {
	projectID       string
	review          scanReviewState
	profile         domain.ScanProfile
	doctor          domain.RuntimeDoctor
	ready           bool
	blockers        []string
	includedModules map[string]struct{}
	laneDescriptors []scanLaneDescriptor
	flowCurrent     string
	flowNext        string
	flowDeferred    string
}

type appShellRefreshMsg struct{}
type appShellSnapshotLoadedMsg struct {
	snapshot tuiSnapshot
	route    appRoute
	at       time.Time
	seq      int
}
type appShellProjectResolvedMsg struct {
	project domain.Project
	existed bool
	err     error
}
type appShellRunDetailLoadedMsg struct {
	runID string
	entry runDetailCacheEntry
	seq   int
}
type appShellProjectTreeLoadedMsg struct {
	projectID string
	lines     []string
	seq       int
}
type appShellFrameTickMsg time.Time

type appSelectableRow struct {
	Label  string
	Hint   string
	Action appShellAction
	Route  appRoute
	Value  string
}

type commandHint struct {
	Key   string
	Label string
}

type factPair struct {
	Label string
	Value string
}

type routeViewState struct {
	Cursor              int
	DetailScroll        int
	FindingsSeverityIdx int
	FindingsStatusIdx   int
}

type shellListItem struct {
	title string
	desc  string
}

func (i shellListItem) Title() string       { return i.title }
func (i shellListItem) Description() string { return i.desc }
func (i shellListItem) FilterValue() string { return i.title + " " + i.desc }

type shellListDelegate struct {
	theme tuiTheme
}

func (d shellListDelegate) Height() int  { return 2 }
func (d shellListDelegate) Spacing() int { return 0 }
func (d shellListDelegate) Update(_ tea.Msg, _ *list.Model) tea.Cmd {
	return nil
}

func (d shellListDelegate) Render(w io.Writer, m list.Model, index int, item list.Item) {
	row, ok := item.(shellListItem)
	if !ok {
		return
	}
	selected := index == m.Index()
	width := maxInt(16, m.Width())
	prefix := "  "
	if selected {
		prefix = "▸ "
	}
	title := d.theme.rowStyle(selected).Width(width).Render(prefix + trimForSelect(row.title, maxInt(10, width-4)))
	if strings.TrimSpace(row.desc) == "" {
		_, _ = fmt.Fprint(w, title)
		return
	}
	desc := d.theme.rowHintStyle(selected).Width(width).Render("  " + trimForSelect(row.desc, maxInt(10, width-4)))
	_, _ = fmt.Fprint(w, lipgloss.JoinVertical(lipgloss.Left, title, desc))
}

func defaultScanReviewState(cfgIsolation string) scanReviewState {
	isolation := domain.IsolationMode(strings.TrimSpace(cfgIsolation))
	if isolation == "" {
		isolation = domain.IsolationAuto
	}
	return scanReviewState{
		Preset:           reviewPresetFullDeep,
		CompliancePreset: domain.CompliancePresetPCIDSS,
		Isolation:        isolation,
		StrictVersions:   true,
		RequireIntegrity: true,
	}
}

func newAppShellModel(app *App, state appShellLaunchState, ctxs ...context.Context) appShellModel {
	if state.Review.Preset == "" {
		state.Review = defaultScanReviewState(app.cfg.SandboxMode)
	}
	palette := textinput.New()
	palette.Placeholder = app.catalog.T("app_palette_placeholder")
	palette.Prompt = "> "
	palette.CharLimit = 64
	palette.Width = 42

	targetInput := textinput.New()
	targetInput.Placeholder = "https://target.internal"
	targetInput.Prompt = "URL> "
	targetInput.CharLimit = 120
	targetInput.Width = 52
	targetInput.SetValue(strings.TrimSpace(state.Review.DASTTarget))

	var baseCtx context.Context
	if len(ctxs) > 0 {
		baseCtx = ctxs[0]
	}
	baseCtx = commandContext(baseCtx)

	snapshot := app.buildTUISnapshot()
	route := state.Route
	if route == appRouteProjects || route < appRouteHome || route > appRouteRuntime {
		route = appRouteHome
	}
	selected := strings.TrimSpace(state.SelectedProjectID)
	if selected == "" {
		if cwd, err := os.Getwd(); err == nil {
			if current := projectForPath(snapshot.Portfolio.Projects, cwd); current != nil {
				selected = current.ID
			}
		}
		if selected == "" {
			if latest := latestProject(snapshot.Portfolio.Projects); latest != nil {
				selected = latest.ID
			}
		}
	}
	width, height := initialTerminalViewport()
	model := appShellModel{
		app:               app,
		baseCtx:           baseCtx,
		width:             width,
		height:            height,
		snapshot:          snapshot,
		snapshotUpdatedAt: time.Now(),
		route:             route,
		selectedProjectID: selected,
		findingsScopeRun:  strings.TrimSpace(state.FindingsScopeRun),
		review:            state.Review,
		notice:            strings.TrimSpace(state.Notice),
		alert:             state.Alert,
		paletteInput:      palette,
		targetInput:       targetInput,
		lastScan:          state.LastScan,
		projectTreeCache:  make(map[string][]string),
		runDetailCache:    make(map[string]runDetailCacheEntry),
		scopedFindingsMap: make(map[string][]domain.Finding),
		routeState:        make(map[appRoute]routeViewState),
	}
	model.reconcileSnapshotState(route)
	model.refreshReviewContext()
	return model
}

func projectForPath(projects []domain.Project, cwd string) *domain.Project {
	cwd = filepath.Clean(strings.TrimSpace(cwd))
	if cwd == "" {
		return nil
	}
	for index := range projects {
		projectPath := filepath.Clean(strings.TrimSpace(projects[index].LocationHint))
		if projectPath == cwd {
			return &projects[index]
		}
	}
	for index := range projects {
		projectPath := filepath.Clean(strings.TrimSpace(projects[index].LocationHint))
		if projectPath == "" {
			continue
		}
		if strings.HasPrefix(cwd, projectPath+string(filepath.Separator)) {
			return &projects[index]
		}
	}
	return nil
}

func (a *App) launchTUI(ctx context.Context) error {
	return a.launchTUIWithState(ctx, appShellLaunchState{
		Route:  appRouteHome,
		Review: defaultScanReviewState(a.cfg.SandboxMode),
	})
}

func (a *App) launchTUIWithState(ctx context.Context, state appShellLaunchState) error {
	baseCtx, cancel := context.WithCancel(commandContext(ctx))
	defer cancel()
	current := state
	for {
		finalModel, err := tea.NewProgram(newAppShellModel(a, current, baseCtx), tea.WithAltScreen()).Run()
		if err != nil {
			return err
		}
		model, ok := finalModel.(appShellModel)
		if !ok {
			return fmt.Errorf("unexpected app shell model type")
		}

		switch model.outcomeAction {
		case appShellActionQuit, appShellActionNone:
			return nil
		case appShellActionSelectCurrent:
			cwd, err := os.Getwd()
			if err != nil {
				return err
			}
			project, _, err := a.ensureProjectWithNotice(baseCtx, cwd, filepath.Base(cwd), false, false)
			if err != nil {
				current = model.nextLaunchState()
				current.Route = appRouteHome
				current.Notice = err.Error()
				current.Alert = true
				continue
			}
			current = model.nextLaunchState()
			current.Route = appRouteScanReview
			current.SelectedProjectID = project.ID
			current.Notice = a.catalog.T("project_registered", project.DisplayName)
			current.Alert = false
		case appShellActionPickFolder:
			project, _, err := a.ensureProjectWithNotice(baseCtx, "", "", true, false)
			if err != nil {
				current = model.nextLaunchState()
				current.Route = appRouteHome
				current.Notice = err.Error()
				current.Alert = true
				continue
			}
			current = model.nextLaunchState()
			current.Route = appRouteScanReview
			current.SelectedProjectID = project.ID
			current.Notice = a.catalog.T("project_registered", project.DisplayName)
			current.Alert = false
		default:
			current = model.nextLaunchState()
		}
	}
}

func (m appShellModel) Init() tea.Cmd {
	return tea.Batch(appShellRefreshCmd(m.autoRefreshInterval()), m.animationCmd(), m.scheduleBackgroundLoads())
}

func (m appShellModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case appShellRefreshMsg:
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
	case appShellSnapshotLoadedMsg:
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
	case appShellProjectResolvedMsg:
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
	case appShellFrameTickMsg:
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
	case scanMissionEventMsg:
		if msg.seq != 0 && msg.seq != m.scanSeq {
			return m, nil
		}
		if m.scanConsole != nil {
			m.scanConsole.update(m.app, msg.event)
		}
		m.scanRun = msg.event.Run
		return m, waitForScanMissionEvent(m.scanEventCh, m.scanSeq)
	case scanMissionDoneMsg:
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
	case appShellRunDetailLoadedMsg:
		if msg.seq != 0 && msg.seq != m.runDetailSeq {
			return m, nil
		}
		m.runDetailPendingID = ""
		if strings.TrimSpace(msg.runID) == "" {
			return m, nil
		}
		m.runDetailCache[msg.runID] = msg.entry
		return m, nil
	case appShellProjectTreeLoadedMsg:
		if msg.seq != 0 && msg.seq != m.projectTreeSeq {
			return m, nil
		}
		m.projectTreePending = ""
		if strings.TrimSpace(msg.projectID) == "" {
			return m, nil
		}
		m.projectTreeCache[m.projectTreeCacheKey(msg.projectID)] = msg.lines
		return m, nil
	case tea.KeyMsg:
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
		case "/":
			return m.openPalette(), nil
		case ":":
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
	}
	return m, nil
}

func (m appShellModel) updatePalette(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.paletteActive = false
		m.paletteCursor = 0
		m.paletteInput.Blur()
		return m, nil
	case "up", "k":
		if m.paletteCursor > 0 {
			m.paletteCursor--
		}
		return m, nil
	case "down", "j":
		if m.paletteCursor < len(m.filteredPaletteCommands())-1 {
			m.paletteCursor++
		}
		return m, nil
	case "enter":
		commands := m.filteredPaletteCommands()
		if len(commands) == 0 {
			m.paletteActive = false
			return m, nil
		}
		command := commands[m.paletteCursor]
		m.paletteActive = false
		m.paletteInput.Blur()
		return m.executePaletteCommand(command)
	}
	var cmd tea.Cmd
	m.paletteInput, cmd = m.paletteInput.Update(msg)
	if m.paletteCursor >= len(m.filteredPaletteCommands()) {
		m.paletteCursor = maxInt(0, len(m.filteredPaletteCommands())-1)
	}
	return m, cmd
}

func (m appShellModel) updateProjectPicker(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	rows := m.projectRows()
	switch msg.String() {
	case "esc":
		m.projectPickerActive = false
		return m, nil
	case "up", "k":
		if m.projectPickerCursor > 0 {
			m.projectPickerCursor--
		}
		return m, nil
	case "down", "j":
		if m.projectPickerCursor < len(rows)-1 {
			m.projectPickerCursor++
		}
		return m, nil
	case "enter":
		row, ok := rows.at(m.projectPickerCursor)
		if !ok {
			m.projectPickerActive = false
			return m, nil
		}
		m.projectPickerActive = false
		if strings.TrimSpace(row.Value) != "" {
			m.selectedProjectID = row.Value
			m.setRouteFresh(appRouteScanReview)
			m.refreshReviewContext()
			m.notice = m.app.catalog.T("app_project_picker_selected", row.Label)
			m.alert = false
			return m, m.scheduleBackgroundLoads()
		}
		return m.activateRow(row)
	}
	return m, nil
}

func (m appShellModel) updateTargetInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.targetInputActive = false
		m.targetInput.Blur()
		return m, nil
	case "enter":
		m.review.DASTTarget = strings.TrimSpace(m.targetInput.Value())
		m.targetInputActive = false
		m.targetInput.Blur()
		m.refreshReviewContext()
		return m, nil
	}
	var cmd tea.Cmd
	m.targetInput, cmd = m.targetInput.Update(msg)
	return m, cmd
}

func (m appShellModel) openPalette() appShellModel {
	m.paletteActive = true
	m.projectPickerActive = false
	m.paletteCursor = 0
	m.paletteInput.SetValue("")
	m.paletteInput.Focus()
	return m
}

func (m appShellModel) openProjectPicker() appShellModel {
	m.projectPickerActive = true
	m.paletteActive = false
	m.targetInputActive = false
	rows := m.projectRows()
	m.projectPickerCursor = 0
	for index, row := range rows {
		if strings.TrimSpace(row.Value) != "" && row.Value == m.selectedProjectID {
			m.projectPickerCursor = index
			break
		}
	}
	return m
}

func (m appShellModel) executePaletteCommand(command paletteCommand) (tea.Model, tea.Cmd) {
	switch command.Action {
	case appShellActionSelectCurrent, appShellActionPickFolder, appShellActionOpenProjectPicker, appShellActionStartScan, appShellActionAbortScan, appShellActionOpenRunFinds, appShellActionClearFinds:
		if command.Action == appShellActionOpenProjectPicker {
			return m.openProjectPicker(), nil
		}
		if command.Action == appShellActionStartScan {
			project, ok := m.selectedProject()
			if !ok {
				m.setRoutePreservingState(appRouteScanReview)
				m.notice = m.app.catalog.T("project_select_required")
				m.alert = true
				m = m.openProjectPicker()
				return m, nil
			}
			profile, doctor, ready, blockers := m.scanReviewContext(project)
			if !ready {
				m.setRoutePreservingState(appRouteScanReview)
				m.notice = strings.Join(blockers, " • ")
				m.alert = true
				return m, nil
			}
			return m.beginLiveScan(project, profile, doctor)
		}
		if command.Action == appShellActionAbortScan {
			if m.scanRunning && m.scanCancel != nil {
				m.scanCancel()
				m.scanAborting = true
				m.notice = m.app.catalog.T("scan_mode_live_cancel_requested")
				m.alert = true
			}
			return m, nil
		}
		if command.Action == appShellActionOpenRunFinds {
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
		if command.Action == appShellActionClearFinds {
			m.findingsScopeRun = ""
			m.resetRouteState(appRouteFindings)
			m.cursor = 0
			m.detailScroll = 0
			m.notice = m.app.catalog.T("app_findings_scope_cleared")
			m.alert = false
			return m, nil
		}
		if command.Action == appShellActionSelectCurrent || command.Action == appShellActionPickFolder {
			return m.beginProjectResolution(command.Action)
		}
	}
	m.setRoutePreservingState(command.Route)
	if command.Route == appRouteScanReview && m.selectedProjectID == "" {
		m = m.openProjectPicker()
	}
	return m, m.scheduleBackgroundLoads()
}

func (m appShellModel) activateSelection() (tea.Model, tea.Cmd) {
	switch m.route {
	case appRouteHome:
		row, ok := m.homeRows().at(m.cursor)
		if !ok {
			return m, nil
		}
		return m.activateRow(row)
	case appRouteProjects:
		row, ok := m.projectRows().at(m.cursor)
		if !ok {
			return m, nil
		}
		return m.activateRow(row)
	case appRouteScanReview:
		return m.activateReviewRow()
	case appRouteLiveScan:
		if !m.scanRunning && !m.scanDone && m.lastScan == nil {
			return m, nil
		}
		switch {
		case m.currentScanRequiredErr() != nil:
			m.setRouteFresh(appRouteRuntime)
		case len(m.currentScanFindings()) > 0:
			m.findingsScopeRun = m.currentScanOutcome().run.ID
			m.setRouteFresh(appRouteFindings)
		default:
			m.setRoutePreservingState(appRouteRuns)
		}
		return m, nil
	case appRouteRuns:
		run, ok := m.selectedRun()
		if !ok {
			return m, nil
		}
		m.findingsScopeRun = run.ID
		m.setRouteFresh(appRouteFindings)
		return m, nil
	default:
		return m, nil
	}
}

func (m appShellModel) activateRow(row appSelectableRow) (tea.Model, tea.Cmd) {
	switch row.Action {
	case appShellActionSelectCurrent, appShellActionPickFolder:
		if m.scanRunning && m.scanCancel != nil {
			m.scanCancel()
		}
		return m.beginProjectResolution(row.Action)
	}
	if strings.TrimSpace(row.Value) != "" {
		m.selectedProjectID = row.Value
		m.refreshReviewContext()
	}
	if row.Route >= 0 {
		m.setRoutePreservingState(row.Route)
	}
	return m, m.scheduleBackgroundLoads()
}

func (m appShellModel) beginProjectResolution(action appShellAction) (tea.Model, tea.Cmd) {
	switch action {
	case appShellActionSelectCurrent, appShellActionPickFolder:
	default:
		return m, nil
	}
	m.projectPickerActive = false
	m.paletteActive = false
	if m.scanRunning && m.scanCancel != nil {
		m.scanCancel()
	}
	m.notice = m.app.catalog.T("app_refreshing")
	m.alert = false
	return m, resolveProjectSelectionCmd(m.app, m.baseCtx, action)
}

func (m appShellModel) activateReviewRow() (tea.Model, tea.Cmd) {
	project, ok := m.selectedProject()
	if !ok {
		return m.openProjectPicker(), nil
	}

	switch m.cursor {
	case 0:
		return m.openProjectPicker(), nil
	case 1:
		m.review.Preset = nextReviewPreset(m.review.Preset)
		m.refreshReviewContext()
	case 2:
		if m.review.Preset == reviewPresetCompliance {
			m.review.CompliancePreset = nextCompliancePreset(m.review.CompliancePreset)
			m.refreshReviewContext()
		}
	case 3:
		m.review.Isolation = nextIsolationMode(m.review.Isolation)
		m.refreshReviewContext()
	case 4:
		m.review.ActiveValidation = !m.review.ActiveValidation
		if !m.review.ActiveValidation {
			m.review.DASTTarget = ""
			m.targetInput.SetValue("")
		}
		m.refreshReviewContext()
	case 5:
		m.targetInputActive = true
		m.targetInput.SetValue(strings.TrimSpace(m.review.DASTTarget))
		m.targetInput.Focus()
	case 6:
		profile, doctor, ready, blockers := m.scanReviewContext(project)
		if !ready {
			m.notice = strings.Join(blockers, " • ")
			m.alert = true
			return m, nil
		}
		return m.beginLiveScan(project, profile, doctor)
	}
	return m, nil
}

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

func (m *appShellModel) moveCursor(delta int) {
	count := m.itemCount()
	if count == 0 {
		m.cursor = 0
		m.detailScroll = 0
		return
	}
	m.cursor += delta
	if m.cursor < 0 {
		m.cursor = count - 1
	}
	if m.cursor >= count {
		m.cursor = 0
	}
	m.detailScroll = 0
}

func (m *appShellModel) clampCursor() {
	count := m.itemCount()
	if count == 0 {
		m.cursor = 0
		return
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	if m.cursor >= count {
		m.cursor = count - 1
	}
}

func (m appShellModel) itemCount() int {
	switch m.route {
	case appRouteHome:
		return len(m.homeRows())
	case appRouteProjects:
		return len(m.projectRows())
	case appRouteScanReview:
		return 7
	case appRouteRuns:
		return len(m.snapshot.Portfolio.Runs)
	case appRouteFindings:
		return len(m.filteredScopedFindings())
	case appRouteRuntime:
		return len(m.snapshot.Runtime.ScannerBundle)
	default:
		return 0
	}
}

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

func (m appShellModel) renderHomeContent(width int) string {
	projects := m.homeRows()
	veryCompact := m.height < 29
	project, projectSelected := m.selectedProject()
	leftWidth, rightWidth, _ := splitShellColumns(width, len(m.app.tuiTheme().gap()), 42, 42)

	nextAction := m.app.catalog.T("app_home_next_select_current")
	if projectSelected {
		nextAction = m.app.catalog.T("app_home_next_review")
	}
	heroTitle := m.currentWorkspaceTitle()
	if projectSelected {
		heroTitle = project.DisplayName
	}
	hero := m.renderHeroPanel(
		width,
		m.app.catalog.T("app_home_launchpad_title"),
		heroTitle,
		nextAction,
		m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_workspace"), Value: m.currentWorkspaceTitle()},
			factPair{Label: m.app.catalog.T("app_label_project"), Value: m.currentProjectValue()},
			factPair{Label: m.app.catalog.T("app_label_health"), Value: m.runtimeSnapshotSummary()},
		)...,
	)
	if veryCompact {
		compactCards := []string{
			hero,
			m.renderPanelCard(width, m.app.catalog.T("app_home_actions"), m.renderSelectableList(width, projects, m.cursor, 0)),
		}
		focusLines := m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_workspace"), Value: m.currentWorkspaceTitle()},
			factPair{Label: m.app.catalog.T("app_label_health"), Value: m.runtimeHealthHeadline()},
			factPair{Label: m.app.catalog.T("app_label_next"), Value: nextAction},
		)
		if projectSelected {
			focusLines = append(focusLines, m.renderFactLines(width,
				factPair{Label: m.app.catalog.T("app_label_project"), Value: project.DisplayName},
				factPair{Label: m.app.catalog.T("app_label_target"), Value: trimForSelect(project.LocationHint, max(30, width-18))},
			)...)
		}
		focusLines = append(focusLines, "", m.app.catalog.T("app_home_guide_step_1"), m.app.catalog.T("app_home_guide_step_2"), m.app.catalog.T("app_home_guide_step_3"))
		focusLines = append(focusLines, "", m.renderActionHintRow(width, m.commandHintActions(m.routePrimerHints())))
		compactCards = append(compactCards, m.renderPanelCard(width, m.app.catalog.T("app_home_focus_title"), focusLines...))
		return strings.Join(compactCards, "\n\n")
	}

	left := []string{
		m.renderPanelCardWithSummary(leftWidth, m.app.catalog.T("app_home_actions"),
			fmt.Sprintf("%s • P • %s", nextAction, m.app.catalog.T("app_action_open_project_picker")),
			m.renderSelectableList(leftWidth, projects, m.cursor, 0),
		),
	}

	var focusLines []string
	focusSummaryParts := []string{}
	if projectSelected {
		focusLines = m.renderFactLines(rightWidth,
			factPair{Label: m.app.catalog.T("app_label_target"), Value: trimForSelect(project.LocationHint, 56)},
			factPair{Label: m.app.catalog.T("app_label_trend"), Value: m.projectTrend(project.ID)},
			factPair{Label: m.app.catalog.T("app_label_next"), Value: nextAction},
		)
		focusSummaryParts = append(focusSummaryParts, trimForSelect(project.DisplayName, 24))
	} else {
		focusLines = m.renderFactLines(rightWidth,
			factPair{Label: m.app.catalog.T("app_label_workspace"), Value: m.currentWorkspaceTitle()},
			factPair{Label: m.app.catalog.T("app_label_project"), Value: m.currentProjectLabel()},
			factPair{Label: m.app.catalog.T("app_label_next"), Value: nextAction},
		)
		focusSummaryParts = append(focusSummaryParts, m.runtimeHealthHeadline())
	}
	if recent := m.homeRecentProjectSummary(3); recent != "" {
		focusSummaryParts = append(focusSummaryParts, fmt.Sprintf("%s %s", m.app.catalog.T("app_label_recent"), recent))
	}
	if risk := m.homeHotFindingSummary(1); risk != "" {
		focusSummaryParts = append(focusSummaryParts, fmt.Sprintf("%s %s", m.app.catalog.T("app_label_risk"), risk))
	}
	guideLines := []string{
		m.app.catalog.T("app_home_guide_step_1"),
		m.app.catalog.T("app_home_guide_step_2"),
		m.app.catalog.T("app_home_guide_step_3"),
	}
	right := []string{
		m.renderPanelCardWithSummary(rightWidth, m.app.catalog.T("app_home_focus_title"), strings.Join(focusSummaryParts, " • "), focusLines...),
		m.renderSelectionBriefCard(rightWidth, m.app.catalog.T("app_home_guide_title"), m.app.catalog.T("app_route_home_primer"), guideLines, m.commandHintActions(m.routePrimerHints())),
	}

	leftPanel := strings.Join(left, "\n\n")
	rightPanel := strings.Join(right, "\n\n")
	return m.renderDeckAndColumns(width, hero, leftPanel, rightPanel, 42, 42)
}

func (m appShellModel) renderProjectsContent(width int) string {
	rows := m.projectRows()
	project, _ := m.selectedProject()
	treeLimit := 12
	if width < 112 {
		treeLimit = 8
	}
	topCards := []tuiMetricCard{
		{Title: m.app.catalog.T("projects_title"), Value: fmt.Sprintf("%d", len(m.snapshot.Portfolio.Projects)), Hint: m.app.catalog.T("app_route_projects_subtitle")},
		{Title: m.app.catalog.T("projects_roster_title"), Value: topProjectStacks(m.snapshot.Portfolio.Projects, 4), Hint: m.app.catalog.T("app_projects_enter_hint")},
	}
	return m.renderMasterDetailRoute(width, topCards, 2,
		m.app.catalog.T("projects_title"),
		fmt.Sprintf("%d %s • %s", len(m.snapshot.Portfolio.Projects), strings.ToLower(m.app.catalog.T("projects_title")), strings.ToLower(m.app.catalog.T("app_projects_enter_hint"))),
		rows, m.cursor, 0, 44, 42,
		func(compactWidth int) []string {
			lines := []string{
				m.renderSelectionBriefCard(compactWidth, m.app.catalog.T("app_projects_brief_title"), m.currentProjectLabel(), m.composeBriefBody(m.projectPreviewLines(compactWidth), m.projectFocusLines(compactWidth)), []string{
					"enter • " + m.app.catalog.T("app_route_scan_review_short"),
					"p • " + m.app.catalog.T("app_action_open_project_picker"),
				}),
			}
			if project.ID != "" {
				lines = append(lines, m.renderPanelCard(compactWidth, project.DisplayName,
					m.renderFactLines(compactWidth,
						factPair{Label: m.app.catalog.T("app_label_target"), Value: trimForSelect(project.LocationHint, max(30, compactWidth-18))},
						factPair{Label: m.app.catalog.T("app_label_stacks"), Value: coalesceString(strings.Join(project.DetectedStacks, ", "), "-")},
						factPair{Label: m.app.catalog.T("app_label_trend"), Value: m.projectTrend(project.ID)},
					)...,
				))
			}
			return lines
		},
		func(rightWidth int) []string {
			if project.ID == "" {
				return []string{
					m.renderSelectionBriefCard(rightWidth, m.app.catalog.T("app_projects_brief_title"), m.currentProjectLabel(), m.composeBriefBody(m.projectPreviewLines(rightWidth), m.projectFocusLines(rightWidth)), []string{
						"enter • " + m.app.catalog.T("app_route_scan_review_short"),
						"p • " + m.app.catalog.T("app_action_open_project_picker"),
					}),
				}
			}
			return []string{
				m.renderSelectionBriefCard(rightWidth, m.app.catalog.T("app_projects_brief_title"), m.currentProjectLabel(), m.composeBriefBody(m.projectPreviewLines(rightWidth), m.projectFocusLines(rightWidth)), []string{
					"enter • " + m.app.catalog.T("app_route_scan_review_short"),
					"p • " + m.app.catalog.T("app_action_open_project_picker"),
				}),
				m.renderPanelCard(rightWidth, project.DisplayName,
					m.renderFactLines(rightWidth,
						factPair{Label: m.app.catalog.T("app_label_target"), Value: trimForSelect(project.LocationHint, max(32, rightWidth-18))},
						factPair{Label: m.app.catalog.T("app_label_stacks"), Value: coalesceString(strings.Join(project.DetectedStacks, ", "), "-")},
						factPair{Label: m.app.catalog.T("app_label_trend"), Value: m.projectTrend(project.ID)},
					)...,
				),
				m.renderPanelCard(rightWidth, m.app.catalog.T("app_project_tree_title"), m.projectTreePreview(project, 2, treeLimit)...),
			}
		},
	)
}

func (m appShellModel) renderScanReviewContent(width int) string {
	project, ok := m.selectedProject()
	if !ok {
		return m.app.tuiTheme().panelStyle(width).Width(width).Render(strings.Join([]string{
			m.renderSection(m.app.catalog.T("app_route_scan_review"),
				m.app.catalog.T("project_select_required"),
				m.app.catalog.T("app_scan_review_pick_project"),
			),
		}, "\n"))
	}

	profile, doctor, ready, blockers := m.scanReviewContext(project)
	laneSummary := m.reviewLaneSummary(project, profile)
	laneHint := "-"
	if len(laneSummary) > 0 {
		laneHint = laneSummary[0]
	}
	leftWidth, rightWidth, _ := splitShellColumns(width, len(m.app.tuiTheme().gap()), 46, 48)
	treeLimit := 10
	laneDetailLimit := 0
	if width < 116 {
		treeLimit = 6
		laneDetailLimit = 18
	}
	hero := m.renderHeroPanel(
		width,
		m.app.catalog.T("app_scan_review_preset"),
		m.reviewPresetLabel(),
		m.scanStartHint(profile, ready),
		m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_project"), Value: project.DisplayName},
			factPair{Label: m.app.catalog.T("app_label_isolation"), Value: strings.ToUpper(string(m.review.Isolation))},
			factPair{Label: m.app.catalog.T("app_label_coverage"), Value: fmt.Sprintf("%d • %s", len(profile.Modules), trimForSelect(laneHint, 42))},
			factPair{Label: m.app.catalog.T("app_label_health"), Value: doctorSummaryLine(m.app, doctor)},
		)...,
	)
	if m.height < 31 {
		controlLines := append(
			m.renderFactLines(width,
				factPair{Label: m.app.catalog.T("app_label_profile"), Value: m.reviewPresetLabel()},
				factPair{Label: m.app.catalog.T("app_label_target"), Value: coalesceString(m.review.DASTTarget, m.app.catalog.T("app_scan_review_target_empty"))},
				factPair{Label: m.app.catalog.T("app_label_health"), Value: ternary(ready, m.app.catalog.T("app_scan_review_ready"), m.app.catalog.T("app_scan_review_start_blocked"))},
			),
			m.app.catalog.T("app_scan_review_lane_summary")+":",
			laneHint,
			m.scanStartHint(profile, ready),
			doctorSummaryLine(m.app, doctor),
		)
		lines := []string{
			m.renderPanelCard(width, m.app.catalog.T("app_scan_review_controls_title"), controlLines...),
			m.renderPanelCard(width, m.app.catalog.T("app_scan_review_lane_summary"), m.reviewLaneSummary(project, profile)...),
		}
		if m.height >= 25 {
			lines = append(lines, m.renderPanelCard(width, m.app.catalog.T("overview_operator_focus"), m.reviewFocusLines(width, project, profile, doctor, ready, blockers)...))
		}
		if len(blockers) > 0 {
			lines = append(lines, m.renderPanelCard(width, m.app.catalog.T("app_scan_review_blockers"), blockers...))
		}
		if m.height >= 26 {
			lines = append(lines, m.renderPanelCard(width, m.app.catalog.T("overview_next_steps"),
				m.app.catalog.T("app_scan_review_enter_hint"),
				m.app.catalog.T("app_scan_review_keys_hint"),
			))
		}
		return strings.Join(lines, "\n\n")
	}

	rows := m.scanReviewRows(project, profile, ready)
	left := strings.Join([]string{
		m.renderPanelCard(leftWidth, m.app.catalog.T("app_scan_review_controls_title"),
			m.renderSelectableList(leftWidth, rows, m.cursor, 0),
			"",
			strings.Join(m.renderFactLines(leftWidth,
				factPair{Label: m.app.catalog.T("app_label_health"), Value: ternary(ready, m.app.catalog.T("app_scan_review_ready"), m.app.catalog.T("app_scan_review_start_blocked"))},
				factPair{Label: m.app.catalog.T("app_label_profile"), Value: m.reviewPresetLabel()},
			), "\n"),
			m.scanStartHint(profile, ready),
			doctorSummaryLine(m.app, doctor),
			m.app.catalog.T("app_scan_review_enter_hint"),
		),
	}, "\n\n")

	rightLines := []string{
		m.renderPanelCard(rightWidth, m.app.catalog.T("app_scan_review_plan_title"),
			m.reviewPlanLines(rightWidth, project, profile)...,
		),
		m.renderSelectionBriefCard(rightWidth, m.app.catalog.T("app_scan_review_brief_title"), m.scanStartHint(profile, ready), m.composeBriefBody(m.reviewPreviewLines(rightWidth, project, profile, doctor, ready, blockers), m.reviewFocusLines(rightWidth, project, profile, doctor, ready, blockers)), []string{
			m.app.catalog.T("app_scan_review_enter_hint"),
			m.app.catalog.T("app_scan_review_keys_hint"),
		}),
	}
	if width >= 150 {
		rightLines = append(rightLines, m.renderPanelCard(rightWidth, m.app.catalog.T("scan_mode_live_scope_title"), m.reviewLaneSectionsForWidth(project, profile, laneDetailLimit)...))
	}
	if width >= 150 {
		rightLines = append(rightLines, m.renderPanelCard(rightWidth, m.app.catalog.T("app_project_tree_title"), m.projectTreePreview(project, 2, treeLimit)...))
	}
	if len(blockers) > 0 {
		rightLines = append(rightLines, m.renderPanelCard(rightWidth, m.app.catalog.T("app_scan_review_blockers"), blockers...))
	}
	right := strings.Join(rightLines, "\n\n")
	return m.renderDeckAndColumns(width, hero, left, right, 46, 48)
}

func (m appShellModel) renderLiveScanContent(width int) string {
	if mission, ok := m.activeScanMissionModel(); ok {
		return m.renderEmbeddedLiveMission(width, mission)
	}
	if m.lastScan == nil {
		lines := append(m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_project"), Value: m.currentProjectValue()},
			factPair{Label: m.app.catalog.T("app_label_health"), Value: m.runtimeSnapshotSummary()},
		), m.app.catalog.T("app_live_scan_empty"))
		return m.renderHeroPanel(width, m.app.catalog.T("app_route_live_scan"), m.app.catalog.T("app_live_scan_empty"), m.app.catalog.T("app_route_live_scan_subtitle"), lines...)
	}
	return m.renderLiveDebriefPanel(*m.lastScan, width)
}

func (m appShellModel) renderEmbeddedLiveMission(width int, mission scanMissionModel) string {
	boardHeight := maxInt(12, minInt(22, m.height-20))
	board := mission.renderMissionBoardWithViewport(width, boardHeight, m.renderDetailViewport)
	sections := []string{
		mission.renderLaunchStrip(width),
		board,
		mission.renderHealthFooter(width),
	}
	if mission.done {
		sections = append(sections, m.renderLiveDebriefPanel(m.currentScanOutcome(), width))
	}
	return strings.Join(sections, "\n\n")
}

func (m appShellModel) renderLiveDebriefPanel(outcome scanMissionOutcome, width int) string {
	theme := m.app.tuiTheme()
	verdict := m.app.catalog.T("scan_outcome_clean")
	nextStep := m.app.catalog.T("app_live_scan_next_runs")
	switch {
	case outcome.requiredErr != nil:
		verdict = m.app.catalog.T("scan_outcome_partial")
		nextStep = m.app.catalog.T("app_live_scan_next_runtime")
	case len(outcome.findings) > 0:
		verdict = m.app.catalog.T("scan_outcome_blocked")
		nextStep = m.app.catalog.T("app_live_scan_next_findings")
	}
	hero := m.renderHeroPanel(
		width,
		m.app.catalog.T("app_route_live_scan"),
		strings.ToUpper(verdict),
		nextStep,
		m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_scope"), Value: outcome.run.ID},
			factPair{Label: m.app.catalog.T("app_label_findings"), Value: fmt.Sprintf("%d", outcome.run.Summary.TotalFindings)},
			factPair{Label: m.app.catalog.T("app_label_tools"), Value: fmt.Sprintf("%d", len(outcome.run.ModuleResults))},
			factPair{Label: m.app.catalog.T("app_label_report"), Value: m.reportDisplayValue(outcome.reportPath)},
			factPair{Label: m.app.catalog.T("app_label_next"), Value: nextStep},
		)...,
	)
	leftWidth, rightWidth, stack := splitShellColumns(width, len(theme.gap()), 42, 42)
	left := []string{
		m.renderPanelCard(leftWidth, m.app.catalog.T("module_execution_title"), m.renderDetailViewport(leftWidth, m.renderLiveRunDigest(outcome.run))),
	}
	briefLines := m.renderFactLines(rightWidth,
		factPair{Label: m.app.catalog.T("app_label_health"), Value: strings.ToUpper(verdict)},
		factPair{Label: m.app.catalog.T("app_label_report"), Value: m.reportDisplayValue(outcome.reportPath)},
		factPair{Label: m.app.catalog.T("app_label_next"), Value: nextStep},
	)
	prioritized := m.app.prioritizedFindings(outcome.findings, 5)
	if len(prioritized) > 0 {
		briefLines = append(briefLines, "", m.app.catalog.T("overview_hot_findings")+":")
		briefLines = append(briefLines, strings.Split(m.renderFindingDigest(prioritized, 5), "\n")...)
	}
	if outcome.requiredErr != nil {
		briefLines = append(briefLines, "", m.app.catalog.T("app_scan_review_blockers")+":", outcome.requiredErr.Error())
	}
	if outcome.scanErr != nil {
		briefLines = append(briefLines, "", m.app.catalog.T("scan_failed")+":", outcome.scanErr.Error())
	}
	if len(prioritized) == 0 && outcome.requiredErr == nil && outcome.scanErr == nil {
		briefLines = append(briefLines, "", m.app.catalog.T("app_live_scan_notice_clean"))
	}
	briefLines = append(briefLines, "", "e • "+m.app.catalog.T("export_title"))
	right := []string{
		m.renderPanelCard(rightWidth, m.app.catalog.T("app_live_scan_brief_title"), briefLines...),
	}
	if stack {
		lines := []string{hero, strings.Join(left, "\n\n"), strings.Join(right, "\n\n")}
		return strings.Join(lines, "\n\n")
	}
	return strings.Join([]string{hero, lipgloss.JoinHorizontal(lipgloss.Top, strings.Join(left, "\n\n"), theme.gap(), strings.Join(right, "\n\n"))}, "\n\n")
}

func (m appShellModel) renderRunsContent(width int) string {
	heroTitle := m.app.catalog.T("runs_title")
	heroBody := m.renderRunQueueSummary()
	heroLines := m.renderFactLines(width,
		factPair{Label: m.app.catalog.T("app_label_sync"), Value: m.snapshotUpdatedClock()},
		factPair{Label: m.app.catalog.T("app_label_trend"), Value: m.app.runTrendLabel(m.snapshot.Portfolio.Runs, 8)},
	)
	if run, ok := m.selectedRun(); ok {
		heroTitle = strings.ToUpper(string(run.Status))
		heroBody = fmt.Sprintf("%s • %s", m.app.projectLabel(run.ProjectID), trimForSelect(run.ID, 42))
		heroLines = append(heroLines, m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_findings"), Value: fmt.Sprintf("%d", run.Summary.TotalFindings)},
		)...)
	}
	content := m.renderMasterDetailRoute(width, nil, 0,
		m.app.catalog.T("runs_ledger_title"),
		m.renderRunQueueSummary(),
		m.runRows(), m.cursor, 0, 42, 48,
		func(compactWidth int) []string {
			return []string{
				m.renderSelectionBriefCard(compactWidth, m.app.catalog.T("app_runs_brief_title"), m.runBriefSummary(), m.composeBriefBody(m.runPreviewLines(compactWidth), m.runFocusLines(compactWidth)), []string{
					"o • " + m.app.catalog.T("app_action_open_run_findings"),
					"c • " + m.app.catalog.T("run_cancel_title"),
					"R • " + m.app.catalog.T("run_retry_title"),
					"e • " + m.app.catalog.T("export_title"),
				}),
				m.renderPanelCard(compactWidth, m.app.catalog.T("app_runs_detail_title"), m.renderRunDetailContent(compactWidth)),
			}
		},
		func(rightWidth int) []string {
			return []string{
				m.renderSelectionBriefCard(rightWidth, m.app.catalog.T("app_runs_brief_title"), m.runBriefSummary(), m.composeBriefBody(m.runPreviewLines(rightWidth), m.runFocusLines(rightWidth)), []string{
					"o • " + m.app.catalog.T("app_action_open_run_findings"),
					"c • " + m.app.catalog.T("run_cancel_title"),
					"R • " + m.app.catalog.T("run_retry_title"),
					"e • " + m.app.catalog.T("export_title"),
				}),
				m.renderPanelCard(rightWidth, m.app.catalog.T("app_runs_detail_title"), m.renderDetailViewport(rightWidth, m.renderRunDetailContent(rightWidth))),
			}
		},
	)
	return strings.Join([]string{m.renderHeroPanel(width, m.app.catalog.T("runs_ledger_title"), heroTitle, heroBody, heroLines...), content}, "\n\n")
}

func (m appShellModel) renderFindingsContent(width int) string {
	findings := m.filteredScopedFindings()
	heroTitle := fmt.Sprintf("%d", len(findings))
	heroBody := m.renderFindingPressureSummary(findings)
	heroLines := m.renderFactLines(width,
		factPair{Label: m.app.catalog.T("findings_filters"), Value: m.currentFindingsSeverityFilterLabel()},
		factPair{Label: m.app.catalog.T("finding_filter_status_label"), Value: m.currentFindingsStatusFilterLabel()},
		factPair{Label: m.app.catalog.T("app_label_sync"), Value: m.snapshotUpdatedClock()},
	)
	if strings.TrimSpace(m.findingsScopeRun) != "" {
		heroLines = append(heroLines, m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_findings_scope_title"), Value: m.findingsScopeLabel()},
		)...)
	}
	if finding, ok := m.selectedFinding(); ok {
		heroTitle = strings.ToUpper(m.app.severityLabel(finding.Severity))
		heroBody = trimForSelect(m.app.displayFindingTitle(finding), 54)
		heroLines = append(heroLines, m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("triage_status"), Value: m.app.findingStatusLabel(m.normalizedFindingStatus(finding.Status))},
		)...)
	}
	content := m.renderMasterDetailRoute(width, nil, 0,
		m.app.catalog.T("findings_queue_title"),
		m.renderFindingPressureSummary(findings),
		m.findingRows(findings), m.cursor, 0, 42, 48,
		func(compactWidth int) []string {
			return []string{
				m.renderSelectionBriefCard(compactWidth, m.app.catalog.T("app_findings_brief_title"), m.findingBriefSummary(), m.composeBriefBody(m.findingPreviewLines(compactWidth), m.findingFocusLines(compactWidth)), []string{
					"f • " + m.app.catalog.T("finding_filter_severity_label"),
					"g • " + m.app.catalog.T("finding_filter_status_label"),
					"0 • " + m.app.catalog.T("artifact_filter_all"),
				}),
				m.renderPanelCard(compactWidth, m.app.catalog.T("app_findings_detail_title"), m.renderFindingDetailContent(compactWidth)),
			}
		},
		func(rightWidth int) []string {
			return []string{
				m.renderSelectionBriefCard(rightWidth, m.app.catalog.T("app_findings_brief_title"), m.findingBriefSummary(), m.composeBriefBody(m.findingPreviewLines(rightWidth), m.findingFocusLines(rightWidth)), []string{
					"f • " + m.app.catalog.T("finding_filter_severity_label"),
					"g • " + m.app.catalog.T("finding_filter_status_label"),
					"0 • " + m.app.catalog.T("artifact_filter_all"),
				}),
				m.renderPanelCard(rightWidth, m.app.catalog.T("app_findings_detail_title"), m.renderDetailViewport(rightWidth, m.renderFindingDetailContent(rightWidth))),
			}
		},
	)
	return strings.Join([]string{m.renderHeroPanel(width, m.app.catalog.T("findings_queue_title"), heroTitle, heroBody, heroLines...), content}, "\n\n")
}

func (m appShellModel) renderRuntimeContent(width int) string {
	heroTitle := m.runtimeHealthHeadline()
	heroBody := m.runtimeSnapshotSummary()
	heroLines := m.renderFactLines(width,
		factPair{Label: m.app.catalog.T("app_label_tools"), Value: fmt.Sprintf("%d", len(m.snapshot.Runtime.ScannerBundle))},
		factPair{Label: m.app.catalog.T("app_label_daemon"), Value: m.app.daemonStateLabel(m.snapshot.Runtime.Daemon)},
		factPair{Label: m.app.catalog.T("app_label_sync"), Value: m.snapshotUpdatedClock()},
	)
	if tool, ok := m.selectedRuntimeTool(); ok {
		heroTitle = tool.Name
		heroBody = strings.ToUpper(coalesceString(tool.ActualVersion, tool.ExpectedVersion))
		heroLines = append(heroLines, m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_verify"), Value: strings.ToUpper(tool.Verification.Status())},
		)...)
	}
	content := m.renderMasterDetailRoute(width, nil, 0,
		m.app.catalog.T("runtime_scanners_title"),
		m.runtimeSnapshotSummary(),
		m.runtimeRows(), m.cursor, 0, 42, 48,
		func(compactWidth int) []string {
			lines := []string{}
			if panel := m.renderRuntimeRefreshPanel(compactWidth); panel != "" {
				lines = append(lines, panel)
			}
			lines = append(lines,
				m.renderSelectionBriefCard(compactWidth, m.app.catalog.T("app_runtime_brief_title"), m.runtimeSnapshotSummary(), m.composeBriefBody(m.runtimePreviewLines(compactWidth), m.runtimeFocusLines(compactWidth)), []string{
					"r • " + m.app.catalog.T("app_help_refresh"),
					"/ • " + m.app.catalog.T("app_help_palette"),
				}),
				m.renderPanelCard(compactWidth, m.app.catalog.T("app_runtime_detail_title"), m.renderRuntimeDetailContent(compactWidth)),
			)
			return lines
		},
		func(rightWidth int) []string {
			lines := []string{}
			if panel := m.renderRuntimeRefreshPanel(rightWidth); panel != "" {
				lines = append(lines, panel)
			}
			lines = append(lines,
				m.renderSelectionBriefCard(rightWidth, m.app.catalog.T("app_runtime_brief_title"), m.runtimeSnapshotSummary(), m.composeBriefBody(m.runtimePreviewLines(rightWidth), m.runtimeFocusLines(rightWidth)), []string{
					"r • " + m.app.catalog.T("app_help_refresh"),
					"/ • " + m.app.catalog.T("app_help_palette"),
				}),
				m.renderPanelCard(rightWidth, m.app.catalog.T("app_runtime_detail_title"), m.renderDetailViewport(rightWidth, m.renderRuntimeDetailContent(rightWidth))),
			)
			return lines
		},
	)
	return strings.Join([]string{m.renderHeroPanel(width, m.app.catalog.T("runtime_trust_signal_title"), heroTitle, heroBody, heroLines...), content}, "\n\n")
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

func (m appShellModel) routeSubtitle() string {
	switch m.route {
	case appRouteProjects:
		return m.app.catalog.T("app_route_projects_subtitle")
	case appRouteScanReview:
		return m.app.catalog.T("app_route_scan_review_subtitle")
	case appRouteLiveScan:
		return m.app.catalog.T("app_route_live_scan_subtitle")
	case appRouteRuns:
		return m.app.catalog.T("runs_title")
	case appRouteFindings:
		return m.app.catalog.T("findings_title")
	case appRouteRuntime:
		return m.app.catalog.T("runtime_command_title")
	default:
		return m.app.catalog.T("app_route_home_subtitle")
	}
}

func (m appShellModel) routeTitle() string {
	switch m.route {
	case appRouteProjects:
		return m.app.catalog.T("app_route_projects")
	case appRouteScanReview:
		return m.app.catalog.T("app_route_scan_review")
	case appRouteLiveScan:
		return m.app.catalog.T("app_route_live_scan")
	case appRouteRuns:
		return m.app.catalog.T("runs_title")
	case appRouteFindings:
		return m.app.catalog.T("findings_title")
	case appRouteRuntime:
		return m.app.catalog.T("runtime_command_title")
	default:
		return m.app.catalog.T("app_route_home")
	}
}

func (m appShellModel) footerText() string {
	if m.width < 96 {
		switch {
		case m.targetInputActive:
			return m.app.catalog.T("app_target_footer_compact")
		case m.paletteActive:
			return m.app.catalog.T("app_palette_footer_compact")
		case m.projectPickerActive:
			return m.app.catalog.T("app_project_picker_footer_compact")
		case m.route == appRouteLiveScan && m.scanRunning:
			return m.app.catalog.T("app_live_scan_footer_compact")
		default:
			return m.app.catalog.T("app_shell_footer_compact")
		}
	}
	if m.targetInputActive {
		return m.app.catalog.T("app_target_footer")
	}
	if m.paletteActive {
		return m.app.catalog.T("app_palette_footer")
	}
	if m.projectPickerActive {
		return m.app.catalog.T("app_project_picker_footer")
	}
	if m.route == appRouteLiveScan && (m.scanRunning || m.scanDone) {
		if m.scanRunning {
			return m.app.catalog.T("scan_mode_live_footer_running") + " • x abort"
		}
		if m.scanRequiredErr != nil {
			return m.app.catalog.T("scan_mode_live_footer_doctor")
		}
		if len(m.scanFindings) > 0 {
			return m.app.catalog.T("scan_mode_live_footer_review")
		}
		return m.app.catalog.T("scan_mode_live_footer_clean")
	}
	switch m.route {
	case appRouteScanReview:
		return m.app.catalog.T("app_scan_review_footer")
	case appRouteLiveScan:
		return m.app.catalog.T("app_live_scan_footer")
	default:
		return m.app.catalog.T("app_shell_footer")
	}
}

func (m appShellModel) nextLaunchState() appShellLaunchState {
	return appShellLaunchState{
		Route:             m.route,
		SelectedProjectID: m.selectedProjectID,
		FindingsScopeRun:  m.findingsScopeRun,
		Review:            m.review,
		Notice:            m.notice,
		Alert:             m.alert,
		LastScan:          m.lastScan,
	}
}

func (m appShellModel) selectedProject() (domain.Project, bool) {
	if strings.TrimSpace(m.selectedProjectID) == "" {
		return domain.Project{}, false
	}
	return m.snapshotProject(m.selectedProjectID)
}

func (m appShellModel) preferredProjectID() string {
	if current, ok := m.selectedProject(); ok {
		return current.ID
	}
	if cwd, err := os.Getwd(); err == nil {
		if current := projectForPath(m.snapshot.Portfolio.Projects, cwd); current != nil {
			return current.ID
		}
	}
	if latest := latestProject(m.snapshot.Portfolio.Projects); latest != nil {
		return latest.ID
	}
	return ""
}

func (m *appShellModel) reconcileSnapshotState(route appRoute) {
	m.selectedProjectID = strings.TrimSpace(m.preferredProjectID())
	if strings.TrimSpace(m.findingsScopeRun) != "" {
		if _, ok := m.snapshotRun(m.findingsScopeRun); !ok {
			m.findingsScopeRun = ""
			if route == appRouteFindings || m.route == appRouteFindings {
				m.resetRouteState(appRouteFindings)
			}
		}
	}
	if m.route == appRouteProjects && !m.projectPickerActive && len(m.snapshot.Portfolio.Projects) == 0 {
		m.route = appRouteHome
	}
}

func (m appShellModel) currentProjectLabel() string {
	project, ok := m.selectedProject()
	if !ok {
		return m.app.catalog.T("projects_focus_empty")
	}
	return fmt.Sprintf("%s • %s", project.DisplayName, trimForSelect(project.LocationHint, 28))
}

func (m appShellModel) homeRows() selectableRows {
	rows := selectableRows{
		{Label: m.app.catalog.T("app_action_select_current"), Hint: m.app.catalog.T("app_action_select_current_hint"), Action: appShellActionSelectCurrent},
		{Label: m.app.catalog.T("app_action_open_project_picker"), Hint: m.app.catalog.T("app_action_open_project_picker_hint"), Action: appShellActionOpenProjectPicker},
		{Label: m.app.catalog.T("app_action_pick_folder"), Hint: m.app.catalog.T("app_action_pick_folder_hint"), Action: appShellActionPickFolder},
	}
	return rows
}

func (m appShellModel) homeRecentProjectSummary(limit int) string {
	if limit <= 0 || len(m.snapshot.Portfolio.Projects) == 0 {
		return ""
	}
	items := make([]string, 0, min(limit, len(m.snapshot.Portfolio.Projects)))
	for _, project := range m.snapshot.Portfolio.Projects[:min(limit, len(m.snapshot.Portfolio.Projects))] {
		items = append(items, trimForSelect(project.DisplayName, 16))
	}
	return strings.Join(items, " • ")
}

func (m appShellModel) homeHotFindingSummary(limit int) string {
	if limit <= 0 {
		return ""
	}
	hot := m.app.prioritizedFindings(m.snapshot.Portfolio.Findings, limit)
	if len(hot) == 0 {
		return ""
	}
	top := hot[0]
	return fmt.Sprintf("%s • %s", strings.ToUpper(m.app.severityLabel(top.Severity)), trimForSelect(m.app.displayFindingTitle(top), 44))
}

func (m appShellModel) projectRows() selectableRows {
	rows := selectableRows{
		{Label: m.app.catalog.T("app_action_select_current"), Hint: m.app.catalog.T("app_action_select_current_hint"), Action: appShellActionSelectCurrent},
		{Label: m.app.catalog.T("app_action_pick_folder"), Hint: m.app.catalog.T("app_action_pick_folder_hint"), Action: appShellActionPickFolder},
	}
	for _, project := range m.snapshot.Portfolio.Projects {
		rows = append(rows, appSelectableRow{
			Label: project.DisplayName,
			Hint:  fmt.Sprintf("%s • %s", trimForSelect(project.LocationHint, 42), coalesceString(strings.Join(project.DetectedStacks, ", "), "-")),
			Route: appRouteScanReview,
			Value: project.ID,
		})
	}
	return rows
}

func (m appShellModel) filteredPaletteCommands() []paletteCommand {
	commands := []paletteCommand{
		{ID: "home", Group: m.app.catalog.T("app_palette_group_nav"), Label: m.app.catalog.T("app_route_home"), Hint: m.app.catalog.T("app_route_home_subtitle"), Route: appRouteHome},
		{ID: "scan-review", Group: m.app.catalog.T("app_palette_group_nav"), Label: m.app.catalog.T("app_route_scan_review"), Hint: m.app.catalog.T("app_route_scan_review_subtitle"), Route: appRouteScanReview},
		{ID: "live-scan", Group: m.app.catalog.T("app_palette_group_nav"), Label: m.app.catalog.T("app_route_live_scan"), Hint: m.app.catalog.T("app_route_live_scan_subtitle"), Route: appRouteLiveScan},
		{ID: "runs", Group: m.app.catalog.T("app_palette_group_nav"), Label: m.app.catalog.T("runs_title"), Hint: m.app.catalog.T("overview_recent_runs"), Route: appRouteRuns},
		{ID: "findings", Group: m.app.catalog.T("app_palette_group_nav"), Label: m.app.catalog.T("findings_title"), Hint: m.app.catalog.T("overview_hot_findings"), Route: appRouteFindings},
		{ID: "runtime", Group: m.app.catalog.T("app_palette_group_nav"), Label: m.app.catalog.T("runtime_command_title"), Hint: m.app.catalog.T("runtime_trust_signal_title"), Route: appRouteRuntime},
		{ID: "current", Group: m.app.catalog.T("app_palette_group_project"), Label: m.app.catalog.T("app_action_select_current"), Hint: m.app.catalog.T("app_action_select_current_hint"), Action: appShellActionSelectCurrent},
		{ID: "pick", Group: m.app.catalog.T("app_palette_group_project"), Label: m.app.catalog.T("app_action_pick_folder"), Hint: m.app.catalog.T("app_action_pick_folder_hint"), Action: appShellActionPickFolder},
		{ID: "project-picker", Group: m.app.catalog.T("app_palette_group_project"), Label: m.app.catalog.T("app_action_open_project_picker"), Hint: m.app.catalog.T("app_action_open_project_picker_hint"), Action: appShellActionOpenProjectPicker},
	}
	if _, ok := m.selectedProject(); ok {
		commands = append(commands, paletteCommand{
			ID:     "start",
			Group:  m.app.catalog.T("app_palette_group_scan"),
			Label:  m.app.catalog.T("app_action_start_scan"),
			Hint:   m.app.catalog.T("app_action_start_scan_hint"),
			Action: appShellActionStartScan,
		})
	}
	if m.scanRunning {
		commands = append(commands, paletteCommand{
			ID:     "abort-scan",
			Group:  m.app.catalog.T("app_palette_group_scan"),
			Label:  m.app.catalog.T("app_action_abort_scan"),
			Hint:   m.app.catalog.T("app_action_abort_scan_hint"),
			Action: appShellActionAbortScan,
		})
	}
	if m.route == appRouteRuns && len(m.snapshot.Portfolio.Runs) > 0 {
		commands = append(commands, paletteCommand{
			ID:     "run-findings",
			Group:  m.app.catalog.T("app_palette_group_inspect"),
			Label:  m.app.catalog.T("app_action_open_run_findings"),
			Hint:   m.app.catalog.T("app_action_open_run_findings_hint"),
			Action: appShellActionOpenRunFinds,
		})
	}
	if strings.TrimSpace(m.findingsScopeRun) != "" {
		commands = append(commands, paletteCommand{
			ID:     "clear-findings-scope",
			Group:  m.app.catalog.T("app_palette_group_inspect"),
			Label:  m.app.catalog.T("app_action_clear_findings_scope"),
			Hint:   m.app.catalog.T("app_action_clear_findings_scope_hint"),
			Action: appShellActionClearFinds,
		})
	}
	query := strings.ToLower(strings.TrimSpace(m.paletteInput.Value()))
	if query == "" {
		return commands
	}
	type scoredCommand struct {
		command paletteCommand
		score   int
	}
	filtered := make([]scoredCommand, 0, len(commands))
	for _, command := range commands {
		score := paletteMatchScore(command, query)
		if score > 0 {
			filtered = append(filtered, scoredCommand{command: command, score: score})
		}
	}
	slices.SortFunc(filtered, func(a, b scoredCommand) int {
		switch {
		case a.score > b.score:
			return -1
		case a.score < b.score:
			return 1
		default:
			return strings.Compare(a.command.Label, b.command.Label)
		}
	})
	commands = make([]paletteCommand, 0, len(filtered))
	for _, item := range filtered {
		commands = append(commands, item.command)
	}
	return commands
}

func paletteMatchScore(command paletteCommand, query string) int {
	normalize := func(value string) string {
		return strings.ToLower(strings.TrimSpace(value))
	}
	query = normalize(query)
	if query == "" {
		return 1
	}

	label := normalize(command.Label)
	hint := normalize(command.Hint)
	group := normalize(command.Group)
	id := normalize(command.ID)
	action := normalize(string(command.Action))

	wholeScore := 0
	switch {
	case label == query:
		wholeScore += 500
	case id == query:
		wholeScore += 420
	case strings.HasPrefix(label, query):
		wholeScore += 260
	case strings.HasPrefix(id, query):
		wholeScore += 220
	case strings.Contains(label, query):
		wholeScore += 140
	case strings.Contains(id, query):
		wholeScore += 110
	}
	if strings.Contains(hint, query) {
		wholeScore += 45
	}
	if strings.Contains(group, query) {
		wholeScore += 35
	}
	if strings.Contains(action, query) {
		wholeScore += 30
	}

	tokens := strings.Fields(query)
	if len(tokens) == 0 {
		return wholeScore
	}

	total := wholeScore
	for _, token := range tokens {
		tokenScore := 0
		switch {
		case strings.HasPrefix(label, token):
			tokenScore += 100
		case strings.Contains(label, token):
			tokenScore += 60
		}
		switch {
		case strings.HasPrefix(id, token):
			tokenScore += 50
		case strings.Contains(id, token):
			tokenScore += 30
		}
		if strings.Contains(hint, token) {
			tokenScore += 18
		}
		if strings.Contains(group, token) {
			tokenScore += 14
		}
		if strings.Contains(action, token) {
			tokenScore += 10
		}
		if tokenScore == 0 {
			return 0
		}
		total += tokenScore
	}
	return total
}

func (m appShellModel) scanReviewContext(project domain.Project) (domain.ScanProfile, domain.RuntimeDoctor, bool, []string) {
	ctx := m.reviewContextValue(project)
	return ctx.profile, ctx.doctor, ctx.ready, append([]string(nil), ctx.blockers...)
}

func (m appShellModel) reviewContextValue(project domain.Project) reviewContextCacheEntry {
	if m.reviewContext.projectID == project.ID && m.reviewContext.review == m.review {
		return m.reviewContext
	}
	return m.buildReviewContext(project)
}

func (m appShellModel) buildReviewContext(project domain.Project) reviewContextCacheEntry {
	profile := m.resolvedReviewProfile(project)
	doctor := m.app.service.RuntimeDoctor(profile, m.review.StrictVersions, m.review.RequireIntegrity)
	blockers := make([]string, 0, 3)
	if m.review.ActiveValidation && strings.TrimSpace(m.review.DASTTarget) == "" {
		blockers = append(blockers, m.app.catalog.T("app_scan_review_requires_target"))
	}
	if !doctor.Ready {
		blockers = append(blockers, doctorSummaryLine(m.app, doctor))
	}
	includedModules := make(map[string]struct{}, len(profile.Modules))
	for _, module := range profile.Modules {
		includedModules[module] = struct{}{}
	}
	laneDescriptors := m.app.scanLaneDescriptorsForProject(project, profile.Modules, m.snapshot.Portfolio.Runs)
	current, next, deferred := m.reviewLaneFlow(laneDescriptors)
	return reviewContextCacheEntry{
		projectID:       project.ID,
		review:          m.review,
		profile:         profile,
		doctor:          doctor,
		ready:           len(blockers) == 0,
		blockers:        append([]string(nil), blockers...),
		includedModules: includedModules,
		laneDescriptors: append([]scanLaneDescriptor(nil), laneDescriptors...),
		flowCurrent:     current,
		flowNext:        next,
		flowDeferred:    deferred,
	}
}

func (m *appShellModel) refreshReviewContext() {
	project, ok := m.selectedProject()
	if !ok {
		m.reviewContext = reviewContextCacheEntry{}
		return
	}
	m.reviewContext = m.buildReviewContext(project)
}

func (m appShellModel) resolvedReviewProfile(project domain.Project) domain.ScanProfile {
	profile := domain.ScanProfile{
		Mode:         domain.ModeDeep,
		Isolation:    m.review.Isolation,
		Coverage:     domain.CoverageFull,
		SeverityGate: domain.SeverityHigh,
		AllowBuild:   false,
		AllowNetwork: false,
	}
	switch m.review.Preset {
	case reviewPresetQuickSafe:
		profile.Mode = domain.ModeSafe
		profile.Coverage = domain.CoveragePremium
	case reviewPresetCompliance:
		profile.PresetID = m.review.CompliancePreset
		profile = m.app.applyCompliancePreset(project, profile, false, false, false, false, true, true, false)
	default:
	}
	if m.review.ActiveValidation {
		profile.Mode = domain.ModeActive
		profile.AllowNetwork = true
		if strings.TrimSpace(m.review.DASTTarget) != "" {
			profile.DASTTargets = []domain.DastTarget{{
				Name:     "primary",
				URL:      strings.TrimSpace(m.review.DASTTarget),
				AuthType: "none",
			}}
		}
	}
	profile.Modules = m.app.resolveModulesForProject(project, profile)
	return profile
}

func (m appShellModel) scanReviewRows(project domain.Project, profile domain.ScanProfile, ready bool) selectableRows {
	rows := selectableRows{
		{Label: m.app.catalog.T("app_scan_review_project"), Hint: fmt.Sprintf("%s • %s", project.DisplayName, m.app.catalog.T("app_projects_enter_hint"))},
		{Label: m.app.catalog.T("app_scan_review_preset"), Hint: fmt.Sprintf("%s • %s", m.reviewPresetLabel(), m.app.catalog.T("app_scan_review_enter_hint"))},
		{Label: m.app.catalog.T("app_scan_review_compliance"), Hint: fmt.Sprintf("%s • %s", m.reviewComplianceLabel(), m.app.catalog.T("app_scan_review_enter_hint"))},
		{Label: m.app.catalog.T("app_scan_review_isolation"), Hint: fmt.Sprintf("%s • %s", strings.ToUpper(string(m.review.Isolation)), m.app.catalog.T("app_scan_review_enter_hint"))},
		{Label: m.app.catalog.T("app_scan_review_active_validation"), Hint: fmt.Sprintf("%s • %s", m.boolLabel(m.review.ActiveValidation), m.app.catalog.T("app_scan_review_enter_hint"))},
		{Label: m.app.catalog.T("app_scan_review_target"), Hint: fmt.Sprintf("%s • %s", coalesceString(m.review.DASTTarget, m.app.catalog.T("app_scan_review_target_empty")), m.app.catalog.T("app_scan_review_keys_hint"))},
		{Label: m.app.catalog.T("app_action_start_scan"), Hint: m.scanStartHint(profile, ready)},
	}
	return rows
}

func (m appShellModel) reviewFocusLines(width int, project domain.Project, profile domain.ScanProfile, doctor domain.RuntimeDoctor, ready bool, blockers []string) []string {
	switch m.cursor {
	case 0:
		return append(m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_project"), Value: project.DisplayName},
			factPair{Label: m.app.catalog.T("app_label_target"), Value: trimForSelect(project.LocationHint, 56)},
		), m.app.catalog.T("app_projects_enter_hint"))
	case 1:
		return m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_profile"), Value: m.reviewPresetLabel()},
			factPair{Label: m.app.catalog.T("app_label_mode"), Value: m.app.modeLabel(profile.Mode)},
			factPair{Label: m.app.catalog.T("app_label_coverage"), Value: m.app.coverageLabel(profile.Coverage)},
		)
	case 2:
		return append(m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_profile"), Value: m.reviewComplianceLabel()},
		), ternary(m.review.Preset == reviewPresetCompliance, m.app.catalog.T("app_scan_review_enter_hint"), m.app.catalog.T("app_scan_review_not_applicable")))
	case 3:
		return append(m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_isolation"), Value: strings.ToUpper(string(m.review.Isolation))},
			factPair{Label: m.app.catalog.T("app_label_mode"), Value: strings.ToUpper(string(profile.Isolation))},
		), m.app.catalog.T("app_scan_review_enter_hint"))
	case 4:
		return append(m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_mode"), Value: m.boolLabel(m.review.ActiveValidation)},
		), ternary(m.review.ActiveValidation, m.app.catalog.T("app_scan_review_requires_target"), m.app.catalog.T("app_scan_review_enter_hint")))
	case 5:
		return append(m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_target"), Value: coalesceString(m.review.DASTTarget, m.app.catalog.T("app_scan_review_target_empty"))},
		), m.app.catalog.T("app_scan_review_keys_hint"))
	default:
		lines := append(m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_health"), Value: ternary(ready, m.app.catalog.T("app_scan_review_ready"), m.app.catalog.T("app_scan_review_start_blocked"))},
			factPair{Label: m.app.catalog.T("app_label_profile"), Value: m.reviewPresetLabel()},
		), m.scanStartHint(profile, ready), doctorSummaryLine(m.app, doctor))
		if len(blockers) > 0 {
			lines = append(lines, blockers...)
		}
		return lines
	}
}

func (m appShellModel) reviewLaneSectionsForWidth(project domain.Project, profile domain.ScanProfile, limit int) []string {
	ctx := m.reviewContextValue(project)
	modules := ctx.includedModules
	if len(modules) == 0 {
		modules = make(map[string]struct{}, len(profile.Modules))
		for _, module := range profile.Modules {
			modules[module] = struct{}{}
		}
	}
	lanes := []struct {
		title   string
		modules []string
	}{
		{title: m.app.catalog.T("app_lane_surface"), modules: []string{"stack-detector", "surface-inventory", "script-audit", "runtime-config-audit"}},
		{title: m.app.catalog.T("app_lane_code"), modules: []string{"semgrep", "codeql", "gitleaks", "secret-heuristics"}},
		{title: m.app.catalog.T("app_lane_supply"), modules: []string{"trivy", "syft", "grype", "osv-scanner", "dependency-confusion", "licensee", "scancode", "govulncheck", "staticcheck", "knip", "vulture"}},
		{title: m.app.catalog.T("app_lane_infra"), modules: []string{"checkov", "tfsec", "kics", "trivy-image"}},
		{title: m.app.catalog.T("app_lane_malware"), modules: []string{"malware-signature", "clamscan", "yara-x", "binary-entropy"}},
		{title: m.app.catalog.T("app_lane_active"), modules: []string{"nuclei", "zaproxy"}},
	}
	lines := make([]string, 0, len(lanes))
	for _, lane := range lanes {
		parts := make([]string, 0, len(lane.modules))
		for _, module := range lane.modules {
			parts = append(parts, fmt.Sprintf("- %s • %s", module, m.reviewModuleState(project, profile, module, modules)))
		}
		lines = append(lines, lane.title)
		if limit > 0 && len(parts) > limit {
			parts = append(parts[:limit], fmt.Sprintf("- … %d %s", len(parts)-limit, strings.ToLower(m.app.catalog.T("scan_modules"))))
		}
		lines = append(lines, parts...)
	}
	return lines
}

func (m appShellModel) reviewModuleState(project domain.Project, profile domain.ScanProfile, module string, included map[string]struct{}) string {
	if module == "nuclei" || module == "zaproxy" {
		if !m.review.ActiveValidation || strings.TrimSpace(m.review.DASTTarget) == "" {
			return m.app.catalog.T("app_scan_review_requires_target_short")
		}
	}
	if _, ok := included[module]; ok {
		return m.app.catalog.T("app_scan_review_ready")
	}
	if !moduleApplicableForProject(project, module) {
		return m.app.catalog.T("app_scan_review_not_applicable")
	}
	if profile.Mode != domain.ModeActive && (module == "nuclei" || module == "zaproxy") {
		return m.app.catalog.T("app_scan_review_requires_target_short")
	}
	return m.app.catalog.T("app_scan_review_waiting")
}

func moduleApplicableForProject(project domain.Project, module string) bool {
	switch module {
	case "govulncheck", "staticcheck":
		return hasAnyStack(project.DetectedStacks, "go")
	case "knip":
		return hasAnyStack(project.DetectedStacks, "javascript", "typescript")
	case "vulture":
		return hasAnyStack(project.DetectedStacks, "python")
	case "tfsec", "kics":
		return hasAnyStack(project.DetectedStacks, "terraform", "iac", "helm", "kubernetes")
	case "trivy-image", "checkov":
		return hasAnyStack(project.DetectedStacks, "docker", "container", "kubernetes", "terraform", "iac", "helm")
	default:
		return true
	}
}

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

func (m appShellModel) reviewPresetLabel() string {
	switch m.review.Preset {
	case reviewPresetQuickSafe:
		return m.app.catalog.T("app_preset_quick_safe")
	case reviewPresetCompliance:
		return m.app.catalog.T("app_preset_compliance")
	default:
		return m.app.catalog.T("app_preset_full_deep")
	}
}

func (m appShellModel) reviewComplianceLabel() string {
	if m.review.Preset != reviewPresetCompliance {
		return "-"
	}
	return m.app.compliancePresetLabel(m.review.CompliancePreset)
}

func (m appShellModel) boolLabel(value bool) string {
	if value {
		return m.app.catalog.T("boolean_yes")
	}
	return m.app.catalog.T("boolean_no")
}

func (m appShellModel) scanStartHint(profile domain.ScanProfile, ready bool) string {
	if !ready {
		return m.app.catalog.T("app_scan_review_start_blocked")
	}
	return fmt.Sprintf("%s • %s • %d %s", m.reviewPresetLabel(), m.app.modeLabel(profile.Mode), len(profile.Modules), strings.ToLower(m.app.catalog.T("scan_modules")))
}

func (m appShellModel) runtimeSnapshotSummary() string {
	available, drift, missing, failed := runtimeToolHealthCounts(m.snapshot.Runtime)
	return fmt.Sprintf("%s %d • %s %d • %s %d • %s %d",
		m.app.catalog.T("runtime_available"), available,
		m.app.catalog.T("runtime_doctor_outdated"), drift,
		m.app.catalog.T("runtime_missing"), missing,
		m.app.catalog.T("runtime_failed_tools"), failed,
	)
}

func (m appShellModel) snapshotUpdatedClock() string {
	if m.snapshotUpdatedAt.IsZero() {
		return "-"
	}
	return m.snapshotUpdatedAt.Local().Format("15:04:05")
}

func (m appShellModel) metaSyncLabel() string {
	if m.snapshotUpdatedAt.IsZero() {
		return "-"
	}
	age := time.Since(m.snapshotUpdatedAt)
	switch {
	case age < 3*time.Second:
		return m.app.catalog.T("app_sync_live")
	case age < 30*time.Second:
		return m.app.catalog.T("app_sync_age_seconds", int(age.Round(time.Second)/time.Second))
	default:
		return m.snapshotUpdatedClock()
	}
}

func (m appShellModel) snapshotFreshnessHint() string {
	if m.snapshotUpdatedAt.IsZero() {
		return "-"
	}
	age := time.Since(m.snapshotUpdatedAt)
	switch {
	case age < 3*time.Second:
		return m.app.catalog.T("app_sync_live")
	case age < 30*time.Second:
		return m.app.catalog.T("app_sync_age_seconds", int(age.Round(time.Second)/time.Second))
	default:
		return m.snapshotUpdatedAt.Local().Format(time.RFC822)
	}
}

func (m appShellModel) refreshTargetRoute() appRoute {
	if m.refreshingRoute >= appRouteHome && m.refreshingRoute <= appRouteRuntime {
		return m.refreshingRoute
	}
	return m.route
}

func (m *appShellModel) invalidateCachesForRoutes(routes ...appRoute) {
	seen := make(map[appRoute]struct{}, len(routes))
	for _, route := range routes {
		if _, ok := seen[route]; ok {
			continue
		}
		seen[route] = struct{}{}
		m.invalidateCachesForRoute(route)
	}
}

func (m *appShellModel) invalidateCachesForRoute(route appRoute) {
	switch route {
	case appRouteHome, appRouteProjects, appRouteScanReview:
		m.projectTreeCache = make(map[string][]string)
		m.projectTreePending = ""
	case appRouteRuns:
		m.runDetailCache = make(map[string]runDetailCacheEntry)
		m.runDetailPendingID = ""
	case appRouteFindings:
		m.scopedFindingsMap = make(map[string][]domain.Finding)
	case appRouteRuntime:
		// Runtime uses live snapshot data directly; keep unrelated route caches warm.
	default:
		m.projectTreeCache = make(map[string][]string)
		m.projectTreePending = ""
		m.runDetailCache = make(map[string]runDetailCacheEntry)
		m.runDetailPendingID = ""
		m.scopedFindingsMap = make(map[string][]domain.Finding)
	}
}

func (m appShellModel) projectTrend(projectID string) string {
	runs := make([]domain.ScanRun, 0, len(m.snapshot.Portfolio.Runs))
	for _, run := range m.snapshot.Portfolio.Runs {
		if run.ProjectID == projectID {
			runs = append(runs, run)
		}
	}
	return m.app.runTrendLabel(runs, 6)
}

func (m appShellModel) projectTreePreview(project domain.Project, depth, limit int) []string {
	key := m.projectTreeCacheKey(project.ID)
	if lines, ok := m.projectTreeCache[key]; ok {
		return projectTreeSlice(lines, limit, m.app.catalog.T("scan_mode_tree_empty"))
	}
	if m.projectTreePending == project.ID {
		return []string{m.app.catalog.T("app_loading_short")}
	}
	return []string{m.app.catalog.T("app_loading_short")}
}

func (m appShellModel) reviewLaneSummary(project domain.Project, profile domain.ScanProfile) []string {
	ctx := m.reviewContextValue(project)
	modules := ctx.includedModules
	if len(modules) == 0 {
		modules = make(map[string]struct{}, len(profile.Modules))
		for _, module := range profile.Modules {
			modules[module] = struct{}{}
		}
	}
	current, next, deferred := ctx.flowCurrent, ctx.flowNext, ctx.flowDeferred
	lanes := []struct {
		title   string
		key     string
		modules []string
	}{
		{title: m.app.catalog.T("app_lane_surface"), key: "surface", modules: []string{"stack-detector", "surface-inventory", "script-audit", "runtime-config-audit"}},
		{title: m.app.catalog.T("app_lane_code"), key: "code", modules: []string{"semgrep", "codeql", "gitleaks", "secret-heuristics", "govulncheck", "staticcheck"}},
		{title: m.app.catalog.T("app_lane_supply"), key: "supply", modules: []string{"trivy", "syft", "grype", "osv-scanner", "dependency-confusion", "licensee", "scancode", "knip", "vulture"}},
		{title: m.app.catalog.T("app_lane_infra"), key: "infra", modules: []string{"checkov", "tfsec", "kics", "trivy-image"}},
		{title: m.app.catalog.T("app_lane_malware"), key: "malware", modules: []string{"malware-signature", "clamscan", "yara-x", "binary-entropy"}},
		{title: m.app.catalog.T("app_lane_active"), key: "active", modules: []string{"nuclei", "zaproxy"}},
	}
	lines := make([]string, 0, len(lanes)+4)
	lines = append(lines,
		fmt.Sprintf("%s: %s", m.app.catalog.T("app_label_current"), current),
		fmt.Sprintf("%s: %s", m.app.catalog.T("app_label_next"), next),
		fmt.Sprintf("%s: %s", m.app.catalog.T("app_label_deferred"), deferred),
		"",
	)
	for _, lane := range lanes {
		ready, na, target := 0, 0, 0
		for _, module := range lane.modules {
			switch m.reviewModuleState(project, profile, module, modules) {
			case m.app.catalog.T("app_scan_review_ready"):
				ready++
			case m.app.catalog.T("app_scan_review_not_applicable"):
				na++
			case m.app.catalog.T("app_scan_review_requires_target_short"):
				target++
			}
		}
		laneInfo := m.app.scanLaneDescriptor(lane.key)
		lines = append(lines, fmt.Sprintf("%s: %d %s • %d %s • %d %s • %s • %s",
			lane.title,
			ready, strings.ToLower(m.app.catalog.T("app_scan_review_ready")),
			na, strings.ToLower(m.app.catalog.T("app_scan_review_not_applicable")),
			target, strings.ToLower(m.app.catalog.T("app_scan_review_requires_target_short")),
			laneInfo.Kind,
			laneInfo.ETA,
		))
	}
	return lines
}

func (m appShellModel) reviewLaneFlow(lanes []scanLaneDescriptor) (string, string, string) {
	if len(lanes) == 0 {
		return "-", "-", "-"
	}
	current := m.app.formatLaneDescriptor(lanes[0], 48)
	next := "-"
	if len(lanes) > 1 {
		next = m.app.formatLaneDescriptor(lanes[1], 48)
	}
	deferred := "-"
	if len(lanes) > 2 {
		deferredTitles := make([]string, 0, len(lanes)-2)
		for _, lane := range lanes[2:] {
			deferredTitles = append(deferredTitles, lane.Title)
		}
		deferred = trimForSelect(strings.Join(deferredTitles, ", "), 42)
	}
	return current, next, deferred
}

func (m appShellModel) reviewPlanLines(width int, project domain.Project, profile domain.ScanProfile) []string {
	ctx := m.reviewContextValue(project)
	current, next, deferred := ctx.flowCurrent, ctx.flowNext, ctx.flowDeferred
	lines := m.renderFactLines(width,
		factPair{Label: m.app.catalog.T("app_label_target"), Value: trimForSelect(project.LocationHint, max(32, width-18))},
		factPair{Label: m.app.catalog.T("app_label_stacks"), Value: coalesceString(strings.Join(project.DetectedStacks, ", "), "-")},
		factPair{Label: m.app.catalog.T("app_label_profile"), Value: m.reviewPresetLabel()},
		factPair{Label: m.app.catalog.T("app_label_isolation"), Value: strings.ToUpper(string(profile.Isolation))},
		factPair{Label: m.app.catalog.T("app_label_current"), Value: current},
		factPair{Label: m.app.catalog.T("app_label_next"), Value: next},
	)
	if strings.TrimSpace(deferred) != "-" {
		lines = append(lines, m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_deferred"), Value: deferred},
		)...)
	}
	return lines
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

func (m appShellModel) selectedRun() (domain.ScanRun, bool) {
	if len(m.snapshot.Portfolio.Runs) == 0 || m.cursor < 0 || m.cursor >= len(m.snapshot.Portfolio.Runs) {
		return domain.ScanRun{}, false
	}
	return m.snapshot.Portfolio.Runs[m.cursor], true
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

func (m appShellModel) cancelSelectedRun() (tea.Model, tea.Cmd) {
	run, ok := m.selectedRun()
	if !ok {
		m.notice = m.app.catalog.T("no_runs")
		m.alert = true
		return m, nil
	}
	if run.Status != domain.ScanQueued && run.Status != domain.ScanRunning {
		m.notice = m.app.catalog.T("run_not_cancelable", string(run.Status))
		m.alert = true
		return m, nil
	}
	updated, err := m.app.service.CancelRun(run.ID)
	if err != nil {
		m.notice = err.Error()
		m.alert = true
		return m, nil
	}
	m.refreshShellSnapshot(appRouteRuns)
	m.focusRun(updated.ID)
	if updated.Status == domain.ScanCanceled {
		m.notice = m.app.catalog.T("run_canceled", updated.ID)
	} else {
		m.notice = m.app.catalog.T("run_cancel_requested", updated.ID)
	}
	m.alert = false
	return m, m.scheduleBackgroundLoads()
}

func (m appShellModel) exportSelectedRunReport() (tea.Model, tea.Cmd) {
	run, ok := m.selectedRun()
	if !ok {
		m.notice = m.app.catalog.T("no_runs")
		m.alert = true
		return m, nil
	}
	reportPath, err := m.app.writeRunExport(run.ID, "html", "", "")
	if err != nil {
		m.notice = err.Error()
		m.alert = true
		return m, nil
	}
	m.notice = m.app.catalog.T("report_saved", reportPath)
	m.alert = false
	return m, nil
}

func (m appShellModel) retrySelectedRun() (tea.Model, tea.Cmd) {
	run, ok := m.selectedRun()
	if !ok {
		m.notice = m.app.catalog.T("no_runs")
		m.alert = true
		return m, nil
	}
	if run.Status != domain.ScanFailed && run.Status != domain.ScanCanceled {
		m.notice = m.app.catalog.T("run_not_retryable", string(run.Status))
		m.alert = true
		return m, nil
	}
	retryRun, err := m.app.service.RetryFailedRun(run.ID)
	if err != nil {
		m.notice = err.Error()
		m.alert = true
		return m, nil
	}
	m.refreshShellSnapshot(appRouteRuns)
	m.focusRun(retryRun.ID)
	m.notice = m.app.catalog.T("run_retry_enqueued", run.ID, retryRun.ID)
	m.alert = false
	return m, m.scheduleBackgroundLoads()
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

func (m appShellModel) runRows() selectableRows {
	rows := make(selectableRows, 0, len(m.snapshot.Portfolio.Runs))
	for _, run := range m.snapshot.Portfolio.Runs {
		rows = append(rows, appSelectableRow{
			Label: fmt.Sprintf("%s • %s", strings.ToUpper(string(run.Status)), m.app.projectLabel(run.ProjectID)),
			Hint:  fmt.Sprintf("%s • %d %s", strings.ToUpper(m.app.modeLabel(run.Profile.Mode)), run.Summary.TotalFindings, strings.ToLower(m.app.catalog.T("scan_findings"))),
			Value: run.ID,
		})
	}
	return rows
}

func (m appShellModel) findingRows(findings []domain.Finding) selectableRows {
	rows := make(selectableRows, 0, len(findings))
	for _, finding := range findings {
		rows = append(rows, appSelectableRow{
			Label: fmt.Sprintf("%s • %s", strings.ToUpper(m.app.severityLabel(finding.Severity)), trimForSelect(m.app.displayFindingTitle(finding), 34)),
			Hint:  fmt.Sprintf("%s • %s", m.app.findingStatusLabel(m.normalizedFindingStatus(finding.Status)), trimForSelect(coalesceString(finding.Location, "-"), 44)),
			Value: finding.Fingerprint,
		})
	}
	return rows
}

func (m appShellModel) runtimeRows() selectableRows {
	rows := make(selectableRows, 0, len(m.snapshot.Runtime.ScannerBundle))
	for _, tool := range m.snapshot.Runtime.ScannerBundle {
		status := m.app.catalog.T("runtime_missing")
		if tool.Available {
			status = m.app.catalog.T("runtime_available")
		}
		rows = append(rows, appSelectableRow{
			Label: fmt.Sprintf("%s • %s", tool.Name, strings.ToUpper(status)),
			Hint:  fmt.Sprintf("%s • %s", strings.ToUpper(tool.Channel), coalesceString(tool.ActualVersion, tool.ExpectedVersion)),
			Value: tool.Name,
		})
	}
	return rows
}

func (m appShellModel) currentFindingsSeverityFilter() string {
	if m.findingsSeverityIdx < 0 || m.findingsSeverityIdx >= len(runFindingSeverityFilters) {
		return "all"
	}
	return runFindingSeverityFilters[m.findingsSeverityIdx]
}

func (m appShellModel) currentFindingsSeverityFilterLabel() string {
	filter := m.currentFindingsSeverityFilter()
	if filter == "all" {
		return m.app.catalog.T("artifact_filter_all")
	}
	return m.app.severityLabel(domain.Severity(filter))
}

func (m appShellModel) currentFindingsStatusFilter() string {
	if m.findingsStatusIdx < 0 || m.findingsStatusIdx >= len(runFindingStatusFilters) {
		return "all"
	}
	return runFindingStatusFilters[m.findingsStatusIdx]
}

func (m appShellModel) currentFindingsStatusFilterLabel() string {
	filter := m.currentFindingsStatusFilter()
	if filter == "all" {
		return m.app.catalog.T("artifact_filter_all")
	}
	return m.app.findingStatusLabel(domain.FindingStatus(filter))
}

func (m appShellModel) renderRunQueueSummary() string {
	counts := m.app.countRunStatuses(m.snapshot.Portfolio.Runs)
	return fmt.Sprintf("%s: %d • %s: %d • %s: %d",
		m.app.catalog.T("status_queued"), counts.Queued,
		m.app.catalog.T("status_running"), counts.Running,
		m.app.catalog.T("status_canceled"), counts.Canceled,
	)
}

func (m appShellModel) renderFindingPressureSummary(findings []domain.Finding) string {
	counts := severityCounts(findings)
	return fmt.Sprintf("%s: %d • %s: %d • %s: %d • %s: %d",
		m.app.catalog.T("summary_critical"), counts[domain.SeverityCritical],
		m.app.catalog.T("summary_high"), counts[domain.SeverityHigh],
		m.app.catalog.T("summary_medium"), counts[domain.SeverityMedium],
		m.app.catalog.T("summary_low"), counts[domain.SeverityLow],
	)
}

func (m appShellModel) filterFindings(findings []domain.Finding) []domain.Finding {
	severityFilter := m.currentFindingsSeverityFilter()
	statusFilter := m.currentFindingsStatusFilter()
	if severityFilter == "all" && statusFilter == "all" {
		return findings
	}
	filtered := make([]domain.Finding, 0, len(findings))
	for _, finding := range findings {
		if severityFilter != "all" && finding.Severity != domain.Severity(severityFilter) {
			continue
		}
		if statusFilter != "all" && m.normalizedFindingStatus(finding.Status) != domain.FindingStatus(statusFilter) {
			continue
		}
		filtered = append(filtered, finding)
	}
	return filtered
}

func (m appShellModel) renderRunDetailContent(width int) string {
	run, ok := m.selectedRun()
	if !ok {
		return m.app.catalog.T("no_runs")
	}
	cacheKey := run.ID
	findings, _ := m.snapshotFindingsForRun(run.ID)
	entry, ok := m.runDetailCache[cacheKey]
	projectName := m.app.projectLabel(run.ProjectID)
	lines := []string{
		m.renderSection(m.app.catalog.T("overview_operator_focus"),
			m.renderFactLines(width,
				factPair{Label: m.app.catalog.T("app_label_project"), Value: projectName},
				factPair{Label: m.app.catalog.T("app_label_health"), Value: m.app.scanPostureSummary(run)},
				factPair{Label: m.app.catalog.T("app_label_findings"), Value: fmt.Sprintf("%d", run.Summary.TotalFindings)},
				factPair{Label: m.app.catalog.T("app_label_baseline"), Value: coalesceString(entry.baselineLabel, m.app.catalog.T("app_loading_short"))},
				factPair{Label: m.app.catalog.T("app_label_blocked"), Value: ternary(run.Summary.Blocked, m.app.catalog.T("boolean_yes"), m.app.catalog.T("boolean_no"))},
				factPair{Label: m.app.catalog.T("app_label_scope"), Value: trimForSelect(run.ID, maxInt(24, width-18))},
			)...,
		),
	}
	if total := len(findings); total > 0 {
		lines = append(lines, m.renderSection(m.app.catalog.T("overview_hot_findings"), strings.Split(m.renderFindingDigest(findings, min(3, total)), "\n")...))
	}
	if !ok {
		lines = append(lines, m.renderSection(m.app.catalog.T("app_loading_title"), m.app.catalog.T("app_loading_short")))
		return strings.Join(lines, "\n\n")
	}
	if entry.err != "" {
		lines = append(lines, m.renderSection(m.app.catalog.T("status"), entry.err))
		return strings.Join(lines, "\n\n")
	}
	if len(entry.traceLines) > 0 {
		lines = append(lines, m.renderSection(m.app.catalog.T("execution_timeline_title"), entry.traceLines...))
	} else {
		lines = append(lines, m.renderSection(m.app.catalog.T("module_execution_title"), m.renderLiveRunDigest(run)))
	}
	return strings.Join(lines, "\n\n")
}

func (m appShellModel) renderFindingDetailContent(width int) string {
	finding, ok := m.selectedFinding()
	if !ok {
		return m.app.catalog.T("overview_no_findings")
	}
	lines := []string{
		m.renderSection(m.app.displayFindingTitle(finding),
			m.renderFactLines(width,
				factPair{Label: m.app.catalog.T("app_label_severity"), Value: strings.ToUpper(m.app.severityLabel(finding.Severity))},
				factPair{Label: m.app.catalog.T("app_label_health"), Value: m.app.findingStatusLabel(m.normalizedFindingStatus(finding.Status))},
				factPair{Label: m.app.catalog.T("app_label_location"), Value: coalesceString(finding.Location, "-")},
				factPair{Label: m.app.catalog.T("app_label_module"), Value: finding.Module},
				factPair{Label: m.app.catalog.T("app_label_scope"), Value: finding.Fingerprint},
			)...,
		),
		m.renderSection(m.app.catalog.T("finding_exposure_title"),
			append(m.renderFactLines(width,
				factPair{Label: m.app.catalog.T("app_label_baseline"), Value: m.app.findingExposureSummary(finding)},
				factPair{Label: m.app.catalog.T("confidence"), Value: fmt.Sprintf("%.2f", finding.Confidence)},
			), coalesceString(strings.Join(finding.Compliance, ", "), "-"))...,
		),
		m.renderSection(m.app.catalog.T("remediation"), coalesceString(finding.Remediation, "-")),
		m.renderSection(m.app.catalog.T("finding_operator_context_title"), m.app.findingOwnershipSummary(finding)),
	}
	if strings.TrimSpace(m.findingsScopeRun) != "" {
		lines = append(lines, m.renderSection(m.app.catalog.T("app_findings_scope_title"), m.findingsScopeLabel()))
	}
	return strings.Join(lines, "\n\n")
}

func (m appShellModel) renderRuntimeDetailContent(width int) string {
	tool, ok := m.selectedRuntimeTool()
	if !ok {
		return strings.Join(m.routeEmptyStateLines(appRouteRuntime), "\n")
	}
	available, drift, missing, failed := runtimeToolHealthCounts(m.snapshot.Runtime)
	lines := []string{
		m.renderSection(tool.Name,
			m.renderFactLines(width,
				factPair{Label: m.app.catalog.T("app_label_health"), Value: ternary(tool.Available, m.app.catalog.T("runtime_available"), m.app.catalog.T("runtime_missing"))},
				factPair{Label: m.app.catalog.T("app_label_channel"), Value: strings.ToUpper(tool.Channel)},
				factPair{Label: m.app.catalog.T("app_label_expected"), Value: coalesceString(tool.ExpectedVersion, "-")},
				factPair{Label: m.app.catalog.T("app_label_actual"), Value: coalesceString(tool.ActualVersion, "-")},
				factPair{Label: m.app.catalog.T("app_label_binary"), Value: coalesceString(tool.Path, "-")},
				factPair{Label: m.app.catalog.T("app_label_verify"), Value: strings.ToUpper(tool.Verification.Status())},
			)...,
		),
		m.renderSection(m.app.catalog.T("runtime_trust_signal_title"),
			append(m.renderFactLines(width,
				factPair{Label: m.app.catalog.T("app_label_health"), Value: m.runtimeFocusMessage()},
				factPair{Label: m.app.catalog.T("app_label_sync"), Value: fmt.Sprintf("%d/%d/%d/%d", available, drift, missing, failed)},
				factPair{Label: m.app.catalog.T("app_label_daemon"), Value: m.app.daemonStateLabel(m.snapshot.Runtime.Daemon)},
				factPair{Label: m.app.catalog.T("app_label_isolation"), Value: strings.ToUpper(string(m.snapshot.Runtime.Isolation.EffectiveMode))},
			), fmt.Sprintf("%d %s • %d %s",
				m.snapshot.Runtime.SupplyChain.VerifiedAssets, strings.ToLower(m.app.catalog.T("runtime_verified_assets")),
				m.snapshot.Runtime.SupplyChain.FailedAssets, strings.ToLower(m.app.catalog.T("runtime_failed_assets")),
			))...,
		),
		m.renderSection(m.app.catalog.T("runtime_supply_chain_title"), m.runtimeSupplyChainDigest()),
	}
	return strings.Join(lines, "\n\n")
}

func (m appShellModel) normalizedFindingStatus(status domain.FindingStatus) domain.FindingStatus {
	if strings.TrimSpace(string(status)) == "" {
		return domain.FindingOpen
	}
	return status
}

func (m appShellModel) runtimeFocusMessage() string {
	available, drift, missing, failed := runtimeToolHealthCounts(m.snapshot.Runtime)
	mirrorAvailable, mirrorMissing := runtimeMirrorHealth(m.snapshot.Runtime)
	switch {
	case missing > 0 || failed > 0 || drift > 0:
		return m.app.catalog.T("runtime_focus_repair")
	case mirrorMissing > 0 && mirrorAvailable == 0:
		return m.app.catalog.T("runtime_focus_mirror")
	case available == 0:
		return m.app.catalog.T("runtime_focus_repair")
	default:
		return m.app.catalog.T("runtime_focus_ready")
	}
}

func (m appShellModel) renderRuntimeRefreshPanel(width int) string {
	if !m.refreshing || m.refreshTargetRoute() != appRouteRuntime || !m.manualRefresh {
		return ""
	}
	return m.renderPanelCard(width, m.app.catalog.T("app_refreshing"),
		append(m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_sync"), Value: m.snapshotFreshnessHint()},
			factPair{Label: m.app.catalog.T("app_label_health"), Value: m.runtimeSnapshotSummary()},
		), m.app.catalog.T("runtime_command_title"))...,
	)
}

func (m appShellModel) projectFocusLines(width int) []string {
	row, ok := m.projectRows().at(m.cursor)
	if !ok {
		return append(m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_project"), Value: m.currentProjectLabel()},
		), m.app.catalog.T("app_projects_enter_hint"))
	}
	switch row.Action {
	case appShellActionSelectCurrent:
		return []string{
			m.app.catalog.T("app_action_select_current"),
			m.app.catalog.T("app_action_select_current_hint"),
			m.app.catalog.T("app_projects_enter_hint"),
		}
	case appShellActionPickFolder:
		return []string{
			m.app.catalog.T("app_action_pick_folder"),
			m.app.catalog.T("app_action_pick_folder_hint"),
			m.app.catalog.T("app_projects_enter_hint"),
		}
	default:
		project, ok := m.selectedProject()
		if !ok {
			return append(m.renderFactLines(width,
				factPair{Label: m.app.catalog.T("app_label_project"), Value: m.currentProjectLabel()},
			), m.app.catalog.T("app_projects_enter_hint"))
		}
		lines := m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_project"), Value: project.DisplayName},
			factPair{Label: m.app.catalog.T("app_label_target"), Value: trimForSelect(project.LocationHint, 56)},
			factPair{Label: m.app.catalog.T("app_label_trend"), Value: m.projectTrend(project.ID)},
		)
		return append(lines, m.app.catalog.T("app_projects_pick_hint"))
	}
}

func (m appShellModel) projectPreviewLines(width int) []string {
	row, ok := m.projectRows().at(m.cursor)
	if !ok {
		return []string{m.app.catalog.T("projects_focus_empty")}
	}
	switch row.Action {
	case appShellActionSelectCurrent:
		return []string{
			m.app.catalog.T("app_action_select_current"),
			m.app.catalog.T("app_action_select_current_hint"),
		}
	case appShellActionPickFolder:
		return []string{
			m.app.catalog.T("app_action_pick_folder"),
			m.app.catalog.T("app_action_pick_folder_hint"),
		}
	default:
		project, ok := m.selectedProject()
		if !ok {
			return []string{m.app.catalog.T("projects_focus_empty")}
		}
		return m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_project"), Value: project.DisplayName},
			factPair{Label: m.app.catalog.T("app_label_target"), Value: trimForSelect(project.LocationHint, 64)},
			factPair{Label: m.app.catalog.T("app_label_stacks"), Value: coalesceString(strings.Join(project.DetectedStacks, ", "), "-")},
		)
	}
}

func (m appShellModel) reviewPreviewLines(width int, project domain.Project, profile domain.ScanProfile, doctor domain.RuntimeDoctor, ready bool, blockers []string) []string {
	switch m.cursor {
	case 0:
		return m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_project"), Value: project.DisplayName},
			factPair{Label: m.app.catalog.T("app_label_target"), Value: trimForSelect(project.LocationHint, 64)},
			factPair{Label: m.app.catalog.T("app_label_stacks"), Value: coalesceString(strings.Join(project.DetectedStacks, ", "), "-")},
		)
	case 1:
		return m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_profile"), Value: m.reviewPresetLabel()},
			factPair{Label: m.app.catalog.T("app_label_mode"), Value: m.app.modeLabel(profile.Mode)},
			factPair{Label: m.app.catalog.T("app_label_coverage"), Value: m.app.coverageLabel(profile.Coverage)},
		)
	case 2:
		return append(m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_profile"), Value: m.reviewComplianceLabel()},
		), ternary(m.review.Preset == reviewPresetCompliance, m.app.catalog.T("app_scan_review_enter_hint"), m.app.catalog.T("app_scan_review_not_applicable")))
	case 3:
		return m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_isolation"), Value: strings.ToUpper(string(m.review.Isolation))},
			factPair{Label: m.app.catalog.T("app_label_mode"), Value: strings.ToUpper(string(profile.Isolation))},
		)
	case 4:
		return m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_mode"), Value: m.boolLabel(m.review.ActiveValidation)},
			factPair{Label: m.app.catalog.T("app_label_target"), Value: coalesceString(m.review.DASTTarget, m.app.catalog.T("app_scan_review_target_empty"))},
		)
	case 5:
		return append(m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_target"), Value: coalesceString(m.review.DASTTarget, m.app.catalog.T("app_scan_review_target_empty"))},
		), m.app.catalog.T("app_scan_review_keys_hint"))
	default:
		lines := m.renderFactLines(width,
			factPair{Label: m.app.catalog.T("app_label_health"), Value: ternary(ready, m.app.catalog.T("app_scan_review_ready"), m.app.catalog.T("app_scan_review_start_blocked"))},
			factPair{Label: m.app.catalog.T("app_label_profile"), Value: m.reviewPresetLabel()},
		)
		lines = append(lines, doctorSummaryLine(m.app, doctor))
		if len(blockers) > 0 {
			lines = append(lines, blockers[0])
		}
		return lines
	}
}

func (m appShellModel) runtimeFocusLines(width int) []string {
	tool, ok := m.selectedRuntimeTool()
	if !ok {
		return []string{m.runtimeFocusMessage(), m.runtimeSnapshotSummary()}
	}
	status := m.app.catalog.T("runtime_missing")
	if tool.Available {
		status = m.app.catalog.T("runtime_available")
	}
	return append(m.renderFactLines(width,
		factPair{Label: m.app.catalog.T("app_label_tools"), Value: tool.Name},
		factPair{Label: m.app.catalog.T("app_label_health"), Value: status},
		factPair{Label: m.app.catalog.T("app_label_actual"), Value: coalesceString(tool.ActualVersion, tool.ExpectedVersion)},
	), m.runtimeFocusMessage())
}

func (m appShellModel) runPreviewLines(width int) []string {
	run, ok := m.selectedRun()
	if !ok {
		return []string{m.app.catalog.T("runs_focus_empty")}
	}
	return m.renderFactLines(width,
		factPair{Label: m.app.catalog.T("app_label_project"), Value: m.app.projectLabel(run.ProjectID)},
		factPair{Label: m.app.catalog.T("app_label_health"), Value: strings.ToUpper(string(run.Status))},
		factPair{Label: m.app.catalog.T("app_label_findings"), Value: fmt.Sprintf("%d", run.Summary.TotalFindings)},
		factPair{Label: m.app.catalog.T("app_label_scope"), Value: trimForSelect(run.ID, maxInt(24, width-18))},
	)
}

func (m appShellModel) runBriefSummary() string {
	run, ok := m.selectedRun()
	if !ok {
		return m.app.catalog.T("runs_focus_empty")
	}
	return trimForSelect(fmt.Sprintf("%s • %s • %d %s",
		strings.ToUpper(string(run.Status)),
		m.app.projectLabel(run.ProjectID),
		run.Summary.TotalFindings,
		m.app.catalog.T("app_label_findings"),
	), 72)
}

func (m appShellModel) findingPreviewLines(width int) []string {
	finding, ok := m.selectedFinding()
	if !ok {
		return []string{m.app.catalog.T("findings_focus_clean")}
	}
	return m.renderFactLines(width,
		factPair{Label: m.app.catalog.T("app_label_severity"), Value: strings.ToUpper(m.app.severityLabel(finding.Severity))},
		factPair{Label: m.app.catalog.T("app_label_health"), Value: m.app.findingStatusLabel(m.normalizedFindingStatus(finding.Status))},
		factPair{Label: m.app.catalog.T("app_label_module"), Value: finding.Module},
		factPair{Label: m.app.catalog.T("app_label_location"), Value: coalesceString(finding.Location, "-")},
		factPair{Label: m.app.catalog.T("show_title"), Value: trimForSelect(m.app.displayFindingTitle(finding), maxInt(24, width-18))},
	)
}

func (m appShellModel) findingBriefSummary() string {
	finding, ok := m.selectedFinding()
	if !ok {
		return m.app.catalog.T("findings_focus_clean")
	}
	parts := []string{
		strings.ToUpper(m.app.severityLabel(finding.Severity)),
		m.app.findingStatusLabel(m.normalizedFindingStatus(finding.Status)),
		coalesceString(finding.Module, "-"),
	}
	return trimForSelect(strings.Join(parts, " • "), 72)
}

func (m appShellModel) runtimePreviewLines(width int) []string {
	tool, ok := m.selectedRuntimeTool()
	if !ok {
		return []string{m.runtimeFocusMessage()}
	}
	status := m.app.catalog.T("runtime_missing")
	if tool.Available {
		status = m.app.catalog.T("runtime_available")
	}
	return m.renderFactLines(width,
		factPair{Label: m.app.catalog.T("app_label_tools"), Value: fmt.Sprintf("%s • %s", tool.Name, strings.ToUpper(status))},
		factPair{Label: m.app.catalog.T("app_label_channel"), Value: strings.ToUpper(tool.Channel)},
		factPair{Label: m.app.catalog.T("app_label_actual"), Value: coalesceString(tool.ActualVersion, tool.ExpectedVersion)},
		factPair{Label: m.app.catalog.T("app_label_verify"), Value: strings.ToUpper(tool.Verification.Status())},
	)
}

func (m appShellModel) runFocusLines(width int) []string {
	run, ok := m.selectedRun()
	if !ok {
		return []string{m.app.catalog.T("no_runs")}
	}
	lines := []string{
		m.app.scanPostureSummary(run),
		trimForSelect(run.ID, maxInt(24, width-6)),
	}
	if run.Summary.TotalFindings > 0 {
		lines = append(lines, m.app.catalog.T("app_action_open_run_findings_hint"))
	} else {
		lines = append(lines, m.app.catalog.T("app_live_scan_next_runs"))
	}
	return lines
}

func (m appShellModel) findingFocusLines(width int) []string {
	finding, ok := m.selectedFinding()
	if !ok {
		return []string{m.app.catalog.T("overview_no_findings")}
	}
	lines := []string{
		trimForSelect(m.app.displayFindingTitle(finding), maxInt(24, width-6)),
		coalesceString(finding.Location, "-"),
	}
	if strings.TrimSpace(m.findingsScopeRun) == "" {
		lines = append(lines, m.app.catalog.T("app_action_open_run_findings_hint"))
	} else {
		lines = append(lines, m.app.catalog.T("app_action_clear_findings_scope_hint"))
	}
	return lines
}

func (m appShellModel) runtimeSupplyChainDigest() string {
	rows := m.app.supplyChainRows(m.snapshot.Runtime.SupplyChain)
	if len(rows) == 0 {
		return "-"
	}
	lines := make([]string, 0, min(4, len(rows)))
	for _, row := range rows[:min(4, len(rows))] {
		lines = append(lines, fmt.Sprintf("%s: %s", row[0], row[1]))
	}
	return strings.Join(lines, "\n")
}

func (m appShellModel) snapshotRun(runID string) (domain.ScanRun, bool) {
	for _, run := range m.snapshot.Portfolio.Runs {
		if run.ID == runID {
			return run, true
		}
	}
	return domain.ScanRun{}, false
}

func (m appShellModel) snapshotProject(projectID string) (domain.Project, bool) {
	for _, project := range m.snapshot.Portfolio.Projects {
		if project.ID == projectID {
			return project, true
		}
	}
	return domain.Project{}, false
}

func (m appShellModel) projectTreeCacheKey(projectID string) string {
	return "project-tree:" + strings.TrimSpace(projectID)
}

func projectTreeSlice(lines []string, limit int, empty string) []string {
	if len(lines) == 0 {
		return []string{empty}
	}
	if limit <= 0 || limit >= len(lines) {
		return append([]string(nil), lines...)
	}
	return append([]string(nil), lines[:limit]...)
}

func (m appShellModel) snapshotFindingsForRun(runID string) ([]domain.Finding, bool) {
	if strings.TrimSpace(runID) == "" {
		return nil, false
	}
	_, hasRun := m.snapshotRun(runID)
	findings := make([]domain.Finding, 0)
	for _, finding := range m.snapshot.Portfolio.Findings {
		if finding.ScanID == runID {
			findings = append(findings, finding)
		}
	}
	return findings, hasRun
}

func (m appShellModel) scopedFindings() []domain.Finding {
	if strings.TrimSpace(m.findingsScopeRun) == "" {
		return m.snapshot.Portfolio.Findings
	}
	if findings, ok := m.scopedFindingsMap[m.findingsScopeRun]; ok {
		return findings
	}
	findings, ok := m.snapshotFindingsForRun(m.findingsScopeRun)
	if !ok {
		findings = nil
	}
	m.scopedFindingsMap[m.findingsScopeRun] = findings
	return findings
}

func (m appShellModel) filteredScopedFindings() []domain.Finding {
	return m.filterFindings(m.scopedFindings())
}

func (m appShellModel) findingsScopeLabel() string {
	if strings.TrimSpace(m.findingsScopeRun) == "" {
		return m.app.catalog.T("app_findings_scope_all")
	}
	if run, ok := m.snapshotRun(m.findingsScopeRun); ok {
		return m.app.catalog.T("app_findings_scope_run", m.app.projectLabel(run.ProjectID))
	}
	return m.app.catalog.T("app_findings_scope_run", trimForSelect(m.findingsScopeRun, 20))
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
		delta, _, baseline, err := app.service.GetRunDelta(runID, "")
		if err != nil {
			entry.err = err.Error()
			return appShellRunDetailLoadedMsg{
				runID: runID,
				entry: entry,
				seq:   seq,
			}
		}
		entry.delta = delta
		entry.baselineLabel = app.catalog.T("diff_no_baseline")
		if baseline != nil {
			entry.baselineLabel = baseline.ID
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

func resolveProjectSelectionCmd(app *App, ctx context.Context, action appShellAction) tea.Cmd {
	baseCtx := commandContext(ctx)
	return func() tea.Msg {
		var (
			project domain.Project
			existed bool
			err     error
		)
		switch action {
		case appShellActionSelectCurrent:
			cwd, cwdErr := os.Getwd()
			if cwdErr != nil {
				err = cwdErr
				break
			}
			project, existed, err = app.service.EnsureProject(baseCtx, cwd, filepath.Base(cwd), false)
		case appShellActionPickFolder:
			project, existed, err = app.service.EnsureProject(baseCtx, "", "", true)
		default:
			err = fmt.Errorf("unsupported project resolution action: %s", action)
		}
		return appShellProjectResolvedMsg{
			project: project,
			existed: existed,
			err:     err,
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
