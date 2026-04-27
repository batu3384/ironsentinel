package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
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

var runTeaProgram = func(model tea.Model, opts ...tea.ProgramOption) (tea.Model, error) {
	return tea.NewProgram(model, opts...).Run()
}

type appShellLaunchState struct {
	Route              appRoute
	SelectedProjectID  string
	FindingsScopeRun   string
	Review             scanReviewState
	ReviewDASTTargets  []domain.DastTarget
	ReviewAuthProfiles []domain.DastAuthProfile
	Notice             string
	Alert              bool
	LastScan           *scanMissionOutcome
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
	findingsCategoryIdx int
	selectedProjectID   string
	findingsScopeRun    string
	review              scanReviewState
	reviewDASTTargets   []domain.DastTarget
	reviewAuthProfiles  []domain.DastAuthProfile
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

// appShellModel is retained as the legacy route-first compatibility surface.

type runDetailCacheEntry struct {
	delta         domain.RunDelta
	baselineLabel string
	traceLines    []string
	err           string
}

type reviewContextCacheEntry struct {
	projectID       string
	snapshotStamp   time.Time
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
	selected = preferredProjectID(snapshot.Portfolio.Projects, selected)
	width, height := initialTerminalViewport()
	model := appShellModel{
		app:                app,
		baseCtx:            baseCtx,
		width:              width,
		height:             height,
		snapshot:           snapshot,
		snapshotUpdatedAt:  time.Now(),
		route:              route,
		selectedProjectID:  selected,
		findingsScopeRun:   strings.TrimSpace(state.FindingsScopeRun),
		review:             state.Review,
		reviewDASTTargets:  append([]domain.DastTarget(nil), state.ReviewDASTTargets...),
		reviewAuthProfiles: append([]domain.DastAuthProfile(nil), state.ReviewAuthProfiles...),
		notice:             strings.TrimSpace(state.Notice),
		alert:              state.Alert,
		paletteInput:       palette,
		targetInput:        targetInput,
		lastScan:           state.LastScan,
		projectTreeCache:   make(map[string][]string),
		runDetailCache:     make(map[string]runDetailCacheEntry),
		scopedFindingsMap:  make(map[string][]domain.Finding),
		routeState:         make(map[appRoute]routeViewState),
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

func (a *App) primaryTUIModelName() string {
	return "console_shell"
}

func (a *App) launchPrimaryTUI(ctx context.Context) error {
	baseCtx, cancel := context.WithCancel(commandContext(ctx))
	defer cancel()
	finalModel, err := runTeaProgram(newConsoleShellModel(a, consoleShellLaunchState{}, baseCtx), tea.WithAltScreen())
	if err != nil {
		return err
	}
	if _, ok := finalModel.(consoleShellModel); !ok {
		return fmt.Errorf("unexpected console shell model type")
	}
	return nil
}

func (a *App) launchTUI(ctx context.Context) error {
	return a.launchPrimaryTUI(ctx)
}

// launchTUIWithState boots the legacy route-first shell for explicit compatibility flows.
func (a *App) launchTUIWithState(ctx context.Context, state appShellLaunchState) error {
	baseCtx, cancel := context.WithCancel(commandContext(ctx))
	defer cancel()
	current := state
	for {
		finalModel, err := runTeaProgram(newAppShellModel(a, current, baseCtx), tea.WithAltScreen())
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
				current = model.nextLegacyLaunchState()
				current.Route = appRouteHome
				current.Notice = err.Error()
				current.Alert = true
				continue
			}
			current = model.nextLegacyLaunchState()
			current.Route = appRouteScanReview
			current.SelectedProjectID = project.ID
			current.Notice = a.catalog.T("project_registered", project.DisplayName)
			current.Alert = false
		case appShellActionPickFolder:
			project, _, err := a.ensureProjectWithNotice(baseCtx, "", "", true, false)
			if err != nil {
				current = model.nextLegacyLaunchState()
				current.Route = appRouteHome
				current.Notice = err.Error()
				current.Alert = true
				continue
			}
			current = model.nextLegacyLaunchState()
			current.Route = appRouteScanReview
			current.SelectedProjectID = project.ID
			current.Notice = a.catalog.T("project_registered", project.DisplayName)
			current.Alert = false
		default:
			current = model.nextLegacyLaunchState()
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
		return m.handleRefreshMsg()
	case appShellSnapshotLoadedMsg:
		return m.handleSnapshotLoadedMsg(msg)
	case appShellProjectResolvedMsg:
		return m.handleProjectResolvedMsg(msg)
	case appShellFrameTickMsg:
		return m.handleFrameTickMsg()
	case scanMissionEventMsg:
		return m.handleScanMissionEventMsg(msg)
	case scanMissionDoneMsg:
		return m.handleScanMissionDoneMsg(msg)
	case appShellRunDetailLoadedMsg:
		return m.handleRunDetailLoadedMsg(msg)
	case appShellProjectTreeLoadedMsg:
		return m.handleProjectTreeLoadedMsg(msg)
	case tea.KeyMsg:
		return m.handleKeyMsg(msg)
	}
	return m, nil
}
