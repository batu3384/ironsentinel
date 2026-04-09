package cli

import (
	"context"
	"strings"
	"time"

	"github.com/batu3384/ironsentinel/internal/domain"
)

type consoleStage int

const (
	consoleStageLaunch consoleStage = iota
	consoleStageMission
	consoleStageDebrief
)

type consoleDrawer int

const (
	consoleDrawerNone consoleDrawer = iota
	consoleDrawerFindings
	consoleDrawerRuntime
	consoleDrawerRun
)

type consoleShellLaunchState struct {
	SelectedProjectID string
	Notice            string
	Alert             bool
}

type consoleShellMissionSession struct {
	cancel  context.CancelFunc
	eventCh <-chan domain.StreamEvent
	doneCh  <-chan scanMissionDoneMsg
}

type consoleShellMissionState struct {
	project     domain.Project
	profile     domain.ScanProfile
	doctor      domain.RuntimeDoctor
	launchedAt  time.Time
	cpuBaseline float64
	console     *liveScanConsole
	run         domain.ScanRun
	findings    []domain.Finding
	scanErr     error
	requiredErr error
	notice      string
	alert       bool
	running     bool
	done        bool
	aborting    bool
	cancel      context.CancelFunc
	eventCh     <-chan domain.StreamEvent
	doneCh      <-chan scanMissionDoneMsg
	seq         int
}

type consoleShellModel struct {
	app     *App
	stage   consoleStage
	drawer  consoleDrawer
	launch  consoleShellLaunchState
	mission consoleShellMissionState
	baseCtx context.Context
	width   int
	height  int
}

var startConsoleShellMission = defaultStartConsoleShellMission

func newConsoleShellModel(app *App, state consoleShellLaunchState, baseCtx context.Context) consoleShellModel {
	width, height := initialTerminalViewport()
	selectedProjectID := strings.TrimSpace(state.SelectedProjectID)
	if selectedProjectID == "" && app != nil {
		snapshot := app.buildTUISnapshot()
		selectedProjectID = preferredProjectID(snapshot.Portfolio.Projects, "")
	}
	return consoleShellModel{
		app:    app,
		stage:  consoleStageLaunch,
		drawer: consoleDrawerNone,
		launch: consoleShellLaunchState{
			SelectedProjectID: selectedProjectID,
			Notice:            strings.TrimSpace(state.Notice),
			Alert:             state.Alert,
		},
		baseCtx: commandContext(baseCtx),
		width:   width,
		height:  height,
	}
}

func (m consoleShellModel) launchProjectLabel() string {
	projectID := strings.TrimSpace(m.launch.SelectedProjectID)
	if projectID == "" || m.app == nil {
		return ""
	}
	snapshot := m.app.buildTUISnapshot()
	if project, ok := projectByID(snapshot.Portfolio.Projects, projectID); ok {
		if strings.TrimSpace(project.DisplayName) != "" {
			return project.DisplayName
		}
	}
	return projectID
}

func (m consoleShellModel) launchReadinessLabel() string {
	if strings.TrimSpace(m.launch.SelectedProjectID) == "" {
		return m.app.catalog.T("console_launch_readiness_waiting")
	}
	return m.app.catalog.T("console_launch_readiness_ready")
}

func defaultStartConsoleShellMission(app *App, ctx context.Context, project domain.Project, profile domain.ScanProfile, seq int) consoleShellMissionSession {
	ctx, cancel := context.WithCancel(commandContext(ctx))
	eventCh := make(chan domain.StreamEvent, 128)
	doneCh := make(chan scanMissionDoneMsg, 1)

	go func() {
		run, findings, err := app.service.Scan(ctx, project.ID, profile, func(event domain.StreamEvent) {
			emitMissionEvent(eventCh, event)
		})
		doneCh <- scanMissionDoneMsg{
			run:      run,
			findings: findings,
			err:      err,
			seq:      seq,
		}
	}()

	return consoleShellMissionSession{
		cancel:  cancel,
		eventCh: eventCh,
		doneCh:  doneCh,
	}
}

func (m consoleShellModel) selectedProject() (domain.Project, bool) {
	projectID := strings.TrimSpace(m.launch.SelectedProjectID)
	if projectID == "" || m.app == nil {
		return domain.Project{}, false
	}
	snapshot := m.app.buildTUISnapshot()
	project, ok := projectByID(snapshot.Portfolio.Projects, projectID)
	return project, ok
}

func (m consoleShellModel) activeMissionModel() (scanMissionModel, bool) {
	if m.stage != consoleStageMission && m.stage != consoleStageDebrief {
		return scanMissionModel{}, false
	}
	if m.mission.console == nil && !m.mission.running && !m.mission.done {
		return scanMissionModel{}, false
	}
	return scanMissionModel{
		app:              m.app,
		project:          m.mission.project,
		profile:          m.mission.profile,
		doctor:           m.mission.doctor,
		launchedAt:       m.mission.launchedAt,
		cpuBaseline:      m.mission.cpuBaseline,
		console:          m.mission.console,
		width:            m.width,
		height:           m.height,
		done:             m.mission.done,
		aborting:         m.mission.aborting,
		notice:           m.mission.notice,
		alert:            m.mission.alert,
		run:              m.mission.run,
		findings:         m.mission.findings,
		scanErr:          m.mission.scanErr,
		requiredErr:      m.mission.requiredErr,
		missionOnly:      true,
		statusOnlyMotion: true,
	}, true
}

func (m consoleShellModel) hasMissionSurface() bool {
	return m.stage == consoleStageMission || m.stage == consoleStageDebrief
}

func (m consoleShellModel) seededMissionRun(profile domain.ScanProfile) domain.ScanRun {
	results := make([]domain.ModuleResult, 0, len(profile.Modules))
	for _, name := range profile.Modules {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		results = append(results, domain.ModuleResult{
			Name:    name,
			Status:  domain.ModuleQueued,
			Summary: m.app.moduleNarrative(name),
		})
	}
	return domain.ScanRun{
		Status:        domain.ScanRunning,
		ModuleResults: results,
	}
}

func (m consoleShellModel) seededMissionConsole(project domain.Project, profile domain.ScanProfile) *liveScanConsole {
	console := m.app.newLiveScanConsole(project, profile)
	if console == nil {
		console = &liveScanConsole{
			project:        project,
			profile:        profile,
			recentFindings: make([]domain.Finding, 0, 5),
		}
	}
	firstModule := firstModuleName(profile.Modules)
	firstPhase := m.app.modulePhaseLabel(firstModule)
	firstTool := m.app.moduleToolLabel(firstModule)
	firstEvent := m.app.moduleNarrative(firstModule)
	if strings.TrimSpace(firstEvent) == "" || firstEvent == firstModule {
		firstEvent = m.app.catalog.T("scan_mc_boot")
	}
	run := m.seededMissionRun(profile)
	console.run = run
	console.lastModule = firstModule
	console.lastPhase = firstPhase
	console.lastTool = firstTool
	console.lastStatus = string(domain.ModuleQueued)
	console.lastEvent = firstEvent
	if len(console.telemetry) == 0 {
		console.telemetry = []string{firstEvent}
	}
	return console
}
