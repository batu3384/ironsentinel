package cli

import (
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func (m consoleShellModel) Init() tea.Cmd {
	return nil
}

func (m consoleShellModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case scanMissionTickMsg:
		return m, nil
	case scanMissionEventMsg:
		return m.handleScanMissionEventMsg(msg)
	case scanMissionDoneMsg:
		return m.handleScanMissionDoneMsg(msg)
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			if m.hasMissionSurface() && m.mission.running {
				if m.mission.cancel != nil {
					m.mission.cancel()
				}
				m.mission.aborting = true
				m.mission.notice = m.app.catalog.T("scan_mode_live_cancel_requested")
				m.mission.alert = true
				return m, nil
			}
			return m, tea.Quit
		case "enter":
			if m.hasMissionSurface() {
				if m.mission.done {
					return m, tea.Quit
				}
				return m, nil
			}
			if strings.TrimSpace(m.launch.SelectedProjectID) == "" {
				return m, nil
			}
			return m.beginMission()
		case "p":
			m.launch.Notice = m.app.catalog.T("console_launch_project_notice")
			m.launch.Alert = false
			return m, nil
		case "f":
			if m.hasMissionSurface() {
				m.drawer = consoleDrawerFindings
			}
			return m, nil
		case "r":
			if m.hasMissionSurface() {
				m.drawer = consoleDrawerRuntime
			}
			return m, nil
		case "d":
			if m.hasMissionSurface() {
				m.drawer = consoleDrawerRun
			}
			return m, nil
		case "esc":
			if m.drawer != consoleDrawerNone {
				m.drawer = consoleDrawerNone
				return m, nil
			}
		}
	}
	return m, nil
}

func (m consoleShellModel) beginMission() (tea.Model, tea.Cmd) {
	project, ok := m.selectedProject()
	if !ok {
		return m, nil
	}

	profile := m.app.quickScanProfile(project)
	doctor := m.app.runtimeDoctor(profile, false, false)
	console := m.seededMissionConsole(project, profile)
	run := m.seededMissionRun(profile)

	m.stage = consoleStageMission
	m.drawer = consoleDrawerNone
	m.mission.seq++
	session := startConsoleShellMission(m.app, m.baseCtx, project, profile, m.mission.seq)
	m.mission = consoleShellMissionState{
		project:     project,
		profile:     profile,
		doctor:      doctor,
		launchedAt:  time.Now(),
		cpuBaseline: missionCPUSeconds(),
		console:     console,
		run:         run,
		running:     true,
		cancel:      session.cancel,
		eventCh:     session.eventCh,
		doneCh:      session.doneCh,
		seq:         m.mission.seq,
	}
	return m, tea.Batch(waitForScanMissionEvent(session.eventCh, m.mission.seq), waitForScanMissionDone(session.doneCh, m.mission.seq))
}

func (m consoleShellModel) handleScanMissionEventMsg(msg scanMissionEventMsg) (tea.Model, tea.Cmd) {
	if msg.seq != 0 && msg.seq != m.mission.seq {
		return m, nil
	}
	if m.mission.console != nil {
		m.mission.console.update(m.app, msg.event)
	}
	m.mission.run = msg.event.Run
	return m, waitForScanMissionEvent(m.mission.eventCh, m.mission.seq)
}

func (m consoleShellModel) handleScanMissionDoneMsg(msg scanMissionDoneMsg) (tea.Model, tea.Cmd) {
	if msg.seq != 0 && msg.seq != m.mission.seq {
		return m, nil
	}
	m.stage = consoleStageDebrief
	m.drawer = consoleDrawerNone
	m.mission.running = false
	m.mission.done = true
	m.mission.run = msg.run
	m.mission.findings = msg.findings
	m.mission.scanErr = msg.err
	m.mission.requiredErr = m.app.enforceRequiredModuleResults(msg.run, m.mission.profile.Modules)
	if m.mission.console != nil {
		m.mission.console.run = msg.run
		if strings.TrimSpace(m.mission.console.lastTool) == "" {
			m.mission.console.lastTool = m.app.moduleToolLabel(m.mission.console.lastModule)
		}
	}
	m.mission.notice = m.app.consoleMissionDoneNotice(msg.run.Status, m.mission.requiredErr, len(m.mission.findings))
	m.mission.alert = m.mission.scanErr != nil || m.mission.requiredErr != nil
	return m, nil
}

func firstModuleName(modules []string) string {
	if len(modules) == 0 {
		return ""
	}
	return strings.TrimSpace(modules[0])
}
