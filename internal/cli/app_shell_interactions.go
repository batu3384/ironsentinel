package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/batu3384/ironsentinel/internal/domain"
)

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
