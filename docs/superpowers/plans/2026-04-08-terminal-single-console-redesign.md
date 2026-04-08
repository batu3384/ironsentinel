# Terminal Single-Console Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the current route-first TUI with a single-console `Launch -> Mission -> Debrief` experience that makes scan activity and outcomes obvious without changing backend truth.

**Architecture:** Build a new `consoleShell` state machine beside the current route-first shell, wire `launchTUI` to the new model once the launch/mission/debrief flow is proven, then retire the old route-first primary path. Reuse the existing scan orchestration, runtime doctor, canonical report pipeline, and CLI fallback surfaces instead of rebuilding backend behavior.

**Tech Stack:** Go, Cobra, Bubble Tea, Lip Gloss, existing IronSentinel service/store/domain packages.

---

## File Structure

### New files

- `internal/cli/console_shell.go`
  - New single-console model types, stage enums, launch state, and `launchTUI` entrypoint wiring.
- `internal/cli/console_shell_update.go`
  - Bubble Tea update loop, stage transitions, key handling, scan event handling, drawer toggles.
- `internal/cli/console_shell_view.go`
  - Same-surface `Launch`, `Mission`, and `Debrief` rendering.
- `internal/cli/console_shell_drawer.go`
  - Right-side drawers for findings, runtime, and run details.
- `internal/cli/console_shell_test.go`
  - End-to-end unit coverage for stage changes, visible status, debrief, and drawer behavior.
- `internal/cli/console_shell_snapshot_test.go`
  - Focused snapshot coverage for launch, running mission, and debrief variants.

### Existing files to modify

- `internal/cli/app_shell.go`
  - Remove `launchTUI` ownership after cutover; keep only compatibility helpers if still referenced.
- `internal/cli/app.go`
  - Route TUI launch and quick-scan follow-up into the new console flow.
- `internal/cli/scan_mode.go`
  - Expose reusable mission-state helpers that the new console can render on the same surface.
- `internal/cli/scan_dashboard.go`
  - Reuse mission panels and pulse logic through smaller, console-friendly render helpers.
- `internal/cli/brand.go`
  - Controlled cyber-neon palette and persistent-small mascot treatment for the new shell.
- `internal/cli/labels.go`
  - Human-facing stage/status labels used in the new console.
- `internal/cli/views.go`
  - Keep plain-mode and non-interactive summaries aligned with the new debrief hierarchy.
- `internal/cli/dashboard.go`
  - Compact plain overview/runtime summaries that mirror the new debrief tone.
- `internal/i18n/catalog_en.go`
  - New launch, mission, debrief, drawer, and motion labels.
- `internal/i18n/catalog_tr.go`
  - Turkish equivalents for the new console language.
- `internal/cli/teatest_snapshot_test.go`
  - Replace route-first visual expectations with new single-console snapshots.

### Existing files expected to shrink or lose primary-path ownership

- `internal/cli/app_shell_frame.go`
- `internal/cli/app_shell_routes.go`
- `internal/cli/app_shell_details.go`
- `internal/cli/app_shell_state.go`
- `internal/cli/app_shell_update.go`

These should stop defining the primary TUI experience once cutover is complete. Do not delete them until the new console is fully wired and tested.

---

### Task 1: Create The Single-Console Shell Scaffold

**Files:**
- Create: `internal/cli/console_shell.go`
- Create: `internal/cli/console_shell_update.go`
- Create: `internal/cli/console_shell_view.go`
- Test: `internal/cli/console_shell_test.go`
- Modify: `internal/cli/app_shell.go`

- [ ] **Step 1: Write the failing scaffold tests**

```go
func TestConsoleShellStartsInLaunchStage(t *testing.T) {
	app, _ := newTestTUIApp(t)
	model := newConsoleShellModel(app, consoleShellLaunchState{}, context.Background())

	if model.stage != consoleStageLaunch {
		t.Fatalf("expected launch stage, got %v", model.stage)
	}
	if model.drawer != consoleDrawerNone {
		t.Fatalf("expected no drawer, got %v", model.drawer)
	}
	view := model.View()
	if !strings.Contains(view, app.catalog.T("console_launch_title")) {
		t.Fatalf("expected launch title in view, got %q", view)
	}
	if strings.Contains(view, app.catalog.T("app_route_home")) {
		t.Fatalf("expected route-first copy to be absent, got %q", view)
	}
}

func TestLaunchTUIUsesConsoleShellProgram(t *testing.T) {
	app, _ := newTestTUIApp(t)
	model := newConsoleShellModel(app, consoleShellLaunchState{}, context.Background())

	if _, ok := interface{}(model).(tea.Model); !ok {
		t.Fatal("expected console shell model to implement tea.Model")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
go test ./internal/cli -run 'Test(ConsoleShellStartsInLaunchStage|LaunchTUIUsesConsoleShellProgram)$' -count=1
```

Expected: FAIL with `undefined: newConsoleShellModel` and `undefined: consoleShellLaunchState`.

- [ ] **Step 3: Write minimal scaffold implementation**

```go
type consoleStage string

const (
	consoleStageLaunch   consoleStage = "launch"
	consoleStageMission  consoleStage = "mission"
	consoleStageDebrief  consoleStage = "debrief"
)

type consoleDrawer string

const (
	consoleDrawerNone     consoleDrawer = ""
	consoleDrawerFindings consoleDrawer = "findings"
	consoleDrawerRuntime  consoleDrawer = "runtime"
	consoleDrawerRun      consoleDrawer = "run"
)

type consoleShellLaunchState struct {
	SelectedProjectID string
	Notice            string
	Alert             bool
}

type consoleShellModel struct {
	app    *App
	stage  consoleStage
	drawer consoleDrawer
	launch consoleShellLaunchState
	baseCtx context.Context
	width  int
	height int
}

func newConsoleShellModel(app *App, state consoleShellLaunchState, baseCtx context.Context) consoleShellModel {
	return consoleShellModel{
		app:    app,
		stage:  consoleStageLaunch,
		drawer: consoleDrawerNone,
		launch: state,
		baseCtx: baseCtx,
		width:  120,
		height: 32,
	}
}

func (m consoleShellModel) Init() tea.Cmd { return nil }

func (m consoleShellModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) { return m, nil }

func (m consoleShellModel) View() string {
	return lipgloss.NewStyle().Padding(1, 2).Render(m.app.catalog.T("console_launch_title"))
}
```

And replace the launch ownership in `internal/cli/app_shell.go`:

```go
func (a *App) launchTUI(ctx context.Context) error {
	baseCtx, cancel := context.WithCancel(commandContext(ctx))
	defer cancel()
	_, err := tea.NewProgram(newConsoleShellModel(a, consoleShellLaunchState{}, baseCtx), tea.WithAltScreen()).Run()
	return err
}
```

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
go test ./internal/cli -run 'Test(ConsoleShellStartsInLaunchStage|LaunchTUIUsesConsoleShellProgram)$' -count=1
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/cli/console_shell.go internal/cli/console_shell_update.go internal/cli/console_shell_view.go internal/cli/console_shell_test.go internal/cli/app_shell.go
git commit -m "feat: add single-console shell scaffold"
```

### Task 2: Build The Launch Surface And One-Action Start Flow

**Files:**
- Modify: `internal/cli/console_shell.go`
- Modify: `internal/cli/console_shell_update.go`
- Modify: `internal/cli/console_shell_view.go`
- Modify: `internal/cli/app.go`
- Modify: `internal/i18n/catalog_en.go`
- Modify: `internal/i18n/catalog_tr.go`
- Test: `internal/cli/console_shell_test.go`

- [ ] **Step 1: Write the failing launch behavior tests**

```go
func TestConsoleShellEnterStartsMissionWhenProjectSelected(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newConsoleShellModel(app, consoleShellLaunchState{SelectedProjectID: project.ID}, context.Background())

	next, _ := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	got := next.(consoleShellModel)

	if got.stage != consoleStageMission {
		t.Fatalf("expected mission stage, got %v", got.stage)
	}
	if got.mission.project.ID != project.ID {
		t.Fatalf("expected selected project %q, got %q", project.ID, got.mission.project.ID)
	}
}

func TestConsoleShellLaunchViewShowsSinglePrimaryAction(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newConsoleShellModel(app, consoleShellLaunchState{SelectedProjectID: project.ID}, context.Background())

	view := model.View()
	if !strings.Contains(view, app.catalog.T("console_launch_cta")) {
		t.Fatalf("expected launch CTA, got %q", view)
	}
	if strings.Contains(view, app.catalog.T("app_route_scan_review")) {
		t.Fatalf("expected scan review route copy to be absent, got %q", view)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
go test ./internal/cli -run 'Test(ConsoleShellEnterStartsMissionWhenProjectSelected|ConsoleShellLaunchViewShowsSinglePrimaryAction)$' -count=1
```

Expected: FAIL because `mission` state and launch CTA strings do not exist yet.

- [ ] **Step 3: Implement launch state and primary-action start**

```go
type consoleMissionState struct {
	project    domain.Project
	profile    domain.ScanProfile
	doctor     domain.RuntimeDoctor
	running    bool
	startedAt  time.Time
	activeTool string
	activeStep string
}

func (m consoleShellModel) selectedProject() (domain.Project, bool) {
	if strings.TrimSpace(m.launch.SelectedProjectID) == "" {
		return domain.Project{}, false
	}
	project, ok := m.app.service.GetProject(m.launch.SelectedProjectID)
	return project, ok
}

func (m consoleShellModel) startQuickMission() (consoleShellModel, tea.Cmd) {
	project, ok := m.selectedProject()
	if !ok {
		m.launch.Notice = m.app.catalog.T("console_launch_select_project")
		m.launch.Alert = true
		return m, nil
	}
	m.stage = consoleStageMission
	m.mission = consoleMissionState{
		project:   project,
		profile:   m.app.quickScanProfile(project),
		running:   true,
		startedAt: time.Now(),
	}
	return m, m.beginMissionScanCmd(project, m.mission.profile)
}

func (m consoleShellModel) beginMissionScanCmd(project domain.Project, profile domain.ScanProfile) tea.Cmd {
	return nil
}

func (m consoleShellModel) handleKeyMsg(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case m.stage == consoleStageLaunch && msg.Type == tea.KeyEnter:
		next, cmd := m.startQuickMission()
		return next, cmd
	case m.stage == consoleStageLaunch && msg.String() == "a":
		m.launch.Notice = m.app.catalog.T("console_launch_advanced_hint")
		return m, nil
	}
	return m, nil
}

func (m consoleShellModel) renderLaunch() string {
	projectLabel := m.app.catalog.T("console_launch_no_target")
	if project, ok := m.selectedProject(); ok {
		projectLabel = project.DisplayName
	}
	lines := []string{
		fmt.Sprintf("%s: %s", m.app.catalog.T("target"), projectLabel),
		m.app.catalog.T("console_launch_cta"),
		m.app.catalog.T("console_launch_hint_line"),
	}
	return strings.Join(lines, "\n")
}
```

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
go test ./internal/cli -run 'Test(ConsoleShellEnterStartsMissionWhenProjectSelected|ConsoleShellLaunchViewShowsSinglePrimaryAction)$' -count=1
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/cli/console_shell.go internal/cli/console_shell_update.go internal/cli/console_shell_view.go internal/cli/app.go internal/i18n/catalog_en.go internal/i18n/catalog_tr.go internal/cli/console_shell_test.go
git commit -m "feat: add single-action launch surface"
```

### Task 3: Build The Mission Surface And Visible Scan Activity

**Files:**
- Modify: `internal/cli/console_shell.go`
- Modify: `internal/cli/console_shell_update.go`
- Modify: `internal/cli/console_shell_view.go`
- Modify: `internal/cli/scan_mode.go`
- Modify: `internal/cli/scan_dashboard.go`
- Modify: `internal/cli/brand.go`
- Modify: `internal/cli/labels.go`
- Test: `internal/cli/console_shell_test.go`
- Test: `internal/cli/console_shell_snapshot_test.go`

- [ ] **Step 1: Write the failing mission visibility tests**

```go
func TestConsoleShellMissionViewShowsRunningStatePhaseAndTool(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newConsoleShellModel(app, consoleShellLaunchState{SelectedProjectID: project.ID}, context.Background())
	model.stage = consoleStageMission
	model.mission = consoleMissionState{
		project:    project,
		running:    true,
		activeStep: "Dependency and Supply Chain",
		activeTool: "trivy",
		startedAt:  time.Now().Add(-8 * time.Second),
	}

	view := model.View()
	for _, fragment := range []string{
		app.catalog.T("console_mission_running"),
		"Dependency and Supply Chain",
		"trivy",
		project.DisplayName,
	} {
		if !strings.Contains(view, fragment) {
			t.Fatalf("expected %q in mission view, got %q", fragment, view)
		}
	}
}

func TestConsoleShellMissionViewDoesNotRenderRouteRibbon(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newConsoleShellModel(app, consoleShellLaunchState{SelectedProjectID: project.ID}, context.Background())
	model.stage = consoleStageMission
	model.mission = consoleMissionState{project: project, running: true}

	view := model.View()
	if strings.Contains(view, app.catalog.T("app_route_home")) || strings.Contains(view, app.catalog.T("app_route_findings")) {
		t.Fatalf("expected route ribbon to be absent, got %q", view)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
go test ./internal/cli -run 'Test(ConsoleShellMissionViewShowsRunningStatePhaseAndTool|ConsoleShellMissionViewDoesNotRenderRouteRibbon)$' -count=1
```

Expected: FAIL because mission rendering is not implemented.

- [ ] **Step 3: Implement mission rail, activity pulse, and reusable mission helpers**

```go
type consoleMissionState struct {
	project        domain.Project
	profile        domain.ScanProfile
	doctor         domain.RuntimeDoctor
	running        bool
	completed      bool
	startedAt      time.Time
	activePhase    string
	activeModule   string
	activeTool     string
	recentEvent    string
	events         []domain.StreamEvent
	run            domain.ScanRun
	findings       []domain.Finding
	requiredErr    error
}

func (m consoleShellModel) missionStatusRail(width int) string {
	label := m.app.catalog.T("console_mission_running")
	if !m.mission.running {
		label = m.app.catalog.T("console_mission_complete")
	}
	chips := []string{
		m.renderMascotSignalChip(),
		m.renderStatusChip(label, m.mission.running),
		trimForSelect(m.mission.activePhase, 28),
		trimForSelect(m.mission.activeTool, 18),
	}
	return lipgloss.JoinHorizontal(lipgloss.Left, chips...)
}

func (m consoleShellModel) renderMascotSignalChip() string {
	return lipgloss.NewStyle().Bold(true).Render("◉")
}

func (m consoleShellModel) renderStatusChip(label string, active bool) string {
	style := lipgloss.NewStyle().Bold(true)
	if active {
		style = style.Foreground(lipgloss.Color("45"))
	}
	return style.Render(label)
}

func (m consoleShellModel) renderMission() string {
	lines := []string{
		m.missionStatusRail(m.width),
		fmt.Sprintf("%s: %s", m.app.catalog.T("target"), m.mission.project.DisplayName),
		fmt.Sprintf("%s: %s", m.app.catalog.T("console_mission_phase"), m.mission.activePhase),
		fmt.Sprintf("%s: %s", m.app.catalog.T("console_mission_module"), m.mission.activeModule),
		fmt.Sprintf("%s: %s", m.app.catalog.T("console_mission_tool"), m.mission.activeTool),
		fmt.Sprintf("%s: %s", m.app.catalog.T("console_mission_recent_event"), m.mission.recentEvent),
	}
	return strings.Join(lines, "\n")
}

func (m consoleShellModel) applyMissionEvent(event domain.StreamEvent) consoleShellModel {
	m.mission.activePhase = strings.TrimSpace(event.Module)
	m.mission.activeModule = strings.TrimSpace(event.Module)
	m.mission.recentEvent = strings.TrimSpace(event.Message)
	if tool := strings.TrimSpace(event.Tool); tool != "" {
		m.mission.activeTool = tool
	}
	m.mission.events = append(m.mission.events, event)
	return m
}
```

Also expose one small shared helper in `internal/cli/scan_mode.go` instead of duplicating status-copy:

```go
func missionStatusLabel(catalog catalogAccessor, running, completed bool) string {
	switch {
	case running:
		return catalog.T("console_mission_running")
	case completed:
		return catalog.T("console_mission_complete")
	default:
		return catalog.T("console_mission_ready")
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
go test ./internal/cli -run 'Test(ConsoleShellMissionViewShowsRunningStatePhaseAndTool|ConsoleShellMissionViewDoesNotRenderRouteRibbon)$' -count=1
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/cli/console_shell.go internal/cli/console_shell_update.go internal/cli/console_shell_view.go internal/cli/scan_mode.go internal/cli/scan_dashboard.go internal/cli/brand.go internal/cli/labels.go internal/cli/console_shell_test.go internal/cli/console_shell_snapshot_test.go
git commit -m "feat: add single-console mission surface"
```

### Task 4: Append Same-Surface Debrief And Add Context Drawers

**Files:**
- Modify: `internal/cli/console_shell.go`
- Modify: `internal/cli/console_shell_update.go`
- Modify: `internal/cli/console_shell_view.go`
- Create: `internal/cli/console_shell_drawer.go`
- Modify: `internal/cli/views.go`
- Modify: `internal/cli/dashboard.go`
- Test: `internal/cli/console_shell_test.go`
- Test: `internal/cli/console_shell_snapshot_test.go`

- [ ] **Step 1: Write the failing debrief and drawer tests**

```go
func TestConsoleShellAppendsDebriefBelowMissionWhenRunCompletes(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newConsoleShellModel(app, consoleShellLaunchState{SelectedProjectID: project.ID}, context.Background())
	model.stage = consoleStageMission
	model.mission = consoleMissionState{
		project:   project,
		running:   false,
		completed: true,
		run:       domain.ScanRun{ID: "run-1", ProjectID: project.ID, Status: domain.ScanCompleted},
		findings:  []domain.Finding{{Title: "reachable vulnerable dependency", Severity: domain.SeverityHigh}},
	}

	view := model.View()
	if !strings.Contains(view, app.catalog.T("console_debrief_title")) {
		t.Fatalf("expected debrief title, got %q", view)
	}
	if !strings.Contains(view, app.catalog.T("console_debrief_next_action")) {
		t.Fatalf("expected next action summary, got %q", view)
	}
}

func TestConsoleShellDrawerOpensWithoutChangingStage(t *testing.T) {
	app, project := newTestTUIApp(t)
	model := newConsoleShellModel(app, consoleShellLaunchState{SelectedProjectID: project.ID}, context.Background())
	model.stage = consoleStageDebrief

	next, _ := model.Update(tea.KeyMsg{Runes: []rune{'f'}})
	got := next.(consoleShellModel)

	if got.stage != consoleStageDebrief {
		t.Fatalf("expected debrief stage, got %v", got.stage)
	}
	if got.drawer != consoleDrawerFindings {
		t.Fatalf("expected findings drawer, got %v", got.drawer)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
go test ./internal/cli -run 'Test(ConsoleShellAppendsDebriefBelowMissionWhenRunCompletes|ConsoleShellDrawerOpensWithoutChangingStage)$' -count=1
```

Expected: FAIL because no debrief append or drawer behavior exists yet.

- [ ] **Step 3: Implement debrief layering and right-side drawers**

```go
func (m consoleShellModel) renderDebrief() string {
	run := m.mission.run
	findings := m.mission.findings
	lines := []string{
		m.app.catalog.T("console_debrief_title"),
		fmt.Sprintf("%s: %s", m.app.catalog.T("status"), m.renderRunStatus(run.Status)),
		fmt.Sprintf("%s: %d", m.app.catalog.T("findings_title"), len(findings)),
		fmt.Sprintf("%s: %s", m.app.catalog.T("console_debrief_next_action"), m.nextDebriefAction(findings, m.mission.requiredErr)),
	}
	return strings.Join(lines, "\n")
}

func (m consoleShellModel) withDrawer(drawer consoleDrawer) consoleShellModel {
	m.drawer = drawer
	return m
}

func (m consoleShellModel) renderDrawer(width int) string {
	switch m.drawer {
	case consoleDrawerFindings:
		return m.renderFindingsDrawer(width)
	case consoleDrawerRuntime:
		return m.renderRuntimeDrawer(width)
	case consoleDrawerRun:
		return m.renderRunDrawer(width)
	default:
		return ""
	}
}

func (m consoleShellModel) View() string {
	body := m.renderLaunch()
	switch m.stage {
	case consoleStageMission:
		body = m.renderMission()
		if m.mission.completed {
			body = lipgloss.JoinVertical(lipgloss.Left, body, "", m.renderDebrief())
		}
	case consoleStageDebrief:
		body = lipgloss.JoinVertical(lipgloss.Left, m.renderMission(), "", m.renderDebrief())
	}
	if m.drawer == consoleDrawerNone {
		return body
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, body, "  ", m.renderDrawer(maxInt(32, m.width/3)))
}
```

And add key handling in `internal/cli/console_shell_update.go`:

```go
case msg.String() == "f" && (m.stage == consoleStageMission || m.stage == consoleStageDebrief):
	return m.withDrawer(consoleDrawerFindings), nil
case msg.String() == "r" && (m.stage == consoleStageMission || m.stage == consoleStageDebrief):
	return m.withDrawer(consoleDrawerRuntime), nil
case msg.String() == "d" && (m.stage == consoleStageMission || m.stage == consoleStageDebrief):
	return m.withDrawer(consoleDrawerRun), nil
case msg.String() == "esc" && m.drawer != consoleDrawerNone:
	m.drawer = consoleDrawerNone
	return m, nil
```

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
go test ./internal/cli -run 'Test(ConsoleShellAppendsDebriefBelowMissionWhenRunCompletes|ConsoleShellDrawerOpensWithoutChangingStage)$' -count=1
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/cli/console_shell.go internal/cli/console_shell_update.go internal/cli/console_shell_view.go internal/cli/console_shell_drawer.go internal/cli/views.go internal/cli/dashboard.go internal/cli/console_shell_test.go internal/cli/console_shell_snapshot_test.go
git commit -m "feat: add single-console debrief and drawers"
```

### Task 5: Cut Over The TUI Entrypoint And Retire Route-First Primary Path

**Files:**
- Modify: `internal/cli/app_shell.go`
- Modify: `internal/cli/app_shell_frame.go`
- Modify: `internal/cli/app_shell_routes.go`
- Modify: `internal/cli/app_shell_state.go`
- Modify: `internal/cli/app_shell_update.go`
- Modify: `internal/cli/root_command.go`
- Modify: `internal/cli/tui_command.go`
- Test: `internal/cli/console_shell_test.go`
- Test: `internal/cli/app_shell_test.go`
- Test: `internal/cli/teatest_snapshot_test.go`

- [ ] **Step 1: Write the failing cutover tests**

```go
func TestLaunchTUIShowsSingleConsoleNotRouteShell(t *testing.T) {
	app, _ := newTestTUIApp(t)
	model := newConsoleShellModel(app, consoleShellLaunchState{}, context.Background())

	view := model.View()
	if strings.Contains(view, app.catalog.T("app_route_live_scan")) || strings.Contains(view, app.catalog.T("app_route_runtime")) {
		t.Fatalf("expected route-first navigation copy to be absent, got %q", view)
	}
}

func TestLegacyRouteShellIsNotPrimaryPathAnymore(t *testing.T) {
	app, _ := newTestTUIApp(t)
	if got := app.primaryTUIModelName(); got != "console_shell" {
		t.Fatalf("expected console_shell primary model, got %q", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
go test ./internal/cli -run 'Test(LaunchTUIShowsSingleConsoleNotRouteShell|LegacyRouteShellIsNotPrimaryPathAnymore)$' -count=1
```

Expected: FAIL because the cutover marker/helper does not exist yet.

- [ ] **Step 3: Wire entrypoint and downgrade old route shell to compatibility code**

```go
func (a *App) primaryTUIModelName() string {
	return "console_shell"
}

func (a *App) launchTUI(ctx context.Context) error {
	baseCtx, cancel := context.WithCancel(commandContext(ctx))
	defer cancel()

	state := consoleShellLaunchState{}
	finalModel, err := tea.NewProgram(newConsoleShellModel(a, state, baseCtx), tea.WithAltScreen()).Run()
	if err != nil {
		return err
	}
	if _, ok := finalModel.(consoleShellModel); !ok {
		return fmt.Errorf("unexpected console shell model type")
	}
	return nil
}
```

Then remove route-ribbon assumptions from route-first tests and snapshots instead of trying to preserve them:

```go
func TestLegacyRouteShellIsNotPrimaryPathAnymore(t *testing.T) {
	app, _ := newTestTUIApp(t)
	if got := app.primaryTUIModelName(); got != "console_shell" {
		t.Fatalf("expected console shell primary model, got %q", got)
	}
}
```

Old `app_shell_*` files may remain for now, but no root command should start there anymore.

- [ ] **Step 4: Run test to verify it passes**

Run:

```bash
go test ./internal/cli -run 'Test(LaunchTUIShowsSingleConsoleNotRouteShell|LegacyRouteShellIsNotPrimaryPathAnymore)$' -count=1
go test ./internal/cli -count=1
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/cli/app_shell.go internal/cli/app_shell_frame.go internal/cli/app_shell_routes.go internal/cli/app_shell_state.go internal/cli/app_shell_update.go internal/cli/root_command.go internal/cli/tui_command.go internal/cli/console_shell_test.go internal/cli/app_shell_test.go internal/cli/teatest_snapshot_test.go
git commit -m "refactor: cut over TUI entrypoint to single-console shell"
```

### Task 6: Align Plain Fallback, Motion Rules, And Documentation

**Files:**
- Modify: `internal/cli/views.go`
- Modify: `internal/cli/dashboard.go`
- Modify: `internal/cli/brand.go`
- Modify: `internal/cli/ui_mode.go`
- Modify: `internal/i18n/catalog_en.go`
- Modify: `internal/i18n/catalog_tr.go`
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Test: `internal/cli/pterm_plain_test.go`
- Test: `internal/cli/console_shell_snapshot_test.go`

- [ ] **Step 1: Write the failing fallback and motion tests**

```go
func TestConsoleShellNoColorStillShowsLaunchMissionDebriefHierarchy(t *testing.T) {
	app, project := newTestTUIApp(t)
	app.cfg.NoColor = true
	model := newConsoleShellModel(app, consoleShellLaunchState{SelectedProjectID: project.ID}, context.Background())
	model.stage = consoleStageDebrief
	model.mission = consoleMissionState{project: project, completed: true, run: domain.ScanRun{ID: "run-1", ProjectID: project.ID, Status: domain.ScanCompleted}}

	view := model.View()
	for _, fragment := range []string{
		project.DisplayName,
		app.catalog.T("console_debrief_title"),
		app.catalog.T("console_debrief_next_action"),
	} {
		if !strings.Contains(view, fragment) {
			t.Fatalf("expected %q in plain console view, got %q", fragment, view)
		}
	}
}

func TestPlainRunSummaryUsesDebriefOrder(t *testing.T) {
	app, _ := newTestTUIApp(t)
	run := domain.ScanRun{ID: "run-1", ProjectID: "project-1", Status: domain.ScanCompleted}
	out := app.renderPlainRunSummary(run, nil)

	if !strings.Contains(out, app.catalog.T("console_debrief_title")) {
		t.Fatalf("expected debrief title in plain summary, got %q", out)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
go test ./internal/cli -run 'Test(ConsoleShellNoColorStillShowsLaunchMissionDebriefHierarchy|PlainRunSummaryUsesDebriefOrder)$' -count=1
```

Expected: FAIL because plain-mode and docs still reflect the old route-first hierarchy.

- [ ] **Step 3: Implement fallback alignment and document the new model**

```go
func (a *App) renderPlainRunSummary(run domain.ScanRun, findings []domain.Finding) string {
	lines := []string{
		a.catalog.T("console_debrief_title"),
		fmt.Sprintf("%s: %s", a.catalog.T("status"), strings.ToUpper(a.statusLabel(string(run.Status)))),
		fmt.Sprintf("%s: %d", a.catalog.T("findings_title"), len(findings)),
		fmt.Sprintf("%s: %s", a.catalog.T("console_debrief_next_action"), a.plainNextAction(run, findings)),
	}
	return strings.Join(lines, "\n")
}

func (a *App) plainNextAction(run domain.ScanRun, findings []domain.Finding) string {
	switch {
	case run.Status != domain.ScanCompleted:
		return a.catalog.T("console_debrief_action_review_runtime")
	case len(findings) > 0:
		return a.catalog.T("console_debrief_action_open_findings")
	default:
		return a.catalog.T("console_debrief_action_export")
	}
}
```

Update docs to describe the new flow explicitly:

```md
## Terminal UX

IronSentinel uses one terminal console with three states:

1. Launch
2. Mission
3. Debrief

`Runs`, `Findings`, and `Runtime` open as contextual drawers rather than separate primary screens.
```

- [ ] **Step 4: Run verification to verify it passes**

Run:

```bash
go test ./internal/cli -count=1
go test ./... -count=1
go vet ./...
bash scripts/quality_local.sh
NO_COLOR=1 go run ./cmd/ironsentinel overview --lang tr
NO_COLOR=1 go run ./cmd/ironsentinel runtime --lang tr
```

Expected:

- all tests PASS
- `go vet` exits `0`
- `quality_local.sh` exits `0`
- plain output reads like launch/debrief summaries rather than route dashboards

- [ ] **Step 5: Commit**

```bash
git add internal/cli/views.go internal/cli/dashboard.go internal/cli/brand.go internal/cli/ui_mode.go internal/i18n/catalog_en.go internal/i18n/catalog_tr.go README.md docs/architecture.md internal/cli/pterm_plain_test.go internal/cli/console_shell_snapshot_test.go
git commit -m "docs: align plain mode and docs with single-console shell"
```

## Self-Review

### Spec coverage

- Single main console: covered by Tasks 1 and 5.
- Same-surface `Launch -> Mission -> Debrief`: covered by Tasks 2, 3, and 4.
- Drawers for `Findings`, `Runtime`, and `Run details`: covered by Task 4.
- Balanced density and removal of route-first clutter: covered by Tasks 2, 3, and 5.
- Controlled cyber neon and small mascot presence: covered by Tasks 3 and 6.
- Motion and fallback rules: covered by Tasks 3 and 6.
- Preserve backend truth and CLI fallback behavior: covered by Tasks 3, 4, and 6.

No uncovered spec section remains.

### Placeholder scan

This plan intentionally avoids unresolved placeholders, vague "handle this later" instructions, test-free implementation steps, and cross-references that force the reader to infer missing details.

### Type consistency

The plan consistently uses these names:

- `consoleShellModel`
- `consoleShellLaunchState`
- `consoleStageLaunch`
- `consoleStageMission`
- `consoleStageDebrief`
- `consoleDrawerFindings`
- `consoleDrawerRuntime`
- `consoleDrawerRun`
- `consoleMissionState`

No later task renames or forks these identifiers.
