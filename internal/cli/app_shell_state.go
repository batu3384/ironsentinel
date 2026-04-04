package cli

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/batu3384/ironsentinel/internal/domain"
)

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
		Route:              m.route,
		SelectedProjectID:  m.selectedProjectID,
		FindingsScopeRun:   m.findingsScopeRun,
		Review:             m.review,
		ReviewDASTTargets:  append([]domain.DastTarget(nil), m.reviewDASTTargets...),
		ReviewAuthProfiles: append([]domain.DastAuthProfile(nil), m.reviewAuthProfiles...),
		Notice:             m.notice,
		Alert:              m.alert,
		LastScan:           m.lastScan,
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
	lines := make([]string, 0, len(ctx.laneDescriptors)+4)
	lines = append(lines,
		fmt.Sprintf("%s: %s", m.app.catalog.T("app_label_current"), current),
		fmt.Sprintf("%s: %s", m.app.catalog.T("app_label_next"), next),
		fmt.Sprintf("%s: %s", m.app.catalog.T("app_label_deferred"), deferred),
		"",
	)
	for _, lane := range ctx.laneDescriptors {
		ready, na, target := 0, 0, 0
		for _, module := range lane.Modules {
			switch m.reviewModuleState(project, profile, module, modules) {
			case m.app.catalog.T("app_scan_review_ready"):
				ready++
			case m.app.catalog.T("app_scan_review_not_applicable"):
				na++
			case m.app.catalog.T("app_scan_review_requires_target_short"):
				target++
			}
		}
		lines = append(lines, fmt.Sprintf("%s: %d %s • %d %s • %d %s • %s • %s",
			lane.Title,
			ready, strings.ToLower(m.app.catalog.T("app_scan_review_ready")),
			na, strings.ToLower(m.app.catalog.T("app_scan_review_not_applicable")),
			target, strings.ToLower(m.app.catalog.T("app_scan_review_requires_target_short")),
			lane.Kind,
			lane.ETA,
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
