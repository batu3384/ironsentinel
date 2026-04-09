package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/pterm/pterm"

	"github.com/batu3384/ironsentinel/internal/domain"
)

type portfolioSnapshot struct {
	Projects          []domain.Project
	Runs              []domain.ScanRun
	Findings          []domain.Finding
	Suppressions      []domain.Suppression
	Triage            []domain.FindingTriage
	ProjectsByID      map[string]domain.Project
	FindingsByRun     map[string][]domain.Finding
	AvailableScanners int
	MissingScanners   int
}

func (a *App) renderOverviewSurfacePlain(snapshot portfolioSnapshot) error {
	fmt.Print(a.overviewPlainReport(snapshot))
	return nil
}

func (a *App) overviewPlainReport(snapshot portfolioSnapshot) string {
	runtime := a.runtimeStatus(false)
	critical, high, open := 0, 0, 0
	queued, running, canceled := 0, 0, 0
	for _, finding := range snapshot.Findings {
		switch finding.Severity {
		case domain.SeverityCritical:
			critical++
		case domain.SeverityHigh:
			high++
		}
		if finding.Status == "" || finding.Status == domain.FindingOpen {
			open++
		}
	}
	for _, run := range snapshot.Runs {
		switch run.Status {
		case domain.ScanQueued:
			queued++
		case domain.ScanRunning:
			running++
		case domain.ScanCanceled:
			canceled++
		}
	}
	available, drift, missing, failed := runtimeToolHealthCounts(runtime)

	headline := strings.TrimSpace(a.renderQueueHeadlineFromSnapshot(snapshot, snapshot.Runs))
	if headline == a.catalog.T("watch_no_active_runs") && len(snapshot.Runs) > 0 {
		latest := snapshot.Runs[0]
		headline = fmt.Sprintf("%s | %s | %s", latest.ID, strings.ToUpper(string(latest.Status)), snapshot.projectLabel(latest.ProjectID))
	}
	hotFindingSummary := a.catalog.T("overview_no_findings")
	if hotFindings := a.prioritizedFindings(snapshot.Findings, 3); len(hotFindings) > 0 {
		summaries := make([]string, 0, len(hotFindings))
		for _, finding := range hotFindings {
			summaries = append(summaries, a.hottestFindingLine(finding, 48))
		}
		hotFindingSummary = strings.Join(summaries, " || ")
	}
	if headline == "" {
		headline = a.catalog.T("watch_no_active_runs")
	}
	lines := []string{
		fmt.Sprintf("%s overview", strings.ToUpper(brandProductName)),
		"",
		renderPlainStage(a.catalog.T("console_stage_launch"),
			fmt.Sprintf("%s: %s", a.catalog.T("status"), a.portfolioPosture(snapshot)),
			fmt.Sprintf("%s: %d", a.catalog.T("projects_title"), len(snapshot.Projects)),
			fmt.Sprintf("%s: %d %s, %d %s, %d %s, %d %s", a.catalog.T("runtime_command_title"), available, a.catalog.T("runtime_available"), drift, a.catalog.T("runtime_doctor_outdated"), missing, a.catalog.T("runtime_missing"), failed, a.catalog.T("runtime_failed_tools")),
			fmt.Sprintf("%s: %s", a.catalog.T("overview_operator_focus"), a.recommendNextStep(snapshot)),
		),
		"",
		renderPlainStage(a.catalog.T("console_stage_mission"),
			fmt.Sprintf("%s: %d (%s %d, %s %d, %s %d)", a.catalog.T("runs_title"), len(snapshot.Runs), a.catalog.T("status_queued"), queued, a.catalog.T("status_running"), running, a.catalog.T("status_canceled"), canceled),
			fmt.Sprintf("%s: %d (%s %d, %s %d, %s %d)", a.catalog.T("findings_title"), len(snapshot.Findings), a.catalog.T("triage_open"), open, a.catalog.T("summary_critical"), critical, a.catalog.T("summary_high"), high),
			fmt.Sprintf("%s: %s", a.catalog.T("overview_recent_runs"), headline),
		),
		"",
		renderPlainStage(a.catalog.T("console_stage_debrief"),
			fmt.Sprintf("%s: %s", a.catalog.T("overview_hot_findings"), hotFindingSummary),
			fmt.Sprintf("%s: %s", a.catalog.T("overview_next_steps"), a.recommendNextStep(snapshot)),
		),
		"",
	}
	return strings.Join(lines, "\n")
}

func (a *App) buildPortfolioSnapshot() portfolioSnapshot {
	runtime := a.runtimeStatus(false)
	available, missing := 0, 0
	for _, tool := range runtime.ScannerBundle {
		if tool.Available {
			available++
			continue
		}
		missing++
	}

	projects := a.service.ListProjects()
	portfolio := a.service.PortfolioData()
	return portfolioSnapshot{
		Projects:          projects,
		Runs:              portfolio.Runs,
		Findings:          portfolio.Findings,
		Suppressions:      portfolio.Suppressions,
		Triage:            portfolio.Triage,
		ProjectsByID:      indexProjectsByID(projects),
		FindingsByRun:     indexFindingsByRun(portfolio.Findings),
		AvailableScanners: available,
		MissingScanners:   missing,
	}
}

func indexProjectsByID(projects []domain.Project) map[string]domain.Project {
	if len(projects) == 0 {
		return nil
	}
	index := make(map[string]domain.Project, len(projects))
	for _, project := range projects {
		index[project.ID] = project
	}
	return index
}

func indexFindingsByRun(findings []domain.Finding) map[string][]domain.Finding {
	if len(findings) == 0 {
		return nil
	}
	index := make(map[string][]domain.Finding)
	for _, finding := range findings {
		index[finding.ScanID] = append(index[finding.ScanID], finding)
	}
	return index
}

func (snapshot portfolioSnapshot) projectLabel(projectID string) string {
	if project, ok := snapshot.ProjectsByID[projectID]; ok {
		return project.DisplayName
	}
	return projectID
}

func (snapshot portfolioSnapshot) findingsForRun(runID string) []domain.Finding {
	return snapshot.FindingsByRun[runID]
}

func (a *App) renderDashboardHeader(snapshot portfolioSnapshot) {
	runtime := a.runtimeStatus(false)
	pterm.Println(a.renderStaticBrandHero(a.catalog.T("overview_title")))
	pterm.Println()

	critical, high, open := 0, 0, 0
	queued, running, canceled := 0, 0, 0
	for _, finding := range snapshot.Findings {
		switch finding.Severity {
		case domain.SeverityCritical:
			critical++
		case domain.SeverityHigh:
			high++
		}
		if finding.Status == "" || finding.Status == domain.FindingOpen {
			open++
		}
	}
	for _, run := range snapshot.Runs {
		switch run.Status {
		case domain.ScanQueued:
			queued++
		case domain.ScanRunning:
			running++
		case domain.ScanCanceled:
			canceled++
		}
	}
	postureToken := a.portfolioPostureToken(snapshot)
	trend := a.runTrendLabel(snapshot.Runs, 8)
	hotFindings := a.prioritizedFindings(snapshot.Findings, 3)
	hotFindingSummary := a.catalog.T("overview_no_findings")
	if len(hotFindings) > 0 {
		lines := make([]string, 0, len(hotFindings))
		for _, finding := range hotFindings {
			lines = append(lines, a.hottestFindingLine(finding, 56))
		}
		hotFindingSummary = strings.Join(lines, "\n")
	}
	available, drift, missing, failed := runtimeToolHealthCounts(runtime)
	mirrorReady, mirrorMissing := runtimeMirrorHealth(runtime)

	_ = pterm.DefaultPanel.
		WithPadding(1).
		WithPanels(pterm.Panels{
			{
				{
					Data: a.ptermSprintf("%s\n\n%s: %s\n%s: [cyan]%d[-]\n%s: [cyan]%d[-]\n%s: [cyan]%s[-]\n%s: [cyan]%s[-]",
						pterm.LightCyan(a.catalog.T("overview_mission_brief")),
						a.catalog.T("status"),
						a.statusBadge(postureToken),
						a.catalog.T("projects_title"),
						len(snapshot.Projects),
						a.catalog.T("runs_title"),
						len(snapshot.Runs),
						a.catalog.T("overview_trendline"),
						trend,
						a.catalog.T("overview_operator_focus"),
						trimForSelect(a.recommendNextStep(snapshot), 88),
					),
				},
				{
					Data: a.ptermSprintf("%s\n\n%s: [cyan]%d[-]\n%s: [cyan]%d[-]\n%s: [cyan]%d[-]\n%s\n%s",
						pterm.LightCyan(a.catalog.T("overview_queue_brief")),
						a.catalog.T("status_queued"),
						queued,
						a.catalog.T("status_running"),
						running,
						a.catalog.T("status_canceled"),
						canceled,
						a.catalog.T("overview_recent_runs"),
						trimForSelect(a.renderQueueHeadlineFromSnapshot(snapshot, snapshot.Runs), 88),
					),
				},
				{
					Data: a.ptermSprintf("%s\n\n%s: %s\n%s: %s\n%s: [cyan]%d[-]\n%s: [cyan]%d[-]\n%s: [cyan]%d[-]\n%s: [cyan]%.1f[-]",
						pterm.LightCyan(a.catalog.T("overview_live_pressure")),
						a.catalog.T("summary_critical"),
						a.severityBadgeCount(domain.SeverityCritical, critical),
						a.catalog.T("summary_high"),
						a.severityBadgeCount(domain.SeverityHigh, high),
						a.catalog.T("triage_open"),
						open,
						a.catalog.T("suppress_list_title"),
						len(snapshot.Suppressions),
						a.catalog.T("finding_attack_chain_title"),
						countAttackChains(snapshot.Findings),
						a.catalog.T("finding_priority"),
						averagePriority(snapshot.Findings),
					),
				},
			},
			{
				{
					Data: a.ptermSprintf("%s\n\n%s: [green]%d[-]\n%s: [yellow]%d[-]\n%s: [yellow]%d[-]\n%s: [red]%d[-]\n%s: [cyan]%d/%d[-]",
						pterm.LightCyan(a.catalog.T("overview_trust_signal")),
						a.catalog.T("runtime_available"),
						available,
						a.catalog.T("runtime_doctor_outdated"),
						drift,
						a.catalog.T("runtime_missing"),
						missing,
						a.catalog.T("runtime_failed_tools"),
						failed,
						a.catalog.T("runtime_mirrors_title"),
						mirrorReady,
						mirrorReady+mirrorMissing,
					),
				},
				{
					Data: a.ptermSprintf("%s\n\n%s: %s\n%s: %s\n%s: [cyan]%d[-]\n%s: [cyan]%s[-]\n%s: [cyan]%s[-]",
						pterm.LightCyan(a.catalog.T("overview_runtime")),
						a.catalog.T("runtime_daemon_state"),
						a.daemonStateLabel(runtime.Daemon),
						a.catalog.T("runtime_effective_mode"),
						strings.ToUpper(string(runtime.Isolation.EffectiveMode)),
						a.catalog.T("runtime_daemon_pid"),
						runtime.Daemon.PID,
						a.catalog.T("runtime_output_dir"),
						a.cfg.OutputDir,
						a.catalog.T("data_dir"),
						a.cfg.DataDir,
					),
				},
				{
					Data: a.ptermSprintf("%s\n\n%s\n\n%s\n%s\n%s",
						pterm.LightCyan(a.catalog.T("overview_hot_findings")),
						hotFindingSummary,
						a.commandHint("console"),
						a.commandHint("runs", "gate", "<run-id>"),
						a.commandHint("export", "<run-id>", "--format", "html"),
					),
				},
			},
		}).Render()
}

func (a *App) renderRecentRunsOverview(snapshot portfolioSnapshot) error {
	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("overview_recent_runs"))
	if len(snapshot.Runs) == 0 {
		pterm.DefaultBasicText.Println(a.catalog.T("no_runs"))
		return nil
	}

	data := pterm.TableData{{a.catalog.T("title"), a.catalog.T("run_id"), a.catalog.T("status"), a.catalog.T("scan_mode"), a.catalog.T("started_at"), a.catalog.T("scan_findings"), a.catalog.T("finding_priority"), a.catalog.T("scan_blocked")}}
	for _, run := range limitRuns(snapshot.Runs, 5) {
		data = append(data, []string{
			snapshot.projectLabel(run.ProjectID),
			run.ID,
			a.statusBadge(string(run.Status)),
			a.modeBadge(run.Profile.Mode),
			run.StartedAt.Local().Format(time.RFC822),
			fmt.Sprintf("%d", run.Summary.TotalFindings),
			fmt.Sprintf("%.1f", averagePriority(snapshot.findingsForRun(run.ID))),
			ternary(run.Summary.Blocked, a.catalog.T("scan_blocked_yes"), a.catalog.T("scan_blocked_no")),
		})
	}
	return pterm.DefaultTable.WithHasHeader().WithData(data).Render()
}

func (a *App) renderRecentFindingsOverview(snapshot portfolioSnapshot) error {
	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("overview_recent_findings"))
	if len(snapshot.Findings) == 0 {
		pterm.DefaultBasicText.Println(a.catalog.T("overview_no_findings"))
		return nil
	}
	a.renderInlineFindingCards(a.prioritizedFindings(snapshot.Findings, 2), 2)

	data := pterm.TableData{{a.catalog.T("severity"), a.catalog.T("triage_status"), a.catalog.T("finding_priority"), a.catalog.T("finding_exposure_title"), a.catalog.T("title"), a.catalog.T("location"), a.catalog.T("title") + " / " + a.catalog.T("project_id")}}
	for _, finding := range limitFindings(a.prioritizedFindings(snapshot.Findings, 6), 6) {
		data = append(data, []string{
			a.severityBadge(finding.Severity),
			a.findingStatusBadge(finding.Status),
			fmt.Sprintf("%.1f", finding.Priority),
			trimForSelect(a.findingExposureSummary(finding), 36),
			trimForSelect(finding.Title, 56),
			trimForSelect(coalesceString(finding.Location, "-"), 42),
			snapshot.projectLabel(finding.ProjectID),
		})
	}
	return pterm.DefaultTable.WithHasHeader().WithData(data).Render()
}

func (a *App) renderRuntimeDetailsModern() error {
	runtime := a.runtimeStatus(false)
	snapshot := a.buildPortfolioSnapshot()
	available, drift, missing, failed := runtimeToolHealthCounts(runtime)
	mirrorReady, mirrorMissing := runtimeMirrorHealth(runtime)
	supported, partial, unsupported := runtimeSupportCounts(runtime.Support)
	operatorFocus := a.catalog.T("runtime_focus_ready")
	if missing > 0 || failed > 0 || runtime.SupplyChain.FailedAssets > 0 || runtime.SupplyChain.FailedTools > 0 {
		operatorFocus = a.catalog.T("runtime_focus_repair")
	} else if mirrorMissing > 0 {
		operatorFocus = a.catalog.T("runtime_focus_mirror")
	}

	pterm.Println(a.renderStaticBrandHero(a.catalog.T("runtime_command_title")))
	pterm.Println()
	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[green]%d[-]\n%s\n[yellow]%d[-]\n%s\n[red]%d[-]\n%s\n[cyan]%d[-]",
				a.catalog.T("runtime_trust_signal_title"),
				available,
				a.catalog.T("runtime_doctor_outdated"),
				drift,
				a.catalog.T("runtime_failed_tools"),
				failed,
				a.catalog.T("runtime_missing"),
				missing,
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]\n%s\n[cyan]%t[-]",
				a.catalog.T("runtime_control_plane_title"),
				a.daemonStateLabel(runtime.Daemon),
				a.catalog.T("runtime_effective_mode"),
				strings.ToUpper(string(runtime.Isolation.EffectiveMode)),
				a.catalog.T("runtime_engine"),
				coalesceString(runtime.Isolation.Engine, "-"),
				a.catalog.T("runtime_rootless"),
				runtime.Isolation.Rootless,
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]",
				a.catalog.T("runtime_storage_title"),
				a.cfg.OutputDir,
				a.catalog.T("data_dir"),
				a.cfg.DataDir,
				a.catalog.T("runtime_tools_dir"),
				a.cfg.ToolsDir,
				a.catalog.T("runtime_release_signal_title"),
				coalesceString(runtime.BundleLockPath, "-"),
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%d/%d[-]\n%s\n[cyan]%d[-]\n%s\n[cyan]%d/%d/%d[-]",
				a.catalog.T("overview_operator_focus"),
				operatorFocus,
				a.catalog.T("runtime_mirrors_title"),
				mirrorReady,
				mirrorReady+mirrorMissing,
				a.catalog.T("runtime_verified_assets"),
				runtime.SupplyChain.VerifiedAssets,
				a.catalog.T("runtime_support_title"),
				supported,
				partial,
				unsupported,
			)},
		},
	}).Render()

	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("runtime_scanners_title"))

	data := pterm.TableData{{a.catalog.T("scanner"), a.catalog.T("status"), a.catalog.T("runtime_verification"), a.catalog.T("runtime_channel"), a.catalog.T("runtime_expected_version"), a.catalog.T("runtime_actual_version"), a.catalog.T("binary_path")}}
	for _, tool := range runtime.ScannerBundle {
		status := a.statusBadge("missing")
		if tool.Available && tool.Verification.Status() == "failed" {
			status = a.statusBadge("failed")
		} else if tool.Available && tool.Healthy {
			status = a.statusBadge("available")
		} else if tool.Available {
			status = a.statusBadge("drift")
		}
		data = append(data, []string{
			tool.Name,
			status,
			a.verificationBadge(tool.Verification),
			strings.ToUpper(tool.Channel),
			coalesceString(tool.ExpectedVersion, "-"),
			coalesceString(tool.ActualVersion, "-"),
			coalesceString(tool.Path, "-"),
		})
	}
	if err := pterm.DefaultTable.WithHasHeader().WithData(data).Render(); err != nil {
		return err
	}

	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("runtime_isolation_contract_title"))
	contractData := pterm.TableData{{a.catalog.T("title"), a.catalog.T("status")}}
	for _, row := range a.isolationContractRows(runtime.Isolation.DefaultContract) {
		contractData = append(contractData, row)
	}
	if err := pterm.DefaultTable.WithHasHeader().WithData(contractData).Render(); err != nil {
		return err
	}

	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("runtime_support_title"))
	supportData := pterm.TableData{{a.catalog.T("title"), a.catalog.T("status")}}
	for _, row := range a.supportRows(runtime.Support) {
		if len(row) == 2 {
			supportData = append(supportData, row)
		}
	}
	if err := pterm.DefaultTable.WithHasHeader().WithData(supportData).Render(); err != nil {
		return err
	}

	if len(runtime.SupplyChain.ReleaseBundles) > 0 {
		pterm.Println()
		pterm.DefaultSection.Println(a.catalog.T("runtime_release_title"))
		releaseData := pterm.TableData{{a.catalog.T("title"), a.catalog.T("status"), a.catalog.T("artifact_count"), a.catalog.T("runtime_release_commit"), a.catalog.T("binary_path")}}
		for _, bundle := range runtime.SupplyChain.ReleaseBundles {
			releaseData = append(releaseData, []string{
				bundle.Version,
				a.releaseBundleStatusLabel(bundle),
				fmt.Sprintf("%d", bundle.ArtifactCount),
				coalesceString(trimForSelect(bundle.Provenance.Commit, 12), "-"),
				bundle.Path,
			})
		}
		if err := pterm.DefaultTable.WithHasHeader().WithData(releaseData).Render(); err != nil {
			return err
		}
	}

	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("runtime_artifact_protection_title"))
	artifactData := pterm.TableData{{a.catalog.T("title"), a.catalog.T("status")}}
	for _, row := range a.artifactProtectionRows(runtime.Artifacts) {
		artifactData = append(artifactData, row)
	}
	if err := pterm.DefaultTable.WithHasHeader().WithData(artifactData).Render(); err != nil {
		return err
	}

	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("runtime_supply_chain_title"))
	supplyChainData := pterm.TableData{{a.catalog.T("title"), a.catalog.T("status")}}
	for _, row := range a.supplyChainRows(runtime.SupplyChain) {
		supplyChainData = append(supplyChainData, row)
	}
	if err := pterm.DefaultTable.WithHasHeader().WithData(supplyChainData).Render(); err != nil {
		return err
	}

	if len(runtime.SupplyChain.TrustedAssets) > 0 {
		pterm.Println()
		pterm.DefaultSection.Println(a.catalog.T("runtime_trusted_assets_title"))
		assetData := pterm.TableData{{a.catalog.T("title"), a.catalog.T("kind"), a.catalog.T("status"), a.catalog.T("runtime_verification"), a.catalog.T("binary_path")}}
		for _, asset := range runtime.SupplyChain.TrustedAssets {
			assetData = append(assetData, []string{
				asset.Name,
				coalesceString(asset.Kind, "-"),
				a.trustedAssetVerificationLabel(asset),
				a.verificationDetailLabel(asset.Verification),
				asset.Path,
			})
		}
		if err := pterm.DefaultTable.WithHasHeader().WithData(assetData).Render(); err != nil {
			return err
		}
	}

	pterm.Println()
	pterm.DefaultSection.Println(a.catalog.T("runtime_mirrors_title"))
	mirrorData := pterm.TableData{{a.catalog.T("mirror_tool"), a.catalog.T("status"), a.catalog.T("artifact_uri"), a.catalog.T("mirror_updated_at"), a.catalog.T("mirror_notes")}}
	for _, mirror := range runtime.Mirrors {
		status := a.statusBadge("missing")
		if mirror.Available {
			status = a.statusBadge("available")
		}
		updatedAt := "-"
		if mirror.UpdatedAt != nil {
			updatedAt = mirror.UpdatedAt.Local().Format(time.RFC822)
		}
		mirrorData = append(mirrorData, []string{
			mirror.Tool,
			status,
			mirror.Path,
			updatedAt,
			coalesceString(mirror.Notes, "-"),
		})
	}
	if err := pterm.DefaultTable.WithHasHeader().WithData(mirrorData).Render(); err != nil {
		return err
	}

	if snapshot.MissingScanners > 0 || runtime.SupplyChain.FailedAssets > 0 || runtime.SupplyChain.FailedTools > 0 {
		pterm.Println()
		pterm.Warning.Println(a.catalog.T("runtime_install_hint"))
		pterm.Println(a.installCommandHint("safe"))
	}
	return nil
}

func (a *App) renderRuntimeDetailsPlain() error {
	fmt.Print(a.runtimePlainReport(a.runtimeStatus(false)))
	return nil
}

func (a *App) runtimePlainReport(runtime domain.RuntimeStatus) string {
	snapshot := a.buildPortfolioSnapshot()
	available, drift, missing, failed := runtimeToolHealthCounts(runtime)
	mirrorReady, mirrorMissing := runtimeMirrorHealth(runtime)
	supported, partial, unsupported := runtimeSupportCounts(runtime.Support)
	operatorFocus := a.catalog.T("runtime_focus_ready")
	if missing > 0 || failed > 0 || runtime.SupplyChain.FailedAssets > 0 || runtime.SupplyChain.FailedTools > 0 {
		operatorFocus = a.catalog.T("runtime_focus_repair")
	} else if mirrorMissing > 0 {
		operatorFocus = a.catalog.T("runtime_focus_mirror")
	}

	lines := []string{
		fmt.Sprintf("%s runtime", strings.ToUpper(brandProductName)),
		"",
		renderPlainStage(a.catalog.T("console_stage_launch"),
			fmt.Sprintf("%s: %s", a.catalog.T("status"), a.portfolioPosture(snapshot)),
			fmt.Sprintf("%s: %d %s, %d %s, %d %s, %d %s", a.catalog.T("runtime_trust_signal_title"), available, a.catalog.T("runtime_available"), drift, a.catalog.T("runtime_doctor_outdated"), missing, a.catalog.T("runtime_missing"), failed, a.catalog.T("runtime_failed_tools")),
			fmt.Sprintf("%s: %s", a.catalog.T("runtime_daemon_state"), a.daemonStateLabel(runtime.Daemon)),
			fmt.Sprintf("%s: %s", a.catalog.T("runtime_effective_mode"), strings.ToUpper(string(runtime.Isolation.EffectiveMode))),
		),
		"",
		renderPlainStage(a.catalog.T("console_stage_mission"),
			fmt.Sprintf("%s: %s", a.catalog.T("runtime_engine"), coalesceString(runtime.Isolation.Engine, "-")),
			fmt.Sprintf("%s: %t", a.catalog.T("runtime_rootless"), runtime.Isolation.Rootless),
			fmt.Sprintf("%s: %d/%d", a.catalog.T("runtime_mirrors_title"), mirrorReady, mirrorReady+mirrorMissing),
			fmt.Sprintf("%s: %d/%d/%d", a.catalog.T("runtime_support_title"), supported, partial, unsupported),
			fmt.Sprintf("%s: %s", a.catalog.T("runtime_scanners_title"), a.catalog.T("show_details")),
		),
	}
	for _, tool := range runtime.ScannerBundle {
		status := a.catalog.T("runtime_missing")
		switch {
		case tool.Available && tool.Verification.Status() == "failed":
			status = a.catalog.T("runtime_failed_tools")
		case tool.Available && tool.Healthy:
			status = a.catalog.T("runtime_available")
		case tool.Available:
			status = a.catalog.T("runtime_doctor_outdated")
		}
		lines = append(lines, fmt.Sprintf("- %s | %s | %s | %s", tool.Name, status, coalesceString(tool.ActualVersion, tool.ExpectedVersion), coalesceString(tool.Path, "-")))
	}
	lines = append(lines,
		"",
		renderPlainStage(a.catalog.T("console_stage_debrief"),
			fmt.Sprintf("%s: %s", a.catalog.T("runtime_output_dir"), a.cfg.OutputDir),
			fmt.Sprintf("%s: %s", a.catalog.T("data_dir"), a.cfg.DataDir),
			fmt.Sprintf("%s: %s", a.catalog.T("overview_operator_focus"), operatorFocus),
		),
		"",
	)
	return strings.Join(lines, "\n")
}

func (a *App) renderRuntimeReleasesView(version string) error {
	runtime := a.runtimeStatus(false)
	selectedBundles, err := selectRuntimeReleaseBundles(runtime.SupplyChain.ReleaseBundles, version)
	if err != nil {
		return fmt.Errorf("%s", a.catalog.T(err.Error(), version))
	}
	selected := selectedBundles[0]
	operatorFocus := a.catalog.T("runtime_release_focus_default")
	if !selected.Signed {
		operatorFocus = a.catalog.T("runtime_release_focus_sign")
	} else if selected.Attested {
		operatorFocus = a.catalog.T("runtime_release_focus_attested")
	}

	pterm.Println(a.renderStaticBrandHero(a.catalog.T("runtime_release_title")))
	pterm.Println()
	releaseTrust := a.catalog.T("runtime_verification_unconfigured")
	if selected.Signed {
		releaseTrust = a.releaseVerificationDetail(selected, selected.Attested)
	}
	artifactFocus := summarizeReleaseArtifacts(selected.Artifacts, 3)
	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("runtime_release_version"), selected.Version)},
			{Data: a.ptermSprintf("%s\n%s", a.catalog.T("status"), a.releaseBundleStatusLabel(selected))},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]\n%s\n[cyan]%s[-]", a.catalog.T("artifact_count"), selected.ArtifactCount, a.catalog.T("runtime_release_attested"), ternary(selected.Attested, a.yesText(), a.noText()))},
		},
		{
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("runtime_release_commit"), coalesceString(trimForSelect(selected.Provenance.Commit, 18), "-"))},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("runtime_release_ref"), coalesceString(selected.Provenance.Ref, "-"))},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("runtime_release_builder"), coalesceString(selected.Provenance.Builder, "-"))},
		},
		{
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("runtime_release_signal_title"), releaseTrust)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("runtime_release_external_attestation"), ternary(selected.ExternalAttested, a.yesText(), a.noText()))},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]",
				a.catalog.T("overview_operator_focus"),
				operatorFocus,
				a.catalog.T("overview_next_steps"),
				a.commandHint("runtime", "release", "verify", "--version", selected.Version),
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]",
				a.catalog.T("runtime_release_artifact_focus"),
				artifactFocus,
			)},
		},
	}).Render()

	pterm.Println()
	provData := pterm.TableData{{a.catalog.T("title"), a.catalog.T("status")}}
	provData = append(provData,
		[]string{a.catalog.T("runtime_release_go_version"), coalesceString(selected.Provenance.GoVersion, "-")},
		[]string{a.catalog.T("runtime_release_host_platform"), coalesceString(selected.Provenance.HostPlatform, "-")},
		[]string{a.catalog.T("runtime_release_repository"), coalesceString(selected.Provenance.Repository, "-")},
		[]string{a.catalog.T("runtime_release_workflow"), coalesceString(selected.Provenance.Workflow, "-")},
		[]string{a.catalog.T("runtime_release_run_id"), coalesceString(selected.Provenance.RunID, "-")},
		[]string{a.catalog.T("runtime_release_run_attempt"), coalesceString(selected.Provenance.RunAttempt, "-")},
		[]string{a.catalog.T("runtime_release_dirty"), ternary(selected.Provenance.SourceDirty, a.yesText(), a.noText())},
		[]string{a.catalog.T("artifact_uri"), coalesceString(selected.ManifestPath, "-")},
		[]string{a.catalog.T("runtime_release_checksums"), coalesceString(selected.ChecksumsPath, "-")},
		[]string{a.catalog.T("runtime_release_signature"), coalesceString(selected.SignaturePath, "-")},
		[]string{a.catalog.T("runtime_release_attestation"), coalesceString(selected.AttestationPath, "-")},
		[]string{a.catalog.T("runtime_release_attestation_signature"), coalesceString(selected.AttestationSignaturePath, "-")},
		[]string{a.catalog.T("runtime_release_attestation_status"), a.verificationBadge(selected.AttestationVerification)},
		[]string{a.catalog.T("runtime_release_external_provider"), coalesceString(selected.ExternalAttestationProvider, "-")},
		[]string{a.catalog.T("runtime_release_external_source_uri"), coalesceString(selected.ExternalAttestationSourceURI, "-")},
		[]string{a.catalog.T("runtime_release_external_attestation"), coalesceString(selected.ExternalAttestationPath, "-")},
		[]string{a.catalog.T("runtime_release_external_status"), a.verificationBadge(selected.ExternalAttestationVerification)},
	)
	if err := pterm.DefaultTable.WithHasHeader().WithData(provData).Render(); err != nil {
		return err
	}

	pterm.Println()
	artifactData := pterm.TableData{{a.catalog.T("title"), a.catalog.T("status"), a.catalog.T("artifact_uri"), a.catalog.T("size")}}
	for _, artifact := range selected.Artifacts {
		artifactData = append(artifactData, []string{
			artifact.Name,
			fmt.Sprintf("%s/%s %s", coalesceString(artifact.OS, "-"), coalesceString(artifact.Arch, "-"), coalesceString(artifact.Format, "-")),
			artifact.Path,
			fmt.Sprintf("%d", artifact.Size),
		})
	}
	return pterm.DefaultTable.WithHasHeader().WithData(artifactData).Render()
}

func (a *App) renderRuntimeLockCoverage(missingOnly bool) error {
	runtime := a.runtimeStatus(false)
	pterm.Println(a.renderStaticBrandHero(a.catalog.T("runtime_lock_title")))
	pterm.Println()
	total := len(runtime.SupplyChain.LockCoverage)
	checksumCovered := 0
	signatureCovered := 0
	sourceCovered := 0
	for _, entry := range runtime.SupplyChain.LockCoverage {
		if entry.ChecksumCovered {
			checksumCovered++
		}
		if entry.SignatureCovered {
			signatureCovered++
		}
		if entry.SourceIntegrityCovered {
			sourceCovered++
		}
	}
	operatorFocus := a.catalog.T("runtime_lock_focus_clean")
	if runtime.SupplyChain.IntegrityGapTools > 0 {
		operatorFocus = a.catalog.T("runtime_lock_focus_gap")
	}
	gapSummary := a.catalog.T("runtime_lock_no_gaps")
	if runtime.SupplyChain.IntegrityGapTools > 0 {
		missingEntries := make([]domain.RuntimeLockCoverage, 0)
		for _, entry := range runtime.SupplyChain.LockCoverage {
			if entry.ChecksumCovered || entry.SignatureCovered || entry.SourceIntegrityCovered {
				continue
			}
			missingEntries = append(missingEntries, entry)
		}
		names := make([]string, 0, len(missingEntries))
		for _, entry := range missingEntries {
			names = append(names, entry.Name)
		}
		if len(names) > 3 {
			gapSummary = strings.Join(names[:3], ", ") + fmt.Sprintf(" +%d", len(names)-3)
		} else {
			gapSummary = strings.Join(names, ", ")
		}
	}
	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]", a.catalog.T("runtime_lock_title"), total)},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]", a.catalog.T("runtime_checksum_label"), checksumCovered, a.catalog.T("runtime_signature_label"), signatureCovered)},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]", a.catalog.T("runtime_source_integrity_label"), sourceCovered, a.catalog.T("runtime_integrity_gap_tools"), runtime.SupplyChain.IntegrityGapTools)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]",
				a.catalog.T("overview_operator_focus"),
				operatorFocus,
				a.catalog.T("overview_next_steps"),
				a.commandHint("runtime", "doctor", "--require-integrity"),
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]",
				a.catalog.T("runtime_lock_gap_summary"),
				coalesceString(gapSummary, "-"),
			)},
		},
	}).Render()
	pterm.Println()

	data := pterm.TableData{{a.catalog.T("scanner"), a.catalog.T("runtime_channel"), a.catalog.T("runtime_expected_version"), a.catalog.T("runtime_checksum_label"), a.catalog.T("runtime_signature_label"), a.catalog.T("runtime_source_integrity_label"), a.catalog.T("runtime_lock_platforms"), a.catalog.T("runtime_lock_source")}}
	rows := 0
	for _, entry := range runtime.SupplyChain.LockCoverage {
		if missingOnly && (entry.ChecksumCovered || entry.SignatureCovered || entry.SourceIntegrityCovered) {
			continue
		}
		data = append(data, []string{
			entry.Name,
			strings.ToUpper(entry.Channel),
			coalesceString(entry.Version, "-"),
			ternary(entry.ChecksumCovered, a.statusBadge("verified"), a.statusBadge("unverified")),
			ternary(entry.SignatureCovered, a.statusBadge("verified"), a.statusBadge("unverified")),
			ternary(entry.SourceIntegrityCovered, a.statusBadge("verified"), a.statusBadge("unverified")),
			coalesceString(strings.Join(entry.Platforms, ", "), "-"),
			coalesceString(entry.Source, "-"),
		})
		rows++
	}
	if rows == 0 {
		pterm.Success.Println(a.catalog.T("runtime_lock_no_gaps"))
		return nil
	}
	return pterm.DefaultTable.WithHasHeader().WithData(data).Render()
}

func (a *App) verifyRuntimeReleases(version string, requireSignature, requireAttestation, requireExternalAttestation, requireCleanSource bool) error {
	runtime := a.runtimeStatus(false)
	selectedBundles, err := selectRuntimeReleaseBundles(runtime.SupplyChain.ReleaseBundles, version)
	if err != nil {
		return fmt.Errorf("%s", a.catalog.T(err.Error(), version))
	}

	pterm.Println(a.renderStaticBrandHero(a.catalog.T("runtime_release_verify_title")))
	pterm.Println()
	data := pterm.TableData{{a.catalog.T("runtime_release_version"), a.catalog.T("status"), a.catalog.T("runtime_verification"), a.catalog.T("artifact_count"), a.catalog.T("binary_path")}}
	failures := make([]string, 0)
	for _, bundle := range selectedBundles {
		issue := runtimeReleaseBundleIssue(bundle, requireSignature, requireAttestation, requireExternalAttestation, requireCleanSource)
		data = append(data, []string{
			bundle.Version,
			a.releaseBundleStatusLabel(bundle),
			coalesceString(issue, a.releaseVerificationDetail(bundle, requireAttestation)),
			fmt.Sprintf("%d", bundle.ArtifactCount),
			bundle.Path,
		})
		if issue != "" {
			failures = append(failures, fmt.Sprintf("%s (%s)", bundle.Version, issue))
		}
	}
	if err := pterm.DefaultTable.WithHasHeader().WithData(data).Render(); err != nil {
		return err
	}
	if len(failures) > 0 {
		return fmt.Errorf("%s", a.catalog.T("runtime_release_verify_failed", strings.Join(failures, "; ")))
	}
	pterm.Success.Println(a.catalog.T("runtime_release_verify_passed"))
	return nil
}

func (a *App) releaseVerificationDetail(bundle domain.RuntimeReleaseBundle, requireAttestation bool) string {
	parts := []string{a.verificationDetailLabel(bundle.Verification)}
	if requireAttestation && bundle.Attested {
		parts = append(parts, a.catalog.T("runtime_release_attestation"))
	}
	if bundle.ExternalAttested {
		parts = append(parts, a.catalog.T("runtime_release_external_attestation"))
	}
	return strings.Join(parts, " + ")
}

func selectRuntimeReleaseBundles(bundles []domain.RuntimeReleaseBundle, version string) ([]domain.RuntimeReleaseBundle, error) {
	if len(bundles) == 0 {
		return nil, fmt.Errorf("runtime_release_none")
	}
	if strings.TrimSpace(version) == "" {
		return bundles, nil
	}
	for _, bundle := range bundles {
		if bundle.Version == version {
			return []domain.RuntimeReleaseBundle{bundle}, nil
		}
	}
	return nil, fmt.Errorf("runtime_release_not_found")
}

func runtimeReleaseBundleIssue(bundle domain.RuntimeReleaseBundle, requireSignature, requireAttestation, requireExternalAttestation, requireCleanSource bool) string {
	if requireSignature && !bundle.Signed {
		return "signature required"
	}
	if requireAttestation && !bundle.Attested {
		return "attestation required"
	}
	if requireCleanSource && bundle.Provenance.SourceDirty {
		return "dirty source"
	}
	if requireExternalAttestation && !bundle.ExternalAttested {
		return "external attestation required"
	}
	if requireAttestation {
		switch bundle.AttestationVerification.Status() {
		case "failed":
			return coalesceString(bundle.AttestationVerification.Notes, "attestation verification failed")
		case "unverified":
			if requireSignature {
				return "attestation signature required"
			}
		}
		if requireSignature && bundle.Attested && !bundle.AttestationVerification.SignatureVerified {
			return "attestation signature required"
		}
	}
	if requireExternalAttestation && bundle.ExternalAttestationVerification.Status() == "failed" {
		return coalesceString(bundle.ExternalAttestationVerification.Notes, "external attestation verification failed")
	}
	switch bundle.Verification.Status() {
	case "verified":
		return ""
	case "failed":
		return coalesceString(bundle.Verification.Notes, "verification failed")
	default:
		if requireSignature {
			return "signature required"
		}
		return coalesceString(bundle.Verification.Notes, "verification incomplete")
	}
}

func (a *App) renderRuntimeSupportView(requested domain.CoverageProfile) error {
	runtime := a.runtimeStatus(false)
	if requested != "" {
		switch requested {
		case domain.CoverageCore, domain.CoveragePremium, domain.CoverageFull:
		default:
			return fmt.Errorf("unsupported coverage profile: %s", requested)
		}
	}

	pterm.Println(a.renderStaticBrandHero(a.catalog.T("runtime_support_title")))
	pterm.Println()
	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("runtime_support_platform"), runtime.Support.Platform)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]", a.catalog.T("runtime_support_recommended"), a.coverageLabel(runtime.Support.Recommended))},
		},
	}).Render()

	data := pterm.TableData{{a.catalog.T("coverage_profile"), a.catalog.T("status"), a.catalog.T("note")}}
	for _, tier := range runtime.Support.Tiers {
		status := a.statusBadge(string(tier.Level))
		data = append(data, []string{
			a.coverageLabel(tier.Coverage),
			status,
			coalesceString(tier.Notes, "-"),
		})
	}
	if err := pterm.DefaultTable.WithHasHeader().WithData(data).Render(); err != nil {
		return err
	}

	if requested != "" {
		if tier, ok := runtime.Support.Coverage(requested); ok {
			pterm.Println()
			switch tier.Level {
			case domain.RuntimeSupportUnsupported:
				pterm.Error.Printf("%s\n", a.catalog.T("runtime_support_requested_unsupported", a.coverageLabel(requested), runtime.Support.Platform))
			case domain.RuntimeSupportPartial:
				pterm.Warning.Printf("%s\n", a.catalog.T("runtime_support_requested_partial", a.coverageLabel(requested), runtime.Support.Platform, tier.Notes))
			default:
				pterm.Success.Printf("%s\n", a.catalog.T("runtime_support_requested_supported", a.coverageLabel(requested), runtime.Support.Platform))
			}
		}
	}

	return nil
}

func (a *App) renderRuntimeDoctor(doctor domain.RuntimeDoctor) {
	passedChecks, warningChecks, failedChecks, skippedChecks := runtimeDoctorCheckCounts(doctor)
	operatorFocus := a.catalog.T("runtime_focus_ready")
	if !doctor.Ready {
		operatorFocus = a.catalog.T("runtime_focus_repair")
	}
	issueSummary := a.catalog.T("runtime_doctor_issue_none")
	if !doctor.Ready {
		issueSummary = a.summarizeDoctorIssues(doctor, 4)
	}
	pterm.Println(a.renderStaticBrandHero(a.catalog.T("runtime_doctor_title")))
	pterm.Println()
	_ = pterm.DefaultPanel.WithPanels(pterm.Panels{
		{
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%t[-]\n%s\n[cyan]%t[-]\n%s\n%s",
				a.catalog.T("scan_mode"),
				strings.ToUpper(string(doctor.Mode)),
				a.catalog.T("runtime_doctor_strict_versions"),
				doctor.StrictVersions,
				a.catalog.T("runtime_doctor_require_integrity"),
				doctor.RequireIntegrity,
				a.catalog.T("status"),
				ternary(doctor.Ready, a.statusBadge("available"), a.statusBadge("failed")),
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]\n%s\n[cyan]%d[-]",
				a.catalog.T("runtime_doctor_required"),
				len(doctor.Required),
				a.catalog.T("runtime_doctor_missing"),
				len(doctor.Missing),
				a.catalog.T("runtime_doctor_outdated"),
				len(doctor.Outdated),
				a.catalog.T("runtime_doctor_integrity_gap"),
				len(doctor.Unverified),
				a.catalog.T("runtime_doctor_verification_failed"),
				len(doctor.FailedVerification)+len(doctor.FailedAssets),
			)},
			{Data: a.ptermSprintf("%s\n[green]%d[-]\n%s\n[yellow]%d[-]\n%s\n[red]%d[-]\n%s\n[gray]%d[-]",
				a.catalog.T("runtime_doctor_system_title"),
				passedChecks,
				a.catalog.T("runtime_doctor_system_warn"),
				warningChecks,
				a.catalog.T("runtime_doctor_system_failed"),
				failedChecks,
				a.catalog.T("runtime_doctor_system_skipped"),
				skippedChecks,
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]\n%s\n[cyan]%s[-]",
				a.catalog.T("overview_operator_focus"),
				operatorFocus,
				a.catalog.T("overview_next_steps"),
				a.installCommandHint(string(doctor.Mode)),
			)},
			{Data: a.ptermSprintf("%s\n[cyan]%s[-]",
				a.catalog.T("runtime_doctor_issue_summary"),
				issueSummary,
			)},
		},
	}).Render()

	if len(doctor.Required) > 0 {
		pterm.Println()
		pterm.DefaultSection.Println(a.catalog.T("runtime_scanners_title"))
		data := pterm.TableData{{a.catalog.T("scanner"), a.catalog.T("runtime_channel"), a.catalog.T("runtime_expected_version"), a.catalog.T("runtime_actual_version"), a.catalog.T("runtime_verification"), a.catalog.T("status")}}
		for _, tool := range doctor.Required {
			status := a.statusBadge("missing")
			if tool.Available && tool.Verification.Status() == "failed" {
				status = a.statusBadge("failed")
			} else if tool.Available && tool.Healthy {
				status = a.statusBadge("available")
			} else if tool.Available {
				status = a.statusBadge("drift")
			}
			data = append(data, []string{
				tool.Name,
				strings.ToUpper(tool.Channel),
				coalesceString(tool.ExpectedVersion, "-"),
				coalesceString(tool.ActualVersion, "-"),
				a.verificationBadge(tool.Verification),
				status,
			})
		}
		_ = pterm.DefaultTable.WithHasHeader().WithData(data).Render()
	}

	if len(doctor.Checks) > 0 {
		pterm.Println()
		pterm.DefaultSection.Println(a.catalog.T("runtime_doctor_system_title"))
		checkData := pterm.TableData{{a.catalog.T("title"), a.catalog.T("status"), a.catalog.T("runtime_doctor_details")}}
		for _, check := range doctor.Checks {
			detail := check.Summary
			if len(check.Details) > 0 {
				detail = strings.Join(check.Details, " | ")
			}
			checkData = append(checkData, []string{
				a.runtimeDoctorCheckLabel(check.Name),
				a.runtimeDoctorCheckStatusBadge(check.Status),
				trimForSelect(coalesceString(detail, "-"), 96),
			})
		}
		_ = pterm.DefaultTable.WithHasHeader().WithData(checkData).Render()
	}

	if len(doctor.FailedAssets) > 0 {
		pterm.Println()
		pterm.DefaultSection.Println(a.catalog.T("runtime_trusted_assets_title"))
		assetData := pterm.TableData{{a.catalog.T("title"), a.catalog.T("kind"), a.catalog.T("status"), a.catalog.T("binary_path")}}
		for _, asset := range doctor.FailedAssets {
			assetData = append(assetData, []string{
				asset.Name,
				coalesceString(asset.Kind, "-"),
				a.trustedAssetVerificationLabel(asset),
				asset.Path,
			})
		}
		_ = pterm.DefaultTable.WithHasHeader().WithData(assetData).Render()
	}

	if len(doctor.Missing) > 0 || len(doctor.Outdated) > 0 || len(doctor.Unverified) > 0 || len(doctor.FailedVerification) > 0 || len(doctor.FailedAssets) > 0 {
		pterm.Println()
		pterm.Warning.Println(a.catalog.T("runtime_install_hint"))
		pterm.Println(a.installCommandHint(string(doctor.Mode)))
	}
}

func (a *App) recommendNextStep(snapshot portfolioSnapshot) string {
	switch {
	case len(snapshot.Projects) == 0:
		return a.catalog.T("overview_hint_scan")
	case snapshot.MissingScanners > 0:
		return a.catalog.T("overview_hint_install")
	case len(snapshot.Findings) > 0:
		return a.catalog.T("overview_hint_review")
	default:
		return a.catalog.T("overview_hint_export")
	}
}

func (a *App) projectLabel(projectID string) string {
	project, ok := a.service.GetProject(projectID)
	if !ok {
		return projectID
	}
	return project.DisplayName
}

func limitRuns(items []domain.ScanRun, count int) []domain.ScanRun {
	if len(items) <= count {
		return items
	}
	return items[:count]
}

func limitFindings(items []domain.Finding, count int) []domain.Finding {
	if len(items) <= count {
		return items
	}
	return items[:count]
}

func coalesceString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
