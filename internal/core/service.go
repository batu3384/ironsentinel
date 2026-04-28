package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/batu3384/ironsentinel/internal/agent"
	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
	"github.com/batu3384/ironsentinel/internal/i18n"
	"github.com/batu3384/ironsentinel/internal/policy"
	"github.com/batu3384/ironsentinel/internal/reports"
	"github.com/batu3384/ironsentinel/internal/sbom"
	"github.com/batu3384/ironsentinel/internal/store"
	"github.com/batu3384/ironsentinel/internal/util"
	"github.com/batu3384/ironsentinel/internal/vex"
)

type Service struct {
	config config.Config
	store  *store.StateStore
	agent  *agent.Service
}

type PortfolioData struct {
	Runs         []domain.ScanRun
	Findings     []domain.Finding
	Suppressions []domain.Suppression
	Triage       []domain.FindingTriage
}

func New(cfg config.Config) (*Service, error) {
	stateStore, err := store.NewStateStore(filepath.Join(cfg.DataDir, "state.db"))
	if err != nil {
		return nil, err
	}

	return &Service{
		config: cfg,
		store:  stateStore,
		agent:  agent.NewService(cfg),
	}, nil
}

func (s *Service) Runtime() domain.RuntimeStatus {
	status := s.agent.RuntimeStatus()
	status.SocketPath = "embedded"
	return status
}

func (s *Service) RuntimeDoctor(profile domain.ScanProfile, strictVersions, requireIntegrity bool) domain.RuntimeDoctor {
	return s.augmentRuntimeDoctor(s.agent.RuntimeDoctor(profile, strictVersions, requireIntegrity))
}

func (s *Service) RefreshMirror(tool string) (domain.RuntimeMirror, error) {
	return s.agent.RefreshMirror(tool)
}

func (s *Service) ResolveIsolationContract(profile domain.ScanProfile) domain.IsolationContract {
	return s.agent.ResolveIsolationContract(profile)
}

func (s *Service) EnsureProject(ctx context.Context, path, displayName string, picker bool) (domain.Project, bool, error) {
	target, err := s.agent.ResolveTarget(ctx, domain.ResolveTargetRequest{
		Path:        path,
		Interactive: picker,
		DisplayName: displayName,
	})
	if err != nil {
		return domain.Project{}, false, err
	}

	if existing, ok := s.store.FindProjectByHandle(target.Handle); ok {
		return existing, true, nil
	}

	project := domain.Project{
		ID:             util.NewID("prj"),
		TargetHandle:   target.Handle,
		DisplayName:    target.DisplayName,
		DetectedStacks: target.DetectedStacks,
		LocationHint:   target.Path,
		CreatedAt:      time.Now().UTC(),
	}
	if err := s.store.CreateProject(project); err != nil {
		return domain.Project{}, false, err
	}
	return project, false, nil
}

func (s *Service) ListProjects() []domain.Project {
	return s.store.ListProjects()
}

func (s *Service) GetProject(id string) (domain.Project, bool) {
	return s.store.GetProject(id)
}

func (s *Service) ListRuns() []domain.ScanRun {
	runs := s.store.ListRuns()
	applyRunSummaries(runs, s.loadFindings(""))
	return runs
}

func (s *Service) PortfolioData() PortfolioData {
	findings := s.loadFindings("")
	runs := s.store.ListRuns()
	applyRunSummaries(runs, findings)
	return PortfolioData{
		Runs:         runs,
		Findings:     findings,
		Suppressions: s.store.ListSuppressions(),
		Triage:       s.store.ListTriage(),
	}
}

func (s *Service) GetRun(id string) (domain.ScanRun, bool) {
	run, ok := s.store.GetRun(id)
	if !ok {
		return domain.ScanRun{}, false
	}
	run.Summary = domain.RecalculateSummary(s.loadFindings(run.ID), run.Profile.SeverityGate)
	return run, true
}

func (s *Service) GetRunExecutionTraces(runID string) ([]domain.ModuleExecutionTrace, error) {
	run, ok := s.GetRun(runID)
	if !ok {
		return nil, fmt.Errorf("run not found: %s", runID)
	}
	return loadExecutionTraces(run), nil
}

func (s *Service) GetRunDelta(runID, baselineRunID string) (domain.RunDelta, domain.ScanRun, *domain.ScanRun, error) {
	current, ok := s.GetRun(runID)
	if !ok {
		return domain.RunDelta{}, domain.ScanRun{}, nil, fmt.Errorf("run not found: %s", runID)
	}

	baseline, err := s.resolveBaselineRun(current, baselineRunID)
	if err != nil {
		return domain.RunDelta{}, domain.ScanRun{}, nil, err
	}

	currentFindings := s.loadFindings(current.ID)
	var baselineFindings []domain.Finding
	if baseline != nil {
		baselineFindings = s.loadFindings(baseline.ID)
	}

	delta := domain.CalculateRunDelta(currentFindings, baselineFindings, current.ID, baselineIDValue(baseline), current.ProjectID)
	return delta, current, baseline, nil
}

func (s *Service) EvaluateGate(runID, baselineRunID string, threshold domain.Severity) (domain.RunDelta, domain.ScanRun, *domain.ScanRun, []domain.Finding, error) {
	return s.EvaluateGateWithVEX(runID, baselineRunID, threshold, "")
}

func (s *Service) EvaluatePolicy(runID, baselineRunID, policyID string) (domain.PolicyEvaluation, domain.ScanRun, *domain.ScanRun, error) {
	return s.EvaluatePolicyWithVEX(runID, baselineRunID, policyID, "")
}

func (s *Service) EvaluateGateWithVEX(runID, baselineRunID string, threshold domain.Severity, vexPath string) (domain.RunDelta, domain.ScanRun, *domain.ScanRun, []domain.Finding, error) {
	delta, current, baseline, _, err := s.getRunDeltaWithVEX(runID, baselineRunID, vexPath)
	if err != nil {
		return domain.RunDelta{}, domain.ScanRun{}, nil, nil, err
	}

	blocking := domain.FilterFindingsAtOrAboveSeverity(delta.NewFindings, threshold)
	filtered := make([]domain.Finding, 0, len(blocking))
	for _, finding := range blocking {
		if vex.SuppressesFinding(finding) {
			continue
		}
		filtered = append(filtered, finding)
	}
	return delta, current, baseline, filtered, nil
}

func (s *Service) EvaluatePolicyWithVEX(runID, baselineRunID, policyID, vexPath string) (domain.PolicyEvaluation, domain.ScanRun, *domain.ScanRun, error) {
	delta, current, baseline, _, err := s.getRunDeltaWithVEX(runID, baselineRunID, vexPath)
	if err != nil {
		return domain.PolicyEvaluation{}, domain.ScanRun{}, nil, err
	}

	pack := policy.Builtin(policyID)
	evaluation := policy.Evaluate(pack, current.ID, baselineIDValue(baseline), s.loadFindingsWithVEX(current, vexPath), delta)
	return evaluation, current, baseline, nil
}

func (s *Service) ListFindings(runID string) []domain.Finding {
	return s.loadFindings(runID)
}

func (s *Service) GetFinding(runID, fingerprint string) (domain.Finding, bool) {
	finding, ok := s.store.FindFinding(runID, fingerprint)
	if !ok {
		return domain.Finding{}, false
	}
	return s.enrichStoredFinding(finding), true
}

func (s *Service) ListSuppressions() []domain.Suppression {
	return s.store.ListSuppressions()
}

func (s *Service) ListTriage() []domain.FindingTriage {
	return s.store.ListTriage()
}

func (s *Service) SaveSuppression(suppression domain.Suppression) error {
	return s.store.SaveSuppression(suppression)
}

func (s *Service) DeleteSuppression(fingerprint string) error {
	return s.store.DeleteSuppression(fingerprint)
}

func (s *Service) SaveFindingTriage(triage domain.FindingTriage) error {
	return s.store.SaveFindingTriage(triage)
}

func (s *Service) DeleteFindingTriage(fingerprint string) error {
	return s.store.DeleteFindingTriage(fingerprint)
}

func (s *Service) CreateCampaign(input domain.Campaign) (domain.Campaign, error) {
	if strings.TrimSpace(input.Title) == "" {
		return domain.Campaign{}, errors.New("campaign title is required")
	}
	if _, ok := s.store.GetProject(input.ProjectID); !ok {
		return domain.Campaign{}, fmt.Errorf("project not found: %s", input.ProjectID)
	}
	if strings.TrimSpace(input.SourceRunID) == "" {
		return domain.Campaign{}, errors.New("campaign source run is required")
	}
	run, ok := s.store.GetRun(input.SourceRunID)
	if !ok {
		return domain.Campaign{}, fmt.Errorf("campaign source run not found: %s", input.SourceRunID)
	}
	if run.ProjectID != input.ProjectID {
		return domain.Campaign{}, fmt.Errorf("campaign source run %s does not belong to project %s", input.SourceRunID, input.ProjectID)
	}
	if strings.TrimSpace(input.BaselineRunID) != "" {
		baseline, ok := s.store.GetRun(input.BaselineRunID)
		if !ok {
			return domain.Campaign{}, fmt.Errorf("campaign baseline run not found: %s", input.BaselineRunID)
		}
		if baseline.ProjectID != input.ProjectID {
			return domain.Campaign{}, fmt.Errorf("campaign baseline run %s does not belong to project %s", input.BaselineRunID, input.ProjectID)
		}
	}
	fingerprints, err := s.resolveCampaignFingerprints(input.ProjectID, input.SourceRunID, input.FindingFingerprints)
	if err != nil {
		return domain.Campaign{}, err
	}
	now := time.Now().UTC()
	campaign := domain.NewCampaign(
		input.ID,
		input.ProjectID,
		input.Title,
		input.Summary,
		input.SourceRunID,
		input.BaselineRunID,
		fingerprints,
		now,
	)
	if err := s.store.SaveCampaign(campaign); err != nil {
		return domain.Campaign{}, err
	}
	return campaign, nil
}

func (s *Service) AddFindingsToCampaign(campaignID string, fingerprints []string) (domain.Campaign, error) {
	campaign, ok := s.store.GetCampaign(campaignID)
	if !ok {
		return domain.Campaign{}, fmt.Errorf("campaign not found: %s", campaignID)
	}
	resolved, err := s.resolveCampaignFingerprints(campaign.ProjectID, campaign.SourceRunID, fingerprints)
	if err != nil {
		return domain.Campaign{}, err
	}
	return s.store.UpdateCampaign(campaignID, func(campaign domain.Campaign) (domain.Campaign, error) {
		combined := append(append([]string(nil), campaign.FindingFingerprints...), resolved...)
		now := time.Now().UTC()
		updated := domain.NewCampaign(
			campaign.ID,
			campaign.ProjectID,
			campaign.Title,
			campaign.Summary,
			campaign.SourceRunID,
			campaign.BaselineRunID,
			combined,
			now,
		)
		updated.Status = campaign.Status
		updated.Owner = campaign.Owner
		updated.DueAt = campaign.DueAt
		updated.PublishedIssues = campaign.PublishedIssues
		updated.CreatedAt = campaign.CreatedAt
		updated.UpdatedAt = now
		return updated, nil
	})
}

func (s *Service) resolveCampaignFingerprints(projectID, runID string, fingerprints []string) ([]string, error) {
	resolved := make([]string, 0, len(fingerprints))
	for _, fingerprint := range fingerprints {
		fingerprint = strings.TrimSpace(fingerprint)
		if fingerprint == "" {
			continue
		}

		finding, ok := s.store.FindFinding(runID, fingerprint)
		if !ok {
			if strings.TrimSpace(runID) != "" {
				return nil, fmt.Errorf("campaign finding not found in run %s: %s", runID, fingerprint)
			}
			return nil, fmt.Errorf("campaign finding not found: %s", fingerprint)
		}
		if finding.ProjectID != projectID {
			return nil, fmt.Errorf("campaign finding %s does not belong to project %s", fingerprint, projectID)
		}
		resolved = append(resolved, fingerprint)
	}
	if len(resolved) == 0 {
		return nil, errors.New("campaign requires at least one valid finding fingerprint")
	}
	return resolved, nil
}

func (s *Service) Export(runID, format, baselineRunID string) (string, error) {
	return s.ExportWithVEX(runID, format, baselineRunID, "")
}

func (s *Service) ExportWithVEX(runID, format, baselineRunID, vexPath string) (string, error) {
	return s.ExportWithVEXAndLanguage(runID, format, baselineRunID, vexPath, i18n.EN)
}

func (s *Service) ExportWithVEXAndLanguage(runID, format, baselineRunID, vexPath string, language i18n.Language) (string, error) {
	report, err := s.BuildRunReportWithVEX(runID, baselineRunID, vexPath)
	if err != nil {
		return "", err
	}
	return reports.ExportLocalized(format, report, language)
}

func (s *Service) BuildRunReport(runID, baselineRunID string) (domain.RunReport, error) {
	return s.BuildRunReportWithVEX(runID, baselineRunID, "")
}

func (s *Service) BuildRunReportWithVEX(runID, baselineRunID, vexPath string) (domain.RunReport, error) {
	delta, run, baseline, vexSummary, err := s.getRunDeltaWithVEX(runID, baselineRunID, vexPath)
	if err != nil {
		return domain.RunReport{}, err
	}
	findings := s.loadFindingsWithVEX(run, vexPath)
	run.Summary = domain.RecalculateSummary(findings, run.Profile.SeverityGate)

	report := domain.RunReport{
		Run:             run,
		Baseline:        baseline,
		Findings:        make([]domain.RunReportFinding, 0, len(findings)),
		Delta:           delta,
		Trends:          trendPointsForProject(s.store.ListRuns(), run.ProjectID),
		ModuleStats:     reports.ModuleExecutionStats(run.ModuleResults),
		ModuleSummaries: reports.BuildModuleSummaries(run.ModuleResults),
		VEX:             vexSummary,
	}
	changeByFingerprint := reports.BuildChangeIndex(delta)
	for _, finding := range findings {
		report.Findings = append(report.Findings, domain.RunReportFinding{
			Finding: finding,
			Change:  reports.DefaultChange(changeByFingerprint[finding.Fingerprint]),
		})
	}
	return report, nil
}

func (s *Service) loadFindings(runID string) []domain.Finding {
	return s.enrichStoredFindings(s.store.ListFindings(runID))
}

func (s *Service) loadFindingsWithVEX(run domain.ScanRun, vexPath string) []domain.Finding {
	findings := s.loadFindings(run.ID)
	if strings.TrimSpace(vexPath) == "" {
		return findings
	}
	document, err := loadOpenVEX(vexPath)
	if err != nil {
		return findings
	}
	applied, _ := vex.Apply(findings, document, sbom.ProductsByComponentName(run.ArtifactRefs))
	return applied
}

func loadOpenVEX(path string) (vex.Document, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return vex.Document{}, err
	}
	return vex.ParseOpenVEX(body)
}

func (s *Service) getRunDeltaWithVEX(runID, baselineRunID, vexPath string) (domain.RunDelta, domain.ScanRun, *domain.ScanRun, domain.VEXSummary, error) {
	current, ok := s.store.GetRun(runID)
	if !ok {
		return domain.RunDelta{}, domain.ScanRun{}, nil, domain.VEXSummary{}, fmt.Errorf("run not found: %s", runID)
	}

	baseline, err := s.resolveBaselineRun(current, baselineRunID)
	if err != nil {
		return domain.RunDelta{}, domain.ScanRun{}, nil, domain.VEXSummary{}, err
	}

	currentFindings := s.loadFindings(current.ID)
	var summary domain.VEXSummary
	if strings.TrimSpace(vexPath) != "" {
		document, err := loadOpenVEX(vexPath)
		if err != nil {
			return domain.RunDelta{}, domain.ScanRun{}, nil, domain.VEXSummary{}, err
		}
		currentFindings, summary = vex.Apply(currentFindings, document, sbom.ProductsByComponentName(current.ArtifactRefs))
	}

	var baselineFindings []domain.Finding
	if baseline != nil {
		baselineFindings = s.loadFindings(baseline.ID)
		if strings.TrimSpace(vexPath) != "" {
			document, err := loadOpenVEX(vexPath)
			if err != nil {
				return domain.RunDelta{}, domain.ScanRun{}, nil, domain.VEXSummary{}, err
			}
			baselineFindings, _ = vex.Apply(baselineFindings, document, sbom.ProductsByComponentName(baseline.ArtifactRefs))
		}
	}

	delta := domain.CalculateRunDelta(currentFindings, baselineFindings, current.ID, baselineIDValue(baseline), current.ProjectID)
	return delta, current, baseline, summary, nil
}

func (s *Service) enrichStoredFindings(findings []domain.Finding) []domain.Finding {
	if len(findings) == 0 {
		return nil
	}

	projects := s.store.ListProjects()
	projectByID := make(map[string]domain.Project, len(projects))
	for _, project := range projects {
		projectByID[project.ID] = project
	}

	indexesByProject := make(map[string][]int)
	findingsByProject := make(map[string][]domain.Finding)
	for index, finding := range findings {
		indexesByProject[finding.ProjectID] = append(indexesByProject[finding.ProjectID], index)
		findingsByProject[finding.ProjectID] = append(findingsByProject[finding.ProjectID], finding)
	}

	enriched := make([]domain.Finding, len(findings))
	for projectID, items := range findingsByProject {
		project, ok := projectByID[projectID]
		if !ok {
			project, _ = s.store.GetProject(projectID)
		}
		group := enrichFindings(project, items)
		for offset, findingIndex := range indexesByProject[projectID] {
			enriched[findingIndex] = group[offset]
		}
	}

	for index, finding := range enriched {
		if finding.ID != "" || finding.Fingerprint != "" {
			continue
		}
		project, _ := s.store.GetProject(findings[index].ProjectID)
		enriched[index] = enrichFinding(project, findings[index])
	}
	return enriched
}

func (s *Service) enrichStoredFinding(finding domain.Finding) domain.Finding {
	project, _ := s.store.GetProject(finding.ProjectID)
	return enrichFinding(project, finding)
}

func (s *Service) EnqueueScan(projectID string, profile domain.ScanProfile) (domain.ScanRun, error) {
	if _, ok := s.store.GetProject(projectID); !ok {
		return domain.ScanRun{}, fmt.Errorf("project not found: %s", projectID)
	}
	run := s.newRun(projectID, profile, domain.ScanQueued, "queue", "")
	if err := s.store.CreateRun(run); err != nil {
		return domain.ScanRun{}, err
	}
	return run, nil
}

func (s *Service) ScheduleScan(projectID string, profile domain.ScanProfile) (domain.ScanRun, error) {
	if _, ok := s.store.GetProject(projectID); !ok {
		return domain.ScanRun{}, fmt.Errorf("project not found: %s", projectID)
	}
	run := s.newRun(projectID, profile, domain.ScanQueued, "scheduled", "")
	if err := s.store.CreateRun(run); err != nil {
		return domain.ScanRun{}, err
	}
	return run, nil
}

func (s *Service) CancelRun(runID string) (domain.ScanRun, error) {
	run, ok, err := s.store.MarkRunCancelRequested(runID)
	if err != nil {
		return domain.ScanRun{}, err
	}
	if !ok {
		return domain.ScanRun{}, fmt.Errorf("run not found: %s", runID)
	}
	return run, nil
}

func (s *Service) RetryFailedRun(runID string) (domain.ScanRun, error) {
	run, ok := s.store.GetRun(runID)
	if !ok {
		return domain.ScanRun{}, fmt.Errorf("run not found: %s", runID)
	}
	if run.Status != domain.ScanFailed && run.Status != domain.ScanCanceled {
		return domain.ScanRun{}, fmt.Errorf("run is not retryable from status: %s", run.Status)
	}

	retryRun := s.newRun(run.ProjectID, run.Profile, domain.ScanQueued, "queue", run.ID)
	if err := s.store.CreateRun(retryRun); err != nil {
		return domain.ScanRun{}, err
	}
	return retryRun, nil
}

func (s *Service) RunQueueWorker(ctx context.Context, once bool, onEvent func(domain.StreamEvent)) error {
	idleTicker := time.NewTicker(500 * time.Millisecond)
	defer idleTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		run, ok, err := s.store.ClaimNextQueuedRun()
		if err != nil {
			return err
		}
		if !ok {
			if once {
				return nil
			}
			select {
			case <-ctx.Done():
				return nil
			case <-idleTicker.C:
				continue
			}
		}

		s.emit(onEvent, domain.StreamEvent{Type: "run.updated", Run: run, Message: "Queued scan claimed by worker.", At: time.Now().UTC()})
		if project, exists := s.store.GetProject(run.ProjectID); exists {
			s.emit(onEvent, domain.StreamEvent{Type: "run.updated", Run: run, Message: "Scan started.", At: time.Now().UTC()})
			_, _, execErr := s.executeRun(ctx, run, project, onEvent)
			if execErr != nil {
				if ctx.Err() != nil && errors.Is(execErr, context.Canceled) {
					return nil
				}
				return execErr
			}
		} else {
			now := time.Now().UTC()
			run.Status = domain.ScanFailed
			run.FinishedAt = &now
			run.Summary = domain.NewScanSummary()
			if err := persistRunUpdate(run, s.store.UpdateRun, "missing-project terminal state"); err != nil {
				return err
			}
			s.emit(onEvent, domain.StreamEvent{Type: "run.failed", Run: run, Message: fmt.Sprintf("project not found: %s", run.ProjectID), At: now})
		}
	}
}

func applyRunSummaries(runs []domain.ScanRun, findings []domain.Finding) {
	if len(runs) == 0 {
		return
	}

	summaries := make(map[string]domain.ScanSummary, len(runs))
	gates := make(map[string]int, len(runs))
	for _, run := range runs {
		summaries[run.ID] = domain.NewScanSummary()
		gates[run.ID] = domain.SeverityRank(run.Profile.SeverityGate)
	}

	for _, finding := range findings {
		summary, ok := summaries[finding.ScanID]
		if !ok {
			continue
		}
		status := finding.Status
		if status == "" {
			status = domain.FindingOpen
		}
		summary.TotalFindings++
		summary.CountsBySeverity[finding.Severity]++
		summary.CountsByCategory[finding.Category]++
		summary.CountsByStatus[status]++
		if domain.SeverityRank(finding.Severity) <= gates[finding.ScanID] {
			summary.Blocked = true
		}
		summaries[finding.ScanID] = summary
	}

	for index := range runs {
		runs[index].Summary = summaries[runs[index].ID]
	}
}

func (s *Service) DASTPlan(projectID string, targets []domain.DastTarget, authProfiles []domain.DastAuthProfile, active bool) domain.DastPlan {
	policy := "baseline"
	if active {
		policy = "active"
	} else if len(targets) > 0 {
		policy = "authenticated"
	}

	steps := []string{
		"Validate ownership of each target before any authenticated or active probe.",
		"Import OpenAPI or route manifests when available to improve crawl coverage.",
		"Start with passive ZAP baseline, then switch to active checks only on staging targets.",
		"Allow signed Nuclei templates only and normalize evidence into the unified finding model.",
	}

	for _, target := range targets {
		resolvedTarget, authProfile, err := domain.ResolveDastTargetAuth(target, authProfiles)
		if err != nil || authProfile == nil {
			continue
		}
		authStep := fmt.Sprintf(
			"Bind target %s to auth profile %s (%s) before crawl expansion.",
			resolvedTarget.Name,
			authProfile.Name,
			authProfile.Type.String(),
		)
		steps = append(steps, authStep)
		if authProfile.SessionCheckURL != "" {
			steps = append(steps, fmt.Sprintf("Verify the session against %s before active probes.", authProfile.SessionCheckURL))
		}
	}

	return domain.DastPlan{
		ProjectID: projectID,
		Policy:    policy,
		Steps:     steps,
	}
}

func (s *Service) Scan(ctx context.Context, projectID string, profile domain.ScanProfile, onEvent func(domain.StreamEvent)) (domain.ScanRun, []domain.Finding, error) {
	project, ok := s.store.GetProject(projectID)
	if !ok {
		return domain.ScanRun{}, nil, fmt.Errorf("project not found: %s", projectID)
	}

	run := s.newRun(project.ID, profile, domain.ScanQueued, "foreground", "")
	if err := s.store.CreateRun(run); err != nil {
		return domain.ScanRun{}, nil, err
	}
	s.emit(onEvent, domain.StreamEvent{Type: "run.updated", Run: run, Message: "Scan queued.", At: time.Now().UTC()})

	run.Status = domain.ScanRunning
	run.StartedAt = time.Now().UTC()
	if err := s.store.UpdateRun(run); err != nil {
		return domain.ScanRun{}, nil, err
	}
	s.emit(onEvent, domain.StreamEvent{Type: "run.updated", Run: run, Message: "Scan started.", At: time.Now().UTC()})

	return s.executeRun(ctx, run, project, onEvent)
}

func (s *Service) newRun(projectID string, profile domain.ScanProfile, status domain.ScanStatus, executionMode, retryOf string) domain.ScanRun {
	return domain.ScanRun{
		ID:               util.NewID("run"),
		ProjectID:        projectID,
		Status:           status,
		StartedAt:        time.Now().UTC(),
		Summary:          domain.NewScanSummary(),
		ArtifactRefs:     nil,
		ModuleResults:    nil,
		Profile:          profile,
		RetriedFromRunID: retryOf,
		ExecutionMode:    executionMode,
	}
}

func (s *Service) executeRun(ctx context.Context, run domain.ScanRun, project domain.Project, onEvent func(domain.StreamEvent)) (domain.ScanRun, []domain.Finding, error) {
	execCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go s.watchRunCancellation(execCtx, run.ID, cancel)

	err := s.agent.StreamScan(execCtx, domain.AgentScanRequest{
		ScanID:       run.ID,
		ProjectID:    project.ID,
		TargetHandle: project.TargetHandle,
		TargetPath:   project.LocationHint,
		DisplayName:  project.DisplayName,
		Profile:      run.Profile,
	}, func(event domain.AgentEvent) error {
		current, ok := s.store.GetRun(run.ID)
		if !ok {
			return fmt.Errorf("run disappeared: %s", run.ID)
		}

		switch event.Type {
		case "module.queued", "module.started", "module.completed", "module.execution":
			if event.Module != nil {
				current.ModuleResults = upsertModuleResult(current.ModuleResults, *event.Module)
				current.ArtifactRefs = appendArtifactRefsUnique(current.ArtifactRefs, event.Module.Artifacts...)
			}
		case "finding.created":
			if event.Finding != nil {
				finding := enrichFinding(project, *event.Finding)
				if err := s.store.AddFinding(finding); err != nil {
					return err
				}
				event.Finding = &finding
			}
		case "scan.completed":
			now := time.Now().UTC()
			current.Status = domain.ScanCompleted
			current.FinishedAt = &now
		case "scan.failed":
			now := time.Now().UTC()
			current.Status = domain.ScanFailed
			current.FinishedAt = &now
		}

		current.Summary = domain.RecalculateSummary(s.store.ListFindings(run.ID), current.Profile.SeverityGate)
		if err := s.store.UpdateRun(current); err != nil {
			return err
		}
		s.emit(onEvent, domain.StreamEvent{
			Type:      mapAgentEventType(event.Type),
			Run:       current,
			Module:    event.Module,
			Finding:   event.Finding,
			Attempt:   event.Attempt,
			Execution: event.Execution,
			Message:   event.Message,
			At:        event.At,
		})
		return nil
	})

	finalRun, _ := s.store.GetRun(run.ID)
	if err != nil {
		now := time.Now().UTC()
		if current, ok := s.store.GetRun(run.ID); ok {
			finalRun = current
		}
		if finalRun.CancelRequested || errors.Is(err, context.Canceled) {
			finalRun.Status = domain.ScanCanceled
		} else {
			finalRun.Status = domain.ScanFailed
		}
		finalRun.FinishedAt = &now
		finalRun.Summary = domain.RecalculateSummary(s.store.ListFindings(run.ID), finalRun.Profile.SeverityGate)
		if updateErr := persistRunUpdate(finalRun, s.store.UpdateRun, "terminal run state"); updateErr != nil {
			return finalRun, s.store.ListFindings(run.ID), fmt.Errorf("scan finished with %s and final state persistence failed: %w", finalRun.Status, updateErr)
		}
		eventType := "run.failed"
		message := err.Error()
		if finalRun.Status == domain.ScanCanceled {
			eventType = "run.canceled"
			message = "Scan canceled."
		}
		s.emit(onEvent, domain.StreamEvent{Type: eventType, Run: finalRun, Message: message, At: time.Now().UTC()})
		return finalRun, s.store.ListFindings(run.ID), err
	}

	finalRun, _ = s.store.GetRun(run.ID)
	return finalRun, s.store.ListFindings(run.ID), nil
}

func (s *Service) watchRunCancellation(ctx context.Context, runID string, cancel context.CancelFunc) {
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run, ok := s.store.GetRun(runID)
			if ok && run.CancelRequested {
				cancel()
				return
			}
		}
	}
}

func (s *Service) emit(callback func(domain.StreamEvent), event domain.StreamEvent) {
	if callback != nil {
		callback(event)
	}
}

func persistRunUpdate(run domain.ScanRun, updater func(domain.ScanRun) error, contextLabel string) error {
	if err := updater(run); err != nil {
		return fmt.Errorf("persist %s: %w", contextLabel, err)
	}
	return nil
}

func (s *Service) resolveBaselineRun(current domain.ScanRun, baselineRunID string) (*domain.ScanRun, error) {
	if baselineRunID != "" {
		baseline, ok := s.GetRun(baselineRunID)
		if !ok {
			return nil, fmt.Errorf("baseline run not found: %s", baselineRunID)
		}
		if baseline.ProjectID != current.ProjectID {
			return nil, fmt.Errorf("baseline run %s belongs to a different project", baselineRunID)
		}
		return &baseline, nil
	}

	runs := s.ListRuns()
	for _, run := range runs {
		if run.ID == current.ID || run.ProjectID != current.ProjectID {
			continue
		}
		if !run.StartedAt.Before(current.StartedAt) {
			continue
		}
		if run.Status != domain.ScanCompleted {
			continue
		}
		candidate := run
		return &candidate, nil
	}

	return nil, nil
}

func baselineIDValue(run *domain.ScanRun) string {
	if run == nil {
		return ""
	}
	return run.ID
}

func upsertModuleResult(results []domain.ModuleResult, module domain.ModuleResult) []domain.ModuleResult {
	for index, item := range results {
		if item.Name == module.Name {
			results[index] = module
			return results
		}
	}
	return append(results, module)
}

func appendArtifactRefsUnique(existing []domain.ArtifactRef, incoming ...domain.ArtifactRef) []domain.ArtifactRef {
	if len(incoming) == 0 {
		return existing
	}
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	for _, item := range existing {
		seen[item.Kind+"|"+item.Label+"|"+item.URI] = struct{}{}
	}
	for _, item := range incoming {
		key := item.Kind + "|" + item.Label + "|" + item.URI
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		existing = append(existing, item)
	}
	return existing
}

func mapAgentEventType(source string) string {
	switch source {
	case "module.completed", "module.started", "module.queued":
		return "module.updated"
	case "module.execution":
		return "module.execution"
	case "finding.created":
		return "finding.created"
	case "scan.completed":
		return "run.completed"
	case "scan.failed":
		return "run.failed"
	default:
		return "run.updated"
	}
}

func loadExecutionTraces(run domain.ScanRun) []domain.ModuleExecutionTrace {
	tracesByModule := make(map[string]domain.ModuleExecutionTrace)
	seen := make(map[string]struct{})
	for _, artifact := range run.ArtifactRefs {
		if artifact.Kind != "execution-journal" || strings.TrimSpace(artifact.URI) == "" {
			continue
		}
		if _, ok := seen[artifact.URI]; ok {
			continue
		}
		seen[artifact.URI] = struct{}{}

		body, err := os.ReadFile(artifact.URI)
		if err != nil {
			continue
		}
		var trace domain.ModuleExecutionTrace
		if err := json.Unmarshal(body, &trace); err != nil {
			continue
		}
		if strings.TrimSpace(trace.Module) == "" {
			continue
		}
		tracesByModule[trace.Module] = trace
	}

	finishedAt := run.StartedAt
	if run.FinishedAt != nil {
		finishedAt = *run.FinishedAt
	}

	ordered := make([]domain.ModuleExecutionTrace, 0, len(run.ModuleResults))
	for _, result := range run.ModuleResults {
		if trace, ok := tracesByModule[result.Name]; ok {
			ordered = append(ordered, trace)
			continue
		}

		trace := domain.ModuleExecutionTrace{
			Module:       result.Name,
			Status:       result.Status,
			FailureKind:  result.FailureKind,
			MaxAttempts:  syntheticModuleAttempts(result),
			AttemptsUsed: syntheticModuleAttempts(result),
			StartedAt:    run.StartedAt,
			FinishedAt:   finishedAt,
			DurationMs:   result.DurationMs,
		}
		if trace.AttemptsUsed > 0 {
			trace.AttemptJournal = []domain.ModuleAttemptTrace{{
				Attempt:      trace.AttemptsUsed,
				StartedAt:    run.StartedAt,
				FinishedAt:   finishedAt,
				DurationMs:   result.DurationMs,
				FailureKind:  result.FailureKind,
				TimedOut:     result.TimedOut,
				ExitCode:     result.ExitCode,
				ArtifactRefs: append([]domain.ArtifactRef(nil), result.Artifacts...),
			}}
		}
		ordered = append(ordered, trace)
	}

	return ordered
}

func syntheticModuleAttempts(result domain.ModuleResult) int {
	if result.Attempts > 0 {
		return result.Attempts
	}
	if result.Status == domain.ModuleSkipped {
		return 0
	}
	return 1
}
