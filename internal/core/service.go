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
	"github.com/batu3384/ironsentinel/internal/policy"
	"github.com/batu3384/ironsentinel/internal/reports"
	"github.com/batu3384/ironsentinel/internal/store"
	"github.com/batu3384/ironsentinel/internal/util"
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
	applyRunSummaries(runs, s.store.ListFindings(""))
	return runs
}

func (s *Service) PortfolioData() PortfolioData {
	findings := s.store.ListFindings("")
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
	run.Summary = domain.RecalculateSummary(s.store.ListFindings(run.ID), run.Profile.SeverityGate)
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

	currentFindings := s.store.ListFindings(current.ID)
	var baselineFindings []domain.Finding
	if baseline != nil {
		baselineFindings = s.store.ListFindings(baseline.ID)
	}

	delta := domain.CalculateRunDelta(currentFindings, baselineFindings, current.ID, baselineIDValue(baseline), current.ProjectID)
	return delta, current, baseline, nil
}

func (s *Service) EvaluateGate(runID, baselineRunID string, threshold domain.Severity) (domain.RunDelta, domain.ScanRun, *domain.ScanRun, []domain.Finding, error) {
	delta, current, baseline, err := s.GetRunDelta(runID, baselineRunID)
	if err != nil {
		return domain.RunDelta{}, domain.ScanRun{}, nil, nil, err
	}

	blocking := domain.FilterFindingsAtOrAboveSeverity(delta.NewFindings, threshold)
	return delta, current, baseline, blocking, nil
}

func (s *Service) EvaluatePolicy(runID, baselineRunID, policyID string) (domain.PolicyEvaluation, domain.ScanRun, *domain.ScanRun, error) {
	delta, current, baseline, err := s.GetRunDelta(runID, baselineRunID)
	if err != nil {
		return domain.PolicyEvaluation{}, domain.ScanRun{}, nil, err
	}

	pack := policy.Builtin(policyID)
	evaluation := policy.Evaluate(pack, current.ID, baselineIDValue(baseline), s.store.ListFindings(current.ID), delta)
	return evaluation, current, baseline, nil
}

func (s *Service) ListFindings(runID string) []domain.Finding {
	return s.store.ListFindings(runID)
}

func (s *Service) GetFinding(runID, fingerprint string) (domain.Finding, bool) {
	return s.store.FindFinding(runID, fingerprint)
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

func (s *Service) Export(runID, format, baselineRunID string) (string, error) {
	delta, run, baseline, err := s.GetRunDelta(runID, baselineRunID)
	if err != nil {
		return "", err
	}
	project, _ := s.store.GetProject(run.ProjectID)
	findings := enrichFindings(project, s.store.ListFindings(runID))
	return reports.Export(format, run, baseline, findings, delta, trendPointsForProject(s.store.ListRuns(), run.ProjectID))
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

func (s *Service) DASTPlan(projectID string, targets []domain.DastTarget, active bool) domain.DastPlan {
	policy := "baseline"
	if active {
		policy = "active"
	} else if len(targets) > 0 {
		policy = "authenticated"
	}

	return domain.DastPlan{
		ProjectID: projectID,
		Policy:    policy,
		Steps: []string{
			"Validate ownership of each target before any authenticated or active probe.",
			"Import OpenAPI or route manifests when available to improve crawl coverage.",
			"Start with passive ZAP baseline, then switch to active checks only on staging targets.",
			"Allow signed Nuclei templates only and normalize evidence into the unified finding model.",
		},
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
