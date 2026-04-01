package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
)

type Service struct {
	config config.Config
}

func NewService(cfg config.Config) *Service {
	return &Service{config: cfg}
}

func (s *Service) RuntimeStatus() domain.RuntimeStatus {
	return DiscoverRuntime(s.config)
}

func (s *Service) RuntimeDoctor(profile domain.ScanProfile, strictVersions, requireIntegrity bool) domain.RuntimeDoctor {
	return EvaluateBundleHealth(s.config, profile, strictVersions, requireIntegrity)
}

func (s *Service) RefreshMirror(tool string) (domain.RuntimeMirror, error) {
	return refreshMirror(s.config, tool)
}

func (s *Service) ResolveIsolationContract(profile domain.ScanProfile) domain.IsolationContract {
	return resolveIsolationContract(s.config, profile)
}

func (s *Service) ResolveTarget(ctx context.Context, request domain.ResolveTargetRequest) (domain.ResolveTargetResponse, error) {
	if err := ctx.Err(); err != nil {
		return domain.ResolveTargetResponse{}, err
	}
	path := request.Path
	if request.Interactive || path == "" {
		selected, err := pickDirectory(ctx, "Select project folder")
		if err != nil {
			return domain.ResolveTargetResponse{}, err
		}
		path = selected
	}

	if path == "" {
		return domain.ResolveTargetResponse{}, errors.New("project path is required")
	}
	if err := ctx.Err(); err != nil {
		return domain.ResolveTargetResponse{}, err
	}

	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return domain.ResolveTargetResponse{}, err
	}
	if _, err := os.Stat(absolutePath); err != nil {
		return domain.ResolveTargetResponse{}, err
	}

	stacks, err := detectStacksWithContext(ctx, absolutePath)
	if err != nil {
		return domain.ResolveTargetResponse{}, err
	}

	displayName := request.DisplayName
	if displayName == "" {
		displayName = filepath.Base(absolutePath)
	}

	return domain.ResolveTargetResponse{
		Handle:         domain.MakeFingerprint(absolutePath),
		Path:           absolutePath,
		DisplayName:    displayName,
		DetectedStacks: stacks,
	}, nil
}

func (s *Service) StreamScan(ctx context.Context, request domain.AgentScanRequest, emit func(domain.AgentEvent) error) error {
	startedAt := time.Now()
	stacks, err := detectStacks(request.TargetPath)
	if err != nil {
		return err
	}
	if err := validateIsolationRequest(s.config, request.Profile); err != nil {
		return err
	}

	outputDir := filepath.Join(s.config.OutputDir, request.ScanID)
	_ = pruneExpiredArtifactRuns(s.config.OutputDir, s.config.ArtifactRetentionDays)
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}

	if err := emit(domain.AgentEvent{
		Type:           "scan.accepted",
		Message:        "Workspace accepted by local agent.",
		DetectedStacks: stacks,
		At:             time.Now(),
	}); err != nil {
		return err
	}

	plan := buildModulePlan(s.config, stacks, request.Profile)
	policy := resolveScanExecutionPolicy(request.Profile, len(plan))
	for _, module := range plan {
		if err := emit(domain.AgentEvent{
			Type: "module.queued",
			Module: &domain.ModuleResult{
				Name:       module.name,
				Category:   module.category,
				Status:     domain.ModuleQueued,
				Summary:    "Queued in scan worker pool.",
				DurationMs: 0,
			},
			At: time.Now(),
		}); err != nil {
			return err
		}
	}

	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	eventCh := make(chan domain.AgentEvent, max(8, len(plan)*4))
	coordinatorErr := make(chan error, 1)
	coordinatorDone := make(chan struct{})
	go func() {
		defer close(coordinatorDone)
		for event := range eventCh {
			if err := emit(event); err != nil {
				select {
				case coordinatorErr <- err:
				default:
				}
				cancel()
				return
			}
		}
	}()

	emitAsync := func(event domain.AgentEvent) error {
		if err := scanCtx.Err(); err != nil {
			return err
		}
		select {
		case <-scanCtx.Done():
			return scanCtx.Err()
		case eventCh <- event:
			return nil
		}
	}

	type moduleJob struct {
		module moduleRunner
	}
	jobs := make(chan moduleJob)
	workerErr := make(chan error, 1)
	var workers sync.WaitGroup
	for worker := 0; worker < policy.WorkerCount; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for job := range jobs {
				if scanCtx.Err() != nil {
					return
				}
				if err := emitAsync(domain.AgentEvent{
					Type: "module.started",
					Module: &domain.ModuleResult{
						Name:       job.module.name,
						Category:   job.module.category,
						Status:     domain.ModuleRunning,
						Summary:    "Running in hardened local or container sandbox.",
						DurationMs: 0,
					},
					At: time.Now(),
				}); err != nil {
					select {
					case workerErr <- err:
					default:
					}
					cancel()
					return
				}

				result, findings, runErr := job.module.run(scanCtx, request, stacks, outputDir, emitAsync)
				if runErr != nil {
					if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
						select {
						case workerErr <- runErr:
						default:
						}
						cancel()
						return
					}
					result = domain.ModuleResult{
						Name:       job.module.name,
						Category:   job.module.category,
						Status:     domain.ModuleFailed,
						Summary:    runErr.Error(),
						DurationMs: 0,
					}
				}

				if err := emitAsync(domain.AgentEvent{
					Type:    "module.completed",
					Module:  &result,
					Message: result.Summary,
					At:      time.Now(),
				}); err != nil {
					select {
					case workerErr <- err:
					default:
					}
					cancel()
					return
				}

				for _, finding := range findings {
					if err := emitAsync(domain.AgentEvent{
						Type:    "finding.created",
						Finding: &finding,
						At:      time.Now(),
					}); err != nil {
						select {
						case workerErr <- err:
						default:
						}
						cancel()
						return
					}
				}
			}
		}()
	}

enqueue:
	for _, module := range plan {
		select {
		case <-scanCtx.Done():
			break enqueue
		case jobs <- moduleJob{module: module}:
		}
	}
	close(jobs)
	workers.Wait()

	if scanCtx.Err() == nil {
		if err := emitAsync(domain.AgentEvent{
			Type:    "scan.completed",
			Message: "Local scan finished in " + time.Since(startedAt).Round(time.Millisecond).String(),
			At:      time.Now(),
		}); err != nil {
			select {
			case workerErr <- err:
			default:
			}
		}
	}
	close(eventCh)
	<-coordinatorDone

	select {
	case err := <-coordinatorErr:
		return err
	default:
	}
	select {
	case err := <-workerErr:
		return err
	default:
	}
	if scanCtx.Err() != nil && !errors.Is(scanCtx.Err(), context.Canceled) {
		return scanCtx.Err()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}

	return nil
}
