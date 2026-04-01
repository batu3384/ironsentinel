package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
)

type moduleRunner struct {
	name     string
	category domain.FindingCategory
	lane     string
	priority int
	run      func(context.Context, domain.AgentScanRequest, []string, string, func(domain.AgentEvent) error) (domain.ModuleResult, []domain.Finding, error)
}

func buildModulePlan(cfg config.Config, stacks []string, profile domain.ScanProfile) []moduleRunner {
	hasStack := func(target string) bool {
		for _, stack := range stacks {
			if stack == target {
				return true
			}
		}
		return false
	}

	modules := []moduleRunner{
		{
			name:     "stack-detector",
			category: domain.CategoryPlatform,
			lane:     "surface",
			priority: 0,
			run: func(_ context.Context, request domain.AgentScanRequest, detectedStacks []string, _ string, _ func(domain.AgentEvent) error) (domain.ModuleResult, []domain.Finding, error) {
				return domain.ModuleResult{
					Name:         "stack-detector",
					Category:     domain.CategoryPlatform,
					Status:       domain.ModuleCompleted,
					Summary:      "Resolved workspace technology stacks and scan strategy.",
					FindingCount: 0,
					DurationMs:   1,
				}, nil, nil
			},
		},
		{
			name:     "surface-inventory",
			category: domain.CategoryPlatform,
			lane:     "surface",
			priority: 1,
			run: func(ctx context.Context, request domain.AgentScanRequest, _ []string, outputDir string, _ func(domain.AgentEvent) error) (domain.ModuleResult, []domain.Finding, error) {
				return heuristicSurfaceInventory(ctx, cfg, request, outputDir)
			},
		},
		{
			name:     "script-audit",
			category: domain.CategoryPlatform,
			lane:     "surface",
			priority: 2,
			run: func(ctx context.Context, request domain.AgentScanRequest, _ []string, outputDir string, _ func(domain.AgentEvent) error) (domain.ModuleResult, []domain.Finding, error) {
				return heuristicScriptAudit(ctx, cfg, request, outputDir)
			},
		},
		{
			name:     "dependency-confusion",
			category: domain.CategorySCA,
			lane:     "supply",
			priority: 0,
			run: func(ctx context.Context, request domain.AgentScanRequest, _ []string, outputDir string, _ func(domain.AgentEvent) error) (domain.ModuleResult, []domain.Finding, error) {
				return heuristicDependencyConfusion(ctx, cfg, request, outputDir)
			},
		},
		{
			name:     "runtime-config-audit",
			category: domain.CategoryPlatform,
			lane:     "surface",
			priority: 3,
			run: func(ctx context.Context, request domain.AgentScanRequest, _ []string, outputDir string, _ func(domain.AgentEvent) error) (domain.ModuleResult, []domain.Finding, error) {
				return heuristicRuntimeConfigAudit(ctx, cfg, request, outputDir)
			},
		},
		{
			name:     "binary-entropy",
			category: domain.CategoryMalware,
			lane:     "malware",
			priority: 1,
			run: func(ctx context.Context, request domain.AgentScanRequest, _ []string, outputDir string, _ func(domain.AgentEvent) error) (domain.ModuleResult, []domain.Finding, error) {
				return heuristicBinaryEntropy(ctx, cfg, request, outputDir)
			},
		},
		{
			name:     "secret-heuristics",
			category: domain.CategorySecret,
			lane:     "code",
			priority: 0,
			run: func(ctx context.Context, request domain.AgentScanRequest, _ []string, outputDir string, _ func(domain.AgentEvent) error) (domain.ModuleResult, []domain.Finding, error) {
				return heuristicSecrets(ctx, cfg, request, outputDir)
			},
		},
		{
			name:     "malware-signature",
			category: domain.CategoryMalware,
			lane:     "malware",
			priority: 0,
			run: func(ctx context.Context, request domain.AgentScanRequest, _ []string, outputDir string, _ func(domain.AgentEvent) error) (domain.ModuleResult, []domain.Finding, error) {
				return heuristicMalware(ctx, cfg, request, outputDir)
			},
		},
		externalModule(cfg, "semgrep", domain.CategorySAST, func(binary string, execution moduleExecution, _ []string) (*exec.Cmd, string, error) {
			return exec.Command(binary, "scan", "--json", "--quiet", "--config", "auto", execution.request.TargetPath), "", nil
		}, parseSemgrep),
		externalModule(cfg, "gitleaks", domain.CategorySecret, func(binary string, execution moduleExecution, _ []string) (*exec.Cmd, string, error) {
			reportPath, _ := executionArtifactPaths(execution, "gitleaks.json")
			return exec.Command(binary, "detect", "--no-banner", "--source", execution.request.TargetPath, "--report-format", "json", "--report-path", reportPath), reportPath, nil
		}, parseGitleaks),
		externalModule(cfg, "trivy", domain.CategorySCA, func(binary string, execution moduleExecution, _ []string) (*exec.Cmd, string, error) {
			args := []string{"fs", "--quiet", "--format", "json"}
			if dirHasEntries(filepath.Join(cfg.MirrorDir, "trivy-db")) {
				args = append(args, "--cache-dir", mirrorPathForRequest(cfg, execution.request, "trivy"))
			}
			if cfg.OfflineMode {
				args = append(args, "--offline-scan", "--skip-db-update", "--skip-java-db-update")
			}
			args = append(args, execution.request.TargetPath)
			return exec.Command(binary, args...), "", nil
		}, parseTrivy),
		externalModule(cfg, "trivy-image", domain.CategoryContainer, func(binary string, execution moduleExecution, _ []string) (*exec.Cmd, string, error) {
			return buildTrivyImageCommand(cfg, binary, execution)
		}, parseTrivyImage),
		externalModule(cfg, "syft", domain.CategorySCA, func(binary string, execution moduleExecution, _ []string) (*exec.Cmd, string, error) {
			return exec.Command(binary, fmt.Sprintf("dir:%s", execution.request.TargetPath), "-o", "cyclonedx-json"), "", nil
		}, parseSBOMArtifact),
		externalModule(cfg, "grype", domain.CategorySCA, buildGrypeCommand, parseGrype),
		externalModule(cfg, "osv-scanner", domain.CategorySCA, func(binary string, execution moduleExecution, _ []string) (*exec.Cmd, string, error) {
			return buildOSVCommand(cfg, binary, execution), "", nil
		}, parseOSV),
		externalModule(cfg, "checkov", domain.CategoryIaC, func(binary string, execution moduleExecution, _ []string) (*exec.Cmd, string, error) {
			return exec.Command(binary, "-d", execution.request.TargetPath, "-o", "json"), "", nil
		}, parseCheckov),
		externalModule(cfg, "tfsec", domain.CategoryIaC, buildTfsecCommand, parseTfsec),
		externalModule(cfg, "kics", domain.CategoryIaC, buildKICSCommand, parseSARIFCategory(domain.CategoryIaC, "KICS")),
		externalModule(cfg, "licensee", domain.CategoryCompliance, buildLicenseeCommand, parseLicensee),
		externalModule(cfg, "scancode", domain.CategoryCompliance, buildScancodeCommand, parseScancode),
		externalModule(cfg, "govulncheck", domain.CategorySCA, func(binary string, execution moduleExecution, stacks []string) (*exec.Cmd, string, error) {
			if !hasStack("go") {
				return nil, "", errSkipModule("go stack not detected")
			}
			command := exec.Command(binary, "-json", "./...")
			command.Dir = execution.request.TargetPath
			return command, "", nil
		}, parseGovulncheck),
		externalModule(cfg, "staticcheck", domain.CategoryMaintainability, func(binary string, execution moduleExecution, stacks []string) (*exec.Cmd, string, error) {
			if !hasStack("go") {
				return nil, "", errSkipModule("go stack not detected")
			}
			command := exec.Command(binary, "-f", "json", "./...")
			command.Dir = execution.request.TargetPath
			return command, "", nil
		}, parseStaticcheck),
		externalModule(cfg, "knip", domain.CategoryMaintainability, func(binary string, execution moduleExecution, stacks []string) (*exec.Cmd, string, error) {
			if !hasStack("javascript") && !hasStack("typescript") {
				return nil, "", errSkipModule("js/ts stack not detected")
			}
			command := exec.Command(binary, "--reporter", "json")
			command.Dir = execution.request.TargetPath
			return command, "", nil
		}, parseKnip),
		externalModule(cfg, "vulture", domain.CategoryMaintainability, func(binary string, execution moduleExecution, stacks []string) (*exec.Cmd, string, error) {
			if !hasStack("python") {
				return nil, "", errSkipModule("python stack not detected")
			}
			return exec.Command(binary, execution.request.TargetPath, "--json"), "", nil
		}, parseVulture),
		externalModule(cfg, "clamscan", domain.CategoryMalware, func(binary string, execution moduleExecution, _ []string) (*exec.Cmd, string, error) {
			return exec.Command(binary, "-r", "--infected", "--no-summary", execution.request.TargetPath), "", nil
		}, parseClam),
		externalModule(cfg, "yara-x", domain.CategoryMalware, func(binary string, execution moduleExecution, stacks []string) (*exec.Cmd, string, error) {
			return buildYARAXCommand(cfg, binary, execution, stacks)
		}, parseYARAX),
		externalModule(cfg, "codeql", domain.CategorySAST, func(binary string, execution moduleExecution, stacks []string) (*exec.Cmd, string, error) {
			return buildCodeQLCommand(binary, execution, stacks)
		}, parseSARIFCategory(domain.CategorySAST, "CodeQL")),
		externalModule(cfg, "nuclei", domain.CategoryDAST, func(binary string, execution moduleExecution, _ []string) (*exec.Cmd, string, error) {
			return buildNucleiCommand(cfg, binary, execution)
		}, parseNuclei),
		externalModule(cfg, "zaproxy", domain.CategoryDAST, func(binary string, execution moduleExecution, _ []string) (*exec.Cmd, string, error) {
			return buildZAPAutomationCommand(cfg, binary, execution)
		}, parseSARIFCategory(domain.CategoryDAST, "ZAP")),
	}

	if len(profile.Modules) == 0 {
		return orderModulePlan(modules)
	}

	allowed := make(map[string]struct{}, len(profile.Modules))
	for _, name := range profile.Modules {
		allowed[strings.TrimSpace(name)] = struct{}{}
	}

	filtered := make([]moduleRunner, 0, len(modules))
	for _, module := range modules {
		if _, ok := allowed[module.name]; ok {
			filtered = append(filtered, module)
		}
	}
	return orderModulePlan(filtered)
}

type outputParser func(domain.AgentScanRequest, string, []byte) (domain.ModuleResult, []domain.Finding, error)
type commandFactory func(binary string, execution moduleExecution, stacks []string) (*exec.Cmd, string, error)

func externalModule(cfg config.Config, name string, category domain.FindingCategory, factory commandFactory, parser outputParser) moduleRunner {
	return moduleRunner{
		name:     name,
		category: category,
		lane:     moduleLane(name, category),
		priority: modulePriority(name),
		run: func(ctx context.Context, request domain.AgentScanRequest, stacks []string, outputDir string, emit func(domain.AgentEvent) error) (domain.ModuleResult, []domain.Finding, error) {
			start := time.Now()
			moduleDir, dirErr := ensureModuleDir(outputDir, name)
			if dirErr != nil {
				return domain.ModuleResult{}, nil, dirErr
			}
			policy := resolveModuleJobPolicy(name, request.Profile)
			writeSkippedManifest := func(status domain.ModuleStatus, summary string, failureKind domain.ModuleFailureKind) domain.ModuleResult {
				result := domain.ModuleResult{
					Name:        name,
					Category:    category,
					Status:      status,
					Summary:     summary,
					DurationMs:  time.Since(start).Milliseconds(),
					FailureKind: failureKind,
				}
				manifest := moduleManifest{
					Module:      name,
					Category:    category,
					Status:      result.Status,
					Summary:     result.Summary,
					StartedAt:   start.UTC(),
					FinishedAt:  time.Now().UTC(),
					DurationMs:  result.DurationMs,
					FailureKind: result.FailureKind,
				}
				if manifestRef, err := writeManifest(cfg, moduleDir, manifest); err == nil {
					result.Artifacts = append(result.Artifacts, manifestRef)
				}
				return result
			}

			execution := resolveModuleExecution(cfg, request, name, outputDir)
			if reason := execution.unavailableReason(); reason != "" {
				return writeSkippedManifest(domain.ModuleSkipped, reason, domain.ModuleFailureSkipped), nil, nil
			}

			binary := execution.binary
			if execution.mode == domain.IsolationLocal {
				resolvedPath, err := findBinary(cfg, name)
				if err != nil {
					return writeSkippedManifest(domain.ModuleSkipped, "Binary not found on PATH.", domain.ModuleFailureToolMiss), nil, nil
				}
				binary = resolvedPath
			}

			buildAttempt := func() (builtCommand, error) {
				command, artifactPath, err := factory(binary, execution, stacks)
				if err != nil {
					return builtCommand{}, err
				}

				environmentEntries := command.Env
				if execution.mode == domain.IsolationLocal {
					applySandbox(command, request)
					environmentEntries = command.Env
				}

				wrappedCommand := execution.build(command, request.TargetPath, outputDir)
				if execution.mode == domain.IsolationContainer {
					environmentEntries = []string{"container:" + execution.engine, "image:" + execution.image}
				}

				workingDir := command.Dir
				if strings.TrimSpace(workingDir) == "" {
					workingDir = execution.request.TargetPath
				}

				return builtCommand{
					command:      wrappedCommand,
					workingDir:   workingDir,
					environment:  envKeys(environmentEntries),
					artifactPath: artifactPath,
				}, nil
			}

			attemptJournal := make([]domain.ModuleAttemptTrace, 0, policy.MaxAttempts)
			var (
				result       domain.ModuleResult
				findings     []domain.Finding
				lastCommand  builtCommand
				lastExitCode *int
				lastTimedOut bool
				lastFailure  domain.ModuleFailureKind
				success      bool
			)

			for attempt := 1; attempt <= policy.MaxAttempts; attempt++ {
				attemptStart := time.Now()
				spec, output, exitCode, timedOut, failureKind, commandErr := executeModuleAttempt(ctx, policy.Timeout, buildAttempt)
				lastCommand = spec
				lastExitCode = exitCode
				lastTimedOut = timedOut
				lastFailure = failureKind

				attemptArtifacts, parsedOutput, artifactErr := collectAttemptArtifacts(cfg, moduleDir, name, outputDir, spec.artifactPath, output, attempt)
				if artifactErr != nil {
					failureKind = domain.ModuleFailureArtifactIO
					lastFailure = failureKind
					if commandErr == nil {
						commandErr = artifactErr
					}
				} else {
					output = parsedOutput
				}

				record := domain.ModuleAttemptTrace{
					Attempt:      attempt,
					StartedAt:    attemptStart.UTC(),
					FinishedAt:   time.Now().UTC(),
					DurationMs:   time.Since(attemptStart).Milliseconds(),
					FailureKind:  failureKind,
					TimedOut:     timedOut,
					ExitCode:     exitCode,
					WorkingDir:   spec.workingDir,
					Environment:  spec.environment,
					ArtifactRefs: attemptArtifacts,
				}
				if spec.command != nil {
					record.Command = spec.command.Path
					if len(spec.command.Args) > 1 {
						record.Args = spec.command.Args[1:]
					}
				}

				if errors.Is(commandErr, errModuleSkipped) {
					attemptJournal = append(attemptJournal, record)
					if err := emitModuleExecutionEvent(emit, name, category, domain.ModuleSkipped, domain.ModuleFailureSkipped, policy, start, attemptJournal, &record); err != nil {
						return domain.ModuleResult{}, nil, err
					}
					return writeSkippedManifest(domain.ModuleSkipped, commandErr.Error(), domain.ModuleFailureSkipped), nil, nil
				}

				if commandErr == nil || len(bytesTrimSpace(output)) > 0 {
					parsedResult, parsedFindings, parseErr := parser(request, name, output)
					if parseErr == nil {
						parsedResult.Name = name
						parsedResult.Category = category
						parsedResult.DurationMs = time.Since(start).Milliseconds()
						parsedResult.Attempts = attempt
						parsedResult.TimedOut = timedOut
						parsedResult.ExitCode = exitCode
						if parsedResult.Status == "" {
							parsedResult.Status = domain.ModuleCompleted
						}

						var primaryArtifact domain.ArtifactRef
						if len(attemptArtifacts) > 0 {
							primaryArtifact = attemptArtifacts[0]
						}
						if primaryArtifact.URI != "" {
							parsedResult.Artifacts = replaceInlineArtifacts(parsedResult.Artifacts, primaryArtifact)
						}
						parsedResult.Artifacts = append(parsedResult.Artifacts, attemptArtifacts...)
						parsedFindings = attachDefaultEvidence(parsedFindings, parsedResult.Artifacts)

						record.FailureKind = domain.ModuleFailureNone
						attemptJournal = append(attemptJournal, record)
						result = parsedResult
						findings = parsedFindings
						lastFailure = domain.ModuleFailureNone
						if err := emitModuleExecutionEvent(emit, name, category, parsedResult.Status, domain.ModuleFailureNone, policy, start, attemptJournal, &record); err != nil {
							return domain.ModuleResult{}, nil, err
						}
						success = true
						break
					}
					commandErr = parseErr
					failureKind = domain.ModuleFailureParse
					record.FailureKind = failureKind
					lastFailure = failureKind
				}

				attemptJournal = append(attemptJournal, record)
				nextStatus := domain.ModuleRunning
				if !shouldRetryModuleAttempt(failureKind, attempt, policy.MaxAttempts) {
					nextStatus = domain.ModuleFailed
				}
				if err := emitModuleExecutionEvent(emit, name, category, nextStatus, failureKind, policy, start, attemptJournal, &record); err != nil {
					return domain.ModuleResult{}, nil, err
				}
				if !shouldRetryModuleAttempt(failureKind, attempt, policy.MaxAttempts) {
					result = domain.ModuleResult{
						Name:        name,
						Category:    category,
						Status:      domain.ModuleFailed,
						Summary:     summarizeModuleFailure(output, commandErr, failureKind),
						DurationMs:  time.Since(start).Milliseconds(),
						Attempts:    attempt,
						TimedOut:    timedOut,
						FailureKind: failureKind,
						ExitCode:    exitCode,
						Artifacts:   append([]domain.ArtifactRef(nil), attemptArtifacts...),
					}
					break
				}
				if backoff := retryBackoffForAttempt(policy.RetryBackoffBase, attempt); backoff > 0 {
					timer := time.NewTimer(backoff)
					select {
					case <-ctx.Done():
						timer.Stop()
						return domain.ModuleResult{}, nil, ctx.Err()
					case <-timer.C:
					}
				}
			}

			if !success && result.Status == "" {
				result = domain.ModuleResult{
					Name:        name,
					Category:    category,
					Status:      domain.ModuleFailed,
					Summary:     "Module execution failed without a parsable result.",
					DurationMs:  time.Since(start).Milliseconds(),
					Attempts:    len(attemptJournal),
					TimedOut:    lastTimedOut,
					FailureKind: lastFailure,
					ExitCode:    lastExitCode,
				}
			}

			journal := domain.ModuleExecutionTrace{
				Module:         name,
				Status:         result.Status,
				FailureKind:    result.FailureKind,
				TimeoutSec:     int(policy.Timeout / time.Second),
				MaxAttempts:    policy.MaxAttempts,
				AttemptsUsed:   len(attemptJournal),
				StartedAt:      start.UTC(),
				FinishedAt:     time.Now().UTC(),
				DurationMs:     result.DurationMs,
				AttemptJournal: attemptJournal,
			}
			if journalRef, err := writeExecutionJournal(cfg, moduleDir, journal); err == nil {
				result.Artifacts = append(result.Artifacts, journalRef)
			}

			manifest := moduleManifest{
				Module:       name,
				Category:     category,
				Status:       result.Status,
				Summary:      result.Summary,
				StartedAt:    start.UTC(),
				FinishedAt:   time.Now().UTC(),
				DurationMs:   result.DurationMs,
				WorkingDir:   lastCommand.workingDir,
				Environment:  lastCommand.environment,
				ReadOnly:     true,
				AllowBuild:   request.Profile.AllowBuild,
				AllowNetwork: request.Profile.AllowNetwork,
				Attempts:     result.Attempts,
				TimedOut:     result.TimedOut,
				FailureKind:  result.FailureKind,
				ExitCode:     result.ExitCode,
				Artifacts:    result.Artifacts,
			}
			if lastCommand.command != nil {
				manifest.Executable = lastCommand.command.Path
				if len(lastCommand.command.Args) > 1 {
					manifest.Args = lastCommand.command.Args[1:]
				}
			}
			if manifestRef, err := writeManifest(cfg, moduleDir, manifest); err == nil {
				result.Artifacts = append(result.Artifacts, manifestRef)
			}

			return result, findings, nil
		},
	}
}

func orderModulePlan(modules []moduleRunner) []moduleRunner {
	ordered := append([]moduleRunner(nil), modules...)
	sort.SliceStable(ordered, func(i, j int) bool {
		left := ordered[i]
		right := ordered[j]
		leftLane := moduleLaneRank(left.lane)
		rightLane := moduleLaneRank(right.lane)
		if leftLane != rightLane {
			return leftLane < rightLane
		}
		if left.priority != right.priority {
			return left.priority < right.priority
		}
		return left.name < right.name
	})
	return ordered
}

func moduleLane(name string, category domain.FindingCategory) string {
	switch name {
	case "stack-detector", "surface-inventory", "script-audit", "runtime-config-audit":
		return "surface"
	case "semgrep", "codeql", "gitleaks", "secret-heuristics":
		return "code"
	case "trivy", "syft", "grype", "osv-scanner", "dependency-confusion", "licensee", "scancode", "govulncheck", "staticcheck", "knip", "vulture":
		return "supply"
	case "checkov", "tfsec", "kics", "trivy-image":
		return "infra"
	case "malware-signature", "clamscan", "yara-x", "binary-entropy":
		return "malware"
	case "nuclei", "zaproxy":
		return "active"
	}
	switch category {
	case domain.CategoryPlatform:
		return "surface"
	case domain.CategorySAST, domain.CategorySecret:
		return "code"
	case domain.CategorySCA, domain.CategoryCompliance, domain.CategoryMaintainability:
		return "supply"
	case domain.CategoryIaC, domain.CategoryContainer:
		return "infra"
	case domain.CategoryMalware:
		return "malware"
	case domain.CategoryDAST:
		return "active"
	default:
		return "surface"
	}
}

func moduleLaneRank(lane string) int {
	switch lane {
	case "surface":
		return 0
	case "code":
		return 1
	case "supply":
		return 2
	case "infra":
		return 3
	case "malware":
		return 4
	case "active":
		return 5
	default:
		return 6
	}
}

func modulePriority(name string) int {
	switch name {
	case "stack-detector":
		return 0
	case "surface-inventory", "secret-heuristics", "malware-signature", "dependency-confusion":
		return 1
	case "script-audit", "runtime-config-audit", "gitleaks", "semgrep", "syft", "checkov", "binary-entropy":
		return 2
	case "trivy", "grype", "osv-scanner", "tfsec", "kics", "clamscan", "yara-x", "licensee", "scancode":
		return 3
	case "govulncheck", "staticcheck", "knip", "vulture", "trivy-image":
		return 4
	case "codeql":
		return 5
	case "nuclei":
		return 6
	case "zaproxy":
		return 7
	default:
		return 4
	}
}

func emitModuleExecutionEvent(
	emit func(domain.AgentEvent) error,
	name string,
	category domain.FindingCategory,
	status domain.ModuleStatus,
	failureKind domain.ModuleFailureKind,
	policy moduleJobPolicy,
	start time.Time,
	attemptJournal []domain.ModuleAttemptTrace,
	lastAttempt *domain.ModuleAttemptTrace,
) error {
	if emit == nil {
		return nil
	}

	trace := domain.ModuleExecutionTrace{
		Module:         name,
		Status:         status,
		FailureKind:    failureKind,
		TimeoutSec:     int(policy.Timeout / time.Second),
		MaxAttempts:    policy.MaxAttempts,
		AttemptsUsed:   len(attemptJournal),
		StartedAt:      start.UTC(),
		FinishedAt:     time.Now().UTC(),
		DurationMs:     time.Since(start).Milliseconds(),
		AttemptJournal: append([]domain.ModuleAttemptTrace(nil), attemptJournal...),
	}

	module := &domain.ModuleResult{
		Name:        name,
		Category:    category,
		Status:      status,
		Attempts:    len(attemptJournal),
		DurationMs:  trace.DurationMs,
		FailureKind: failureKind,
	}
	if lastAttempt != nil {
		module.TimedOut = lastAttempt.TimedOut
		module.ExitCode = lastAttempt.ExitCode
	}

	return emit(domain.AgentEvent{
		Type:      "module.execution",
		Module:    module,
		Attempt:   lastAttempt,
		Execution: &trace,
		At:        trace.FinishedAt,
	})
}

var errModuleSkipped = errors.New("module skipped")

func errSkipModule(message string) error {
	return fmt.Errorf("%w: %s", errModuleSkipped, message)
}

func parseSemgrep(request domain.AgentScanRequest, module string, output []byte) (domain.ModuleResult, []domain.Finding, error) {
	var payload struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Path    string `json:"path"`
			Extra   struct {
				Message  string `json:"message"`
				Severity string `json:"severity"`
			} `json:"extra"`
		} `json:"results"`
	}

	payloadBytes := extractJSONPayload(output)
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return domain.ModuleResult{}, nil, err
	}

	findings := make([]domain.Finding, 0, len(payload.Results))
	for index, item := range payload.Results {
		severity := mapSeverity(item.Extra.Severity)
		findings = append(findings, domain.Finding{
			ID:           domain.NewFindingID(request.ScanID, index),
			ScanID:       request.ScanID,
			ProjectID:    request.ProjectID,
			Category:     domain.CategorySAST,
			RuleID:       item.CheckID,
			Title:        item.Extra.Message,
			Severity:     severity,
			Confidence:   0.74,
			Reachability: "possible",
			Fingerprint:  domain.MakeFingerprint(module, item.CheckID, item.Path, item.Extra.Message),
			Remediation:  "Review the code path, confirm exploitability, and patch according to the rule guidance.",
			Location:     item.Path,
			Module:       module,
		})
	}

	return domain.ModuleResult{
		Status:       domain.ModuleCompleted,
		Summary:      fmt.Sprintf("Semgrep returned %d findings.", len(findings)),
		FindingCount: len(findings),
	}, findings, nil
}

func parseGitleaks(request domain.AgentScanRequest, module string, output []byte) (domain.ModuleResult, []domain.Finding, error) {
	var payload []struct {
		RuleID      string `json:"RuleID"`
		Description string `json:"Description"`
		File        string `json:"File"`
	}

	if len(bytesTrimSpace(output)) == 0 {
		return domain.ModuleResult{Status: domain.ModuleCompleted, Summary: "Gitleaks returned no findings."}, nil, nil
	}

	if err := json.Unmarshal(output, &payload); err != nil {
		return domain.ModuleResult{}, nil, err
	}

	findings := make([]domain.Finding, 0, len(payload))
	for index, item := range payload {
		findings = append(findings, domain.Finding{
			ID:           domain.NewFindingID(request.ScanID, index),
			ScanID:       request.ScanID,
			ProjectID:    request.ProjectID,
			Category:     domain.CategorySecret,
			RuleID:       item.RuleID,
			Title:        item.Description,
			Severity:     domain.SeverityHigh,
			Confidence:   0.9,
			Reachability: "unknown",
			Fingerprint:  domain.MakeFingerprint(module, item.RuleID, item.File),
			Remediation:  "Rotate the secret and rewrite repository history if the value was committed.",
			Location:     item.File,
			Module:       module,
		})
	}

	return domain.ModuleResult{
		Status:       domain.ModuleCompleted,
		Summary:      fmt.Sprintf("Gitleaks returned %d findings.", len(findings)),
		FindingCount: len(findings),
	}, findings, nil
}

func parseTrivy(request domain.AgentScanRequest, module string, output []byte) (domain.ModuleResult, []domain.Finding, error) {
	var payload struct {
		Results []struct {
			Target          string `json:"Target"`
			Vulnerabilities []struct {
				VulnerabilityID string `json:"VulnerabilityID"`
				Title           string `json:"Title"`
				Severity        string `json:"Severity"`
				PrimaryURL      string `json:"PrimaryURL"`
			} `json:"Vulnerabilities"`
			Misconfigurations []struct {
				ID       string `json:"ID"`
				Title    string `json:"Title"`
				Severity string `json:"Severity"`
			} `json:"Misconfigurations"`
		} `json:"Results"`
	}

	payloadBytes := extractJSONPayload(output)
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return domain.ModuleResult{}, nil, err
	}

	findings := make([]domain.Finding, 0)
	index := 0
	for _, result := range payload.Results {
		for _, vulnerability := range result.Vulnerabilities {
			findings = append(findings, domain.Finding{
				ID:           domain.NewFindingID(request.ScanID, index),
				ScanID:       request.ScanID,
				ProjectID:    request.ProjectID,
				Category:     domain.CategorySCA,
				RuleID:       vulnerability.VulnerabilityID,
				Title:        vulnerability.Title,
				Severity:     mapSeverity(vulnerability.Severity),
				Confidence:   0.75,
				Reachability: "unknown",
				Fingerprint:  domain.MakeFingerprint(module, vulnerability.VulnerabilityID, result.Target),
				EvidenceRef:  vulnerability.PrimaryURL,
				Remediation:  "Patch or pin the vulnerable package version and verify reachability before release.",
				Location:     result.Target,
				Module:       module,
			})
			index++
		}
		for _, misconfiguration := range result.Misconfigurations {
			findings = append(findings, domain.Finding{
				ID:           domain.NewFindingID(request.ScanID, index),
				ScanID:       request.ScanID,
				ProjectID:    request.ProjectID,
				Category:     domain.CategoryIaC,
				RuleID:       misconfiguration.ID,
				Title:        misconfiguration.Title,
				Severity:     mapSeverity(misconfiguration.Severity),
				Confidence:   0.71,
				Reachability: "not-applicable",
				Fingerprint:  domain.MakeFingerprint(module, misconfiguration.ID, result.Target),
				Remediation:  "Apply the recommended IaC control and rerun the profile.",
				Location:     result.Target,
				Module:       module,
			})
			index++
		}
	}

	return domain.ModuleResult{
		Status:       domain.ModuleCompleted,
		Summary:      fmt.Sprintf("Trivy returned %d findings.", len(findings)),
		FindingCount: len(findings),
	}, findings, nil
}

func parseSBOMArtifact(_ domain.AgentScanRequest, _ string, output []byte) (domain.ModuleResult, []domain.Finding, error) {
	if len(bytesTrimSpace(output)) == 0 {
		return domain.ModuleResult{Status: domain.ModuleSkipped, Summary: "No SBOM was generated."}, nil, nil
	}

	return domain.ModuleResult{
		Status:       domain.ModuleCompleted,
		Summary:      "Generated CycloneDX SBOM artifact.",
		FindingCount: 0,
		Artifacts: []domain.ArtifactRef{
			{Kind: "sbom", Label: "CycloneDX", URI: "inline"},
		},
	}, nil, nil
}

func parseOSV(request domain.AgentScanRequest, module string, output []byte) (domain.ModuleResult, []domain.Finding, error) {
	if strings.Contains(string(output), "No package sources found") {
		return domain.ModuleResult{
			Status:       domain.ModuleCompleted,
			Summary:      "OSV found no package sources for the selected target.",
			FindingCount: 0,
		}, nil, nil
	}

	var payload struct {
		Results []struct {
			Packages []struct {
				Package struct {
					Name string `json:"name"`
				} `json:"package"`
				Vulnerabilities []struct {
					ID       string `json:"id"`
					Summary  string `json:"summary"`
					Severity []struct {
						Type  string `json:"type"`
						Score string `json:"score"`
					} `json:"severity"`
				} `json:"vulnerabilities"`
			} `json:"packages"`
		} `json:"results"`
	}

	payloadBytes := extractJSONPayload(output)
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return domain.ModuleResult{}, nil, err
	}

	findings := make([]domain.Finding, 0)
	index := 0
	for _, result := range payload.Results {
		for _, pkg := range result.Packages {
			for _, vulnerability := range pkg.Vulnerabilities {
				findings = append(findings, domain.Finding{
					ID:           domain.NewFindingID(request.ScanID, index),
					ScanID:       request.ScanID,
					ProjectID:    request.ProjectID,
					Category:     domain.CategorySCA,
					RuleID:       vulnerability.ID,
					Title:        vulnerability.Summary,
					Severity:     domain.SeverityHigh,
					Confidence:   0.7,
					Reachability: "unknown",
					Fingerprint:  domain.MakeFingerprint(module, vulnerability.ID, pkg.Package.Name),
					Remediation:  "Upgrade the affected dependency and verify the lockfile update under the same profile.",
					Location:     pkg.Package.Name,
					Module:       module,
				})
				index++
			}
		}
	}

	return domain.ModuleResult{
		Status:       domain.ModuleCompleted,
		Summary:      fmt.Sprintf("OSV returned %d findings.", len(findings)),
		FindingCount: len(findings),
	}, findings, nil
}

func parseCheckov(request domain.AgentScanRequest, module string, output []byte) (domain.ModuleResult, []domain.Finding, error) {
	var payload struct {
		Results struct {
			FailedChecks []struct {
				CheckID   string `json:"check_id"`
				CheckName string `json:"check_name"`
				FilePath  string `json:"file_path"`
				Severity  string `json:"severity"`
			} `json:"failed_checks"`
		} `json:"results"`
	}

	payloadBytes := extractJSONPayload(output)
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return domain.ModuleResult{}, nil, err
	}

	findings := make([]domain.Finding, 0, len(payload.Results.FailedChecks))
	for index, check := range payload.Results.FailedChecks {
		findings = append(findings, domain.Finding{
			ID:           domain.NewFindingID(request.ScanID, index),
			ScanID:       request.ScanID,
			ProjectID:    request.ProjectID,
			Category:     domain.CategoryIaC,
			RuleID:       check.CheckID,
			Title:        check.CheckName,
			Severity:     mapSeverity(check.Severity),
			Confidence:   0.78,
			Reachability: "not-applicable",
			Fingerprint:  domain.MakeFingerprint(module, check.CheckID, check.FilePath),
			Remediation:  "Apply the IaC control recommended by Checkov and rerun the policy pack.",
			Location:     check.FilePath,
			Module:       module,
		})
	}

	return domain.ModuleResult{
		Status:       domain.ModuleCompleted,
		Summary:      fmt.Sprintf("Checkov returned %d findings.", len(findings)),
		FindingCount: len(findings),
	}, findings, nil
}

func parseGovulncheck(request domain.AgentScanRequest, module string, output []byte) (domain.ModuleResult, []domain.Finding, error) {
	items := parseJSONLines(output)
	findings := make([]domain.Finding, 0)
	index := 0
	for _, item := range items {
		osv, ok := item["osv"].(map[string]any)
		if !ok {
			continue
		}
		id, _ := osv["id"].(string)
		summary, _ := osv["summary"].(string)
		if id == "" {
			continue
		}
		findings = append(findings, domain.Finding{
			ID:           domain.NewFindingID(request.ScanID, index),
			ScanID:       request.ScanID,
			ProjectID:    request.ProjectID,
			Category:     domain.CategorySCA,
			RuleID:       id,
			Title:        summary,
			Severity:     domain.SeverityHigh,
			Confidence:   0.8,
			Reachability: "reachable",
			Fingerprint:  domain.MakeFingerprint(module, id, "go"),
			Remediation:  "Upgrade the Go module and verify reachable call paths are removed from the release artifact.",
			Location:     "go.mod",
			Module:       module,
		})
		index++
	}

	return domain.ModuleResult{
		Status:       domain.ModuleCompleted,
		Summary:      fmt.Sprintf("govulncheck returned %d findings.", len(findings)),
		FindingCount: len(findings),
	}, findings, nil
}

func parseStaticcheck(request domain.AgentScanRequest, module string, output []byte) (domain.ModuleResult, []domain.Finding, error) {
	items := parseJSONLines(output)
	findings := make([]domain.Finding, 0)
	index := 0
	for _, item := range items {
		code, _ := item["code"].(string)
		location, _ := item["location"].(map[string]any)
		message, _ := item["message"].(string)
		file, _ := location["file"].(string)
		if code == "" {
			continue
		}
		findings = append(findings, domain.Finding{
			ID:           domain.NewFindingID(request.ScanID, index),
			ScanID:       request.ScanID,
			ProjectID:    request.ProjectID,
			Category:     domain.CategoryMaintainability,
			RuleID:       code,
			Title:        message,
			Severity:     domain.SeverityLow,
			Confidence:   0.65,
			Reachability: "not-applicable",
			Fingerprint:  domain.MakeFingerprint(module, code, file),
			Remediation:  "Clean up the unused or suspicious code path to keep the scan surface tight.",
			Location:     file,
			Module:       module,
		})
		index++
	}
	return domain.ModuleResult{
		Status:       domain.ModuleCompleted,
		Summary:      fmt.Sprintf("Staticcheck returned %d findings.", len(findings)),
		FindingCount: len(findings),
	}, findings, nil
}

func parseKnip(request domain.AgentScanRequest, module string, output []byte) (domain.ModuleResult, []domain.Finding, error) {
	var payload struct {
		Files        []string `json:"files"`
		Dependencies []string `json:"dependencies"`
	}

	if err := json.Unmarshal(output, &payload); err != nil {
		return domain.ModuleResult{}, nil, err
	}

	findings := make([]domain.Finding, 0, len(payload.Files)+len(payload.Dependencies))
	index := 0
	for _, file := range payload.Files {
		findings = append(findings, domain.Finding{
			ID:           domain.NewFindingID(request.ScanID, index),
			ScanID:       request.ScanID,
			ProjectID:    request.ProjectID,
			Category:     domain.CategoryMaintainability,
			RuleID:       "knip.unused_file",
			Title:        "Potential unused file detected",
			Severity:     domain.SeverityLow,
			Confidence:   0.72,
			Reachability: "not-applicable",
			Fingerprint:  domain.MakeFingerprint(module, "file", file),
			Remediation:  "Confirm the file is dead code and remove it to reduce attack surface and maintenance drag.",
			Location:     file,
			Module:       module,
		})
		index++
	}
	for _, dependency := range payload.Dependencies {
		findings = append(findings, domain.Finding{
			ID:           domain.NewFindingID(request.ScanID, index),
			ScanID:       request.ScanID,
			ProjectID:    request.ProjectID,
			Category:     domain.CategoryMaintainability,
			RuleID:       "knip.unused_dependency",
			Title:        "Potential unused dependency detected",
			Severity:     domain.SeverityLow,
			Confidence:   0.7,
			Reachability: "not-applicable",
			Fingerprint:  domain.MakeFingerprint(module, "dependency", dependency),
			Remediation:  "Remove the dependency if unused to reduce supply-chain exposure.",
			Location:     dependency,
			Module:       module,
		})
		index++
	}

	return domain.ModuleResult{
		Status:       domain.ModuleCompleted,
		Summary:      fmt.Sprintf("Knip returned %d maintainability findings.", len(findings)),
		FindingCount: len(findings),
	}, findings, nil
}

func parseVulture(request domain.AgentScanRequest, module string, output []byte) (domain.ModuleResult, []domain.Finding, error) {
	var payload []struct {
		Name       string `json:"name"`
		Type       string `json:"type"`
		Filename   string `json:"filename"`
		Confidence int    `json:"confidence"`
	}
	if err := json.Unmarshal(output, &payload); err != nil {
		return domain.ModuleResult{}, nil, err
	}

	findings := make([]domain.Finding, 0, len(payload))
	for index, item := range payload {
		findings = append(findings, domain.Finding{
			ID:           domain.NewFindingID(request.ScanID, index),
			ScanID:       request.ScanID,
			ProjectID:    request.ProjectID,
			Category:     domain.CategoryMaintainability,
			RuleID:       "vulture." + item.Type,
			Title:        "Potential dead Python code: " + item.Name,
			Severity:     domain.SeverityLow,
			Confidence:   float64(item.Confidence) / 100,
			Reachability: "not-applicable",
			Fingerprint:  domain.MakeFingerprint(module, item.Type, item.Name, item.Filename),
			Remediation:  "Confirm whether the symbol is truly unused, then remove it and rerun the profile.",
			Location:     item.Filename,
			Module:       module,
		})
	}

	return domain.ModuleResult{
		Status:       domain.ModuleCompleted,
		Summary:      fmt.Sprintf("Vulture returned %d maintainability findings.", len(findings)),
		FindingCount: len(findings),
	}, findings, nil
}

func parseClam(request domain.AgentScanRequest, module string, output []byte) (domain.ModuleResult, []domain.Finding, error) {
	lines := strings.Split(string(output), "\n")
	findings := make([]domain.Finding, 0)
	index := 0
	for _, line := range lines {
		if !strings.Contains(line, "FOUND") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}
		location := strings.TrimSpace(parts[0])
		signature := strings.TrimSpace(strings.TrimSuffix(parts[1], "FOUND"))
		findings = append(findings, domain.Finding{
			ID:           domain.NewFindingID(request.ScanID, index),
			ScanID:       request.ScanID,
			ProjectID:    request.ProjectID,
			Category:     domain.CategoryMalware,
			RuleID:       "clamav." + strings.ReplaceAll(strings.ToLower(signature), " ", "_"),
			Title:        "ClamAV signature matched: " + signature,
			Severity:     domain.SeverityCritical,
			Confidence:   0.95,
			Reachability: "not-applicable",
			Fingerprint:  domain.MakeFingerprint(module, signature, location),
			Remediation:  "Quarantine the file, inspect repository history, and rerun the malware profile after cleanup.",
			Location:     location,
			Module:       module,
		})
		index++
	}

	return domain.ModuleResult{
		Status:       domain.ModuleCompleted,
		Summary:      fmt.Sprintf("ClamAV returned %d malware findings.", len(findings)),
		FindingCount: len(findings),
	}, findings, nil
}

func parseNuclei(request domain.AgentScanRequest, module string, output []byte) (domain.ModuleResult, []domain.Finding, error) {
	items := parseJSONLines(output)
	findings := make([]domain.Finding, 0)
	index := 0
	for _, item := range items {
		info, _ := item["info"].(map[string]any)
		title, _ := info["name"].(string)
		severity, _ := info["severity"].(string)
		templateID, _ := item["template-id"].(string)
		matched, _ := item["matched-at"].(string)
		if templateID == "" {
			continue
		}
		findings = append(findings, domain.Finding{
			ID:           domain.NewFindingID(request.ScanID, index),
			ScanID:       request.ScanID,
			ProjectID:    request.ProjectID,
			Category:     domain.CategoryDAST,
			RuleID:       templateID,
			Title:        title,
			Severity:     mapSeverity(severity),
			Confidence:   0.68,
			Reachability: "reachable",
			Fingerprint:  domain.MakeFingerprint(module, templateID, matched),
			Remediation:  "Validate the finding against the staging target and apply the matching fix or compensating control.",
			Location:     matched,
			Module:       module,
		})
		index++
	}

	return domain.ModuleResult{
		Status:       domain.ModuleCompleted,
		Summary:      fmt.Sprintf("Nuclei returned %d findings.", len(findings)),
		FindingCount: len(findings),
	}, findings, nil
}

func mapSeverity(input string) domain.Severity {
	switch strings.ToLower(input) {
	case "critical", "error":
		return domain.SeverityCritical
	case "high", "warning":
		return domain.SeverityHigh
	case "medium":
		return domain.SeverityMedium
	case "low":
		return domain.SeverityLow
	default:
		return domain.SeverityInfo
	}
}

func bytesTrimSpace(data []byte) []byte {
	return []byte(strings.TrimSpace(string(data)))
}

func extractJSONPayload(data []byte) []byte {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil
	}
	lines := strings.Split(trimmed, "\n")
	for index, line := range lines {
		candidate := strings.TrimSpace(line)
		if looksLikeJSONLine(candidate) {
			return []byte(strings.TrimSpace(strings.Join(lines[index:], "\n")))
		}
	}
	return bytesTrimSpace(data)
}

func looksLikeJSONLine(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}
	if strings.HasPrefix(line, "{") {
		return true
	}
	if !strings.HasPrefix(line, "[") {
		return false
	}
	if closing := strings.Index(line, "]"); closing > 0 && closing < len(line)-1 {
		switch line[closing+1] {
		case ' ', '\t':
			return false
		}
	}
	if len(line) == 1 {
		return false
	}
	switch line[1] {
	case '{', '[', '"', ']', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 't', 'f', 'n':
		return true
	default:
		return false
	}
}
