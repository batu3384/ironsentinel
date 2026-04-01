package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
)

var runtimeAuditPatterns = []struct {
	ruleID      string
	title       string
	severity    domain.Severity
	pattern     *regexp.Regexp
	remediation string
}{
	{
		ruleID:      "runtime.exposed_debug_mode",
		title:       "Debug mode appears to be enabled in runtime configuration",
		severity:    domain.SeverityMedium,
		pattern:     regexp.MustCompile(`(?im)\b(debug|flask_env|node_env)\s*[:=]\s*(true|1|development)\b`),
		remediation: "Disable debug-oriented runtime flags in committed configuration and load safe defaults per environment.",
	},
	{
		ruleID:      "runtime.host_network",
		title:       "Host-level network exposure declared in workload config",
		severity:    domain.SeverityHigh,
		pattern:     regexp.MustCompile(`(?im)\b(hostNetwork|hostPID|hostIPC)\s*:\s*true\b`),
		remediation: "Avoid host-level namespace sharing unless it is explicitly required and hardened with compensating controls.",
	},
	{
		ruleID:      "runtime.privilege_escalation",
		title:       "Runtime configuration allows elevated privileges",
		severity:    domain.SeverityHigh,
		pattern:     regexp.MustCompile(`(?im)\b(privileged|allowPrivilegeEscalation)\s*:\s*true\b`),
		remediation: "Drop unnecessary privileges and keep runtime workloads under least-privilege defaults.",
	},
	{
		ruleID:      "runtime.readonly_disabled",
		title:       "Writable root filesystem declared for a runtime workload",
		severity:    domain.SeverityMedium,
		pattern:     regexp.MustCompile(`(?im)\breadOnlyRootFilesystem\s*:\s*false\b`),
		remediation: "Prefer read-only root filesystems and explicit writable mounts for mutable data paths.",
	},
	{
		ruleID:      "runtime.exposed_bind",
		title:       "Workload binds to all interfaces",
		severity:    domain.SeverityMedium,
		pattern:     regexp.MustCompile(`(?im)\b(0\.0\.0\.0|::)\b`),
		remediation: "Bind only to the required network interface or place the service behind an explicit ingress boundary.",
	},
}

var restrictedLicensePatterns = []struct {
	pattern  *regexp.Regexp
	severity domain.Severity
}{
	{pattern: regexp.MustCompile(`(?i)\b(agpl|gpl|sspl|commons-clause)\b`), severity: domain.SeverityHigh},
	{pattern: regexp.MustCompile(`(?i)\b(lgpl|mpl|epl)\b`), severity: domain.SeverityMedium},
}

func heuristicDependencyConfusion(ctx context.Context, cfg config.Config, request domain.AgentScanRequest, outputDir string) (domain.ModuleResult, []domain.Finding, error) {
	start := time.Now()
	findings := make([]domain.Finding, 0, 8)
	index := 0
	projectName := normalizeDependencyToken(request.DisplayName)

	addFinding := func(ruleID, title string, severity domain.Severity, remediation, location string) {
		findings = append(findings, domain.Finding{
			ID:           domain.NewFindingID(request.ScanID, index),
			ScanID:       request.ScanID,
			ProjectID:    request.ProjectID,
			Category:     domain.CategorySCA,
			RuleID:       ruleID,
			Title:        title,
			Severity:     severity,
			Confidence:   0.68,
			Reachability: "possible",
			Fingerprint:  domain.MakeFingerprint("dependency-confusion", ruleID, location, title),
			Remediation:  remediation,
			Location:     location,
			Module:       "dependency-confusion",
		})
		index++
	}

	npmrcPath := filepath.Join(request.TargetPath, ".npmrc")
	hasNPMRegistryPin := fileContainsAny(npmrcPath, []string{"registry=", "@", ":registry="})
	packageJSONPath := filepath.Join(request.TargetPath, "package.json")
	if bytes, err := os.ReadFile(packageJSONPath); err == nil {
		var payload struct {
			Name            string            `json:"name"`
			Dependencies    map[string]string `json:"dependencies"`
			DevDependencies map[string]string `json:"devDependencies"`
		}
		if json.Unmarshal(bytes, &payload) == nil {
			for name := range mergeStringMap(payload.Dependencies, payload.DevDependencies) {
				if looksInternalPackage(name, payload.Name, projectName) && !hasNPMRegistryPin {
					addFinding(
						"dependency_confusion.unpinned_npm_scope",
						fmt.Sprintf("Potential dependency confusion risk for npm package %q", name),
						domain.SeverityHigh,
						"Pin the package scope to a trusted private registry and prevent ambiguous fallback to the public ecosystem.",
						"package.json",
					)
				}
			}
		}
	}

	requirementsPath := filepath.Join(request.TargetPath, "requirements.txt")
	if bytes, err := os.ReadFile(requirementsPath); err == nil {
		text := string(bytes)
		if strings.Contains(text, "--extra-index-url") {
			addFinding(
				"dependency_confusion.pip_extra_index_url",
				"pip configuration uses extra-index-url, which can widen dependency confusion exposure",
				domain.SeverityHigh,
				"Prefer a single pinned private index or explicitly trusted primary source for private packages.",
				"requirements.txt",
			)
		}
		if !strings.Contains(text, "--index-url") {
			for _, line := range strings.Split(text, "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
					continue
				}
				token := normalizeDependencyToken(strings.SplitN(line, "=", 2)[0])
				if looksInternalPackage(token, request.DisplayName, projectName) {
					addFinding(
						"dependency_confusion.pip_unpinned_internal",
						fmt.Sprintf("Potential dependency confusion risk for Python package %q", token),
						domain.SeverityMedium,
						"Route internal packages through a pinned private package index and avoid fallback to public repositories.",
						"requirements.txt",
					)
				}
			}
		}
	}

	result := domain.ModuleResult{
		Name:         "dependency-confusion",
		Category:     domain.CategorySCA,
		Status:       domain.ModuleCompleted,
		Summary:      fmt.Sprintf("Inspected registry pinning and package naming patterns in %dms.", time.Since(start).Milliseconds()),
		FindingCount: len(findings),
		DurationMs:   time.Since(start).Milliseconds(),
	}
	if artifact, err := writeHeuristicEvidence(cfg, outputDir, "dependency-confusion", result, findings); err == nil {
		result.Artifacts = append(result.Artifacts, artifact)
		findings = attachDefaultEvidence(findings, result.Artifacts)
	}
	return result, findings, ctx.Err()
}

func heuristicRuntimeConfigAudit(ctx context.Context, cfg config.Config, request domain.AgentScanRequest, outputDir string) (domain.ModuleResult, []domain.Finding, error) {
	start := time.Now()
	findings := make([]domain.Finding, 0, 12)
	index := 0

	addFinding := func(ruleID, title string, severity domain.Severity, remediation, location string) {
		findings = append(findings, domain.Finding{
			ID:           domain.NewFindingID(request.ScanID, index),
			ScanID:       request.ScanID,
			ProjectID:    request.ProjectID,
			Category:     domain.CategoryPlatform,
			RuleID:       ruleID,
			Title:        title,
			Severity:     severity,
			Confidence:   0.73,
			Reachability: "repository",
			Fingerprint:  domain.MakeFingerprint("runtime-config-audit", ruleID, location),
			Remediation:  remediation,
			Location:     location,
			Module:       "runtime-config-audit",
		})
		index++
	}

	err := filepath.WalkDir(request.TargetPath, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || ctx.Err() != nil {
			return walkErr
		}
		if shouldIgnoreManagedScanPath(cfg, request.TargetPath, path) {
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			if _, ignored := ignoredDirs[entry.Name()]; ignored && path != request.TargetPath {
				return filepath.SkipDir
			}
			return nil
		}

		relative := trimLocation(request.TargetPath, path)
		info, err := entry.Info()
		if err == nil {
			perm := info.Mode().Perm()
			if perm&0o002 != 0 && isSensitiveRepoFile(strings.ToLower(relative), strings.ToLower(entry.Name()), strings.ToLower(filepath.Ext(entry.Name()))) {
				addFinding(
					"runtime.world_writable_sensitive_file",
					"Sensitive runtime file is world-writable",
					domain.SeverityHigh,
					"Restrict write permissions on secrets, state, and runtime config files to the minimum required owner or service account.",
					relative,
				)
			}
		}

		if !isCandidateTextFile(path) {
			return nil
		}
		bytes, err := os.ReadFile(path)
		if err != nil || len(bytes) == 0 || len(bytes) > 1024*1024 {
			return nil
		}
		if xcodeProjectUsesDebugInRelease(relative, bytes) {
			addFinding(
				"runtime.exposed_debug_mode",
				"Debug mode appears to be enabled in runtime configuration",
				domain.SeverityMedium,
				"Keep Xcode release builds on optimized, non-debug settings and reserve DEBUG-only flags for the Debug configuration.",
				relative,
			)
			return nil
		}
		if shouldSkipGenericRuntimeAudit(relative, bytes) {
			return nil
		}
		for _, matcher := range runtimeAuditPatterns {
			if matcher.pattern.Match(bytes) {
				addFinding(matcher.ruleID, matcher.title, matcher.severity, matcher.remediation, relative)
			}
		}
		if strings.HasPrefix(strings.ToLower(entry.Name()), ".env") {
			addFinding(
				"runtime.committed_env_file",
				"Committed environment file detected in repository",
				domain.SeverityMedium,
				"Keep deployment environment variables outside the repository and inject them at runtime from a secret source.",
				relative,
			)
		}
		return nil
	})

	result := domain.ModuleResult{
		Name:         "runtime-config-audit",
		Category:     domain.CategoryPlatform,
		Status:       domain.ModuleCompleted,
		Summary:      fmt.Sprintf("Audited runtime configuration surface in %dms.", time.Since(start).Milliseconds()),
		FindingCount: len(findings),
		DurationMs:   time.Since(start).Milliseconds(),
	}
	if artifact, writeErr := writeHeuristicEvidence(cfg, outputDir, "runtime-config-audit", result, findings); writeErr == nil {
		result.Artifacts = append(result.Artifacts, artifact)
		findings = attachDefaultEvidence(findings, result.Artifacts)
	}
	return result, findings, err
}

func shouldSkipGenericRuntimeAudit(relative string, contents []byte) bool {
	lower := strings.ToLower(filepath.ToSlash(relative))
	if strings.HasSuffix(lower, ".xcodeproj/project.pbxproj") {
		return !xcodeProjectUsesDebugInRelease(relative, contents)
	}
	return false
}

func xcodeProjectUsesDebugInRelease(relative string, contents []byte) bool {
	lower := strings.ToLower(filepath.ToSlash(relative))
	if !strings.HasSuffix(lower, ".xcodeproj/project.pbxproj") {
		return false
	}
	text := string(contents)
	releaseHasDebugLeak := regexp.MustCompile(`(?s)/\*\s*Release\s*\*/.*?(DEBUG=1|ENABLE_TESTABILITY\s*=\s*YES;|SWIFT_ACTIVE_COMPILATION_CONDITIONS\s*=\s*DEBUG;|SWIFT_OPTIMIZATION_LEVEL\s*=\s*"-Onone";|MTL_ENABLE_DEBUG_INFO\s*=\s*INCLUDE_SOURCE;)`)
	return releaseHasDebugLeak.MatchString(text)
}

func heuristicBinaryEntropy(ctx context.Context, cfg config.Config, request domain.AgentScanRequest, outputDir string) (domain.ModuleResult, []domain.Finding, error) {
	start := time.Now()
	findings := make([]domain.Finding, 0, 8)
	index := 0

	err := filepath.WalkDir(request.TargetPath, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || ctx.Err() != nil {
			return walkErr
		}
		if shouldIgnoreManagedScanPath(cfg, request.TargetPath, path) {
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			if _, ignored := ignoredDirs[entry.Name()]; ignored && path != request.TargetPath {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil || !looksLikeBinaryCandidate(path, info.Mode()) || info.Size() < 4096 {
			return nil
		}
		bytes, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if len(bytes) > 2*1024*1024 {
			bytes = bytes[:2*1024*1024]
		}
		entropy := shannonEntropy(bytes)
		if entropy < 7.15 {
			return nil
		}
		severity := domain.SeverityMedium
		title := fmt.Sprintf("High-entropy binary artifact detected (entropy %.2f)", entropy)
		if entropy >= 7.6 {
			severity = domain.SeverityHigh
			title = fmt.Sprintf("Possible packed or obfuscated binary artifact detected (entropy %.2f)", entropy)
		}
		findings = append(findings, domain.Finding{
			ID:           domain.NewFindingID(request.ScanID, index),
			ScanID:       request.ScanID,
			ProjectID:    request.ProjectID,
			Category:     domain.CategoryMalware,
			RuleID:       "binary.entropy",
			Title:        title,
			Severity:     severity,
			Confidence:   0.61,
			Reachability: "repository",
			Fingerprint:  domain.MakeFingerprint("binary-entropy", trimLocation(request.TargetPath, path), fmt.Sprintf("%.2f", entropy)),
			Remediation:  "Inspect the binary source, provenance, and unpacking path before shipping the artifact to production environments.",
			Location:     trimLocation(request.TargetPath, path),
			Module:       "binary-entropy",
		})
		index++
		return nil
	})

	result := domain.ModuleResult{
		Name:         "binary-entropy",
		Category:     domain.CategoryMalware,
		Status:       domain.ModuleCompleted,
		Summary:      fmt.Sprintf("Inspected compiled and binary artifacts for packed or obfuscated content in %dms.", time.Since(start).Milliseconds()),
		FindingCount: len(findings),
		DurationMs:   time.Since(start).Milliseconds(),
	}
	if artifact, writeErr := writeHeuristicEvidence(cfg, outputDir, "binary-entropy", result, findings); writeErr == nil {
		result.Artifacts = append(result.Artifacts, artifact)
		findings = attachDefaultEvidence(findings, result.Artifacts)
	}
	return result, findings, err
}

func buildTrivyImageCommand(cfg config.Config, binary string, execution moduleExecution) (*exec.Cmd, string, error) {
	if !execution.request.Profile.AllowNetwork || cfg.OfflineMode {
		return nil, "", errSkipModule("container image scanning requires network access or a pre-pulled image")
	}
	image := discoverContainerImageTarget(execution.request.TargetPath)
	if image == "" {
		return nil, "", errSkipModule("no container image reference detected")
	}
	args := []string{"image", "--quiet", "--format", "json"}
	if dirHasEntries(filepath.Join(cfg.MirrorDir, "trivy-db")) {
		args = append(args, "--cache-dir", mirrorPathForRequest(cfg, execution.request, "trivy"))
	}
	if cfg.OfflineMode {
		args = append(args, "--offline-scan", "--skip-db-update", "--skip-java-db-update")
	}
	args = append(args, image)
	return exec.Command(binary, args...), "", nil
}

func buildLicenseeCommand(binary string, execution moduleExecution, _ []string) (*exec.Cmd, string, error) {
	return exec.Command(binary, "detect", execution.request.TargetPath, "--json"), "", nil
}

func buildScancodeCommand(binary string, execution moduleExecution, _ []string) (*exec.Cmd, string, error) {
	reportExecPath, _ := executionArtifactPaths(execution, "scancode.json")
	return exec.Command(binary, "--json-pp", reportExecPath, execution.request.TargetPath), reportExecPath, nil
}

func buildGrypeCommand(binary string, execution moduleExecution, _ []string) (*exec.Cmd, string, error) {
	return exec.Command(binary, fmt.Sprintf("dir:%s", execution.request.TargetPath), "-o", "json"), "", nil
}

func buildTfsecCommand(binary string, execution moduleExecution, stacks []string) (*exec.Cmd, string, error) {
	if !hasAnyStackValue(stacks, "terraform", "iac") {
		return nil, "", errSkipModule("terraform stack not detected")
	}
	return exec.Command(binary, execution.request.TargetPath, "--format", "json", "--no-color"), "", nil
}

func buildKICSCommand(binary string, execution moduleExecution, stacks []string) (*exec.Cmd, string, error) {
	if !hasAnyStackValue(stacks, "terraform", "iac", "kubernetes", "helm", "docker", "container") {
		return nil, "", errSkipModule("iac stack not detected")
	}
	reportExecPath, _ := executionArtifactPaths(execution, "kics.sarif")
	outputDir := filepath.Dir(reportExecPath)
	return exec.Command(binary, "scan", "-p", execution.request.TargetPath, "--report-formats", "sarif", "--output-name", "kics", "--output-path", outputDir, "--no-progress"), reportExecPath, nil
}

func buildYARAXCommand(cfg config.Config, binary string, execution moduleExecution, _ []string) (*exec.Cmd, string, error) {
	if !dirHasEntries(cfg.YARARulesDir) {
		return nil, "", errSkipModule("no YARA rule set configured")
	}
	return exec.Command(binary, "scan", "--output-format", "json", cfg.YARARulesDir, execution.request.TargetPath), "", nil
}

func parseGrype(request domain.AgentScanRequest, module string, output []byte) (domain.ModuleResult, []domain.Finding, error) {
	var payload struct {
		Matches []struct {
			Vulnerability struct {
				ID       string `json:"id"`
				Severity string `json:"severity"`
				Data     string `json:"dataSource"`
			} `json:"vulnerability"`
			Artifact struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Type      string `json:"type"`
				Locations []struct {
					Path string `json:"path"`
				} `json:"locations"`
			} `json:"artifact"`
			MatchDetails []struct {
				Type string `json:"type"`
			} `json:"matchDetails"`
		} `json:"matches"`
	}

	payloadBytes := extractJSONPayload(output)
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return domain.ModuleResult{}, nil, err
	}

	findings := make([]domain.Finding, 0, len(payload.Matches))
	for index, match := range payload.Matches {
		location := match.Artifact.Name
		if len(match.Artifact.Locations) > 0 && strings.TrimSpace(match.Artifact.Locations[0].Path) != "" {
			location = match.Artifact.Locations[0].Path
		}
		title := strings.TrimSpace(match.Vulnerability.ID)
		if title == "" {
			continue
		}
		if strings.TrimSpace(match.Artifact.Version) != "" {
			title = fmt.Sprintf("%s affects %s@%s", match.Vulnerability.ID, match.Artifact.Name, match.Artifact.Version)
		}
		findings = append(findings, domain.Finding{
			ID:           domain.NewFindingID(request.ScanID, index),
			ScanID:       request.ScanID,
			ProjectID:    request.ProjectID,
			Category:     domain.CategorySCA,
			RuleID:       match.Vulnerability.ID,
			Title:        title,
			Severity:     mapSeverity(match.Vulnerability.Severity),
			Confidence:   0.8,
			Reachability: "possible",
			Fingerprint:  domain.MakeFingerprint(module, match.Vulnerability.ID, location),
			EvidenceRef:  match.Vulnerability.Data,
			Remediation:  "Upgrade or remove the impacted package and verify the compiled artifact no longer carries the vulnerable component.",
			Location:     location,
			Module:       module,
		})
	}

	return domain.ModuleResult{
		Status:       domain.ModuleCompleted,
		Summary:      fmt.Sprintf("Grype returned %d compiled artifact findings.", len(findings)),
		FindingCount: len(findings),
	}, findings, nil
}

func parseTrivyImage(request domain.AgentScanRequest, module string, output []byte) (domain.ModuleResult, []domain.Finding, error) {
	var payload struct {
		Results []struct {
			Target          string `json:"Target"`
			Vulnerabilities []struct {
				VulnerabilityID string `json:"VulnerabilityID"`
				Title           string `json:"Title"`
				Severity        string `json:"Severity"`
				PrimaryURL      string `json:"PrimaryURL"`
			} `json:"Vulnerabilities"`
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
				Category:     domain.CategoryContainer,
				RuleID:       vulnerability.VulnerabilityID,
				Title:        vulnerability.Title,
				Severity:     mapSeverity(vulnerability.Severity),
				Confidence:   0.79,
				Reachability: "image",
				Fingerprint:  domain.MakeFingerprint(module, vulnerability.VulnerabilityID, result.Target),
				EvidenceRef:  vulnerability.PrimaryURL,
				Remediation:  "Rebuild the container image on top of a patched base layer and republish the signed artifact.",
				Location:     result.Target,
				Module:       module,
			})
			index++
		}
	}

	return domain.ModuleResult{
		Status:       domain.ModuleCompleted,
		Summary:      fmt.Sprintf("Trivy image mode returned %d container image findings.", len(findings)),
		FindingCount: len(findings),
	}, findings, nil
}

func parseLicensee(request domain.AgentScanRequest, module string, output []byte) (domain.ModuleResult, []domain.Finding, error) {
	if len(bytesTrimSpace(output)) == 0 {
		return domain.ModuleResult{Status: domain.ModuleCompleted, Summary: "Licensee returned no license compliance findings."}, nil, nil
	}

	var payload struct {
		MatchedLicense string `json:"matched_license"`
		License        string `json:"license"`
		Confidence     int    `json:"confidence"`
	}
	if err := json.Unmarshal(extractJSONPayload(output), &payload); err != nil {
		return domain.ModuleResult{}, nil, err
	}
	expression := firstNonEmpty(payload.MatchedLicense, payload.License)
	if strings.TrimSpace(expression) == "" {
		finding := domain.Finding{
			ID:           domain.NewFindingID(request.ScanID, 0),
			ScanID:       request.ScanID,
			ProjectID:    request.ProjectID,
			Category:     domain.CategoryCompliance,
			RuleID:       "licensee.unknown",
			Title:        "Repository license could not be confidently identified",
			Severity:     domain.SeverityMedium,
			Confidence:   0.62,
			Reachability: "repository",
			Fingerprint:  domain.MakeFingerprint(module, "licensee.unknown", request.ProjectID),
			Remediation:  "Add an explicit project license file and validate downstream license obligations before distribution.",
			Location:     "LICENSE",
			Module:       module,
		}
		return domain.ModuleResult{Status: domain.ModuleCompleted, Summary: "Licensee detected an unknown repository license.", FindingCount: 1}, []domain.Finding{finding}, nil
	}
	if severity, ok := restrictedLicenseSeverity(expression); ok {
		finding := domain.Finding{
			ID:           domain.NewFindingID(request.ScanID, 0),
			ScanID:       request.ScanID,
			ProjectID:    request.ProjectID,
			Category:     domain.CategoryCompliance,
			RuleID:       "licensee.restricted",
			Title:        fmt.Sprintf("Repository license %q requires legal review", expression),
			Severity:     severity,
			Confidence:   0.8,
			Reachability: "repository",
			Fingerprint:  domain.MakeFingerprint(module, expression, request.ProjectID),
			Remediation:  "Review license obligations, redistribution terms, and policy exceptions before release.",
			Location:     "LICENSE",
			Module:       module,
		}
		return domain.ModuleResult{Status: domain.ModuleCompleted, Summary: "Licensee detected a restricted repository license.", FindingCount: 1}, []domain.Finding{finding}, nil
	}
	return domain.ModuleResult{Status: domain.ModuleCompleted, Summary: fmt.Sprintf("Licensee detected repository license %q.", expression)}, nil, nil
}

func parseScancode(request domain.AgentScanRequest, module string, output []byte) (domain.ModuleResult, []domain.Finding, error) {
	var payload struct {
		Files []struct {
			Path               string   `json:"path"`
			LicenseExpressions []string `json:"license_expressions,omitempty"`
			LicenseDetections  []struct {
				LicenseExpression string `json:"license_expression"`
			} `json:"license_detections,omitempty"`
		} `json:"files"`
	}
	if err := json.Unmarshal(extractJSONPayload(output), &payload); err != nil {
		return domain.ModuleResult{}, nil, err
	}

	findings := make([]domain.Finding, 0)
	seen := make(map[string]struct{})
	index := 0
	for _, file := range payload.Files {
		licenses := append([]string(nil), file.LicenseExpressions...)
		for _, detection := range file.LicenseDetections {
			licenses = append(licenses, detection.LicenseExpression)
		}
		for _, expression := range licenses {
			severity, restricted := restrictedLicenseSeverity(expression)
			if !restricted {
				continue
			}
			key := file.Path + "|" + expression
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			findings = append(findings, domain.Finding{
				ID:           domain.NewFindingID(request.ScanID, index),
				ScanID:       request.ScanID,
				ProjectID:    request.ProjectID,
				Category:     domain.CategoryCompliance,
				RuleID:       "scancode.restricted_license",
				Title:        fmt.Sprintf("Restricted license expression detected: %s", expression),
				Severity:     severity,
				Confidence:   0.76,
				Reachability: "repository",
				Fingerprint:  domain.MakeFingerprint(module, expression, file.Path),
				Remediation:  "Review dependency redistribution terms and align package intake with the approved license policy.",
				Location:     file.Path,
				Module:       module,
			})
			index++
		}
	}

	return domain.ModuleResult{
		Status:       domain.ModuleCompleted,
		Summary:      fmt.Sprintf("ScanCode returned %d license compliance findings.", len(findings)),
		FindingCount: len(findings),
	}, findings, nil
}

func parseTfsec(request domain.AgentScanRequest, module string, output []byte) (domain.ModuleResult, []domain.Finding, error) {
	var payload struct {
		Results []struct {
			RuleID      string `json:"rule_id"`
			LongID      string `json:"long_id"`
			Description string `json:"description"`
			Impact      string `json:"impact"`
			Resolution  string `json:"resolution"`
			Severity    string `json:"severity"`
			Location    struct {
				Filename string `json:"filename"`
			} `json:"location"`
		} `json:"results"`
	}

	if err := json.Unmarshal(extractJSONPayload(output), &payload); err != nil {
		return domain.ModuleResult{}, nil, err
	}

	findings := make([]domain.Finding, 0, len(payload.Results))
	for index, item := range payload.Results {
		ruleID := firstNonEmpty(item.LongID, item.RuleID)
		findings = append(findings, domain.Finding{
			ID:           domain.NewFindingID(request.ScanID, index),
			ScanID:       request.ScanID,
			ProjectID:    request.ProjectID,
			Category:     domain.CategoryIaC,
			RuleID:       ruleID,
			Title:        item.Description,
			Severity:     mapSeverity(item.Severity),
			Confidence:   0.79,
			Reachability: "infrastructure",
			Fingerprint:  domain.MakeFingerprint(module, ruleID, item.Location.Filename),
			Remediation:  firstNonEmpty(item.Resolution, "Apply the Terraform hardening guidance and rerun the infrastructure scan."),
			Location:     item.Location.Filename,
			Module:       module,
		})
	}

	return domain.ModuleResult{
		Status:       domain.ModuleCompleted,
		Summary:      fmt.Sprintf("tfsec returned %d infrastructure findings.", len(findings)),
		FindingCount: len(findings),
	}, findings, nil
}

func parseYARAX(request domain.AgentScanRequest, module string, output []byte) (domain.ModuleResult, []domain.Finding, error) {
	trimmed := extractJSONPayload(output)
	if len(trimmed) == 0 {
		return domain.ModuleResult{Status: domain.ModuleCompleted, Summary: "YARA-X returned no malware matches."}, nil, nil
	}

	type yaraMatch struct {
		Rule string `json:"rule"`
		Path string `json:"path"`
	}

	findings := make([]domain.Finding, 0)
	index := 0
	var list []yaraMatch
	if err := json.Unmarshal(trimmed, &list); err == nil {
		for _, match := range list {
			findings = append(findings, newYARAFinding(request, module, index, match.Rule, match.Path))
			index++
		}
		return domain.ModuleResult{Status: domain.ModuleCompleted, Summary: fmt.Sprintf("YARA-X returned %d signature matches.", len(findings)), FindingCount: len(findings)}, findings, nil
	}

	var payload struct {
		Matches []yaraMatch `json:"matches"`
	}
	if err := json.Unmarshal(trimmed, &payload); err != nil {
		return domain.ModuleResult{}, nil, err
	}
	for _, match := range payload.Matches {
		findings = append(findings, newYARAFinding(request, module, index, match.Rule, match.Path))
		index++
	}
	return domain.ModuleResult{Status: domain.ModuleCompleted, Summary: fmt.Sprintf("YARA-X returned %d signature matches.", len(findings)), FindingCount: len(findings)}, findings, nil
}

func newYARAFinding(request domain.AgentScanRequest, module string, index int, rule, path string) domain.Finding {
	return domain.Finding{
		ID:           domain.NewFindingID(request.ScanID, index),
		ScanID:       request.ScanID,
		ProjectID:    request.ProjectID,
		Category:     domain.CategoryMalware,
		RuleID:       "yara." + strings.ToLower(strings.ReplaceAll(strings.TrimSpace(rule), " ", "_")),
		Title:        "YARA signature matched: " + strings.TrimSpace(rule),
		Severity:     domain.SeverityHigh,
		Confidence:   0.87,
		Reachability: "repository",
		Fingerprint:  domain.MakeFingerprint(module, rule, path),
		Remediation:  "Inspect the matched artifact, confirm provenance, and quarantine or delete suspicious binaries before release.",
		Location:     path,
		Module:       module,
	}
}

func restrictedLicenseSeverity(expression string) (domain.Severity, bool) {
	for _, matcher := range restrictedLicensePatterns {
		if matcher.pattern.MatchString(expression) {
			return matcher.severity, true
		}
	}
	return "", false
}

func discoverContainerImageTarget(root string) string {
	candidates := make([]string, 0, 4)
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			if _, ignored := ignoredDirs[entry.Name()]; ignored && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		lowerBase := strings.ToLower(entry.Name())
		if lowerBase != "dockerfile" && !strings.HasSuffix(lowerBase, ".yml") && !strings.HasSuffix(lowerBase, ".yaml") {
			return nil
		}
		bytes, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		for _, line := range strings.Split(string(bytes), "\n") {
			line = strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(strings.ToUpper(line), "FROM "):
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					candidates = append(candidates, fields[1])
				}
			case strings.HasPrefix(strings.ToLower(line), "image:"):
				candidates = append(candidates, strings.TrimSpace(strings.TrimPrefix(line, "image:")))
			}
		}
		return nil
	})
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate != "" {
			return candidate
		}
	}
	return ""
}

func normalizeDependencyToken(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "@")
	value = strings.ReplaceAll(value, "/", "-")
	return value
}

func looksInternalPackage(name, projectName, normalizedProjectName string) bool {
	name = normalizeDependencyToken(name)
	projectName = normalizeDependencyToken(projectName)
	switch {
	case strings.Contains(name, "internal"), strings.Contains(name, "private"), strings.Contains(name, "corp"), strings.Contains(name, "company"):
		return true
	case projectName != "" && strings.Contains(name, projectName):
		return true
	case normalizedProjectName != "" && strings.Contains(name, normalizedProjectName):
		return true
	default:
		return false
	}
}

func mergeStringMap(sets ...map[string]string) map[string]string {
	merged := make(map[string]string)
	for _, set := range sets {
		for key, value := range set {
			merged[key] = value
		}
	}
	return merged
}

func fileContainsAny(path string, fragments []string) bool {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	text := string(bytes)
	for _, fragment := range fragments {
		if strings.Contains(text, fragment) {
			return true
		}
	}
	return false
}

func looksLikeBinaryCandidate(path string, mode fs.FileMode) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".exe", ".dll", ".so", ".dylib", ".bin", ".img", ".elf", ".apk", ".ipa", ".jar", ".war", ".ear", ".o", ".a":
		return true
	}
	return mode&0o111 != 0 && !isCandidateTextFile(path)
}

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range data {
		freq[int(b)]++
	}
	var entropy float64
	size := float64(len(data))
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / size
		entropy -= p * math.Log2(p)
	}
	return entropy
}
