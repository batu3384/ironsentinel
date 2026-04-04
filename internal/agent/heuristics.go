package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
)

var ignoredDirs = map[string]struct{}{
	".git":         {},
	".next":        {},
	"node_modules": {},
	"dist":         {},
	"build":        {},
	"coverage":     {},
	".venv":        {},
	"venv":         {},
}

var secretPatterns = []struct {
	ruleID      string
	title       string
	severity    domain.Severity
	pattern     *regexp.Regexp
	remediation string
}{
	{
		ruleID:      "secret.aws_access_key",
		title:       "Potential AWS access key detected",
		severity:    domain.SeverityHigh,
		pattern:     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		remediation: "Rotate the credential and move it into a secret manager or runtime injection path.",
	},
	{
		ruleID:      "secret.generic_assignment",
		title:       "Potential hard-coded secret assignment",
		severity:    domain.SeverityMedium,
		pattern:     regexp.MustCompile(`(?i)(secret|token|password|api[_-]?key)\s*[:=]\s*["'][^"']{8,}["']`),
		remediation: "Remove the literal secret and inject it from a local secret store, vault, or CI secret scope.",
	},
	{
		ruleID:      "secret.github_pat",
		title:       "Potential GitHub personal access token",
		severity:    domain.SeverityCritical,
		pattern:     regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`),
		remediation: "Revoke the token immediately and replace local storage with a secret reference.",
	},
}

var scriptAuditPatterns = []struct {
	ruleID      string
	title       string
	severity    domain.Severity
	pattern     *regexp.Regexp
	remediation string
}{
	{
		ruleID:      "script.remote_pipe_shell",
		title:       "Remote script piped directly into a shell",
		severity:    domain.SeverityHigh,
		pattern:     regexp.MustCompile(`(?i)(curl|wget)[^\n|]{0,200}\|\s*(sh|bash|zsh)\b`),
		remediation: "Download the script first, verify integrity, and execute it from a reviewed local copy.",
	},
	{
		ruleID:      "script.remote_process_substitution",
		title:       "Remote script executed through process substitution",
		severity:    domain.SeverityHigh,
		pattern:     regexp.MustCompile(`(?i)(bash|sh|zsh)\s*<\(\s*(curl|wget)\b`),
		remediation: "Replace process substitution with a reviewed local script and pin the downloaded artifact checksum.",
	},
	{
		ruleID:      "script.privileged_container",
		title:       "Privileged container execution detected",
		severity:    domain.SeverityHigh,
		pattern:     regexp.MustCompile(`(?i)docker\s+run\b[^\n]{0,200}--privileged\b`),
		remediation: "Avoid privileged containers unless there is a documented exception and a hardened isolation boundary.",
	},
	{
		ruleID:      "script.disable_tls_verify",
		title:       "TLS verification disabled in fetch command",
		severity:    domain.SeverityMedium,
		pattern:     regexp.MustCompile(`(?i)(curl|wget)[^\n]{0,200}(\s-k\b|\s--insecure\b|\s--no-check-certificate\b)`),
		remediation: "Keep TLS verification enabled and trust only pinned certificates or checksummed artifacts.",
	},
	{
		ruleID:      "script.world_writable_permissions",
		title:       "World-writable permissions command detected",
		severity:    domain.SeverityMedium,
		pattern:     regexp.MustCompile(`(?i)\bchmod\s+777\b`),
		remediation: "Avoid granting world-writable permissions; scope access to the minimum required principal.",
	},
}

const eicarSignature = "X5O!P%@AP[4\\PZX54(P^)" +
	"7CC)7}$EICAR-STANDARD-" +
	"ANTIVIRUS-TEST-FILE!$H+H*"

func detectStacks(root string) ([]string, error) {
	return detectStacksWithContext(context.Background(), root)
}

func detectStacksWithContext(ctx context.Context, root string) ([]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stacks := make([]string, 0, 8)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return nil
		}

		if entry.IsDir() {
			if _, ignored := ignoredDirs[entry.Name()]; ignored && path != root {
				return filepath.SkipDir
			}
			return nil
		}

		base := filepath.Base(path)
		switch {
		case base == "package.json":
			stacks = append(stacks, "javascript", "typescript")
		case base == "go.mod":
			stacks = append(stacks, "go")
		case base == "requirements.txt" || base == "pyproject.toml":
			stacks = append(stacks, "python")
		case base == "pom.xml" || strings.HasPrefix(base, "build.gradle"):
			stacks = append(stacks, "java")
		case strings.HasSuffix(base, ".csproj") || strings.HasSuffix(base, ".sln"):
			stacks = append(stacks, ".net")
		case base == "Dockerfile":
			stacks = append(stacks, "docker", "container")
		case strings.HasSuffix(base, ".tf"):
			stacks = append(stacks, "terraform", "iac")
		case base == "Chart.yaml":
			stacks = append(stacks, "helm", "kubernetes", "iac")
		case strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml"):
			if strings.Contains(path, "k8s") || strings.Contains(path, "kubernetes") {
				stacks = append(stacks, "kubernetes", "iac")
			}
		}

		return nil
	})

	return domain.NormalizeStacks(stacks), err
}

func heuristicSecrets(ctx context.Context, cfg config.Config, request domain.AgentScanRequest, outputDir string) (domain.ModuleResult, []domain.Finding, error) {
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

		if !isCandidateTextFile(path) {
			return nil
		}

		contents, err := os.ReadFile(path)
		if err != nil || len(contents) == 0 || len(contents) > 1024*1024 {
			return nil
		}

		for _, matcher := range secretPatterns {
			if matcher.pattern.Match(contents) {
				fingerprint := domain.MakeFingerprint(request.ScanID, matcher.ruleID, path)
				findings = append(findings, domain.Finding{
					ID:           domain.NewFindingID(request.ScanID, index),
					ScanID:       request.ScanID,
					ProjectID:    request.ProjectID,
					Category:     domain.CategorySecret,
					RuleID:       matcher.ruleID,
					Title:        matcher.title,
					Severity:     matcher.severity,
					Confidence:   0.82,
					Reachability: domain.ReachabilityUnknown,
					Fingerprint:  fingerprint,
					Remediation:  matcher.remediation,
					Location:     trimLocation(request.TargetPath, path),
					Module:       "secret-heuristics",
				})
				index++
			}
		}

		return nil
	})

	result := domain.ModuleResult{
		Name:         "secret-heuristics",
		Category:     domain.CategorySecret,
		Status:       domain.ModuleCompleted,
		Summary:      fmt.Sprintf("Scanned local text files for high-confidence secret patterns in %dms.", time.Since(start).Milliseconds()),
		FindingCount: len(findings),
		DurationMs:   time.Since(start).Milliseconds(),
	}

	if artifact, err := writeHeuristicEvidence(cfg, outputDir, "secret-heuristics", result, findings); err == nil {
		result.Artifacts = append(result.Artifacts, artifact)
		findings = attachDefaultEvidence(findings, result.Artifacts)
	}

	return result, findings, err
}

func heuristicSurfaceInventory(ctx context.Context, cfg config.Config, request domain.AgentScanRequest, outputDir string) (domain.ModuleResult, []domain.Finding, error) {
	start := time.Now()
	type inventoryStats struct {
		TotalFiles     int      `json:"totalFiles"`
		SourceFiles    int      `json:"sourceFiles"`
		ConfigFiles    int      `json:"configFiles"`
		ScriptFiles    int      `json:"scriptFiles"`
		HiddenFiles    int      `json:"hiddenFiles"`
		WorkflowFiles  int      `json:"workflowFiles"`
		BinaryFiles    int      `json:"binaryFiles"`
		FlaggedTargets []string `json:"flaggedTargets,omitempty"`
	}

	stats := inventoryStats{}
	findings := make([]domain.Finding, 0, 8)
	seen := make(map[string]struct{})
	index := 0

	addFinding := func(ruleID, title string, severity domain.Severity, remediation, location string) {
		fingerprint := domain.MakeFingerprint(request.ScanID, ruleID, location)
		if _, ok := seen[fingerprint]; ok {
			return
		}
		seen[fingerprint] = struct{}{}
		findings = append(findings, domain.Finding{
			ID:           domain.NewFindingID(request.ScanID, index),
			ScanID:       request.ScanID,
			ProjectID:    request.ProjectID,
			Category:     domain.CategoryPlatform,
			RuleID:       ruleID,
			Title:        title,
			Severity:     severity,
			Confidence:   0.78,
			Reachability: domain.ReachabilityRepository,
			Fingerprint:  fingerprint,
			Remediation:  remediation,
			Location:     location,
			Module:       "surface-inventory",
		})
		index++
		stats.FlaggedTargets = append(stats.FlaggedTargets, location)
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

		stats.TotalFiles++
		relative := trimLocation(request.TargetPath, path)
		lowerPath := strings.ToLower(relative)
		base := strings.ToLower(filepath.Base(path))
		ext := strings.ToLower(filepath.Ext(path))

		if strings.HasPrefix(filepath.Base(relative), ".") {
			stats.HiddenFiles++
		}
		if isSourceCodeFile(ext) {
			stats.SourceFiles++
		}
		if isConfigFile(base, ext) {
			stats.ConfigFiles++
		}
		if isScriptAuditFile(relative) {
			stats.ScriptFiles++
		}
		if strings.Contains(filepath.ToSlash(lowerPath), ".github/workflows/") {
			stats.WorkflowFiles++
		}

		if isSensitiveRepoFile(lowerPath, base, ext) && !isSampleFixture(lowerPath) {
			addFinding(
				"surface.sensitive_repo_file",
				"Sensitive operational file committed to the repository",
				domain.SeverityHigh,
				"Move the file out of version control, rotate any exposed secrets, and store the artifact in a secure secret or artifact vault.",
				relative,
			)
		}

		if isBinaryBlob(path, ext) {
			stats.BinaryFiles++
			if shouldFlagBinaryArtifact(lowerPath, base, ext) {
				addFinding(
					"surface.binary_artifact",
					"Binary or opaque artifact committed to the repository",
					domain.SeverityMedium,
					"Review whether the binary is required in source control; prefer reproducible builds and signed release artifacts instead.",
					relative,
				)
			}
		}
		return nil
	})

	sort.Strings(stats.FlaggedTargets)
	result := domain.ModuleResult{
		Name:         "surface-inventory",
		Category:     domain.CategoryPlatform,
		Status:       domain.ModuleCompleted,
		Summary:      fmt.Sprintf("Mapped %d files across source, config, workflow, script, and binary surfaces.", stats.TotalFiles),
		FindingCount: len(findings),
		DurationMs:   time.Since(start).Milliseconds(),
	}

	payload := struct {
		Module   string              `json:"module"`
		Status   domain.ModuleStatus `json:"status"`
		Summary  string              `json:"summary"`
		Stats    inventoryStats      `json:"stats"`
		Findings []domain.Finding    `json:"findings"`
	}{
		Module:   "surface-inventory",
		Status:   result.Status,
		Summary:  result.Summary,
		Stats:    stats,
		Findings: findings,
	}
	if artifact, artifactErr := writeHeuristicPayloadEvidence(cfg, outputDir, "surface-inventory", payload); artifactErr == nil {
		result.Artifacts = append(result.Artifacts, artifact)
		findings = attachDefaultEvidence(findings, result.Artifacts)
	}

	return result, findings, err
}

func heuristicMalware(ctx context.Context, cfg config.Config, request domain.AgentScanRequest, outputDir string) (domain.ModuleResult, []domain.Finding, error) {
	start := time.Now()
	findings := make([]domain.Finding, 0, 2)
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

		contents, err := os.ReadFile(path)
		if err != nil || len(contents) == 0 {
			return nil
		}

		if bytes.Contains(contents, []byte(eicarSignature)) {
			fingerprint := domain.MakeFingerprint(request.ScanID, "malware.eicar", path)
			findings = append(findings, domain.Finding{
				ID:           domain.NewFindingID(request.ScanID, index),
				ScanID:       request.ScanID,
				ProjectID:    request.ProjectID,
				Category:     domain.CategoryMalware,
				RuleID:       "malware.eicar",
				Title:        "EICAR test signature detected",
				Severity:     domain.SeverityCritical,
				Confidence:   0.99,
				Reachability: domain.ReachabilityNotApplicable,
				Fingerprint:  fingerprint,
				Remediation:  "Remove the file, inspect the repository history, and rerun the malware profile.",
				Location:     trimLocation(request.TargetPath, path),
				Module:       "malware-signature",
			})
			index++
		}

		return nil
	})

	result := domain.ModuleResult{
		Name:         "malware-signature",
		Category:     domain.CategoryMalware,
		Status:       domain.ModuleCompleted,
		Summary:      "Scanned workspace content for built-in malware signatures including EICAR.",
		FindingCount: len(findings),
		DurationMs:   time.Since(start).Milliseconds(),
	}

	if artifact, err := writeHeuristicEvidence(cfg, outputDir, "malware-signature", result, findings); err == nil {
		result.Artifacts = append(result.Artifacts, artifact)
		findings = attachDefaultEvidence(findings, result.Artifacts)
	}

	return result, findings, err
}

func heuristicScriptAudit(ctx context.Context, cfg config.Config, request domain.AgentScanRequest, outputDir string) (domain.ModuleResult, []domain.Finding, error) {
	start := time.Now()
	type auditedTarget struct {
		Label    string `json:"label"`
		Location string `json:"location"`
	}

	targets := make([]auditedTarget, 0, 32)
	findings := make([]domain.Finding, 0, 8)
	seen := make(map[string]struct{})
	index := 0

	addFinding := func(ruleID, title string, severity domain.Severity, remediation, location string) {
		fingerprint := domain.MakeFingerprint(request.ScanID, ruleID, location)
		if _, ok := seen[fingerprint]; ok {
			return
		}
		seen[fingerprint] = struct{}{}
		findings = append(findings, domain.Finding{
			ID:           domain.NewFindingID(request.ScanID, index),
			ScanID:       request.ScanID,
			ProjectID:    request.ProjectID,
			Category:     domain.CategoryPlatform,
			RuleID:       ruleID,
			Title:        title,
			Severity:     severity,
			Confidence:   0.84,
			Reachability: domain.ReachabilityExecutionSurface,
			Fingerprint:  fingerprint,
			Remediation:  remediation,
			Location:     location,
			Module:       "script-audit",
		})
		index++
	}

	auditContent := func(location, label, body string) {
		targets = append(targets, auditedTarget{Label: label, Location: location})
		for _, matcher := range scriptAuditPatterns {
			matches := matcher.pattern.FindStringIndex(body)
			if len(matches) == 0 {
				continue
			}
			line := 1 + strings.Count(body[:matches[0]], "\n")
			addFinding(matcher.ruleID, matcher.title, matcher.severity, matcher.remediation, fmt.Sprintf("%s:%d", location, line))
		}
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
		if filepath.Base(path) == "package.json" {
			body, readErr := os.ReadFile(path)
			if readErr != nil || len(body) == 0 {
				return nil
			}
			var pkg struct {
				Scripts map[string]string `json:"scripts"`
			}
			if json.Unmarshal(body, &pkg) == nil {
				names := make([]string, 0, len(pkg.Scripts))
				for name := range pkg.Scripts {
					names = append(names, name)
				}
				sort.Strings(names)
				for _, name := range names {
					command := strings.TrimSpace(pkg.Scripts[name])
					if command == "" {
						continue
					}
					auditContent(fmt.Sprintf("%s#scripts.%s", relative, name), name, command)
				}
			}
			return nil
		}

		if !isScriptAuditFile(relative) {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil || len(body) == 0 || len(body) > 1024*1024 {
			return nil
		}
		auditContent(relative, filepath.Base(path), string(body))
		return nil
	})

	result := domain.ModuleResult{
		Name:         "script-audit",
		Category:     domain.CategoryPlatform,
		Status:       domain.ModuleCompleted,
		Summary:      fmt.Sprintf("Audited %d execution surfaces for risky bootstrap, privilege, and remote execution patterns.", len(targets)),
		FindingCount: len(findings),
		DurationMs:   time.Since(start).Milliseconds(),
	}

	payload := struct {
		Module   string              `json:"module"`
		Status   domain.ModuleStatus `json:"status"`
		Summary  string              `json:"summary"`
		Targets  []auditedTarget     `json:"targets"`
		Findings []domain.Finding    `json:"findings"`
	}{
		Module:   "script-audit",
		Status:   result.Status,
		Summary:  result.Summary,
		Targets:  targets,
		Findings: findings,
	}
	if artifact, artifactErr := writeHeuristicPayloadEvidence(cfg, outputDir, "script-audit", payload); artifactErr == nil {
		result.Artifacts = append(result.Artifacts, artifact)
		findings = attachDefaultEvidence(findings, result.Artifacts)
	}

	return result, findings, err
}

func writeHeuristicEvidence(cfg config.Config, outputDir, module string, result domain.ModuleResult, findings []domain.Finding) (domain.ArtifactRef, error) {
	payload := struct {
		Module   string              `json:"module"`
		Status   domain.ModuleStatus `json:"status"`
		Summary  string              `json:"summary"`
		Findings []domain.Finding    `json:"findings"`
	}{
		Module:   module,
		Status:   result.Status,
		Summary:  result.Summary,
		Findings: findings,
	}
	return writeHeuristicPayloadEvidence(cfg, outputDir, module, payload)
}

func writeHeuristicPayloadEvidence(cfg config.Config, outputDir, module string, payload any) (domain.ArtifactRef, error) {
	moduleDir, err := ensureModuleDir(outputDir, module)
	if err != nil {
		return domain.ArtifactRef{}, err
	}
	return writeArtifact(cfg, moduleDir, "evidence.json", "evidence", module+" evidence", mustJSON(payload))
}

func mustJSON(payload any) []byte {
	body, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return []byte("{}")
	}
	return body
}

func isCandidateTextFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".png", ".jpg", ".jpeg", ".gif", ".zip", ".gz", ".tar", ".pdf", ".jar", ".ico", ".woff", ".woff2":
		return false
	default:
		return true
	}
}

func trimLocation(root, path string) string {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return relative
}

func parseJSONLines(data []byte) []map[string]any {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	items := make([]map[string]any, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var payload map[string]any
		if json.Unmarshal([]byte(line), &payload) == nil {
			items = append(items, payload)
		}
	}
	return items
}

func isSourceCodeFile(ext string) bool {
	switch strings.ToLower(ext) {
	case ".go", ".js", ".jsx", ".ts", ".tsx", ".py", ".java", ".kt", ".cs", ".rb", ".php", ".rs", ".swift", ".c", ".cc", ".cpp", ".h", ".hpp":
		return true
	default:
		return false
	}
}

func isConfigFile(base, ext string) bool {
	switch {
	case base == "dockerfile", base == "docker-compose.yml", base == "docker-compose.yaml", base == ".env", base == ".npmrc", base == ".pypirc", base == "chart.yaml", base == "makefile":
		return true
	case ext == ".yaml", ext == ".yml", ext == ".json", ext == ".toml", ext == ".ini", ext == ".cfg", ext == ".conf", ext == ".tf":
		return true
	default:
		return false
	}
}

func isSensitiveRepoFile(lowerPath, base, ext string) bool {
	switch {
	case base == ".env" || strings.HasPrefix(base, ".env."):
		return true
	case base == ".npmrc" || base == ".pypirc":
		return true
	case base == "id_rsa" || base == "id_ed25519":
		return true
	case ext == ".pem" || ext == ".key" || ext == ".p12" || ext == ".pfx":
		return true
	case ext == ".tfstate" || strings.Contains(lowerPath, ".kube/config"):
		return true
	default:
		return false
	}
}

func isSampleFixture(lowerPath string) bool {
	return strings.Contains(lowerPath, "example") || strings.Contains(lowerPath, "sample") || strings.Contains(lowerPath, "fixture") || strings.Contains(lowerPath, ".dist") || strings.HasSuffix(lowerPath, ".example")
}

func shouldIgnoreManagedScanPath(cfg config.Config, root, path string) bool {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	for _, managed := range []string{cfg.DataDir, cfg.OutputDir} {
		if managed == "" {
			continue
		}
		managed = filepath.Clean(managed)
		if managed != root && !strings.HasPrefix(managed, root+string(os.PathSeparator)) {
			continue
		}
		if path == managed || strings.HasPrefix(path, managed+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func isScriptAuditFile(path string) bool {
	lower := filepath.ToSlash(strings.ToLower(path))
	base := filepath.Base(lower)
	ext := filepath.Ext(lower)
	switch {
	case strings.Contains(lower, ".github/workflows/"):
		return true
	case base == "makefile" || base == "dockerfile" || base == "package.json":
		return true
	case ext == ".sh" || ext == ".bash" || ext == ".zsh" || ext == ".command":
		return true
	case ext == ".yaml" || ext == ".yml":
		return true
	default:
		return false
	}
}

func isBinaryBlob(path, ext string) bool {
	switch strings.ToLower(ext) {
	case ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".woff", ".woff2", ".ico", ".zip", ".gz", ".tar":
		return false
	case ".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".jar", ".a", ".o":
		return true
	}
	body, err := os.ReadFile(path)
	if err != nil || len(body) == 0 {
		return false
	}
	if len(body) > 1024 {
		body = body[:1024]
	}
	if bytes.Contains(body, []byte{0x00}) {
		return true
	}
	if bytes.HasPrefix(body, []byte("MZ")) || bytes.HasPrefix(body, []byte{0x7f, 'E', 'L', 'F'}) {
		return true
	}
	if bytes.HasPrefix(body, []byte{0xfe, 0xed, 0xfa, 0xce}) || bytes.HasPrefix(body, []byte{0xcf, 0xfa, 0xed, 0xfe}) {
		return true
	}
	return false
}

func shouldFlagBinaryArtifact(lowerPath, base, ext string) bool {
	if strings.Contains(lowerPath, "/vendor/") || strings.Contains(lowerPath, "/fixtures/") || strings.Contains(lowerPath, "/testdata/") {
		return false
	}
	if base == ".ds_store" || strings.HasSuffix(lowerPath, ".xcuserstate") || strings.Contains(lowerPath, "/xcuserdata/") {
		return false
	}
	switch strings.ToLower(ext) {
	case ".jar", ".class", ".o", ".a":
		return false
	default:
		return true
	}
}
