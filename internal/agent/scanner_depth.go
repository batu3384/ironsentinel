package agent

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
)

func buildCodeQLCommand(binary string, execution moduleExecution, stacks []string) (*exec.Cmd, string, error) {
	language, querySuite, buildMode, buildCommand, ok := resolveCodeQLPlan(stacks)
	if !ok {
		return nil, "", errSkipModule("no CodeQL-supported stack detected")
	}
	if buildCommand != "" && !execution.request.Profile.AllowBuild {
		return nil, "", errSkipModule("CodeQL requires build permission for compiled languages")
	}
	if execution.mode == domain.IsolationLocal && runtime.GOOS == "windows" {
		return nil, "", errSkipModule("CodeQL local orchestration currently requires container isolation on Windows")
	}

	reportExecPath, _ := executionArtifactPaths(execution, "codeql.sarif")
	dbExecPath, _ := executionArtifactPaths(execution, "codeql-db")
	scriptExecPath, _, err := writeExecutionFile(execution, "codeql-run.sh", []byte(buildCodeQLScript(binary, execution.request.TargetPath, language, querySuite, dbExecPath, reportExecPath, buildMode, buildCommand)), 0o755)
	if err != nil {
		return nil, "", err
	}

	command := exec.Command("sh", scriptExecPath)
	command.Dir = execution.request.TargetPath
	return command, reportExecPath, nil
}

func buildNucleiCommand(cfg config.Config, binary string, execution moduleExecution) (*exec.Cmd, string, error) {
	if execution.request.Profile.Mode != domain.ModeActive || len(execution.request.Profile.DASTTargets) == 0 {
		return nil, "", errSkipModule("active DAST targets not requested")
	}
	if !execution.request.Profile.AllowNetwork || cfg.OfflineMode {
		return nil, "", errSkipModule("network access is required for active DAST execution")
	}

	targetURL := strings.TrimSpace(execution.request.Profile.DASTTargets[0].URL)
	if targetURL == "" {
		return nil, "", errSkipModule("DAST target URL is empty")
	}
	reportExecPath, _ := executionArtifactPaths(execution, "nuclei.jsonl")
	command := exec.Command(binary, "-u", targetURL, "-jsonl", "-jle", reportExecPath, "-duc", "-dut")
	return command, reportExecPath, nil
}

func buildZAPAutomationCommand(cfg config.Config, binary string, execution moduleExecution) (*exec.Cmd, string, error) {
	if len(execution.request.Profile.DASTTargets) == 0 {
		return nil, "", errSkipModule("DAST target list empty")
	}
	if !execution.request.Profile.AllowNetwork || cfg.OfflineMode {
		return nil, "", errSkipModule("network access is required for ZAP automation runs")
	}

	target := execution.request.Profile.DASTTargets[0]
	targetURL := strings.TrimSpace(target.URL)
	if targetURL == "" {
		return nil, "", errSkipModule("DAST target URL is empty")
	}

	resolvedTarget, authProfile, err := domain.ResolveDastTargetAuth(target, execution.request.Profile.DASTAuthProfiles)
	if err != nil {
		return nil, "", errSkipModule(err.Error())
	}

	planExecPath, _, err := writeExecutionFile(execution, "zap-automation.yaml", []byte(buildZAPAutomationPlan(resolvedTarget, authProfile, execution)), 0o600)
	if err != nil {
		return nil, "", err
	}
	reportExecPath, _ := executionArtifactPaths(execution, "zap-report.sarif.json")
	zapHomeExecPath, zapHomeHostPath := executionArtifactPaths(execution, filepath.Join(".runtime", "home", ".ZAP"))
	if err := os.MkdirAll(zapHomeHostPath, 0o755); err != nil {
		return nil, "", err
	}
	command := exec.Command(binary, "-dir", zapHomeExecPath, "-cmd", "-autorun", planExecPath)
	command.Dir = execution.request.TargetPath
	if authProfile != nil {
		zapEnv, err := buildZAPAuthEnv(resolvedTarget, *authProfile)
		if err != nil {
			return nil, "", errSkipModule(err.Error())
		}
		command.Env = append(os.Environ(), zapEnv...)
	}
	return command, reportExecPath, nil
}

func parseSARIFCategory(category domain.FindingCategory, scanner string) outputParser {
	return func(request domain.AgentScanRequest, module string, output []byte) (domain.ModuleResult, []domain.Finding, error) {
		if len(bytesTrimSpace(output)) == 0 {
			return domain.ModuleResult{
				Status:       domain.ModuleCompleted,
				Summary:      fmt.Sprintf("%s returned no findings.", scanner),
				FindingCount: 0,
			}, nil, nil
		}

		var payload struct {
			Runs []struct {
				Tool struct {
					Driver struct {
						Rules []struct {
							ID               string `json:"id"`
							Name             string `json:"name"`
							HelpURI          string `json:"helpUri"`
							ShortDescription struct {
								Text string `json:"text"`
							} `json:"shortDescription"`
							FullDescription struct {
								Text string `json:"text"`
							} `json:"fullDescription"`
							DefaultConfiguration struct {
								Level string `json:"level"`
							} `json:"defaultConfiguration"`
							Properties map[string]any `json:"properties"`
						} `json:"rules"`
					} `json:"driver"`
				} `json:"tool"`
				Results []struct {
					RuleID    string `json:"ruleId"`
					RuleIndex *int   `json:"ruleIndex,omitempty"`
					Level     string `json:"level"`
					Message   struct {
						Text string `json:"text"`
					} `json:"message"`
					Locations           []sarifLocation   `json:"locations"`
					Fingerprints        map[string]string `json:"fingerprints"`
					PartialFingerprints map[string]string `json:"partialFingerprints"`
					Properties          map[string]any    `json:"properties"`
				} `json:"results"`
			} `json:"runs"`
		}

		if err := json.Unmarshal(output, &payload); err != nil {
			return domain.ModuleResult{}, nil, err
		}

		findings := make([]domain.Finding, 0)
		index := 0
		for _, run := range payload.Runs {
			rulesByID := make(map[string]struct {
				Name         string
				HelpURI      string
				ShortText    string
				FullText     string
				DefaultLevel string
				Properties   map[string]any
			}, len(run.Tool.Driver.Rules))
			rulesByIndex := make(map[int]string, len(run.Tool.Driver.Rules))
			for idx, rule := range run.Tool.Driver.Rules {
				rulesByID[rule.ID] = struct {
					Name         string
					HelpURI      string
					ShortText    string
					FullText     string
					DefaultLevel string
					Properties   map[string]any
				}{
					Name:         rule.Name,
					HelpURI:      rule.HelpURI,
					ShortText:    rule.ShortDescription.Text,
					FullText:     rule.FullDescription.Text,
					DefaultLevel: rule.DefaultConfiguration.Level,
					Properties:   rule.Properties,
				}
				rulesByIndex[idx] = rule.ID
			}

			for _, result := range run.Results {
				ruleID := strings.TrimSpace(result.RuleID)
				if ruleID == "" && result.RuleIndex != nil {
					ruleID = rulesByIndex[*result.RuleIndex]
				}
				if ruleID == "" {
					continue
				}
				rule := rulesByID[ruleID]
				location := firstSARIFLocation(result.Locations)
				title := strings.TrimSpace(result.Message.Text)
				if title == "" {
					title = firstNonEmpty(rule.ShortText, rule.Name, ruleID)
				}

				fingerprint := firstNonEmpty(result.PartialFingerprints["primaryLocationLineHash"], result.Fingerprints["primaryLocationLineHash"])
				if fingerprint == "" {
					fingerprint = domain.MakeFingerprint(module, ruleID, title, location)
				}

				findings = append(findings, domain.Finding{
					ID:           domain.NewFindingID(request.ScanID, index),
					ScanID:       request.ScanID,
					ProjectID:    request.ProjectID,
					Category:     category,
					RuleID:       ruleID,
					Title:        title,
					Severity:     resolveSARIFSeverity(result.Level, result.Properties, rule.Properties, rule.DefaultLevel, category),
					Confidence:   resolveSARIFConfidence(result.Properties, category),
					Reachability: resolveSARIFReachability(category),
					Fingerprint:  fingerprint,
					EvidenceRef:  rule.HelpURI,
					Remediation:  firstNonEmpty(rule.FullText, defaultRemediationForCategory(category)),
					Location:     location,
					Module:       module,
				})
				index++
			}
		}

		return domain.ModuleResult{
			Status:       domain.ModuleCompleted,
			Summary:      fmt.Sprintf("%s returned %d findings.", scanner, len(findings)),
			FindingCount: len(findings),
		}, findings, nil
	}
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
	} `json:"physicalLocation"`
}

func resolveCodeQLPlan(stacks []string) (language string, querySuite string, buildMode string, buildCommand string, ok bool) {
	switch {
	case hasAnyStackValue(stacks, "javascript", "typescript"):
		return "javascript-typescript", "javascript-code-scanning.qls", "none", "", true
	case hasAnyStackValue(stacks, "python"):
		return "python", "python-code-scanning.qls", "none", "", true
	case hasAnyStackValue(stacks, "go"):
		return "go", "go-code-scanning.qls", "", "go build ./...", true
	default:
		return "", "", "", "", false
	}
}

func buildCodeQLScript(binary, sourceRoot, language, querySuite, dbPath, reportPath, buildMode, buildCommand string) string {
	lines := []string{
		"#!/bin/sh",
		"set -eu",
		fmt.Sprintf("DB=%s", posixQuote(dbPath)),
		fmt.Sprintf("OUT=%s", posixQuote(reportPath)),
		fmt.Sprintf("SRC=%s", posixQuote(sourceRoot)),
		"rm -rf \"$DB\"",
	}

	createArgs := []string{
		posixQuote(binary),
		"database", "create",
		"\"$DB\"",
		"--language=" + posixQuote(language),
		"--source-root", "\"$SRC\"",
	}
	if buildMode != "" {
		createArgs = append(createArgs, "--build-mode="+posixQuote(buildMode))
	}
	if buildCommand != "" {
		createArgs = append(createArgs, "--command", posixQuote(buildCommand))
	}
	lines = append(lines, strings.Join(createArgs, " "))
	lines = append(lines,
		strings.Join([]string{
			posixQuote(binary),
			"database", "analyze",
			"\"$DB\"",
			"--format=sarif-latest",
			"--output", "\"$OUT\"",
			posixQuote(querySuite),
		}, " "),
		"rm -rf \"$DB\"",
	)
	return strings.Join(lines, "\n") + "\n"
}

func buildZAPAutomationPlan(target domain.DastTarget, authProfile *domain.DastAuthProfile, execution moduleExecution) string {
	reportDir := execution.outputDir
	if execution.mode != domain.IsolationContainer {
		reportDir = execution.hostOutputDir
	}

	lines := []string{
		"env:",
		"  contexts:",
		"    - name: ironsentinel",
		"      urls:",
		fmt.Sprintf("        - %s", yamlQuote(target.URL)),
	}
	if authProfile != nil {
		lines = append(lines, buildZAPContextAuthLines(*authProfile)...)
		lines = append(lines, buildZAPContextVerificationLines(*authProfile)...)
	}
	lines = append(lines,
		"  parameters:",
		"    failOnError: true",
		"    progressToStdout: true",
		"jobs:",
	)

	if looksLikeOpenAPISpec(target.URL) {
		lines = append(lines,
			"  - type: openapi",
			"    parameters:",
			fmt.Sprintf("      apiUrl: %s", yamlQuote(target.URL)),
			"      context: ironsentinel",
		)
		if authProfile != nil && authProfile.Name != "" {
			lines = append(lines, fmt.Sprintf("      user: %s", yamlQuote(authProfile.Name)))
		}
	} else {
		lines = append(lines,
			"  - type: spider",
			"    parameters:",
			"      context: ironsentinel",
			fmt.Sprintf("      url: %s", yamlQuote(target.URL)),
			"      maxDuration: 3",
		)
		if authProfile != nil && authProfile.Name != "" {
			lines = append(lines, fmt.Sprintf("      user: %s", yamlQuote(authProfile.Name)))
		}
	}

	lines = append(lines,
		"  - type: passiveScan-wait",
		"    parameters:",
		"      maxDuration: 5",
	)

	if execution.request.Profile.Mode == domain.ModeActive {
		lines = append(lines,
			"  - type: activeScan",
			"    parameters:",
			"      context: ironsentinel",
			"      maxRuleDurationInMins: 2",
			"      maxScanDurationInMins: 8",
		)
		if authProfile != nil && authProfile.Name != "" {
			lines = append(lines, fmt.Sprintf("      user: %s", yamlQuote(authProfile.Name)))
		}
	}

	lines = append(lines,
		"  - type: report",
		"    parameters:",
		"      template: sarif-json",
		fmt.Sprintf("      reportDir: %s", yamlQuote(reportDir)),
		"      reportFile: zap-report.sarif.json",
	)

	return strings.Join(lines, "\n") + "\n"
}

func buildZAPContextAuthLines(profile domain.DastAuthProfile) []string {
	switch profile.Type {
	case domain.DastAuthBrowser:
		username := strings.TrimSpace(os.Getenv(profile.UsernameEnv))
		password := strings.TrimSpace(os.Getenv(profile.PasswordEnv))
		if username == "" || password == "" {
			return nil
		}
		lines := []string{
			"      authentication:",
			"        method: browser",
			"        parameters:",
			fmt.Sprintf("          loginPageUrl: %s", yamlQuote(profile.LoginPageURL)),
		}
		if profile.LoginPageWait > 0 {
			lines = append(lines, fmt.Sprintf("          loginPageWait: %d", profile.LoginPageWait))
		}
		if profile.BrowserID != "" {
			lines = append(lines, fmt.Sprintf("          browserId: %s", yamlQuote(profile.BrowserID)))
		}
		lines = append(lines,
			"      sessionManagement:",
			"        method: autodetect",
			"      users:",
			fmt.Sprintf("        - name: %s", yamlQuote(profile.Name)),
			"          credentials:",
			fmt.Sprintf("            username: %s", yamlQuote(username)),
			fmt.Sprintf("            password: %s", yamlQuote(password)),
		)
		return lines
	case domain.DastAuthForm:
		lines := []string{
			"      authentication:",
			"        method: form",
			"        parameters:",
			fmt.Sprintf("          loginPageUrl: %s", yamlQuote(profile.LoginPageURL)),
			fmt.Sprintf("          loginRequestUrl: %s", yamlQuote(profile.LoginRequestURL)),
			fmt.Sprintf("          loginRequestBody: %s", yamlQuote(profile.LoginRequestBody)),
		}
		return lines
	default:
		return nil
	}
}

func buildZAPContextVerificationLines(profile domain.DastAuthProfile) []string {
	if profile.Type == domain.DastAuthBrowser {
		return []string{
			"      verification:",
			"        method: autodetect",
		}
	}
	if profile.Type == domain.DastAuthForm {
		lines := []string{
			"      verification:",
			"        method: response",
		}
		if profile.LoggedInRegex != "" {
			lines = append(lines, fmt.Sprintf("        loggedInRegex: %s", yamlQuote(profile.LoggedInRegex)))
		}
		if profile.LoggedOutRegex != "" {
			lines = append(lines, fmt.Sprintf("        loggedOutRegex: %s", yamlQuote(profile.LoggedOutRegex)))
		}
		return lines
	}
	if strings.TrimSpace(profile.SessionCheckURL) == "" {
		return nil
	}

	lines := []string{
		"      verification:",
		"        method: response",
		fmt.Sprintf("        pollUrl: %s", yamlQuote(profile.SessionCheckURL)),
	}
	if profile.SessionCheckPattern != "" {
		lines = append(lines, fmt.Sprintf("        pollAdditionalHeadersRegex: %s", yamlQuote(profile.SessionCheckPattern)))
	}
	return lines
}

func buildZAPAuthEnv(target domain.DastTarget, profile domain.DastAuthProfile) ([]string, error) {
	site := strings.TrimSpace(target.URL)

	switch profile.Type {
	case domain.DastAuthBearer:
		token := strings.TrimSpace(os.Getenv(profile.SecretEnv))
		if token == "" {
			return nil, fmt.Errorf("dast auth profile %q requires env %s", profile.Name, profile.SecretEnv)
		}
		return []string{
			"ZAP_AUTH_HEADER=Authorization",
			"ZAP_AUTH_HEADER_VALUE=Bearer " + token,
			"ZAP_AUTH_HEADER_SITE=" + site,
		}, nil
	case domain.DastAuthHeader:
		value := strings.TrimSpace(os.Getenv(profile.SecretEnv))
		if value == "" {
			return nil, fmt.Errorf("dast auth profile %q requires env %s", profile.Name, profile.SecretEnv)
		}
		headerName := strings.TrimSpace(profile.HeaderName)
		if headerName == "" {
			return nil, fmt.Errorf("dast auth profile %q requires headerName", profile.Name)
		}
		return []string{
			"ZAP_AUTH_HEADER=" + headerName,
			"ZAP_AUTH_HEADER_VALUE=" + value,
			"ZAP_AUTH_HEADER_SITE=" + site,
		}, nil
	case domain.DastAuthBasic:
		username := strings.TrimSpace(os.Getenv(profile.UsernameEnv))
		password := strings.TrimSpace(os.Getenv(profile.PasswordEnv))
		if username == "" || password == "" {
			return nil, fmt.Errorf("dast auth profile %q requires envs %s and %s", profile.Name, profile.UsernameEnv, profile.PasswordEnv)
		}
		encoded := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		return []string{
			"ZAP_AUTH_HEADER=Authorization",
			"ZAP_AUTH_HEADER_VALUE=Basic " + encoded,
			"ZAP_AUTH_HEADER_SITE=" + site,
		}, nil
	case domain.DastAuthBrowser:
		return nil, nil
	case domain.DastAuthForm:
		return nil, nil
	case domain.DastAuthNone, "":
		return nil, nil
	default:
		return nil, fmt.Errorf("dast auth profile %q type %q is not supported", profile.Name, profile.Type)
	}
}

func executionArtifactPaths(execution moduleExecution, name string) (string, string) {
	hostPath := filepath.Join(execution.hostOutputDir, name)
	if execution.mode == domain.IsolationContainer {
		return path.Join("/artifacts", name), hostPath
	}
	return hostPath, hostPath
}

func writeExecutionFile(execution moduleExecution, name string, body []byte, mode os.FileMode) (string, string, error) {
	execPath, hostPath := executionArtifactPaths(execution, name)
	if err := os.MkdirAll(filepath.Dir(hostPath), 0o755); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(hostPath, body, mode); err != nil {
		return "", "", err
	}
	return execPath, hostPath, nil
}

func resolveSARIFSeverity(level string, resultProps, ruleProps map[string]any, defaultLevel string, category domain.FindingCategory) domain.Severity {
	if score := firstSecuritySeverity(resultProps, ruleProps); score > 0 {
		switch {
		case score >= 9:
			return domain.SeverityCritical
		case score >= 7:
			return domain.SeverityHigh
		case score >= 4:
			return domain.SeverityMedium
		default:
			return domain.SeverityLow
		}
	}

	candidate := strings.TrimSpace(level)
	if candidate == "" {
		candidate = strings.TrimSpace(defaultLevel)
	}
	if candidate == "" && category == domain.CategoryDAST {
		candidate = "warning"
	}
	return mapSeverity(candidate)
}

func resolveSARIFConfidence(properties map[string]any, category domain.FindingCategory) float64 {
	if properties != nil {
		if precision, ok := properties["precision"].(string); ok {
			switch strings.ToLower(strings.TrimSpace(precision)) {
			case "very-high":
				return 0.95
			case "high":
				return 0.85
			case "medium":
				return 0.72
			case "low":
				return 0.58
			}
		}
	}
	if category == domain.CategoryDAST {
		return 0.7
	}
	return 0.78
}

func resolveSARIFReachability(category domain.FindingCategory) domain.Reachability {
	if category == domain.CategoryDAST {
		return domain.ReachabilityReachable
	}
	return domain.ReachabilityPossible
}

func firstSecuritySeverity(propertySets ...map[string]any) float64 {
	for _, properties := range propertySets {
		if properties == nil {
			continue
		}
		for _, key := range []string{"security-severity", "securitySeverity"} {
			value, ok := properties[key]
			if !ok {
				continue
			}
			switch typed := value.(type) {
			case string:
				score, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
				if err == nil {
					return score
				}
			case float64:
				return typed
			}
		}
	}
	return 0
}

func firstSARIFLocation(locations []sarifLocation) string {
	if len(locations) == 0 {
		return ""
	}
	return strings.TrimSpace(locations[0].PhysicalLocation.ArtifactLocation.URI)
}

func looksLikeOpenAPISpec(targetURL string) bool {
	lower := strings.ToLower(strings.TrimSpace(targetURL))
	return strings.Contains(lower, "openapi") || strings.Contains(lower, "swagger") || strings.HasSuffix(lower, ".json") || strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml")
}

func yamlQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func posixQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

func defaultRemediationForCategory(category domain.FindingCategory) string {
	switch category {
	case domain.CategoryDAST:
		return "Validate the finding against a controlled target and apply the corresponding server-side fix or compensating control."
	default:
		return "Review the finding in context, confirm exploitability, and apply the recommended code or dependency fix."
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func hasAnyStackValue(stacks []string, targets ...string) bool {
	for _, stack := range stacks {
		for _, target := range targets {
			if stack == target {
				return true
			}
		}
	}
	return false
}
