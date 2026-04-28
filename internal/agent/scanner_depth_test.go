package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/batu3384/ironsentinel/internal/config"
	"github.com/batu3384/ironsentinel/internal/domain"
)

func TestBuildNucleiCommandUsesSignedTemplateFlags(t *testing.T) {
	execution := moduleExecution{
		mode:          domain.IsolationLocal,
		hostOutputDir: t.TempDir(),
		outputDir:     t.TempDir(),
		request: domain.AgentScanRequest{
			Profile: domain.ScanProfile{
				Mode:         domain.ModeActive,
				AllowNetwork: true,
				DASTTargets:  []domain.DastTarget{{URL: "https://example.test"}},
			},
		},
	}

	command, reportPath, err := buildNucleiCommand(config.Config{}, "nuclei", execution)
	if err != nil {
		t.Fatalf("build nuclei command: %v", err)
	}

	args := strings.Join(command.Args, " ")
	for _, fragment := range []string{"-u https://example.test", "-jsonl", "-jle " + reportPath, "-duc", "-dut"} {
		if !strings.Contains(args, fragment) {
			t.Fatalf("expected nuclei args to contain %q, got %s", fragment, args)
		}
	}
}

func TestBuildCodeQLCommandWritesScriptForJavascript(t *testing.T) {
	target := t.TempDir()
	output := t.TempDir()
	execution := moduleExecution{
		mode:           domain.IsolationLocal,
		hostTargetPath: target,
		hostOutputDir:  output,
		request: domain.AgentScanRequest{
			TargetPath: target,
			Profile: domain.ScanProfile{
				Mode:       domain.ModeDeep,
				Isolation:  domain.IsolationLocal,
				AllowBuild: false,
			},
		},
	}

	command, reportPath, err := buildCodeQLCommand("/usr/local/bin/codeql", execution, []string{"javascript", "typescript"})
	if err != nil {
		t.Fatalf("build codeql command: %v", err)
	}
	if !strings.HasSuffix(command.Path, "sh") {
		t.Fatalf("expected codeql command to run through sh, got %s", command.Path)
	}
	if want := filepath.Join(output, "codeql.sarif"); reportPath != want {
		t.Fatalf("expected report path %q, got %q", want, reportPath)
	}

	scriptPath := filepath.Join(output, "codeql-run.sh")
	body, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read codeql script: %v", err)
	}
	script := string(body)
	for _, fragment := range []string{"database create", "javascript-typescript", "javascript-code-scanning.qls", "--build-mode='none'"} {
		if !strings.Contains(script, fragment) {
			t.Fatalf("expected script to contain %q, got %s", fragment, script)
		}
	}
}

func TestBuildCodeQLCommandRequiresBuildPermissionForGo(t *testing.T) {
	execution := moduleExecution{
		mode:           domain.IsolationLocal,
		hostTargetPath: t.TempDir(),
		hostOutputDir:  t.TempDir(),
		request: domain.AgentScanRequest{
			TargetPath: t.TempDir(),
			Profile: domain.ScanProfile{
				Mode:       domain.ModeDeep,
				Isolation:  domain.IsolationLocal,
				AllowBuild: false,
			},
		},
	}

	_, _, err := buildCodeQLCommand("codeql", execution, []string{"go"})
	if !errors.Is(err, errModuleSkipped) {
		t.Fatalf("expected build permission error to skip module, got %v", err)
	}
}

func TestBuildZAPAutomationCommandWritesPlan(t *testing.T) {
	output := t.TempDir()
	execution := moduleExecution{
		mode:          domain.IsolationLocal,
		hostOutputDir: output,
		outputDir:     output,
		request: domain.AgentScanRequest{
			TargetPath: t.TempDir(),
			Profile: domain.ScanProfile{
				Mode:         domain.ModeActive,
				AllowNetwork: true,
				DASTTargets:  []domain.DastTarget{{URL: "https://api.example.test/openapi.json"}},
			},
		},
	}

	command, reportPath, err := buildZAPAutomationCommand(config.Config{}, "zaproxy", execution)
	if err != nil {
		t.Fatalf("build zap command: %v", err)
	}
	if want := filepath.Join(output, "zap-report.sarif.json"); reportPath != want {
		t.Fatalf("expected report path %q, got %q", want, reportPath)
	}
	args := strings.Join(command.Args, " ")
	if !strings.Contains(args, "-autorun") {
		t.Fatalf("expected autorun args, got %s", args)
	}
	if !strings.Contains(args, "rm -f") || !strings.Contains(args, "zap-automation.yaml") {
		t.Fatalf("expected zap command to clean the sensitive automation plan after execution, got %s", args)
	}
	if !strings.Contains(args, filepath.Join(output, ".runtime", "home", ".ZAP")) {
		t.Fatalf("expected zap args to include writable home dir, got %s", args)
	}

	planBody, err := os.ReadFile(filepath.Join(output, "zap-automation.yaml"))
	if err != nil {
		t.Fatalf("read zap plan: %v", err)
	}
	plan := string(planBody)
	for _, fragment := range []string{"type: openapi", "type: activeScan", "template: sarif-json", "reportFile: zap-report.sarif.json"} {
		if !strings.Contains(plan, fragment) {
			t.Fatalf("expected zap plan to contain %q, got %s", fragment, plan)
		}
	}
}

func TestBuildZAPAutomationCommandInjectsBearerAuthAndVerification(t *testing.T) {
	t.Setenv("STAGING_API_TOKEN", "top-secret-token")

	output := t.TempDir()
	execution := moduleExecution{
		mode:          domain.IsolationLocal,
		hostOutputDir: output,
		outputDir:     output,
		request: domain.AgentScanRequest{
			TargetPath: t.TempDir(),
			Profile: domain.ScanProfile{
				Mode:         domain.ModeDeep,
				AllowNetwork: true,
				DASTTargets: []domain.DastTarget{{
					Name:        "api",
					URL:         "https://api.example.test",
					AuthType:    domain.DastAuthBearer,
					AuthProfile: "staging-bearer",
				}},
				DASTAuthProfiles: []domain.DastAuthProfile{{
					Name:                "staging-bearer",
					Type:                domain.DastAuthBearer,
					SecretEnv:           "STAGING_API_TOKEN",
					SessionCheckURL:     "https://api.example.test/me",
					SessionCheckPattern: "200 OK",
				}},
			},
		},
	}

	command, _, err := buildZAPAutomationCommand(config.Config{}, "zaproxy", execution)
	if err != nil {
		t.Fatalf("build zap command: %v", err)
	}

	env := strings.Join(command.Env, "\n")
	for _, fragment := range []string{
		"ZAP_AUTH_HEADER=Authorization",
		"ZAP_AUTH_HEADER_VALUE=Bearer top-secret-token",
		"ZAP_AUTH_HEADER_SITE=https://api.example.test",
	} {
		if !strings.Contains(env, fragment) {
			t.Fatalf("expected zap env to contain %q, got %s", fragment, env)
		}
	}

	planBody, err := os.ReadFile(filepath.Join(output, "zap-automation.yaml"))
	if err != nil {
		t.Fatalf("read zap plan: %v", err)
	}
	plan := string(planBody)
	for _, fragment := range []string{"verification:", "pollUrl: 'https://api.example.test/me'", "pollAdditionalHeadersRegex: '200 OK'"} {
		if !strings.Contains(plan, fragment) {
			t.Fatalf("expected zap plan to contain %q, got %s", fragment, plan)
		}
	}
}

func TestBuildZAPAutomationCommandConfiguresBrowserAuthContext(t *testing.T) {
	t.Setenv("STAGING_WEB_USER", "analyst@example.test")
	t.Setenv("STAGING_WEB_PASS", "super-secret-password")

	output := t.TempDir()
	execution := moduleExecution{
		mode:          domain.IsolationLocal,
		hostOutputDir: output,
		outputDir:     output,
		request: domain.AgentScanRequest{
			TargetPath: t.TempDir(),
			Profile: domain.ScanProfile{
				Mode:         domain.ModeActive,
				AllowNetwork: true,
				DASTTargets: []domain.DastTarget{{
					Name:        "portal",
					URL:         "https://app.example.test",
					AuthType:    domain.DastAuthBrowser,
					AuthProfile: "staging-browser",
				}},
				DASTAuthProfiles: []domain.DastAuthProfile{{
					Name:            "staging-browser",
					Type:            domain.DastAuthBrowser,
					LoginPageURL:    "https://app.example.test/login",
					LoginPageWait:   5,
					BrowserID:       "firefox-headless",
					UsernameEnv:     "STAGING_WEB_USER",
					PasswordEnv:     "STAGING_WEB_PASS",
					SessionCheckURL: "https://app.example.test/account",
				}},
			},
		},
	}

	_, _, err := buildZAPAutomationCommand(config.Config{}, "zaproxy", execution)
	if err != nil {
		t.Fatalf("build zap command: %v", err)
	}

	planBody, err := os.ReadFile(filepath.Join(output, "zap-automation.yaml"))
	if err != nil {
		t.Fatalf("read zap plan: %v", err)
	}
	plan := string(planBody)
	for _, fragment := range []string{
		"method: browser",
		"loginPageUrl: 'https://app.example.test/login'",
		"loginPageWait: 5",
		"browserId: 'firefox-headless'",
		"method: autodetect",
		"name: 'staging-browser'",
		"username: 'analyst@example.test'",
		"password: 'super-secret-password'",
		"user: 'staging-browser'",
	} {
		if !strings.Contains(plan, fragment) {
			t.Fatalf("expected zap browser auth plan to contain %q, got %s", fragment, plan)
		}
	}
}

func TestBuildZAPAutomationCommandConfiguresFormAuthContext(t *testing.T) {
	output := t.TempDir()
	execution := moduleExecution{
		mode:          domain.IsolationLocal,
		hostOutputDir: output,
		outputDir:     output,
		request: domain.AgentScanRequest{
			TargetPath: t.TempDir(),
			Profile: domain.ScanProfile{
				Mode:         domain.ModeActive,
				AllowNetwork: true,
				DASTTargets: []domain.DastTarget{{
					Name:        "portal",
					URL:         "https://app.example.test",
					AuthType:    domain.DastAuthForm,
					AuthProfile: "staging-form",
				}},
				DASTAuthProfiles: []domain.DastAuthProfile{{
					Name:             "staging-form",
					Type:             domain.DastAuthForm,
					LoginPageURL:     "https://app.example.test/login",
					LoginRequestURL:  "https://app.example.test/sessions",
					LoginRequestBody: "username={%username%}&password={%password%}",
					UsernameEnv:      "STAGING_WEB_USER",
					PasswordEnv:      "STAGING_WEB_PASS",
					LoggedInRegex:    "dashboard",
					LoggedOutRegex:   "sign in",
				}},
			},
		},
	}

	_, _, err := buildZAPAutomationCommand(config.Config{}, "zaproxy", execution)
	if err != nil {
		t.Fatalf("build zap command: %v", err)
	}

	planBody, err := os.ReadFile(filepath.Join(output, "zap-automation.yaml"))
	if err != nil {
		t.Fatalf("read zap plan: %v", err)
	}
	plan := string(planBody)
	for _, fragment := range []string{
		"method: form",
		"loginPageUrl: 'https://app.example.test/login'",
		"loginRequestUrl: 'https://app.example.test/sessions'",
		"loginRequestBody: 'username={%username%}&password={%password%}'",
		"method: response",
		"loggedInRegex: 'dashboard'",
		"loggedOutRegex: 'sign in'",
	} {
		if !strings.Contains(plan, fragment) {
			t.Fatalf("expected zap form auth plan to contain %q, got %s", fragment, plan)
		}
	}
}

func TestParseSARIFCategoryParsesFindings(t *testing.T) {
	parser := parseSARIFCategory(domain.CategorySAST, "CodeQL")
	output := []byte(`{
  "runs": [
    {
      "tool": {
        "driver": {
          "rules": [
            {
              "id": "js/xss",
              "name": "Potential XSS",
              "helpUri": "https://example.test/rule",
              "shortDescription": {"text": "Potential XSS"},
              "fullDescription": {"text": "Escape user input before rendering."},
              "defaultConfiguration": {"level": "warning"},
              "properties": {"security-severity": "8.5", "precision": "high"}
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "js/xss",
          "message": {"text": "Unsanitized user input reaches HTML sink."},
          "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": "src/app.js"}}}
          ],
          "partialFingerprints": {"primaryLocationLineHash": "abc123"}
        }
      ]
    }
  ]
}`)

	result, findings, err := parser(domain.AgentScanRequest{ScanID: "run-1", ProjectID: "prj-1"}, "codeql", output)
	if err != nil {
		t.Fatalf("parse sarif: %v", err)
	}
	if result.FindingCount != 1 || len(findings) != 1 {
		t.Fatalf("expected one finding, got result=%d findings=%d", result.FindingCount, len(findings))
	}
	if findings[0].Severity != domain.SeverityHigh {
		t.Fatalf("expected SARIF security severity to map to high, got %s", findings[0].Severity)
	}
	if findings[0].Fingerprint != "abc123" {
		t.Fatalf("expected partial fingerprint to be used, got %s", findings[0].Fingerprint)
	}
	if findings[0].EvidenceRef != "https://example.test/rule" {
		t.Fatalf("expected help URI as evidence ref, got %s", findings[0].EvidenceRef)
	}
}
