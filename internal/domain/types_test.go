package domain

import (
	"encoding/json"
	"testing"
)

func TestIndexDastAuthProfilesRejectsInvalidProfiles(t *testing.T) {
	tests := []struct {
		name     string
		profiles []DastAuthProfile
		wantErr  string
	}{
		{
			name: "bearer requires secret env",
			profiles: []DastAuthProfile{{
				Name: "api",
				Type: DastAuthBearer,
			}},
			wantErr: `dast auth profile "api" bearer secretEnv is required`,
		},
		{
			name: "header requires header name",
			profiles: []DastAuthProfile{{
				Name:      "gateway",
				Type:      DastAuthHeader,
				SecretEnv: "API_TOKEN",
			}},
			wantErr: `dast auth profile "gateway" headerName is required for header auth`,
		},
		{
			name: "basic requires both credentials",
			profiles: []DastAuthProfile{{
				Name:        "legacy",
				Type:        DastAuthBasic,
				UsernameEnv: "LEGACY_USER",
			}},
			wantErr: `dast auth profile "legacy" passwordEnv is required for basic auth`,
		},
		{
			name: "browser requires login page",
			profiles: []DastAuthProfile{{
				Name:        "browser",
				Type:        DastAuthBrowser,
				UsernameEnv: "WEB_USER",
				PasswordEnv: "WEB_PASS",
			}},
			wantErr: `dast auth profile "browser" loginPageUrl is required for browser auth`,
		},
		{
			name: "form requires login request url",
			profiles: []DastAuthProfile{{
				Name:             "form",
				Type:             DastAuthForm,
				LoginPageURL:     "https://app.example.test/login",
				LoginRequestBody: "username={%username%}&password={%password%}",
				UsernameEnv:      "WEB_USER",
				PasswordEnv:      "WEB_PASS",
			}},
			wantErr: `dast auth profile "form" loginRequestUrl is required for form auth`,
		},
		{
			name: "form requires verification signal",
			profiles: []DastAuthProfile{{
				Name:             "form",
				Type:             DastAuthForm,
				LoginPageURL:     "https://app.example.test/login",
				LoginRequestURL:  "https://app.example.test/session",
				LoginRequestBody: "username={%username%}&password={%password%}",
				UsernameEnv:      "WEB_USER",
				PasswordEnv:      "WEB_PASS",
			}},
			wantErr: `dast auth profile "form" requires sessionCheckUrl or loggedInRegex/loggedOutRegex for form auth verification`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := IndexDastAuthProfiles(test.profiles)
			if err == nil {
				t.Fatalf("expected error")
			}
			if err.Error() != test.wantErr {
				t.Fatalf("error = %q, want %q", err.Error(), test.wantErr)
			}
		})
	}
}

func TestResolveDastTargetAuthRejectsAuthTypeMismatch(t *testing.T) {
	_, _, err := ResolveDastTargetAuth(
		DastTarget{
			Name:        "portal",
			URL:         "https://app.example.test",
			AuthType:    DastAuthBearer,
			AuthProfile: "staging-browser",
		},
		[]DastAuthProfile{{
			Name:         "staging-browser",
			Type:         DastAuthBrowser,
			LoginPageURL: "https://app.example.test/login",
			UsernameEnv:  "WEB_USER",
			PasswordEnv:  "WEB_PASS",
		}},
	)
	if err == nil {
		t.Fatalf("expected mismatch error")
	}
	if got, want := err.Error(), `dast target "portal" auth type "bearer" conflicts with profile "staging-browser" type "browser"`; got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}

func TestNormalizeReachabilityCanonicalizesKnownValues(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  Reachability
	}{
		{name: "reachable", input: " reachable ", want: ReachabilityReachable},
		{name: "possible", input: "Possible", want: ReachabilityPossible},
		{name: "repository", input: "repository", want: ReachabilityRepository},
		{name: "image", input: "image", want: ReachabilityImage},
		{name: "infrastructure", input: "Infrastructure", want: ReachabilityInfrastructure},
		{name: "execution surface", input: "execution surface", want: ReachabilityExecutionSurface},
		{name: "not applicable", input: "not_applicable", want: ReachabilityNotApplicable},
		{name: "empty", input: "   ", want: Reachability("")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := NormalizeReachability(test.input); got != test.want {
				t.Fatalf("NormalizeReachability(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

func TestReachabilityStringUsesCanonicalValue(t *testing.T) {
	value := Reachability(" Execution_Surface ")

	if got := value.String(); got != string(ReachabilityExecutionSurface) {
		t.Fatalf("Reachability.String() = %q, want %q", got, ReachabilityExecutionSurface)
	}
}

func TestReachabilityJSONNormalizesOnMarshalAndUnmarshal(t *testing.T) {
	type payload struct {
		Reachability Reachability `json:"reachability"`
	}

	encoded, err := json.Marshal(payload{Reachability: Reachability(" Not_Applicable ")})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if string(encoded) != `{"reachability":"not-applicable"}` {
		t.Fatalf("json.Marshal() = %s", encoded)
	}

	var decoded payload
	if err := json.Unmarshal([]byte(`{"reachability":"Execution Surface"}`), &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if decoded.Reachability != ReachabilityExecutionSurface {
		t.Fatalf("decoded reachability = %q, want %q", decoded.Reachability, ReachabilityExecutionSurface)
	}
}

func TestRecalculateSummaryBlocksAtGate(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityMedium, Category: CategorySAST, Status: FindingInvestigating},
		{Severity: SeverityCritical, Category: CategorySecret, Status: FindingOpen},
		{Severity: SeverityLow, Category: CategoryMaintainability, Status: FindingAcceptedRisk},
	}

	summary := RecalculateSummary(findings, SeverityHigh)

	if !summary.Blocked {
		t.Fatalf("expected gate to block when a critical finding exists")
	}
	if summary.TotalFindings != 3 {
		t.Fatalf("expected 3 findings, got %d", summary.TotalFindings)
	}
	if summary.CountsBySeverity[SeverityCritical] != 1 {
		t.Fatalf("expected 1 critical finding, got %d", summary.CountsBySeverity[SeverityCritical])
	}
	if summary.CountsByCategory[CategorySecret] != 1 {
		t.Fatalf("expected 1 secret finding, got %d", summary.CountsByCategory[CategorySecret])
	}
	if summary.CountsByStatus[FindingInvestigating] != 1 {
		t.Fatalf("expected 1 investigating finding, got %d", summary.CountsByStatus[FindingInvestigating])
	}
}

func TestCalculateRunDeltaClassifiesNewExistingAndResolved(t *testing.T) {
	current := []Finding{
		{Fingerprint: "fp-existing", Severity: SeverityHigh, Title: "Existing finding"},
		{Fingerprint: "fp-new", Severity: SeverityCritical, Title: "New finding"},
	}
	baseline := []Finding{
		{Fingerprint: "fp-existing", Severity: SeverityHigh, Title: "Existing finding"},
		{Fingerprint: "fp-resolved", Severity: SeverityMedium, Title: "Resolved finding"},
	}

	delta := CalculateRunDelta(current, baseline, "run-2", "run-1", "prj-1")

	if delta.CountsByChange[FindingNew] != 1 {
		t.Fatalf("expected 1 new finding, got %d", delta.CountsByChange[FindingNew])
	}
	if delta.CountsByChange[FindingExisting] != 1 {
		t.Fatalf("expected 1 existing finding, got %d", delta.CountsByChange[FindingExisting])
	}
	if delta.CountsByChange[FindingResolved] != 1 {
		t.Fatalf("expected 1 resolved finding, got %d", delta.CountsByChange[FindingResolved])
	}
	if len(delta.NewFindings) != 1 || delta.NewFindings[0].Fingerprint != "fp-new" {
		t.Fatalf("expected fp-new to be classified as new")
	}
	if len(delta.ResolvedFindings) != 1 || delta.ResolvedFindings[0].Fingerprint != "fp-resolved" {
		t.Fatalf("expected fp-resolved to be classified as resolved")
	}
}
