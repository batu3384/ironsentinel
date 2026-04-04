package github

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/batu3384/ironsentinel/internal/domain"
)

func TestBuildCampaignIssuePayload(t *testing.T) {
	campaign := domain.Campaign{
		ID:            "cmp-1",
		ProjectID:     "prj-1",
		Title:         "Fix reachable SCA",
		Summary:       "Top security campaign",
		SourceRunID:   "run-7",
		BaselineRunID: "run-6",
	}
	findings := []domain.Finding{
		{Title: "Low priority noise", Severity: domain.SeverityLow, Category: domain.CategorySCA},
		{Title: "Reachable package issue", Severity: domain.SeverityCritical, Category: domain.CategorySCA, Module: "deps", Remediation: "Pin the dependency."},
		{Title: "Leaked credential", Severity: domain.SeverityHigh, Category: domain.CategorySecret, Location: ".env"},
	}

	payload := BuildCampaignIssuePayload(campaign, findings)
	if payload.Title != "Fix reachable SCA" {
		t.Fatalf("unexpected title: %+v", payload)
	}
	if got, want := strings.Join(payload.Labels, ","), "ironsentinel,security,severity:critical,category:sca,category:secret"; got != want {
		t.Fatalf("unexpected labels: got %q want %q", got, want)
	}

	for _, fragment := range []string{
		"## Summary",
		"Top security campaign",
		"## Campaign",
		"Project: `prj-1`",
		"Source run: `run-7`",
		"Baseline run: `run-6`",
		"## Severity Distribution",
		"- critical: 1",
		"- high: 1",
		"- low: 1",
		"## Top Findings",
		"| Severity | Category | Title | Module | Location |",
		"| critical | sca | Reachable package issue | deps | - |",
		"| high | secret | Leaked credential | - | .env |",
		"## Remediation Hints",
		"- Pin the dependency.",
		"## Local Follow-Up",
		"`ironsentinel campaigns show cmp-1`",
		"`ironsentinel findings --run run-7`",
	} {
		if !strings.Contains(payload.Body, fragment) {
			t.Fatalf("expected issue body to contain %q, got:\n%s", fragment, payload.Body)
		}
	}
}

func TestBuildCampaignIssuePayloadUsesSummaryFallback(t *testing.T) {
	payload := BuildCampaignIssuePayload(domain.Campaign{
		ID:          "cmp-2",
		ProjectID:   "prj-2",
		Title:       "Untitled",
		SourceRunID: "run-2",
	}, nil)

	if !strings.Contains(payload.Body, "No summary provided.") {
		t.Fatalf("expected summary fallback, got:\n%s", payload.Body)
	}
}

func TestCreateIssuePostsPayloadAndDecodesResponse(t *testing.T) {
	var method string
	var path string
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		path = r.URL.Path
		data, _ := io.ReadAll(r.Body)
		body = string(data)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"number":17,"state":"open","html_url":"https://github.com/batu3384/ironsentinel/issues/17"}`))
	}))
	defer server.Close()

	client, err := NewClient("ghs-test", server.Client())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	client.baseURL = server.URL

	issue, err := client.CreateIssue(context.Background(), Repository{Owner: "batu3384", Name: "ironsentinel"}, IssuePayload{
		Title:  "Fix reachable SCA",
		Body:   "Top security campaign",
		Labels: []string{"campaign", "ironsentinel"},
	})
	if err != nil {
		t.Fatalf("create issue: %v", err)
	}
	if method != http.MethodPost {
		t.Fatalf("expected POST request, got %s", method)
	}
	if path != "/repos/batu3384/ironsentinel/issues" {
		t.Fatalf("unexpected path: %s", path)
	}
	if !strings.Contains(body, `"title":"Fix reachable SCA"`) || !strings.Contains(body, `"labels":["campaign","ironsentinel"]`) {
		t.Fatalf("unexpected request body: %s", body)
	}
	if issue.Number != 17 || issue.State != "open" || issue.URL != "https://github.com/batu3384/ironsentinel/issues/17" {
		t.Fatalf("unexpected issue response: %+v", issue)
	}
}

func TestCreateIssueMapsNonSuccessResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"validation failed"}`))
	}))
	defer server.Close()

	client, err := NewClient("ghs-test", server.Client())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	client.baseURL = server.URL

	_, err = client.CreateIssue(context.Background(), Repository{Owner: "batu3384", Name: "ironsentinel"}, IssuePayload{
		Title: "Fix reachable SCA",
		Body:  "Top security campaign",
	})
	if err == nil || !strings.Contains(err.Error(), "issue create failed") || !strings.Contains(err.Error(), "validation failed") {
		t.Fatalf("expected mapped create issue error, got %v", err)
	}
}
