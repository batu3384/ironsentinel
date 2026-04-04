package github

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/batu3384/ironsentinel/internal/domain"
)

type IssuePayload struct {
	Title  string   `json:"title"`
	Body   string   `json:"body"`
	Labels []string `json:"labels,omitempty"`
}

type IssueResponse struct {
	Number int    `json:"number"`
	State  string `json:"state"`
	URL    string `json:"html_url"`
}

func BuildCampaignIssuePayload(campaign domain.Campaign, findings []domain.Finding) IssuePayload {
	items := append([]domain.Finding(nil), findings...)
	slices.SortFunc(items, compareCampaignFindings)
	labels := buildCampaignLabels(items)

	lines := make([]string, 0, 24+len(items))
	lines = append(lines,
		"",
		"## Summary",
		valueOrDefault(strings.TrimSpace(campaign.Summary), "No summary provided."),
		"",
		"## Campaign",
		fmt.Sprintf("- Project: `%s`", strings.TrimSpace(campaign.ProjectID)),
		fmt.Sprintf("- Source run: `%s`", strings.TrimSpace(campaign.SourceRunID)),
		fmt.Sprintf("- Baseline run: `%s`", valueOrDash(strings.TrimSpace(campaign.BaselineRunID))),
		fmt.Sprintf("- Findings tracked: `%d`", len(items)),
		"",
		"## Severity Distribution",
	)
	for _, severity := range domain.AllSeverities() {
		count := countSeverity(items, severity)
		if count == 0 {
			continue
		}
		lines = append(lines, fmt.Sprintf("- %s: %d", strings.ToLower(string(severity)), count))
	}
	lines = append(lines, "", "## Top Findings")
	lines = append(lines, "| Severity | Category | Title | Module | Location |", "| --- | --- | --- | --- | --- |")
	for _, finding := range items {
		lines = append(lines, formatCampaignFindingLine(finding))
	}
	if hints := remediationHints(items); len(hints) > 0 {
		lines = append(lines, "", "## Remediation Hints")
		lines = append(lines, hints...)
	}
	lines = append(lines,
		"",
		"## Local Follow-Up",
		fmt.Sprintf("- `ironsentinel campaigns show %s`", strings.TrimSpace(campaign.ID)),
		fmt.Sprintf("- `ironsentinel findings --run %s`", strings.TrimSpace(campaign.SourceRunID)),
	)

	return IssuePayload{
		Title:  strings.TrimSpace(campaign.Title),
		Body:   strings.TrimSpace(strings.Join(lines, "\n")),
		Labels: labels,
	}
}

func (c *Client) CreateIssue(ctx context.Context, repo Repository, payload IssuePayload) (IssueResponse, error) {
	resp, err := c.postJSON(ctx, fmt.Sprintf("/repos/%s/%s/issues", repo.Owner, repo.Name), payload)
	if err != nil {
		return IssueResponse{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return IssueResponse{}, mapHTTPError("issue create", repo, resp)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	var issue IssueResponse
	if err := json.NewDecoder(resp.Body).Decode(&issue); err != nil {
		return IssueResponse{}, err
	}
	return issue, nil
}

func compareCampaignFindings(left, right domain.Finding) int {
	if rankDiff := domain.SeverityRank(left.Severity) - domain.SeverityRank(right.Severity); rankDiff != 0 {
		return rankDiff
	}
	if left.Title != right.Title {
		if left.Title < right.Title {
			return -1
		}
		return 1
	}
	if left.Location != right.Location {
		if left.Location < right.Location {
			return -1
		}
		return 1
	}
	switch {
	case left.Fingerprint < right.Fingerprint:
		return -1
	case left.Fingerprint > right.Fingerprint:
		return 1
	default:
		return 0
	}
}

func formatCampaignFindingLine(finding domain.Finding) string {
	title := strings.TrimSpace(finding.Title)
	if title == "" {
		title = finding.Fingerprint
	}
	return fmt.Sprintf("| %s | %s | %s | %s | %s |",
		strings.ToLower(string(finding.Severity)),
		strings.ToLower(string(finding.Category)),
		escapeTableCell(title),
		valueOrDefault(strings.TrimSpace(finding.Module), "-"),
		valueOrDefault(strings.TrimSpace(finding.Location), "-"),
	)
}

func valueOrDash(value string) string {
	if value == "" {
		return "n/a"
	}
	return value
}

func valueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func countSeverity(findings []domain.Finding, severity domain.Severity) int {
	count := 0
	for _, finding := range findings {
		if finding.Severity == severity {
			count++
		}
	}
	return count
}

func remediationHints(findings []domain.Finding) []string {
	hints := make([]string, 0, len(findings))
	seen := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		hint := strings.TrimSpace(finding.Remediation)
		if hint == "" {
			continue
		}
		if _, ok := seen[hint]; ok {
			continue
		}
		seen[hint] = struct{}{}
		hints = append(hints, "- "+hint)
	}
	slices.Sort(hints)
	return hints
}

func buildCampaignLabels(findings []domain.Finding) []string {
	labels := []string{"ironsentinel", "security"}
	if len(findings) > 0 {
		labels = append(labels, "severity:"+strings.ToLower(string(findings[0].Severity)))
	}
	seenCategories := map[string]struct{}{}
	for _, finding := range findings {
		category := strings.ToLower(string(finding.Category))
		if category == "" {
			continue
		}
		if _, ok := seenCategories[category]; ok {
			continue
		}
		seenCategories[category] = struct{}{}
		labels = append(labels, "category:"+category)
	}
	return labels
}

func escapeTableCell(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}
