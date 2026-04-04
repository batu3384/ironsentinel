package domain

import (
	"sort"
	"strings"
	"time"
)

type CampaignStatus string

const (
	CampaignOpen       CampaignStatus = "open"
	CampaignInProgress CampaignStatus = "in_progress"
	CampaignCompleted  CampaignStatus = "completed"
	CampaignArchived   CampaignStatus = "archived"
)

type CampaignIssueRef struct {
	Provider string `json:"provider"`
	Repo     string `json:"repo"`
	Number   int    `json:"number"`
	URL      string `json:"url"`
	State    string `json:"state"`
}

type Campaign struct {
	ID                  string             `json:"id"`
	ProjectID           string             `json:"projectId"`
	Title               string             `json:"title"`
	Summary             string             `json:"summary"`
	Status              CampaignStatus     `json:"status"`
	Owner               string             `json:"owner,omitempty"`
	DueAt               *time.Time         `json:"dueAt,omitempty"`
	CreatedAt           time.Time          `json:"createdAt"`
	UpdatedAt           time.Time          `json:"updatedAt"`
	FindingFingerprints []string           `json:"findingFingerprints"`
	SourceRunID         string             `json:"sourceRunId,omitempty"`
	BaselineRunID       string             `json:"baselineRunId,omitempty"`
	PublishedIssues     []CampaignIssueRef `json:"publishedIssues,omitempty"`
}

func NewCampaign(id, projectID, title, summary, sourceRunID, baselineRunID string, findingFingerprints []string, now time.Time) Campaign {
	normalized := make([]string, 0, len(findingFingerprints))
	seen := map[string]struct{}{}
	for _, fingerprint := range findingFingerprints {
		value := strings.TrimSpace(fingerprint)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)

	return Campaign{
		ID:                  id,
		ProjectID:           projectID,
		Title:               strings.TrimSpace(title),
		Summary:             strings.TrimSpace(summary),
		Status:              CampaignOpen,
		CreatedAt:           now.UTC(),
		UpdatedAt:           now.UTC(),
		FindingFingerprints: normalized,
		SourceRunID:         strings.TrimSpace(sourceRunID),
		BaselineRunID:       strings.TrimSpace(baselineRunID),
	}
}

func (c Campaign) HighestSeverity(findings []Finding) Severity {
	best := SeverityInfo
	lookup := make(map[string]struct{}, len(c.FindingFingerprints))
	for _, fingerprint := range c.FindingFingerprints {
		lookup[fingerprint] = struct{}{}
	}
	for _, finding := range findings {
		if _, ok := lookup[finding.Fingerprint]; !ok {
			continue
		}
		if SeverityRank(finding.Severity) < SeverityRank(best) {
			best = finding.Severity
		}
	}
	return best
}
