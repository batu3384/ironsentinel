package domain

import (
	"testing"
	"time"
)

func TestNewCampaignNormalizesFindingFingerprints(t *testing.T) {
	now := time.Date(2026, 4, 4, 15, 0, 0, 0, time.UTC)
	campaign := NewCampaign("cmp-1", "prj-1", "  Fix reachable SCA  ", "  Source run summary  ", " run-1 ", " run-0 ", []string{"fp-2", " ", "fp-1", "fp-1"}, now)

	if campaign.Status != CampaignOpen {
		t.Fatalf("expected open status, got %s", campaign.Status)
	}
	if len(campaign.FindingFingerprints) != 2 {
		t.Fatalf("expected deduped findings, got %+v", campaign.FindingFingerprints)
	}
	if campaign.FindingFingerprints[0] != "fp-1" || campaign.FindingFingerprints[1] != "fp-2" {
		t.Fatalf("expected sorted fingerprints, got %+v", campaign.FindingFingerprints)
	}
	if campaign.Title != "Fix reachable SCA" || campaign.Summary != "Source run summary" {
		t.Fatalf("expected trimmed title and summary, got %+v", campaign)
	}
	if campaign.SourceRunID != "run-1" || campaign.BaselineRunID != "run-0" {
		t.Fatalf("expected trimmed run ids, got %+v", campaign)
	}
	if !campaign.CreatedAt.Equal(now.UTC()) || !campaign.UpdatedAt.Equal(now.UTC()) {
		t.Fatalf("expected UTC timestamps, got created=%s updated=%s", campaign.CreatedAt, campaign.UpdatedAt)
	}
}

func TestCampaignHighestSeverity(t *testing.T) {
	campaign := Campaign{
		FindingFingerprints: []string{"fp-1"},
	}
	findings := []Finding{
		{Fingerprint: "fp-1", Severity: SeverityHigh},
		{Fingerprint: "fp-2", Severity: SeverityCritical},
	}
	if got := campaign.HighestSeverity(findings); got != SeverityHigh {
		t.Fatalf("expected highest matching severity to be high, got %s", got)
	}
}
