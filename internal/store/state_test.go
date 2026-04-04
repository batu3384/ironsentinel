package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/batu3384/ironsentinel/internal/domain"
)

func TestSuppressionLifecycle(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("new state store: %v", err)
	}

	suppression := domain.Suppression{
		Fingerprint: "fp-1",
		Reason:      "accepted risk",
		Owner:       "security",
		ExpiresAt:   time.Now().UTC().Add(24 * time.Hour),
		TicketRef:   "SEC-1",
	}
	if err := store.SaveSuppression(suppression); err != nil {
		t.Fatalf("save suppression: %v", err)
	}

	items := store.ListSuppressions()
	if len(items) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(items))
	}
	if items[0].Fingerprint != "fp-1" {
		t.Fatalf("unexpected suppression fingerprint: %s", items[0].Fingerprint)
	}

	if err := store.DeleteSuppression("fp-1"); err != nil {
		t.Fatalf("delete suppression: %v", err)
	}
	if len(store.ListSuppressions()) != 0 {
		t.Fatalf("expected suppressions to be empty after delete")
	}
}

func TestFindingTriageOverlaysFindingFields(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("new state store: %v", err)
	}

	finding := domain.Finding{
		ScanID:      "run-1",
		Fingerprint: "fp-2",
		Title:       "Potential issue",
	}
	if err := store.AddFinding(finding); err != nil {
		t.Fatalf("add finding: %v", err)
	}

	triage := domain.FindingTriage{
		Fingerprint: "fp-2",
		Status:      domain.FindingInvestigating,
		Tags:        []string{"security", "needs-owner"},
		Note:        "triage note",
		Owner:       "sec-team",
		UpdatedAt:   time.Now().UTC(),
	}
	if err := store.SaveFindingTriage(triage); err != nil {
		t.Fatalf("save triage: %v", err)
	}

	items := store.ListFindings("run-1")
	if len(items) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(items))
	}
	if items[0].Status != domain.FindingInvestigating {
		t.Fatalf("expected investigating status, got %s", items[0].Status)
	}
	if len(items[0].Tags) != 2 {
		t.Fatalf("expected 2 tags, got %d", len(items[0].Tags))
	}
	if items[0].Owner != "sec-team" {
		t.Fatalf("unexpected owner: %s", items[0].Owner)
	}
}

func TestCampaignRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("new state store: %v", err)
	}

	now := time.Now().UTC()
	campaign := domain.NewCampaign("cmp-1", "prj-1", "Fix secrets", "summary", "run-1", "", []string{"fp-1", "fp-2"}, now)

	if err := store.SaveCampaign(campaign); err != nil {
		t.Fatalf("save campaign: %v", err)
	}

	got, ok := store.GetCampaign(campaign.ID)
	if !ok {
		t.Fatalf("expected campaign %s", campaign.ID)
	}
	if got.Title != "Fix secrets" || len(got.FindingFingerprints) != 2 {
		t.Fatalf("unexpected stored campaign: %+v", got)
	}
	if got.Status != domain.CampaignOpen {
		t.Fatalf("expected open campaign, got %s", got.Status)
	}
}

func TestListCampaignsFiltersByProject(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("new state store: %v", err)
	}

	now := time.Now().UTC()
	first := domain.NewCampaign("cmp-1", "prj-1", "One", "", "", "", []string{"fp-1"}, now)
	second := domain.NewCampaign("cmp-2", "prj-2", "Two", "", "", "", []string{"fp-2"}, now)

	if err := store.SaveCampaign(first); err != nil {
		t.Fatalf("save first campaign: %v", err)
	}
	if err := store.SaveCampaign(second); err != nil {
		t.Fatalf("save second campaign: %v", err)
	}

	items := store.ListCampaigns("prj-1")
	if len(items) != 1 || items[0].ID != "cmp-1" {
		t.Fatalf("unexpected filtered campaigns: %+v", items)
	}
}

func TestCampaignListOrdersByUpdatedAtDescending(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStateStore(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("new state store: %v", err)
	}

	firstTime := time.Date(2026, 4, 4, 10, 0, 0, 0, time.UTC)
	secondTime := time.Date(2026, 4, 4, 10, 0, 0, 100_000_000, time.UTC)
	first := domain.NewCampaign("cmp-1", "prj-1", "First", "", "", "", []string{"fp-1"}, firstTime)
	second := domain.NewCampaign("cmp-2", "prj-1", "Second", "", "", "", []string{"fp-2"}, secondTime)

	if err := store.SaveCampaign(first); err != nil {
		t.Fatalf("save first campaign: %v", err)
	}
	if err := store.SaveCampaign(second); err != nil {
		t.Fatalf("save second campaign: %v", err)
	}

	items := store.ListCampaigns("prj-1")
	if len(items) != 2 {
		t.Fatalf("expected 2 campaigns, got %d", len(items))
	}
	if items[0].ID != "cmp-2" || items[1].ID != "cmp-1" {
		t.Fatalf("expected campaigns ordered by updatedAt desc, got %+v", items)
	}
}

func TestCampaignPayloadOnlySchemaUpgradePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	store, err := NewStateStore(path)
	if err != nil {
		t.Fatalf("new state store: %v", err)
	}
	if err := store.db.Close(); err != nil {
		t.Fatalf("close state store: %v", err)
	}

	legacyStore, err := NewStateStore(path)
	if err != nil {
		t.Fatalf("reopen state store: %v", err)
	}
	t.Cleanup(func() { _ = legacyStore.db.Close() })

	if _, err := legacyStore.db.Exec(`DROP TABLE IF EXISTS campaigns`); err != nil {
		t.Fatalf("drop campaigns: %v", err)
	}
	if _, err := legacyStore.db.Exec(`
		CREATE TABLE campaigns (
			id TEXT PRIMARY KEY,
			project_id TEXT NOT NULL,
			payload TEXT NOT NULL
		)
	`); err != nil {
		t.Fatalf("create legacy campaigns table: %v", err)
	}

	campaign := domain.NewCampaign("cmp-legacy", "prj-1", "Legacy", "", "run-1", "", []string{"fp-1"}, time.Now().UTC())
	if err := legacyStore.SaveCampaign(campaign); err != nil {
		t.Fatalf("save campaign against payload-only schema: %v", err)
	}
	if got, ok := legacyStore.GetCampaign("cmp-legacy"); !ok || got.Title != "Legacy" {
		t.Fatalf("expected campaign from payload-only schema, got %+v ok=%v", got, ok)
	}
}
