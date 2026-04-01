package store

import (
	"database/sql"
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

func indexExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()

	var count int
	if err := db.QueryRow(`SELECT COUNT(1) FROM sqlite_master WHERE type = 'index' AND name = ?`, name).Scan(&count); err != nil {
		t.Fatalf("lookup index %s: %v", name, err)
	}
	return count > 0
}
