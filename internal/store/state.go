package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/batu3384/ironsentinel/internal/domain"
)

type StateStore struct {
	mu   sync.RWMutex
	path string
	db   *sql.DB
}

func (s *StateStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

type schemaMigration struct {
	version int
	upSQL   []string
	downSQL []string
}

func NewStateStore(path string) (*StateStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	store := &StateStore{
		path: path,
		db:   db,
	}
	if err := store.bootstrap(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *StateStore) bootstrap() error {
	if err := s.exec(`PRAGMA busy_timeout = 30000;`, `PRAGMA foreign_keys = ON;`); err != nil {
		return err
	}
	if mode, err := s.pragmaString("journal_mode"); err != nil {
		return err
	} else if !strings.EqualFold(mode, "wal") {
		if err := s.exec(`PRAGMA journal_mode = WAL;`); err != nil {
			return err
		}
	}
	if err := s.exec(`PRAGMA synchronous = NORMAL;`); err != nil {
		return err
	}
	if err := s.applyMigrations(); err != nil {
		return err
	}

	empty, err := s.isEmpty()
	if err != nil {
		return err
	}
	if !empty {
		return nil
	}
	return nil
}

func (s *StateStore) pragmaString(name string) (string, error) {
	row := s.db.QueryRow(`PRAGMA ` + name + `;`)
	var value string
	if err := row.Scan(&value); err != nil {
		return "", err
	}
	return value, nil
}

func (s *StateStore) pragmaInt(name string) (int, error) {
	row := s.db.QueryRow(`PRAGMA ` + name + `;`)
	var value int
	if err := row.Scan(&value); err != nil {
		return 0, err
	}
	return value, nil
}

func (s *StateStore) exec(statements ...string) error {
	for _, statement := range statements {
		if strings.TrimSpace(statement) == "" {
			continue
		}
		if _, err := s.db.Exec(statement); err != nil {
			return err
		}
	}
	return nil
}

func (s *StateStore) applyMigrations() error {
	currentVersion, err := s.pragmaInt("user_version")
	if err != nil {
		return err
	}

	for _, migration := range schemaMigrations {
		if migration.version <= currentVersion {
			continue
		}
		if err := s.runMigration(migration); err != nil {
			return err
		}
	}
	return nil
}

func (s *StateStore) runMigration(migration schemaMigration) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	for _, statement := range migration.upSQL {
		if strings.TrimSpace(statement) == "" {
			continue
		}
		if _, err := tx.Exec(statement); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d;`, migration.version)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *StateStore) isEmpty() (bool, error) {
	for _, table := range []string{"projects", "runs", "findings", "suppressions", "triage"} {
		query := `SELECT COUNT(1) FROM ` + table
		var count int
		if err := s.db.QueryRow(query).Scan(&count); err != nil {
			return false, err
		}
		if count > 0 {
			return false, nil
		}
	}
	return true, nil
}

func (s *StateStore) CreateProject(project domain.Project) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return upsertProject(s.db, project)
}

func (s *StateStore) FindProjectByHandle(handle string) (domain.Project, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	project, err := querySingleJSON[domain.Project](s.db, `SELECT payload FROM projects WHERE target_handle = ? LIMIT 1`, handle)
	if err != nil {
		return domain.Project{}, false
	}
	return project, true
}

func (s *StateStore) ListProjects() []domain.Project {
	s.mu.RLock()
	defer s.mu.RUnlock()

	items, err := queryJSONList[domain.Project](s.db, `SELECT payload FROM projects ORDER BY created_at DESC`)
	if err != nil {
		return nil
	}
	return items
}

func (s *StateStore) GetProject(id string) (domain.Project, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	project, err := querySingleJSON[domain.Project](s.db, `SELECT payload FROM projects WHERE id = ? LIMIT 1`, id)
	if err != nil {
		return domain.Project{}, false
	}
	return project, true
}

func (s *StateStore) SaveCampaign(campaign domain.Campaign) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return upsertCampaign(s.db, campaign)
}

func (s *StateStore) GetCampaign(id string) (domain.Campaign, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	campaign, err := querySingleJSON[domain.Campaign](s.db, `SELECT payload FROM campaigns WHERE id = ? LIMIT 1`, id)
	if err != nil {
		return domain.Campaign{}, false
	}
	return campaign, true
}

func (s *StateStore) UpdateCampaign(id string, mutate func(domain.Campaign) (domain.Campaign, error)) (domain.Campaign, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	campaign, err := querySingleJSON[domain.Campaign](s.db, `SELECT payload FROM campaigns WHERE id = ? LIMIT 1`, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Campaign{}, fmt.Errorf("campaign not found: %s", id)
		}
		return domain.Campaign{}, err
	}
	updated, err := mutate(campaign)
	if err != nil {
		return domain.Campaign{}, err
	}
	if err := upsertCampaign(s.db, updated); err != nil {
		return domain.Campaign{}, err
	}
	return updated, nil
}

func (s *StateStore) ListCampaigns(projectID string) []domain.Campaign {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT payload FROM campaigns`
	args := make([]any, 0, 1)
	if strings.TrimSpace(projectID) != "" {
		query += ` WHERE project_id = ?`
		args = append(args, projectID)
	}
	query += ` ORDER BY julianday(json_extract(payload, '$.updatedAt')) DESC, julianday(json_extract(payload, '$.createdAt')) DESC`

	items, err := queryJSONList[domain.Campaign](s.db, query, args...)
	if err != nil {
		return nil
	}
	return items
}

func (s *StateStore) CreateRun(run domain.ScanRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return upsertRun(s.db, run)
}

func (s *StateStore) UpdateRun(run domain.ScanRun) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return upsertRun(s.db, run)
}

func (s *StateStore) GetRun(id string) (domain.ScanRun, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	run, err := querySingleJSON[domain.ScanRun](s.db, `SELECT payload FROM runs WHERE id = ? LIMIT 1`, id)
	if err != nil {
		return domain.ScanRun{}, false
	}
	return run, true
}

func (s *StateStore) ListRuns() []domain.ScanRun {
	s.mu.RLock()
	defer s.mu.RUnlock()

	items, err := queryJSONList[domain.ScanRun](s.db, `SELECT payload FROM runs ORDER BY started_at DESC`)
	if err != nil {
		return nil
	}
	return items
}

func (s *StateStore) ClaimNextQueuedRun() (domain.ScanRun, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return domain.ScanRun{}, false, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	run, err := querySingleJSON[domain.ScanRun](tx, `SELECT payload FROM runs WHERE status = ? ORDER BY started_at ASC LIMIT 1`, string(domain.ScanQueued))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ScanRun{}, false, nil
		}
		return domain.ScanRun{}, false, err
	}

	now := time.Now().UTC()
	run.Status = domain.ScanRunning
	run.StartedAt = now
	run.FinishedAt = nil
	if err := upsertRun(tx, run); err != nil {
		return domain.ScanRun{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return domain.ScanRun{}, false, err
	}
	return run, true, nil
}

func (s *StateStore) MarkRunCancelRequested(id string) (domain.ScanRun, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	run, err := querySingleJSON[domain.ScanRun](s.db, `SELECT payload FROM runs WHERE id = ? LIMIT 1`, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ScanRun{}, false, nil
		}
		return domain.ScanRun{}, false, err
	}

	run.CancelRequested = true
	if run.Status == domain.ScanQueued {
		now := time.Now().UTC()
		run.Status = domain.ScanCanceled
		run.FinishedAt = &now
	}
	if err := upsertRun(s.db, run); err != nil {
		return domain.ScanRun{}, false, err
	}
	return run, true, nil
}

func (s *StateStore) AddFinding(finding domain.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return upsertFinding(s.db, finding)
}

func (s *StateStore) ListFindings(scanID string) []domain.Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()

	findings, err := s.loadFindings(scanID)
	if err != nil {
		return nil
	}

	suppressions, err := s.loadSuppressionMap()
	if err != nil {
		return nil
	}
	triage, err := s.loadTriageMap()
	if err != nil {
		return nil
	}

	now := time.Now()
	filtered := make([]domain.Finding, 0, len(findings))
	for _, finding := range findings {
		suppression, suppressed := suppressions[finding.Fingerprint]
		if suppressed && suppression.ExpiresAt.After(now) {
			continue
		}
		filtered = append(filtered, applyTriage(finding, triage))
	}

	sort.Slice(filtered, func(i, j int) bool {
		return domain.SeverityRank(filtered[i].Severity) < domain.SeverityRank(filtered[j].Severity)
	})
	return filtered
}

func (s *StateStore) FindFinding(scanID, fingerprint string) (domain.Finding, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var (
		query string
		args  []any
	)
	if strings.TrimSpace(scanID) != "" {
		query = `SELECT payload FROM findings WHERE scan_id = ? AND fingerprint = ? LIMIT 1`
		args = []any{scanID, fingerprint}
	} else {
		query = `SELECT payload FROM findings WHERE fingerprint = ? ORDER BY scan_id DESC LIMIT 1`
		args = []any{fingerprint}
	}

	finding, err := querySingleJSON[domain.Finding](s.db, query, args...)
	if err != nil {
		return domain.Finding{}, false
	}

	triage, err := s.loadTriageMap()
	if err != nil {
		return domain.Finding{}, false
	}
	return applyTriage(finding, triage), true
}

func (s *StateStore) ListTriage() []domain.FindingTriage {
	s.mu.RLock()
	defer s.mu.RUnlock()

	items, err := queryJSONList[domain.FindingTriage](s.db, `SELECT payload FROM triage ORDER BY updated_at DESC`)
	if err != nil {
		return nil
	}
	return items
}

func (s *StateStore) SaveFindingTriage(triage domain.FindingTriage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return upsertTriage(s.db, triage)
}

func (s *StateStore) DeleteFindingTriage(fingerprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM triage WHERE fingerprint = ?`, fingerprint)
	return err
}

func (s *StateStore) ListSuppressions() []domain.Suppression {
	s.mu.RLock()
	defer s.mu.RUnlock()

	items, err := queryJSONList[domain.Suppression](s.db, `SELECT payload FROM suppressions ORDER BY expires_at ASC`)
	if err != nil {
		return nil
	}
	return items
}

func (s *StateStore) DeleteSuppression(fingerprint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM suppressions WHERE fingerprint = ?`, fingerprint)
	return err
}

func (s *StateStore) SaveSuppression(suppression domain.Suppression) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return upsertSuppression(s.db, suppression)
}

func (s *StateStore) loadFindings(scanID string) ([]domain.Finding, error) {
	if strings.TrimSpace(scanID) != "" {
		return queryJSONList[domain.Finding](s.db, `SELECT payload FROM findings WHERE scan_id = ?`, scanID)
	}
	return queryJSONList[domain.Finding](s.db, `SELECT payload FROM findings`)
}

func (s *StateStore) loadSuppressionMap() (map[string]domain.Suppression, error) {
	items, err := queryJSONList[domain.Suppression](s.db, `SELECT payload FROM suppressions`)
	if err != nil {
		return nil, err
	}
	index := make(map[string]domain.Suppression, len(items))
	for _, item := range items {
		index[item.Fingerprint] = item
	}
	return index, nil
}

func (s *StateStore) loadTriageMap() (map[string]domain.FindingTriage, error) {
	items, err := queryJSONList[domain.FindingTriage](s.db, `SELECT payload FROM triage`)
	if err != nil {
		return nil, err
	}
	index := make(map[string]domain.FindingTriage, len(items))
	for _, item := range items {
		index[item.Fingerprint] = item
	}
	return index, nil
}

func applyTriage(finding domain.Finding, triage map[string]domain.FindingTriage) domain.Finding {
	item, ok := triage[finding.Fingerprint]
	if !ok {
		finding.Status = domain.FindingOpen
		return finding
	}
	finding.Status = item.Status
	finding.Tags = mergeFindingTags(finding.Tags, item.Tags)
	finding.Note = item.Note
	finding.Owner = item.Owner
	updatedAt := item.UpdatedAt
	finding.UpdatedAt = &updatedAt
	return finding
}

func mergeFindingTags(existing, triageTags []string) []string {
	if len(existing) == 0 && len(triageTags) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(existing)+len(triageTags))
	merged := make([]string, 0, len(existing)+len(triageTags))
	appendTag := func(tag string) {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			return
		}
		key := strings.ToLower(tag)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		merged = append(merged, tag)
	}
	for _, tag := range existing {
		appendTag(tag)
	}
	for _, tag := range triageTags {
		appendTag(tag)
	}
	return merged
}

type sqlQueryer interface {
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

func querySingleJSON[T any](db sqlQueryer, query string, args ...any) (T, error) {
	var zero T
	var payload string
	if err := db.QueryRow(query, args...).Scan(&payload); err != nil {
		return zero, err
	}
	var item T
	if err := json.Unmarshal([]byte(payload), &item); err != nil {
		return zero, err
	}
	return item, nil
}

func queryJSONList[T any](db sqlQueryer, query string, args ...any) ([]T, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	items := make([]T, 0)
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var item T
		if err := json.Unmarshal([]byte(payload), &item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func upsertProject(exec sqlExecutor, project domain.Project) error {
	payload, err := json.Marshal(project)
	if err != nil {
		return err
	}
	_, err = exec.Exec(
		`INSERT INTO projects (id, target_handle, display_name, created_at, payload)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   target_handle = excluded.target_handle,
		   display_name = excluded.display_name,
		   created_at = excluded.created_at,
		   payload = excluded.payload`,
		project.ID,
		project.TargetHandle,
		project.DisplayName,
		project.CreatedAt.UTC().Format(time.RFC3339Nano),
		string(payload),
	)
	return err
}

func upsertCampaign(exec sqlExecutor, campaign domain.Campaign) error {
	payload, err := json.Marshal(campaign)
	if err != nil {
		return err
	}

	_, err = exec.Exec(
		`INSERT INTO campaigns (id, project_id, payload)
		 VALUES (?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   project_id = excluded.project_id,
		   payload = excluded.payload`,
		campaign.ID,
		campaign.ProjectID,
		string(payload),
	)
	return err
}

func upsertRun(exec sqlExecutor, run domain.ScanRun) error {
	payload, err := json.Marshal(run)
	if err != nil {
		return err
	}

	var finishedAt any
	if run.FinishedAt != nil {
		finishedAt = run.FinishedAt.UTC().Format(time.RFC3339Nano)
	}

	_, err = exec.Exec(
		`INSERT INTO runs (id, project_id, status, started_at, finished_at, payload)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   project_id = excluded.project_id,
		   status = excluded.status,
		   started_at = excluded.started_at,
		   finished_at = excluded.finished_at,
		   payload = excluded.payload`,
		run.ID,
		run.ProjectID,
		string(run.Status),
		run.StartedAt.UTC().Format(time.RFC3339Nano),
		finishedAt,
		string(payload),
	)
	return err
}

func upsertFinding(exec sqlExecutor, finding domain.Finding) error {
	payload, err := json.Marshal(finding)
	if err != nil {
		return err
	}
	_, err = exec.Exec(
		`INSERT INTO findings (scan_id, fingerprint, severity, payload)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(scan_id, fingerprint) DO UPDATE SET
		   severity = excluded.severity,
		   payload = excluded.payload`,
		finding.ScanID,
		finding.Fingerprint,
		string(finding.Severity),
		string(payload),
	)
	return err
}

func upsertSuppression(exec sqlExecutor, suppression domain.Suppression) error {
	payload, err := json.Marshal(suppression)
	if err != nil {
		return err
	}
	_, err = exec.Exec(
		`INSERT INTO suppressions (fingerprint, expires_at, payload)
		 VALUES (?, ?, ?)
		 ON CONFLICT(fingerprint) DO UPDATE SET
		   expires_at = excluded.expires_at,
		   payload = excluded.payload`,
		suppression.Fingerprint,
		suppression.ExpiresAt.UTC().Format(time.RFC3339Nano),
		string(payload),
	)
	return err
}

func upsertTriage(exec sqlExecutor, triage domain.FindingTriage) error {
	payload, err := json.Marshal(triage)
	if err != nil {
		return err
	}
	_, err = exec.Exec(
		`INSERT INTO triage (fingerprint, updated_at, payload)
		 VALUES (?, ?, ?)
		 ON CONFLICT(fingerprint) DO UPDATE SET
		   updated_at = excluded.updated_at,
		   payload = excluded.payload`,
		triage.Fingerprint,
		triage.UpdatedAt.UTC().Format(time.RFC3339Nano),
		string(payload),
	)
	return err
}

type sqlExecutor interface {
	Exec(query string, args ...any) (sql.Result, error)
}

var schemaMigrations = []schemaMigration{
	{
		version: 1,
		upSQL:   []string{schemaTablesSQL},
		downSQL: []string{schemaDropTablesSQL},
	},
	{
		version: 2,
		upSQL:   []string{schemaIndexesSQL},
		downSQL: []string{schemaDropIndexesSQL},
	},
	{
		version: 3,
		upSQL:   []string{schemaCampaignsSQL, schemaCampaignIndexesSQL},
		downSQL: []string{schemaCampaignDropIndexesSQL, schemaCampaignDropTablesSQL},
	},
}

const schemaTablesSQL = `
CREATE TABLE IF NOT EXISTS projects (
	id TEXT PRIMARY KEY,
	target_handle TEXT NOT NULL UNIQUE,
	display_name TEXT NOT NULL,
	created_at TEXT NOT NULL,
	payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
	id TEXT PRIMARY KEY,
	project_id TEXT NOT NULL,
	status TEXT NOT NULL,
	started_at TEXT NOT NULL,
	finished_at TEXT,
	payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
	scan_id TEXT NOT NULL,
	fingerprint TEXT NOT NULL,
	severity TEXT NOT NULL,
	payload TEXT NOT NULL,
	PRIMARY KEY (scan_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS suppressions (
	fingerprint TEXT PRIMARY KEY,
	expires_at TEXT NOT NULL,
	payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS triage (
	fingerprint TEXT PRIMARY KEY,
	updated_at TEXT NOT NULL,
	payload TEXT NOT NULL
);
`

const schemaCampaignsSQL = `
CREATE TABLE IF NOT EXISTS campaigns (
	id TEXT PRIMARY KEY,
	project_id TEXT NOT NULL,
	payload TEXT NOT NULL
);
`

const schemaIndexesSQL = `
CREATE INDEX IF NOT EXISTS idx_runs_project_started_at ON runs(project_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_suppressions_expires_at ON suppressions(expires_at);
CREATE INDEX IF NOT EXISTS idx_triage_updated_at ON triage(updated_at DESC);
`

const schemaCampaignIndexesSQL = `
CREATE INDEX IF NOT EXISTS idx_campaigns_project_id ON campaigns(project_id);
`

const schemaDropIndexesSQL = `
DROP INDEX IF EXISTS idx_runs_project_started_at;
DROP INDEX IF EXISTS idx_findings_scan_id;
DROP INDEX IF EXISTS idx_findings_severity;
DROP INDEX IF EXISTS idx_suppressions_expires_at;
DROP INDEX IF EXISTS idx_triage_updated_at;
`

const schemaDropTablesSQL = `
DROP TABLE IF EXISTS triage;
DROP TABLE IF EXISTS suppressions;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS runs;
DROP TABLE IF EXISTS projects;
DROP TABLE IF EXISTS campaigns;
`

const schemaCampaignDropIndexesSQL = `
DROP INDEX IF EXISTS idx_campaigns_project_id;
`

const schemaCampaignDropTablesSQL = `
DROP TABLE IF EXISTS campaigns;
`
