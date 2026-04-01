package store

import (
	"database/sql"
	"fmt"
)

func (s *StateStore) IntegrityCheck() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`PRAGMA integrity_check;`)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	results := make([]string, 0, 4)
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return nil, err
		}
		results = append(results, line)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("integrity_check returned no rows")
	}

	fkRows, err := s.db.Query(`PRAGMA foreign_key_check;`)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = fkRows.Close()
	}()
	for fkRows.Next() {
		var (
			table string
			rowid sql.NullInt64
			ref   sql.NullString
			index sql.NullInt64
		)
		if err := fkRows.Scan(&table, &rowid, &ref, &index); err != nil {
			return nil, err
		}
		results = append(results, fmt.Sprintf("foreign_key_check:%s:%d:%s:%d", table, rowid.Int64, ref.String, index.Int64))
	}
	if err := fkRows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

func (s *StateStore) Path() string {
	return s.path
}
