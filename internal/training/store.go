// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package training

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite" // SQLite driver
)

// TraceEntry represents a captured trace for training data extraction.
type TraceEntry struct {
	ID               int64  `db:"id"`
	Timestamp        string `db:"timestamp"`
	Category         string `db:"category"`
	RecommendedModel string `db:"recommended_model"`
	Prompt           string `db:"prompt"`
	Response         string `db:"response"`
	ModelUsed        string `db:"model_used"`
	IsPromotedModel  bool   `db:"is_promoted_model"`
	LatencyMs        int64  `db:"latency_ms"`
	TokensIn         int    `db:"tokens_in"`
	TokensOut        int    `db:"tokens_out"`
	UsedForTraining  bool   `db:"used_for_training"`
	TrainingRunID    string `db:"training_run_id"`
}

// Store is a SQLite-backed trace store for continuous model improvement.
type Store struct {
	db *sql.DB
}

// NewStore opens a SQLite database at the given path and ensures the schema exists.
func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open training store: %w", err)
	}

	if err := createSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}

	return &Store{db: db}, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// createSchema ensures the training_traces table and index exist.
func createSchema(db *sql.DB) error {
	schema := `
CREATE TABLE IF NOT EXISTS training_traces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    category TEXT NOT NULL,
    recommended_model TEXT DEFAULT '',
    prompt TEXT NOT NULL,
    response TEXT NOT NULL,
    model_used TEXT NOT NULL,
    is_promoted_model BOOLEAN DEFAULT FALSE,
    latency_ms INTEGER DEFAULT 0,
    tokens_in INTEGER DEFAULT 0,
    tokens_out INTEGER DEFAULT 0,
    used_for_training BOOLEAN DEFAULT FALSE,
    training_run_id TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_category_unused
ON training_traces(category, used_for_training);
`
	_, err := db.Exec(schema)
	return err
}

// CaptureTrace inserts a new trace entry into the store.
func (s *Store) CaptureTrace(entry TraceEntry) error {
	query := `
INSERT INTO training_traces (
    timestamp, category, recommended_model, prompt, response,
    model_used, is_promoted_model, latency_ms, tokens_in, tokens_out,
    used_for_training, training_run_id
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`
	_, err := s.db.Exec(query,
		entry.Timestamp,
		entry.Category,
		entry.RecommendedModel,
		entry.Prompt,
		entry.Response,
		entry.ModelUsed,
		entry.IsPromotedModel,
		entry.LatencyMs,
		entry.TokensIn,
		entry.TokensOut,
		entry.UsedForTraining,
		entry.TrainingRunID,
	)
	if err != nil {
		return fmt.Errorf("insert trace: %w", err)
	}
	return nil
}

// CountByCategory returns the count of unused traces for the given category.
func (s *Store) CountByCategory(category string) (int, error) {
	var count int
	query := `
SELECT COUNT(*)
FROM training_traces
WHERE category = ? AND used_for_training = FALSE
`
	err := s.db.QueryRow(query, category).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count traces: %w", err)
	}
	return count, nil
}

// ExtractForTraining retrieves up to limit unused traces for the given category,
// ordered by timestamp DESC (newest first).
func (s *Store) ExtractForTraining(category string, limit int) ([]TraceEntry, error) {
	query := `
SELECT id, timestamp, category, recommended_model, prompt, response,
       model_used, is_promoted_model, latency_ms, tokens_in, tokens_out,
       used_for_training, training_run_id
FROM training_traces
WHERE category = ? AND used_for_training = FALSE
ORDER BY timestamp DESC
LIMIT ?
`
	rows, err := s.db.Query(query, category, limit)
	if err != nil {
		return nil, fmt.Errorf("query traces: %w", err)
	}
	defer rows.Close()

	var entries []TraceEntry
	for rows.Next() {
		var e TraceEntry
		err := rows.Scan(
			&e.ID,
			&e.Timestamp,
			&e.Category,
			&e.RecommendedModel,
			&e.Prompt,
			&e.Response,
			&e.ModelUsed,
			&e.IsPromotedModel,
			&e.LatencyMs,
			&e.TokensIn,
			&e.TokensOut,
			&e.UsedForTraining,
			&e.TrainingRunID,
		)
		if err != nil {
			return nil, fmt.Errorf("scan trace: %w", err)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate traces: %w", err)
	}
	return entries, nil
}

// MarkUsed marks the given trace IDs as used in a transaction.
func (s *Store) MarkUsed(ids []int64, runID string) error {
	if len(ids) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
UPDATE training_traces
SET used_for_training = TRUE, training_run_id = ?
WHERE id = ?
`)
	if err != nil {
		return fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, id := range ids {
		if _, err := stmt.Exec(runID, id); err != nil {
			return fmt.Errorf("update trace %d: %w", id, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}
