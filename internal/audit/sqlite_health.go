// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"os"
	"time"
)

// SQLiteHealthSnapshot is a point-in-time, content-free view of the mandatory
// audit store. Paths and database errors are deliberately not part of the value
// so callers cannot accidentally turn local storage identity into telemetry.
type SQLiteHealthSnapshot struct {
	DBSizeBytes   int64
	WALSizeBytes  int64
	PageCount     int64
	FreelistCount int64
	CheckpointMs  float64
}

// CollectSQLiteHealth snapshots the already-open mandatory store while pinning
// it against Close. The caller decides whether and where to export the values;
// Store owns no global telemetry registration or background goroutine.
func (s *Store) CollectSQLiteHealth(ctx context.Context) (SQLiteHealthSnapshot, error) {
	if ctx == nil {
		return SQLiteHealthSnapshot{}, fmt.Errorf("audit: SQLite health context is required")
	}
	release, err := s.acquireReady()
	if err != nil {
		return SQLiteHealthSnapshot{}, err
	}
	defer release()

	var snapshot SQLiteHealthSnapshot
	if stat, statErr := os.Stat(s.dbPath); statErr == nil {
		snapshot.DBSizeBytes = stat.Size()
	} else if !os.IsNotExist(statErr) {
		return SQLiteHealthSnapshot{}, fmt.Errorf("audit: inspect SQLite database health: %w", statErr)
	}
	if stat, statErr := os.Stat(s.dbPath + "-wal"); statErr == nil {
		snapshot.WALSizeBytes = stat.Size()
	} else if !os.IsNotExist(statErr) {
		return SQLiteHealthSnapshot{}, fmt.Errorf("audit: inspect SQLite WAL health: %w", statErr)
	}
	if err := s.db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&snapshot.PageCount); err != nil {
		return SQLiteHealthSnapshot{}, fmt.Errorf("audit: read SQLite page count: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&snapshot.FreelistCount); err != nil {
		return SQLiteHealthSnapshot{}, fmt.Errorf("audit: read SQLite freelist count: %w", err)
	}
	startedAt := time.Now()
	if _, err := s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)"); err != nil {
		return SQLiteHealthSnapshot{}, fmt.Errorf("audit: checkpoint SQLite health: %w", err)
	}
	snapshot.CheckpointMs = float64(time.Since(startedAt).Milliseconds())
	return snapshot, nil
}
