// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
)

// walFrameBytes is the size of one WAL frame at the default 4096-byte page:
// the page plus the 24-byte frame header.
const walFrameBytes = 4096 + 24

// CheckpointWALIfLarge copies the write-ahead log into the database once it
// holds more than limitBytes of frames and reports whether it did, so the
// next write restarts the log from its start instead of appending to it.
//
// The store runs with wal_autocheckpoint=0 and its periodic PASSIVE checkpoint
// (CollectSQLiteHealth) runs on a second connection, so it cannot restart the
// log while hooks keep writing: SQLite restarts a log only when a writer finds
// every frame already copied, and a busy gateway commits new frames before
// that checkpoint finishes. The log then grew with every audit row (about
// 3.4 MB per hook decision, 5 GB after 1,500 hooks) until the load stopped.
//
// The checkpoint here runs on the store's single writer connection, so it
// takes its turn between statements: no other connection writes meanwhile and
// the writer finds the log fully copied afterwards. A TRUNCATE or RESTART
// checkpoint from the second connection waits for readers while holding off
// the writer, and under load it stalled some appends for seconds. The pause is
// bounded by the frames written since the second connection's copy. The
// frames in use come from a NOOP checkpoint, not from the file size: a
// restarted log keeps its length on disk.
func (s *Store) CheckpointWALIfLarge(ctx context.Context, limitBytes int64) (bool, error) {
	if ctx == nil {
		return false, fmt.Errorf("audit: WAL checkpoint context is required")
	}
	release, err := s.acquireReady()
	if err != nil {
		return false, err
	}
	defer release()
	var busy, frames, copied int
	if err := s.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(NOOP)").Scan(&busy, &frames, &copied); err != nil {
		return false, fmt.Errorf("audit: read SQLite WAL length: %w", err)
	}
	if int64(frames)*walFrameBytes <= limitBytes {
		return false, nil
	}
	// Copy the bulk from the second connection first: it does not hold off the
	// writer. The writer connection then only has the frames written meanwhile
	// left to copy, which keeps the pause short.
	if db, err := s.checkpointConn(); err == nil {
		_ = db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)").Scan(&busy, &frames, &copied)
	}
	if err := s.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)").Scan(&busy, &frames, &copied); err != nil {
		return false, fmt.Errorf("audit: checkpoint SQLite WAL: %w", err)
	}
	return busy == 0, nil
}
