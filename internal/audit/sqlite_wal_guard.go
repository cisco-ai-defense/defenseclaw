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
// The final restart checkpoint runs on the store's single writer connection,
// so it takes its turn between statements: no other connection writes
// meanwhile and the writer finds the log fully copied afterwards. A TRUNCATE
// or RESTART checkpoint from the second connection waits for readers while holding off
// the writer, and under load it stalled some appends for seconds. The pause is
// bounded by the frames written since the second connection's copy. The
// frames in use come from a PASSIVE checkpoint on the dedicated connection,
// not from the file size: a restarted log keeps its length on disk. SQLite
// treats an unknown checkpoint mode such as NOOP as PASSIVE, so using NOOP
// on the single writer connection copies and syncs the WAL there.
func (s *Store) CheckpointWALIfLarge(ctx context.Context, limitBytes int64) (bool, error) {
	if ctx == nil {
		return false, fmt.Errorf("audit: WAL checkpoint context is required")
	}
	release, err := s.acquireReady()
	if err != nil {
		return false, err
	}
	defer release()
	db, err := s.checkpointConn()
	if err != nil {
		return false, fmt.Errorf("audit: open SQLite checkpoint connection: %w", err)
	}
	var busy, frames, copied int
	if err := db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)").Scan(&busy, &frames, &copied); err != nil {
		return false, fmt.Errorf("audit: read SQLite WAL length: %w", err)
	}
	if int64(frames)*walFrameBytes <= limitBytes {
		return false, nil
	}
	// The dedicated connection copied the bulk above without holding off the
	// writer. The writer connection only has frames written meanwhile left to
	// copy, which lets it restart the log without a long pause.
	if err := s.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)").Scan(&busy, &frames, &copied); err != nil {
		return false, fmt.Errorf("audit: checkpoint SQLite WAL: %w", err)
	}
	return busy == 0, nil
}
