// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"time"
)

// durableBatchObserved is a test seam: it sees the size of every batch the
// durable connection commits.
var durableBatchObserved func(store *Store, size int)

// durableDirSyncError marks a failure to flush the database folder after a
// batch committed; the callers add their own context to it.
type durableDirSyncError struct{ err error }

func (e *durableDirSyncError) Error() string {
	return "flush the audit database folder: " + e.err.Error()
}
func (e *durableDirSyncError) Unwrap() error { return e.err }

// durableGrouped runs run in a transaction on the store synchronous=FULL
// connection (auditDurablePragmas) and returns once it is committed to disk.
// Concurrent callers share one transaction, so they share one flush of the
// write-ahead log. Every commit on this connection costs a flush, and a
// managed sandbox call makes about five of them: the journal row, its
// decision, the fallback and the settlement of its receipt, and the flush
// that confirms the audit row. Each waited for the one before it, so one
// gateway could finish only about 30 of those calls a second however many
// cores or accounts it had, and the calls queued behind each other past their
// answer window (rel-1-0-6 GAP-0490). A write that arrives while a
// transaction runs joins the next, so a lone write runs as before, and each
// caller sees only its own error. dirSync asks for the database folder to be
// flushed once the batch has committed (a WAL file created since the store
// opened keeps its entry).
func (s *Store) durableGrouped(ctx context.Context, dirSync bool, run func(context.Context, *sql.Tx) error) error {
	return s.durableGroup.do(&groupedWrite{ctx: ctx, data: dirSync, run: run}, s.runDurableBatch)
}

func (s *Store) runDurableBatch(batch []*groupedWrite) {
	if durableBatchObserved != nil {
		durableBatchObserved(s, len(batch))
	}
	db, err := s.durableConn()
	if err != nil {
		for _, item := range batch {
			item.err = err
		}
		return
	}
	live := make([]*groupedWrite, 0, len(batch))
	for _, item := range batch {
		item.err = nil
		if ctxErr := item.ctx.Err(); ctxErr != nil {
			item.err = ctxErr
			continue
		}
		live = append(live, item)
	}
	if len(live) == 0 {
		return
	}
	// A shared transaction ends only when every caller in it has given up:
	// an interrupted statement would roll back the rows of the others.
	ctx := live[0].ctx
	if len(live) > 1 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(context.WithoutCancel(live[0].ctx))
		defer cancel()
		var remaining atomic.Int64
		remaining.Store(int64(len(live)))
		for _, item := range live {
			defer context.AfterFunc(item.ctx, func() {
				if remaining.Add(-1) == 0 {
					cancel()
				}
			})()
		}
	}
	failed, err := commitDurableBatch(ctx, db, live)
	switch {
	case err == nil:
	case failed != nil && len(live) > 1 && !isSQLiteBusy(err):
		// One write failed on its own account: run each alone, so the
		// others commit and every caller sees its own outcome.
		for _, item := range live {
			_, item.err = commitDurableBatch(item.ctx, db, []*groupedWrite{item})
		}
	default:
		for _, item := range live {
			item.err = err
		}
		return
	}
	flush := false
	for _, item := range live {
		flush = flush || item.err == nil && item.data.(bool)
	}
	if !flush {
		return
	}
	if dirErr := syncAuditDBDir(filepath.Dir(s.dbPath)); dirErr != nil {
		for _, item := range live {
			if item.err == nil && item.data.(bool) {
				item.err = &durableDirSyncError{err: dirErr}
			}
		}
	}
}

// commitDurableBatch runs the writes of items in one transaction, and again
// while the store answers SQLITE_BUSY (hookDeliveryJournalBusyWait). When a
// write fails it returns that write with its error.
func commitDurableBatch(ctx context.Context, db *sql.DB, items []*groupedWrite) (*groupedWrite, error) {
	deadline := time.Now().Add(hookDeliveryJournalBusyWait)
	pause := 10 * time.Millisecond
	for {
		failed, err := attemptDurableBatch(ctx, db, items)
		if err == nil || !isSQLiteBusy(err) || ctx.Err() != nil || !time.Now().Add(pause).Before(deadline) {
			return failed, err
		}
		timer := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			timer.Stop()
			return failed, err
		case <-timer.C:
		}
		pause = min(2*pause, hookDeliveryJournalBusyPause)
	}
}

func attemptDurableBatch(ctx context.Context, db *sql.DB, items []*groupedWrite) (*groupedWrite, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		if err := item.run(ctx, tx); err != nil {
			_ = tx.Rollback()
			return item, err
		}
	}
	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("commit: %w", err)
	}
	return nil, nil
}
