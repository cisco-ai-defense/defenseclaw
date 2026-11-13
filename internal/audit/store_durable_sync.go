// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

// secureClientAuditDurablePragmas are the Secure Client audit pragmas with
// synchronous=FULL and fullfsync on, for the durable connection only a
// Secure Client store opens. The pool runs synchronous=NORMAL: a WAL commit
// is on disk only after the next checkpoint, so a power loss can take back
// the last commits. On the durable connection SQLite flushes the whole WAL at
// every commit (with F_FULLFSYNC on macOS), which makes every commit before
// it durable too. Other stores commit their durable writes on the writer
// connection with the same two pragmas set for the batch (durableBatchConn).
var secureClientAuditDurablePragmas = buildAuditDurablePragmas(secureClientAuditPragmas)

func buildAuditDurablePragmas(pragmas string) string {
	const normal, full = "&_pragma=synchronous(NORMAL)", "&_pragma=synchronous(FULL)"
	if strings.Count(pragmas, normal) != 1 {
		panic("audit: the audit pragmas do not set synchronous=NORMAL once")
	}
	return strings.Replace(pragmas, normal, full, 1) + "&_pragma=fullfsync(1)"
}

// SyncCommittedWrites makes every audit write committed before the call
// survive a power loss: it commits one readiness write with synchronous=FULL
// (durableGrouped), then flushes the database folder so a
// WAL file created since the store opened keeps its entry. A producer that
// marks an occurrence reported once it is stored (a trust anchor or
// credential change event) calls it first, so the marker never outlives
// the row, and so does the runtime before it sends a record held for its
// local write (observability.RemoteExportAfterLocalWrite). An in-memory
// store has nothing to flush.
func (s *Store) SyncCommittedWrites(ctx context.Context) error {
	if s == nil || s.db == nil || s.dbPathGuard == nil || s.dbPathGuard.inMemory {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	release, err := s.acquireReady()
	if err != nil {
		return err
	}
	// The hook-call write group takes the store lifecycle lock in its own
	// batch runner; holding it here too would nest the read lock under a
	// waiting Close (durableQueue).
	defer s.releaseUnlessGrouped(release)()
	// Concurrent callers share one commit, and so one flush (durableGrouped):
	// the flush of a commit covers every write committed before it.
	invalid := false
	err = s.durableGrouped(ctx, true, func(ctx context.Context, tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `
			UPDATE observability_store_readiness
			SET verification_generation = verification_generation + 1,
				last_verified_at = ?
			WHERE id = 1`, time.Now().UTC().Format(time.RFC3339Nano))
		if err != nil {
			return err
		}
		if changed, err := result.RowsAffected(); err != nil || changed != 1 {
			invalid = true
			return errors.New("the readiness state is invalid")
		}
		return nil
	})
	var dirErr *durableDirSyncError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &dirErr):
		return fmt.Errorf("audit: %w", err)
	case invalid:
		return errors.New("audit: flush committed audit writes to disk: the readiness state is invalid")
	}
	return fmt.Errorf("audit: flush committed audit writes to disk: %w", err)
}

// durableConn returns the store's synchronous=FULL connection, opened on
// first use like the checkpoint connection and closed with the store.
func (s *Store) durableConn() (*sql.DB, error) {
	s.checkpointMu.Lock()
	defer s.checkpointMu.Unlock()
	if s.durableDB != nil {
		return s.durableDB, nil
	}
	if !s.secureClientSchema {
		// Durable writes of other stores ride the writer connection
		// (durableQueue, durableBatchConn): there is no second connection.
		return nil, errors.New("audit: only a Secure Client store opens a durable connection")
	}
	db, err := openSQLiteWithPragmas(s.dbPath, secureClientAuditDurablePragmas)
	if err != nil {
		return nil, fmt.Errorf("audit: open SQLite durable connection: %w", err)
	}
	// sql.Open is lazy. Force the open, then repeat the path guard's
	// post-open checks so the cached pool is bound to the validated file.
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("audit: verify SQLite durable connection: %w", err)
	}
	if err := revalidateHardenedAuditSQLite(s.dbPathGuard); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("audit: revalidate database paths for durable connection: %w", err)
	}
	s.durableDB = db
	return db, nil
}

// syncAuditDBDir flushes dir (fsync on POSIX; Windows journals the
// directory, and a directory handle cannot be flushed there).
func syncAuditDBDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
