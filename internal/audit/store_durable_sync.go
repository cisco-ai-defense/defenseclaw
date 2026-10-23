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
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// auditDurablePragmas are the audit pragmas with synchronous=FULL and
// fullfsync on. The store's pool runs synchronous=NORMAL: a WAL commit is
// on disk only after the next checkpoint, so a power loss can take back the
// last commits. On the durable connection SQLite flushes the whole WAL at
// every commit (with F_FULLFSYNC on macOS), which makes every commit before
// it durable too.
var auditDurablePragmas = buildAuditDurablePragmas()

func buildAuditDurablePragmas() string {
	const normal, full = "&_pragma=synchronous(NORMAL)", "&_pragma=synchronous(FULL)"
	if strings.Count(auditPragmas, normal) != 1 {
		panic("audit: the audit pragmas do not set synchronous=NORMAL once")
	}
	return strings.Replace(auditPragmas, normal, full, 1) + "&_pragma=fullfsync(1)"
}

// SyncCommittedWrites makes every audit write committed before the call
// survive a power loss: it commits one readiness write on the durable
// connection (auditDurablePragmas), then flushes the database folder so a
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
	defer release()
	db, err := s.durableConn()
	if err != nil {
		return err
	}
	result, err := db.ExecContext(ctx, `
		UPDATE observability_store_readiness
		SET verification_generation = verification_generation + 1,
			last_verified_at = ?
		WHERE id = 1`, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("audit: flush committed audit writes to disk: %w", err)
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return errors.New("audit: flush committed audit writes to disk: the readiness state is invalid")
	}
	if err := syncAuditDBDir(filepath.Dir(s.dbPath)); err != nil {
		return fmt.Errorf("audit: flush the audit database folder: %w", err)
	}
	return nil
}

// durableConn returns the store's synchronous=FULL connection, opened on
// first use like the checkpoint connection and closed with the store.
func (s *Store) durableConn() (*sql.DB, error) {
	s.checkpointMu.Lock()
	defer s.checkpointMu.Unlock()
	if s.durableDB != nil {
		return s.durableDB, nil
	}
	db, err := openSQLiteWithPragmas(s.dbPath, auditDurablePragmas)
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
