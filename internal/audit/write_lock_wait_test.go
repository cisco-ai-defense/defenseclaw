// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type countingBusyObserver struct{ calls atomic.Int64 }

func (o *countingBusyObserver) RecordSQLiteBusyMetric(context.Context, string) error {
	o.calls.Add(1)
	return nil
}

// GAP-1021: a write lock another process holds costs one busy wait, not one
// per statement: later writes fail at once, and the first write after the
// release commits and gives the connection its busy timeout back.
func TestHeldWriteLockFailsLaterWritesAtOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	store.BindSQLiteBusyObservabilityV8(&countingBusyObserver{})
	ctx := context.Background()
	if _, err := store.execDB(ctx, "lock_test", `CREATE TABLE lock_probe (v INTEGER)`); err != nil {
		t.Fatal(err)
	}
	other, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	conn, err := other.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := store.execDB(ctx, "lock_test", `INSERT INTO lock_probe VALUES (1)`); !isSQLiteBusy(err) {
		t.Fatalf("first write under the lock: %v, want busy", err)
	}
	if took := time.Since(started); took > 2*time.Duration(auditBusyTimeoutMillis)*time.Millisecond {
		t.Fatalf("first write waited %v; one busy wait is %d ms", took, auditBusyTimeoutMillis)
	}
	if !store.writeLockHeld() {
		t.Fatal("a whole busy wait did not mark the lock held")
	}
	// Callers that retry a whole transaction on transient contention
	// (IsSQLiteBusy) stop at a held lock.
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, heldErr := store.txExecPrepared(ctx, tx, "lock_test", `INSERT INTO lock_probe VALUES (4)`)
	_ = tx.Rollback()
	if !isSQLiteBusy(heldErr) || IsSQLiteBusy(heldErr) {
		t.Fatalf("busy error under a held lock = %v; want busy, not transient", heldErr)
	}
	waitBusyTimeout(t, store, 0)
	for i := 0; i < 5; i++ {
		started := time.Now()
		if _, err := store.execDB(ctx, "lock_test", `INSERT INTO lock_probe VALUES (2)`); !isSQLiteBusy(err) {
			t.Fatalf("write %d under the held lock: %v, want busy", i, err)
		}
		if took := time.Since(started); took > 100*time.Millisecond {
			t.Fatalf("write %d under the held lock waited %v", i, took)
		}
	}
	if _, err := conn.ExecContext(ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.execDB(ctx, "lock_test", `INSERT INTO lock_probe VALUES (3)`); err != nil {
		t.Fatalf("write after the release: %v", err)
	}
	if store.writeLockHeld() {
		t.Fatal("a committed write did not end the hold")
	}
	waitBusyTimeout(t, store, auditBusyTimeoutMillis)
	if err := store.verifyMandatoryPragmas(ctx); err != nil {
		t.Fatal(err)
	}
}

func waitBusyTimeout(t *testing.T, store *Store, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var got int
		if err := store.db.QueryRow(`PRAGMA busy_timeout`).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("busy_timeout = %d, want %d", got, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
