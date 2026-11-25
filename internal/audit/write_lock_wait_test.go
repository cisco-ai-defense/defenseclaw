// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"fmt"
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

// GAP-1108: the busy timeout of a held lock is set in the background
// (setWriteLockHeld), and the call that met the hold goes straight on to its
// next write. With one P or a loaded host that write took the connection
// before the background apply and waited out the full busy timeout under the
// held lock: the first locked hook call answered after about 1.1 s. The test
// parks the background apply, as such a host does, and needs both an
// autocommit write and a grouped write (the call's batch) to fail at once.
func TestHeldWriteLockWriteBeforeTheBackgroundApplyFailsAtOnce(t *testing.T) {
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
	// The connection has its full busy timeout (a new pool connection, or
	// the first write of the hold) and the hold is known, but its background
	// apply has not run.
	parkApply := func() {
		if _, err := store.db.ExecContext(ctx, fmt.Sprintf("PRAGMA busy_timeout = %d", auditBusyTimeoutMillis)); err != nil {
			t.Fatal(err)
		}
		store.lockWait.mu.Lock()
		store.lockWait.held, store.lockWait.applied, store.lockWait.applying = true, -1, true
		store.lockWait.firstBusy = time.Now()
		store.lockWait.mu.Unlock()
	}
	// Well under one busy wait (auditBusyTimeoutMillis).
	const bound = writeLockHeldAfter
	grouped := func() error {
		return store.runGroupedTx([]*groupedWrite{{ctx: ctx, run: func(ctx context.Context, tx *sql.Tx) error {
			_, err := store.txExecPrepared(ctx, tx, "lock_test", `INSERT INTO lock_probe VALUES (2)`)
			return err
		}}}, groupedTxHooks{
			op:     "lock_test",
			begin:  func(err error) error { return err },
			commit: func(_ context.Context, tx *sql.Tx, _ []*groupedWrite) error { return tx.Commit() },
		})
	}
	for _, write := range []struct {
		name string
		run  func() error
	}{
		{"autocommit", func() error {
			_, err := store.execDB(ctx, "lock_test", `INSERT INTO lock_probe VALUES (1)`)
			return err
		}},
		{"grouped", grouped},
	} {
		parkApply()
		started := time.Now()
		err := write.run()
		took := time.Since(started)
		if !isSQLiteBusy(err) {
			t.Fatalf("%s write under the held lock: %v, want busy", write.name, err)
		}
		if took > bound {
			t.Errorf("%s write under the held lock waited %v before the background apply landed (bound %v)", write.name, took, bound)
		}
	}
	store.lockWait.mu.Lock()
	store.lockWait.applying = false
	store.lockWait.mu.Unlock()
	if _, err := conn.ExecContext(ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	if err := grouped(); err != nil {
		t.Fatalf("grouped write after the release: %v", err)
	}
	if store.writeLockHeld() {
		t.Fatal("a committed write did not end the hold")
	}
	waitBusyTimeout(t, store, auditBusyTimeoutMillis)
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
