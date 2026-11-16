// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// holdAuditWriteLock takes the write lock of the store at path on a
// connection of its own and returns the release.
func holdAuditWriteLock(t *testing.T, path string) func() {
	t.Helper()
	contender, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(0)")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := contender.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(t.Context(), `BEGIN IMMEDIATE`); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
			_ = conn.Close()
			_ = contender.Close()
		})
	}
	t.Cleanup(release)
	return release
}

// rel-1-0-4 GAP-1790 (T11, managed RHEL, 2.97 GB store, cold start): the
// journal row of a benign managed call met SQLITE_BUSY while the store pool
// connection held the write lock past the 0.75 s busy timeout, the gateway
// answered 503 and the hook denied the call about 1.2 s into its 3.5 s budget.
// A busy journal write now waits for the lock within its bound, and the row
// lands once the lock is free.
func TestHookDeliveryJournalWaitsOutABusyStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	store := openTestStore(t, path)
	ctx := t.Context()
	// Create the journal table first, so the insert below is the statement
	// that meets the held lock.
	if err := store.JournalHookDelivery(ctx, "warm", "p", []byte(`{}`), journalRows(10)); err != nil {
		t.Fatal(err)
	}

	release := holdAuditWriteLock(t, path)
	const held = 1200 * time.Millisecond // past the 750 ms busy timeout
	timer := time.AfterFunc(held, release)
	defer timer.Stop()

	started := time.Now()
	if err := store.JournalHookDelivery(ctx, "busy", "p", []byte(`{"ID":"busy"}`), journalRows(10)); err != nil {
		t.Fatalf("journal write while the lock was held %v (then freed) = %v after %v; want the row once the lock is free",
			held, err, time.Since(started).Round(time.Millisecond))
	}
	if waited := time.Since(started); waited < held-100*time.Millisecond {
		t.Fatalf("journal write returned after %v, before the lock was freed at %v", waited, held)
	}
	entry, found, err := store.HookDelivery(ctx, "busy")
	if err != nil || !found || string(entry.Occurrence) != `{"ID":"busy"}` {
		t.Fatalf("journal row after the busy wait = %+v, %t, %v; want it stored once", entry, found, err)
	}
	if found, err := store.UpdateHookDelivery(ctx, "busy", []byte(`{"ID":"busy","v":2}`), journalRows(10)); err != nil || !found {
		t.Fatalf("update after the busy wait = %t, %v", found, err)
	}
}

// The retry is bounded: a lock that is never freed fails the write with the
// busy error once the wait ends, and a cancelled call stops at once.
func TestHookDeliveryJournalBusyWaitIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	store := openTestStore(t, path)
	if err := store.JournalHookDelivery(t.Context(), "warm", "p", []byte(`{}`), journalRows(10)); err != nil {
		t.Fatal(err)
	}
	wait := hookDeliveryJournalBusyWait
	hookDeliveryJournalBusyWait = 300 * time.Millisecond
	t.Cleanup(func() { hookDeliveryJournalBusyWait = wait })
	holdAuditWriteLock(t, path)

	started := time.Now()
	err := store.JournalHookDelivery(t.Context(), "stuck", "p", []byte(`{}`), journalRows(10))
	if !isSQLiteBusy(err) {
		t.Fatalf("journal write under a lock never freed = %v; want SQLITE_BUSY", err)
	}
	if took := time.Since(started); took > hookDeliveryJournalBusyWait+2*time.Second {
		t.Fatalf("journal write under a lock never freed took %v; want about the %v bound plus one busy timeout",
			took, hookDeliveryJournalBusyWait)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	started = time.Now()
	if err := store.JournalHookDelivery(ctx, "cancelled", "p", []byte(`{}`), journalRows(10)); err == nil {
		t.Fatal("a cancelled journal write landed under a held lock")
	}
	if took := time.Since(started); took > time.Second {
		t.Fatalf("a cancelled journal write took %v", took)
	}
}
