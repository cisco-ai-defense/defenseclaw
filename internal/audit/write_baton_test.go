// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// One holder at a time, and a waiter leaves with its context (rel-1-0-6
// GAP-0490).
func TestWriteBatonHasOneHolder(t *testing.T) {
	var baton writeBaton
	var holders atomic.Int32
	var overlapped atomic.Bool
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := baton.acquire(t.Context())
			if err != nil {
				t.Error(err)
				return
			}
			defer release()
			if holders.Add(1) > 1 {
				overlapped.Store(true)
			}
			time.Sleep(200 * time.Microsecond)
			holders.Add(-1)
		}()
	}
	wg.Wait()
	if overlapped.Load() {
		t.Fatal("two holders had the baton together")
	}
}

func TestWriteBatonWaiterLeavesWithItsContext(t *testing.T) {
	var baton writeBaton
	release, err := baton.acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, err := baton.acquire(ctx); err == nil {
		t.Fatal("a waiter got the baton while it was held")
	}
	release()
	again, err := baton.acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	again()
}

func batonHeld(t *testing.T, store *Store) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	release, err := store.writeBaton.acquire(ctx)
	if err == nil {
		release()
	}
	return err != nil
}

// A correlation occurrence reads before it writes, so it holds the baton
// from its begin to its commit or rollback: no other writer of the process
// commits between its read and its write.
func TestCorrelationOccurrenceHoldsTheWriteBaton(t *testing.T) {
	for _, finish := range []string{"commit", "rollback"} {
		t.Run(finish, func(t *testing.T) {
			store, repo := newCorrelationTestStore(t)
			instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyExternal)
			event := receiptAcceptanceEvent(t, instance, CorrelationRailHook, "model_end", time.Now().UTC())
			tx, _, err := repo.BeginOccurrence(t.Context(), CorrelationOccurrenceInput{Event: event})
			if err != nil {
				t.Fatal(err)
			}
			if !batonHeld(t, store) {
				t.Fatal("an open occurrence does not hold the write baton")
			}
			if finish == "commit" {
				err = tx.Commit()
			} else {
				err = tx.Rollback()
			}
			if err != nil {
				t.Fatal(err)
			}
			if batonHeld(t, store) {
				t.Fatal("a finished occurrence still holds the write baton")
			}
		})
	}
}

// The grouped pool transaction and the durable batch wait for the baton, and
// run once it is free.
func TestGroupedAndDurableWritesWaitForTheWriteBaton(t *testing.T) {
	store, _ := newCorrelationTestStore(t)
	release, err := store.writeBaton.acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var ran atomic.Int32
	write := func(ctx context.Context, group func(context.Context, func(context.Context, *sql.Tx) error) error) error {
		return group(ctx, func(ctx context.Context, tx *sql.Tx) error {
			ran.Add(1)
			_, err := tx.ExecContext(ctx, `SELECT 1`)
			return err
		})
	}
	groups := map[string]func(context.Context, func(context.Context, *sql.Tx) error) error{
		"pool": store.callGroupWrite,
		"durable": func(ctx context.Context, run func(context.Context, *sql.Tx) error) error {
			return store.durableGrouped(ctx, false, run)
		},
	}
	for name, group := range groups {
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		err := write(ctx, group)
		cancel()
		if err == nil {
			t.Fatalf("%s write ran while the baton was held", name)
		}
	}
	if ran.Load() != 0 {
		t.Fatalf("%d writes ran while the baton was held", ran.Load())
	}
	release()
	for name, group := range groups {
		if err := write(t.Context(), group); err != nil {
			t.Fatalf("%s write after the baton was free: %v", name, err)
		}
	}
	if ran.Load() != int32(len(groups)) {
		t.Fatalf("%d writes ran, want %d", ran.Load(), len(groups))
	}
}

// The folder flush of a durable batch is made once for a write-ahead log
// file, again for a different file, and when the file cannot be read.
func TestDurableFolderFlushIsMadeOncePerWALFile(t *testing.T) {
	dir := t.TempDir()
	store := &Store{dbPath: filepath.Join(dir, "audit.db")}
	wal := store.dbPath + "-wal"
	var flushes int
	prior := auditDirSync
	auditDirSync = func(string) error { flushes++; return nil }
	t.Cleanup(func() { auditDirSync = prior })
	if err := os.WriteFile(wal, []byte("wal"), 0o600); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := store.syncDurableDir(); err != nil {
			t.Fatal(err)
		}
	}
	if flushes != 1 {
		t.Fatalf("%d folder flushes for one WAL file, want 1", flushes)
	}
	// A different file at the path (the new one exists before the old one
	// goes) is a new directory entry.
	next := wal + ".next"
	if err := os.WriteFile(next, []byte("wal"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, wal); err != nil {
		t.Fatal(err)
	}
	if err := store.syncDurableDir(); err != nil || flushes != 2 {
		t.Fatalf("a replaced WAL file: flushes %d err %v, want 2", flushes, err)
	}
	if err := os.Remove(wal); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := store.syncDurableDir(); err != nil {
			t.Fatal(err)
		}
	}
	if flushes != 4 {
		t.Fatalf("flushes %d without a WAL file, want every batch to flush (4)", flushes)
	}
	auditDirSync = func(string) error { return errors.New("disk") }
	if err := os.WriteFile(wal, []byte("wal"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.syncDurableDir(); err == nil {
		t.Fatal("a failed folder flush was reported as done")
	}
	auditDirSync = func(string) error { flushes++; return nil }
	if err := store.syncDurableDir(); err != nil || flushes != 5 {
		t.Fatalf("after a failed flush: flushes %d err %v, want the flush retried (5)", flushes, err)
	}
}
