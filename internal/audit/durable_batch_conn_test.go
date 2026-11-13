// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// A writer connection whose NORMAL pragmas cannot be put back after a durable
// batch is dropped: the next writer connection runs the store pragmas
// (synchronous NORMAL, fullfsync off), never a leftover FULL or a NORMAL the
// durable path would take for FULL (S8 lead review P2-2).
func TestDurableBatchRestoreFailureDropsTheConnection(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "audit.db"))
	before := durableRestoreFailures.Load()
	durableRestoreFault = func(pragma string) error {
		if pragma == "PRAGMA synchronous = NORMAL" {
			return errors.New("restore refused")
		}
		return nil
	}
	t.Cleanup(func() { durableRestoreFault = nil })
	conn, err := store.durableBatchConn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	conn.restore()
	durableRestoreFault = nil
	if got := durableRestoreFailures.Load() - before; got != 1 {
		t.Fatalf("restore failures counted %d, want 1", got)
	}
	for name, want := range map[string]int64{"synchronous": 1, "fullfsync": 0} {
		var got int64
		if err := store.db.QueryRow("PRAGMA " + name).Scan(&got); err != nil || got != want {
			t.Fatalf("next writer connection PRAGMA %s = %d (%v), want %d", name, got, err, want)
		}
	}
}

// A batch of the hook-call write group that carries a durable write (the hook
// journal row) runs on synchronous=FULL, with the ordinary writes that ride in
// it, and the writer is back on NORMAL after it.
func TestHookCallBatchWithAJournalRowCommitsFull(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "audit.db"))
	ctx := t.Context()
	synchronous := func(ctx context.Context, tx *sql.Tx) (int64, error) {
		var got int64
		err := tx.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&got)
		return got, err
	}
	// Hold the baton so the first write leads a batch of its own, and the
	// next two queue together behind it.
	release, err := store.writeBaton.acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		sync int64
		err  error
	}
	first, ordinary, durable := make(chan result, 1), make(chan result, 1), make(chan result, 1)
	go func() {
		var got int64
		err := store.callGroupWrite(ctx, func(ctx context.Context, tx *sql.Tx) (err error) {
			got, err = synchronous(ctx, tx)
			return err
		})
		first <- result{got, err}
	}()
	waitDepth := func(n int64) {
		deadline := time.Now().Add(5 * time.Second)
		for store.callGroup.snapshot(time.Now()).Depth < n {
			if time.Now().After(deadline) {
				t.Fatalf("queue depth never reached %d", n)
			}
			time.Sleep(time.Millisecond)
		}
	}
	// The leader took its write out of the queue and waits for the baton.
	for {
		store.callGroup.mu.Lock()
		active := store.callGroup.active
		store.callGroup.mu.Unlock()
		if active {
			break
		}
		time.Sleep(time.Millisecond)
	}
	go func() {
		var got int64
		err := store.callGroupWrite(ctx, func(ctx context.Context, tx *sql.Tx) (err error) {
			got, err = synchronous(ctx, tx)
			return err
		})
		ordinary <- result{got, err}
	}()
	waitDepth(1)
	go func() {
		var got int64
		err := store.durableGrouped(ctx, false, func(ctx context.Context, tx *sql.Tx) (err error) {
			got, err = synchronous(ctx, tx)
			return err
		})
		durable <- result{got, err}
	}()
	waitDepth(2)
	release()
	if r := <-first; r.err != nil || r.sync != 1 {
		t.Fatalf("ordinary batch synchronous = %d (%v), want 1 (NORMAL)", r.sync, r.err)
	}
	if r := <-ordinary; r.err != nil || r.sync != 2 {
		t.Fatalf("ordinary write beside a journal row synchronous = %d (%v), want 2 (FULL)", r.sync, r.err)
	}
	if r := <-durable; r.err != nil || r.sync != 2 {
		t.Fatalf("journal row synchronous = %d (%v), want 2 (FULL)", r.sync, r.err)
	}
	var after int64
	if err := store.db.QueryRow("PRAGMA synchronous").Scan(&after); err != nil || after != 1 {
		t.Fatalf("writer after the durable batch synchronous = %d (%v), want 1", after, err)
	}
}
