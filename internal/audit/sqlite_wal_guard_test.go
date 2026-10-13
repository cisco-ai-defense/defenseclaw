// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"math"
	"os"
	"testing"
	"time"
)

// The periodic size check must use the checkpoint connection even when the
// WAL is below the restart limit. A busy checkpoint must not hold the only
// audit writer connection needed by hook correlation and decision writes.
func TestCheckpointWALSizeCheckDoesNotHoldAuditWriter(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	if err := store.LogEvent(Event{Action: "hook_decision", Target: "before-checkpoint"}); err != nil {
		t.Fatal(err)
	}
	checkpointDB, err := store.checkpointConn()
	if err != nil {
		t.Fatal(err)
	}
	// Reserve the dedicated pool to simulate a slow in-progress checkpoint.
	tx, err := checkpointDB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	guardDone := make(chan error, 1)
	go func() {
		_, err := store.CheckpointWALIfLarge(t.Context(), math.MaxInt64)
		guardDone <- err
	}()
	select {
	case err := <-guardDone:
		t.Fatalf("WAL size check did not wait for checkpoint connection: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	appendDone := make(chan error, 1)
	go func() {
		appendDone <- store.LogEvent(Event{Action: "hook_decision", Target: "during-checkpoint"})
	}()
	select {
	case err := <-appendDone:
		if err != nil {
			t.Fatalf("hook audit append failed during checkpoint: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("hook audit append waited for checkpoint")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-guardDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("WAL size check did not finish after checkpoint connection was released")
	}
}

func TestCheckpointWALIfLargeRestartsTheLogOnlyWhenItIsLong(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	logEvents := func(n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if err := store.LogEvent(Event{Action: "hook_decision", Target: "wal-guard", Severity: "INFO", SessionID: "s"}); err != nil {
				t.Fatalf("LogEvent: %v", err)
			}
		}
	}
	logEvents(200)
	wal := store.dbPath + "-wal"
	info, err := os.Stat(wal)
	if err != nil || info.Size() < 1<<20 {
		t.Fatalf("WAL did not grow without a checkpoint: %v size=%v", err, info)
	}
	grown := info.Size()
	ctx := context.Background()
	if done, err := store.CheckpointWALIfLarge(ctx, grown+1); err != nil || done {
		t.Fatalf("below the limit: done=%v err=%v, want a no-op", done, err)
	}
	if done, err := store.CheckpointWALIfLarge(ctx, grown/2); err != nil || !done {
		t.Fatalf("over the limit: done=%v err=%v, want a checkpoint", done, err)
	}
	// The next writes reuse the log from its start: the file does not grow.
	logEvents(50)
	if info, err = os.Stat(wal); err != nil || info.Size() > grown {
		t.Fatalf("WAL grew from %d to %v after the checkpoint (err %v), want it reused", grown, info, err)
	}
	// The file keeps its length after a restart, so the length in use decides:
	// a limit between the frames in use and the file size does nothing.
	if done, err := store.CheckpointWALIfLarge(ctx, grown/2); err != nil || done {
		t.Fatalf("restarted log, file %d bytes: done=%v err=%v, want a no-op", grown, done, err)
	}
}
