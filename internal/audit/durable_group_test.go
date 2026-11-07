// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// holdFirstDurableBatch makes the first batch of store wait until release is
// closed, and records the size of every batch of store. Writes that arrive
// meanwhile queue behind it, so the next batch is exactly those writes.
func holdFirstDurableBatch(t *testing.T, store *Store) (release func(), entered <-chan struct{}, sizes func() []int) {
	t.Helper()
	var mu sync.Mutex
	var seen []int
	gate, first := make(chan struct{}), make(chan struct{})
	var once sync.Once
	durableBatchObserved = func(s *Store, size int) {
		if s != store {
			return
		}
		mu.Lock()
		seen = append(seen, size)
		mu.Unlock()
		once.Do(func() {
			close(first)
			<-gate
		})
	}
	t.Cleanup(func() { durableBatchObserved = nil })
	var closeOnce sync.Once
	return func() { closeOnce.Do(func() { close(gate) }) }, first, func() []int {
		mu.Lock()
		defer mu.Unlock()
		return append([]int(nil), seen...)
	}
}

func waitDurableQueue(t *testing.T, store *Store, depth int64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for store.durableGroup.snapshot(time.Now()).Depth < depth {
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d writes queued", store.durableGroup.snapshot(time.Now()).Depth, depth)
		}
		time.Sleep(time.Millisecond)
	}
}

// Concurrent durable writes (journal rows, their decisions and the flush that
// confirms an audit row) commit in one transaction: the writes queued while
// one commit runs share the next, and every caller sees its own outcome
// (rel-1-0-6 GAP-0490). A lone write is a batch of one.
func TestDurableWritesShareOneCommit(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "audit.db"))
	ctx := t.Context()
	limits := journalRows(1000)
	release, entered, sizes := holdFirstDurableBatch(t, store)

	const writers = 24
	errs := make(chan error, writers)
	write := func(i int) {
		id := fmt.Sprintf("share-%02d", i)
		err := store.JournalHookDelivery(ctx, id, "proc", []byte(`{"n":1}`), limits)
		errs <- err
	}
	go write(0)
	<-entered
	for i := 1; i < writers-1; i++ {
		go write(i)
	}
	// A flush-only caller rides the same batch.
	go func() { errs <- store.SyncCommittedWrites(ctx) }()
	waitDurableQueue(t, store, writers-1)
	release()
	for i := 0; i < writers; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("durable write failed: %v", err)
		}
	}
	if got := sizes(); len(got) != 2 || got[0] != 1 || got[1] != writers-1 {
		t.Fatalf("batch sizes = %v, want [1 %d]", got, writers-1)
	}
	if ids := journalIDs(t, store, 100); len(ids) != writers-1 {
		t.Fatalf("journal has %d rows, want %d", len(ids), writers-1)
	}
	// The decision of each row commits through the same path.
	found, err := store.UpdateHookDelivery(ctx, "share-03", []byte(`{"n":2}`), limits)
	if err != nil || !found {
		t.Fatalf("update = %t, %v; want the row updated", found, err)
	}
	entry, ok, err := store.HookDelivery(ctx, "share-03")
	if err != nil || !ok || string(entry.Occurrence) != `{"n":2}` {
		t.Fatalf("row = %q, %t, %v; want the updated occurrence", entry.Occurrence, ok, err)
	}
}

// A write that fails does not fail the writes that share its transaction.
func TestDurableWriteFailureStaysWithItsCaller(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "audit.db"))
	ctx := t.Context()
	limits := journalRows(1000)
	if err := store.JournalHookDelivery(ctx, "seed", "proc", []byte(`{}`), limits); err != nil {
		t.Fatal(err)
	}
	release, entered, sizes := holdFirstDurableBatch(t, store)

	boom := errors.New("refused by the writer")
	results := make(chan error, 8)
	go func() { results <- store.SyncCommittedWrites(ctx) }()
	<-entered
	failing := make(chan error, 1)
	go func() {
		failing <- store.durableGrouped(ctx, false, func(context.Context, *sql.Tx) error { return boom })
	}()
	for i := 0; i < 5; i++ {
		go func() {
			err := store.JournalHookDelivery(ctx, fmt.Sprintf("kept-%d", i), "proc", []byte(`{}`), limits)
			results <- err
		}()
	}
	waitDurableQueue(t, store, 6)
	release()
	if err := <-failing; !errors.Is(err, boom) {
		t.Fatalf("failing write = %v, want its own error", err)
	}
	for i := 0; i < 6; i++ {
		if err := <-results; err != nil {
			t.Fatalf("a neighboring write failed with %v", err)
		}
	}
	if got := sizes(); len(got) != 2 || got[1] != 6 {
		t.Fatalf("batch sizes = %v, want the failing write and five others in one batch", got)
	}
	if ids := journalIDs(t, store, 100); len(ids) != 6 {
		t.Fatalf("journal has %d rows, want the seed and five others", len(ids))
	}
}
