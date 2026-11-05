// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// r108 SWEEP-100: a shared transaction first runs its writes without
// savepoints. A batch whose writes all succeed runs each write once, in that
// form, and commits them all.
func TestR108GroupedTxRunsItsWritesWithoutSavepointsFirst(t *testing.T) {
	store := newV8HistoryStore(t)
	ctx := context.Background()
	if _, err := store.db.ExecContext(ctx, `CREATE TABLE zz_direct_probe (id TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var runs []string
	write := func(id string) *groupedWrite {
		return &groupedWrite{ctx: ctx, run: func(ctx context.Context, tx *sql.Tx) error {
			mu.Lock()
			runs = append(runs, fmt.Sprintf("%s direct=%t", id, groupedWriteDirect(ctx)))
			mu.Unlock()
			_, err := tx.ExecContext(ctx, `INSERT INTO zz_direct_probe (id) VALUES (?)`, id)
			return err
		}}
	}
	batch := []*groupedWrite{write("a"), write("b"), write("c")}
	if err := store.runGroupedTx(batch, groupedTxHooks{
		op: "zz_direct_probe", begin: func(err error) error { return err },
		commit: func(_ context.Context, tx *sql.Tx, _ []*groupedWrite) error { return tx.Commit() },
	}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"a direct=true", "b direct=true", "c direct=true"}; fmt.Sprint(runs) != fmt.Sprint(want) {
		t.Fatalf("runs = %v, want %v", runs, want)
	}
	var stored int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM zz_direct_probe`).Scan(&stored); err != nil || stored != 3 {
		t.Fatalf("stored %d rows (%v), want 3", stored, err)
	}
}

// A write that fails in the savepoint-free attempt rolls the whole attempt
// back; the batch runs again with a savepoint per write, the failed write is
// its own, and the others are stored exactly once. The benign twin of the
// test above.
func TestR108GroupedTxFallsBackToSavepointsWhenAWriteFails(t *testing.T) {
	store := newV8HistoryStore(t)
	ctx := context.Background()
	if _, err := store.db.ExecContext(ctx, `CREATE TABLE zz_direct_probe (id TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	var runs []string
	insert := func(id string, fail bool) *groupedWrite {
		return &groupedWrite{ctx: ctx, run: func(ctx context.Context, tx *sql.Tx) error {
			runs = append(runs, fmt.Sprintf("%s direct=%t", id, groupedWriteDirect(ctx)))
			if _, err := tx.ExecContext(ctx, `INSERT INTO zz_direct_probe (id) VALUES (?)`, id); err != nil {
				return err
			}
			if fail {
				return errors.New("rejected")
			}
			return nil
		}}
	}
	batch := []*groupedWrite{insert("a", false), insert("bad", true), insert("c", false)}
	_ = store.runGroupedTx(batch, groupedTxHooks{
		op: "zz_direct_probe", begin: func(err error) error { return err },
		commit: func(_ context.Context, tx *sql.Tx, _ []*groupedWrite) error { return tx.Commit() },
	})
	want := []string{"a direct=true", "bad direct=true", "a direct=false", "bad direct=false", "c direct=false"}
	if fmt.Sprint(runs) != fmt.Sprint(want) {
		t.Fatalf("runs = %v, want %v", runs, want)
	}
	for index, id := range []string{"a", "bad", "c"} {
		var stored int
		if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM zz_direct_probe WHERE id = ?`, id).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		wantStored, wantErr := 1, false
		if id == "bad" {
			wantStored, wantErr = 0, true
		}
		if stored != wantStored || (batch[index].err != nil) != wantErr {
			t.Errorf("%s: stored %d, err %v; want %d stored, error %t", id, stored, batch[index].err, wantStored, wantErr)
		}
	}
}

// The hook-call write group carries a call's other writes before its answer
// (callGroupWrite) with the flushes: writes queued behind a busy writer share
// one transaction, and each caller returns after its own commit.
func TestR108CallGroupWritesShareOneTransaction(t *testing.T) {
	store := newV8HistoryStore(t)
	ctx := context.Background()
	if _, err := store.db.ExecContext(ctx, `CREATE TABLE zz_call_group_probe (id TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var sizes []int
	previous := writeGroupBatchObserved
	writeGroupBatchObserved = func(op string, size int) {
		if op == "hook_call_transaction" {
			mu.Lock()
			sizes = append(sizes, size)
			mu.Unlock()
		}
	}
	t.Cleanup(func() { writeGroupBatchObserved = previous })
	conn := holdWriterConn(t, store)
	const callers = 6
	errs := make(chan error, callers)
	for index := range callers {
		go func() {
			errs <- store.callGroupWrite(ctx, func(ctx context.Context, tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx, `INSERT INTO zz_call_group_probe (id) VALUES (?)`, fmt.Sprint(index))
				return err
			})
		}()
		if index == 0 {
			waitCallGroup(t, store, 0)
		}
	}
	waitCallGroup(t, store, callers-1)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	for range callers {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	var stored int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM zz_call_group_probe`).Scan(&stored); err != nil || stored != callers {
		t.Fatalf("stored %d rows (%v), want %d", stored, err, callers)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(sizes) != 2 || sizes[0] != 1 || sizes[1] != callers-1 {
		t.Fatalf("transactions = %v, want [1 %d]", sizes, callers-1)
	}
}

func waitCallGroup(t *testing.T, store *Store, want int) {
	t.Helper()
	for range 10000 {
		store.callGroup.mu.Lock()
		active, pending := store.callGroup.active, len(store.callGroup.pending)
		store.callGroup.mu.Unlock()
		if active && pending == want {
			return
		}
		sleepContext(context.Background(), 1e6) //nolint:errcheck
	}
	t.Fatalf("call-group writes behind a running leader never reached %d", want)
}
