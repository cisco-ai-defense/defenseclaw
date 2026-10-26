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
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

func newGroupCommitWriter(t *testing.T) (*Store, *EventHistoryWriter) {
	t.Helper()
	store := newV8HistoryStore(t)
	writer, err := NewEventHistoryWriter(store, &testProjectionSigner{keyID: "integrity-key-v1"},
		&testEventHistoryHealthReporter{}, testLocalProfileResolver{profile: observabilityredaction.ProfileNone})
	if err != nil {
		t.Fatal(err)
	}
	return store, writer
}

// observeAppendBatches records the size of every event-history transaction.
func observeAppendBatches(t *testing.T) func() []int {
	t.Helper()
	var mu sync.Mutex
	var sizes []int
	previous := writeGroupBatchObserved
	writeGroupBatchObserved = func(op string, size int) {
		if op != "v8_event_history_transaction" {
			return
		}
		mu.Lock()
		sizes = append(sizes, size)
		mu.Unlock()
	}
	t.Cleanup(func() { writeGroupBatchObserved = previous })
	return func() []int {
		mu.Lock()
		defer mu.Unlock()
		return append([]int(nil), sizes...)
	}
}

func waitPendingAppends(t *testing.T, writer *EventHistoryWriter, want int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		writer.group.mu.Lock()
		pending := len(writer.group.pending)
		writer.group.mu.Unlock()
		if pending == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("pending appends never reached %d", want)
}

func countAuditEvents(t *testing.T, store *Store, ids ...string) int {
	t.Helper()
	total := 0
	for _, id := range ids {
		var n int
		if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id = ?`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		total += n
	}
	return total
}

// GAP-1790, GAP-1822: appends that queue behind a busy writer connection
// share the next transaction instead of committing one by one, and every
// caller returns only after its own row is committed.
func TestConcurrentEventHistoryAppendsShareOneTransaction(t *testing.T) {
	store, writer := newGroupCommitWriter(t)
	batches := observeAppendBatches(t)
	ctx := context.Background()
	conn, err := store.db.Conn(ctx) // the store's only connection: every append waits
	if err != nil {
		t.Fatal(err)
	}
	const callers = 8
	ids := make([]string, callers)
	errs := make(chan error, callers)
	for index := range callers {
		ids[index] = fmt.Sprintf("group-commit-%d", index)
		record := newV8HistoryRecord(t, ids[index], "private")
		projection := projectV8HistoryRecord(t, record, observabilityredaction.ProfileNone)
		go func() { errs <- writer.AppendContext(ctx, record, projection) }()
		if index == 0 {
			waitPendingAppends(t, writer, 0) // the leader took its batch and waits for the connection
		}
	}
	waitPendingAppends(t, writer, callers-1)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	for range callers {
		if err := <-errs; err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if got := countAuditEvents(t, store, ids...); got != callers {
		t.Fatalf("committed %d of %d rows", got, callers)
	}
	sizes := batches()
	if len(sizes) != 2 || sizes[0] != 1 || sizes[1] != callers-1 {
		t.Fatalf("transactions = %v, want [1 %d]: the queued appends must share one", sizes, callers-1)
	}
}

// An append that fails inside a shared transaction is rolled back alone, and
// an append whose caller gave up while it waited is never written.
func TestGroupedAppendFailureAndCancellationStayTheirOwn(t *testing.T) {
	store, writer := newGroupCommitWriter(t)
	batches := observeAppendBatches(t)
	ctx := context.Background()
	conn, err := store.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	type call struct {
		id         string
		ctx        context.Context
		record     observability.Record
		projection observabilityredaction.Projection
	}
	leader := newV8HistoryRecord(t, "group-leader", "private")
	good := newV8HistoryRecord(t, "group-good", "private")
	bad := newV8HistoryRecord(t, "group-bad", "private")
	gone := newV8HistoryRecord(t, "group-gone", "private")
	goneCtx, cancelGone := context.WithCancel(ctx)
	calls := []call{
		{"group-leader", ctx, leader, projectV8HistoryRecord(t, leader, observabilityredaction.ProfileNone)},
		{"group-good", ctx, good, projectV8HistoryRecord(t, good, observabilityredaction.ProfileNone)},
		// A projection of another record does not belong to this one: the
		// writer rejects it.
		{"group-bad", ctx, bad, projectV8HistoryRecord(t, good, observabilityredaction.ProfileNone)},
		{"group-gone", goneCtx, gone, projectV8HistoryRecord(t, gone, observabilityredaction.ProfileNone)},
	}
	results := make([]chan error, len(calls))
	for index, c := range calls {
		results[index] = make(chan error, 1)
		go func() { results[index] <- writer.AppendContext(c.ctx, c.record, c.projection) }()
		waitPendingAppends(t, writer, index)
	}
	cancelGone()
	if err := <-results[3]; err == nil {
		t.Fatal("an append whose caller gave up while it waited succeeded")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	for index, want := range []bool{true, true, false} {
		err := <-results[index]
		if (err == nil) != want {
			t.Fatalf("%s: err = %v, want success %v", calls[index].id, err, want)
		}
	}
	for id, want := range map[string]int{"group-leader": 1, "group-good": 1, "group-bad": 0, "group-gone": 0} {
		if got := countAuditEvents(t, store, id); got != want {
			t.Errorf("%s: %d rows, want %d", id, got, want)
		}
	}
	if sizes := batches(); len(sizes) != 2 || sizes[1] != 2 {
		t.Fatalf("transactions = %v, want the good and the bad append in one", sizes)
	}
}

// GAP-1980: when SQLite rolls back the whole shared transaction under one
// write (SQLITE_FULL, SQLITE_IOERR, SQLITE_NOMEM do), its savepoint is gone
// too. The batch must stop and fail every write, with nothing stored: a later
// write must not run in autocommit and be stored while its caller is told it
// failed.
func TestGroupedWriteStopsWhenTheSharedTransactionIsLost(t *testing.T) {
	store := newV8HistoryStore(t)
	ctx := context.Background()
	if _, err := store.db.ExecContext(ctx, `CREATE TABLE zz_grouped_write_probe (id TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	insert := func(id string) func(context.Context, *sql.Tx) error {
		return func(ctx context.Context, tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO zz_grouped_write_probe (id) VALUES (?)`, id)
			return err
		}
	}
	lost := func(ctx context.Context, tx *sql.Tx) error {
		if err := insert("lost")(ctx, tx); err != nil {
			return err
		}
		// What SQLite does on such an error: the whole transaction ends.
		if _, err := tx.ExecContext(ctx, `ROLLBACK`); err != nil {
			return err
		}
		return errors.New("database or disk is full")
	}
	ids := []string{"before", "lost", "after"}
	batch := []*groupedWrite{
		{ctx: ctx, run: insert("before")},
		{ctx: ctx, run: lost},
		{ctx: ctx, run: insert("after")},
	}
	_ = store.runGroupedTx(batch, groupedTxHooks{
		op:    "zz_grouped_write_probe",
		begin: func(err error) error { return err },
		commit: func(ctx context.Context, tx *sql.Tx, _ []*groupedWrite) error {
			return tx.Commit()
		},
	})
	for index, item := range batch {
		var stored int
		if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM zz_grouped_write_probe WHERE id = ?`, ids[index]).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if item.err == nil {
			t.Errorf("%s: no error, but the shared transaction was rolled back", ids[index])
		}
		if stored != 0 {
			t.Errorf("%s: %d rows stored while the caller got %v", ids[index], stored, item.err)
		}
	}
}
