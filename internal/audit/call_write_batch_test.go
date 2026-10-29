// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// observeTransactions records the op of every grouped transaction.
func observeTransactions(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var ops []string
	previous := writeGroupBatchObserved
	writeGroupBatchObserved = func(op string, _ int) {
		mu.Lock()
		ops = append(ops, op)
		mu.Unlock()
	}
	t.Cleanup(func() { writeGroupBatchObserved = previous })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), ops...)
	}
}

// GAP-1303, GAP-1791, GAP-0614: the event-history appends of one hook call
// commit in one transaction at its flush, not one each, and the work queued
// behind them (the export) runs only after that commit.
func TestCallWriteBatchCommitsTheCallsAppendsTogether(t *testing.T) {
	store, writer := newGroupCommitWriter(t)
	transactions := observeTransactions(t)
	ctx := WithCallWriteBatch(context.Background(), store)
	ids := []string{"call-batch-1", "call-batch-2", "call-batch-3"}
	for _, id := range ids {
		record := newV8HistoryRecord(t, id, "private")
		if err := writer.AppendContext(ctx, record, projectV8HistoryRecord(t, record, observabilityredaction.ProfileNone)); err != nil {
			t.Fatalf("append %s: %v", id, err)
		}
	}
	two := newV8HistoryRecord(t, "call-batch-4", "private")
	three := newV8HistoryRecord(t, "call-batch-5", "private")
	if err := writer.AppendBatchContext(ctx, []observability.Record{two, three}, []observabilityredaction.Projection{
		projectV8HistoryRecord(t, two, observabilityredaction.ProfileNone),
		projectV8HistoryRecord(t, three, observabilityredaction.ProfileNone),
	}); err != nil {
		t.Fatalf("append batch: %v", err)
	}
	ids = append(ids, "call-batch-4", "call-batch-5")
	if got := countAuditEvents(t, store, ids...); got != 0 {
		t.Fatalf("%d rows committed before the flush", got)
	}
	exportedAfter := -1
	if !DeferAfterCallWrites(ctx, store, func() { exportedAfter = countAuditEvents(t, store, ids...) }) {
		t.Fatal("no open batch took the export")
	}
	FlushCallWrites(ctx)
	if exportedAfter != len(ids) {
		t.Fatalf("export ran with %d of %d rows committed", exportedAfter, len(ids))
	}
	if got := transactions(); len(got) != 1 || got[0] != "hook_call_transaction" {
		t.Fatalf("transactions = %v, want one hook_call_transaction", got)
	}
	// Closed, the batch takes nothing: a later write commits on its own.
	CloseCallWrites(ctx)
	late := newV8HistoryRecord(t, "call-batch-late", "private")
	if err := writer.AppendContext(ctx, late, projectV8HistoryRecord(t, late, observabilityredaction.ProfileNone)); err != nil {
		t.Fatal(err)
	}
	if got := countAuditEvents(t, store, "call-batch-late"); got != 1 {
		t.Fatalf("a write after close was not committed at once (%d rows)", got)
	}
	if DeferAfterCallWrites(ctx, store, func() {}) {
		t.Fatal("a closed batch took work")
	}
}

// A write the shared transaction could not commit is written again on its
// own, and the caller that tracks it sees its failure; the other writes of
// the call commit.
func TestCallWriteBatchReportsAWriteThatFailed(t *testing.T) {
	store, writer := newGroupCommitWriter(t)
	ctx := WithCallWriteBatch(context.Background(), store)
	good := newV8HistoryRecord(t, "call-good", "private")
	bad := newV8HistoryRecord(t, "call-bad", "private")
	if err := writer.AppendContext(ctx, good, projectV8HistoryRecord(t, good, observabilityredaction.ProfileNone)); err != nil {
		t.Fatal(err)
	}
	badCtx, outcome := WithCallWriteOutcome(ctx)
	// A projection of another record does not belong to this one.
	if err := writer.AppendContext(badCtx, bad, projectV8HistoryRecord(t, good, observabilityredaction.ProfileNone)); err != nil {
		t.Fatalf("the queued append failed before the flush: %v", err)
	}
	goodCtx, goodOutcome := WithCallWriteOutcome(ctx)
	other := newV8HistoryRecord(t, "call-other", "private")
	if err := writer.AppendContext(goodCtx, other, projectV8HistoryRecord(t, other, observabilityredaction.ProfileNone)); err != nil {
		t.Fatal(err)
	}
	FlushCallWrites(ctx)
	if outcome.Err() == nil {
		t.Fatal("the failed append reported success")
	}
	if goodOutcome.Err() != nil {
		t.Fatalf("a committed append reported %v", goodOutcome.Err())
	}
	for id, want := range map[string]int{"call-good": 1, "call-bad": 0, "call-other": 1} {
		if got := countAuditEvents(t, store, id); got != want {
			t.Errorf("%s: %d rows, want %d", id, got, want)
		}
	}
}

// Correlation observations of a call join its transaction too.
func TestCallWriteBatchCommitsObservationsWithTheAppends(t *testing.T) {
	store, writer := newGroupCommitWriter(t)
	transactions := observeTransactions(t)
	ctx := WithCallWriteBatch(context.Background(), store)
	record := newV8HistoryRecord(t, "call-observed", "private")
	if err := writer.AppendContext(ctx, record, projectV8HistoryRecord(t, record, observabilityredaction.ProfileNone)); err != nil {
		t.Fatal(err)
	}
	repo, err := store.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	if !CallWritesOpen(ctx, store) {
		t.Fatal("the batch is not open")
	}
	// No observation: nothing is queued and nothing fails.
	if err := repo.RecordObservations(ctx); err != nil {
		t.Fatal(err)
	}
	FlushCallWrites(ctx)
	if got := transactions(); len(got) != 1 || got[0] != "hook_call_transaction" {
		t.Fatalf("transactions = %v, want one hook_call_transaction", got)
	}
	if got := countAuditEvents(t, store, "call-observed"); got != 1 {
		t.Fatalf("%d rows", got)
	}
}
