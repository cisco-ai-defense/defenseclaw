// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/scanner"

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

func countScanResults(t *testing.T, store *Store, id string) int {
	t.Helper()
	var n int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM scan_results WHERE id = ?`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func hookRuleScan(id string, findings ...scanner.Finding) *scanner.ScanResult {
	return &scanner.ScanResult{
		ScanID: id, Scanner: "hook-rules", Target: "claudecode:PreToolUse", TargetType: "tool_call",
		Timestamp: time.Now().UTC(), Findings: findings,
	}
}

// GAP-1790, GAP-1791: the rule scan of a benign hook call (a runtime scan
// without findings) commits with the call's other writes at its flush, not
// in a transaction of its own on the store's one connection before the
// verdict. A scan with findings, and a scan outside a call, still commit at
// once.
func TestHookScanSummaryCommitsWithTheCallsWrites(t *testing.T) {
	store, _ := newGroupCommitWriter(t)
	logger := NewLogger(store)
	transactions := observeTransactions(t)
	ctx := WithCallWriteBatch(context.Background(), store)
	benign := uuid.Must(uuid.NewV7()).String()
	if _, err := logger.persistScanWithCorrelation(ctx, hookRuleScan(benign), "allow",
		ScanCorrelation{EvaluationID: "eval-benign", SessionID: "s1"}, nil); err != nil {
		t.Fatal(err)
	}
	if got := countScanResults(t, store, benign); got != 0 {
		t.Fatalf("the benign scan summary committed before the call's flush (%d rows)", got)
	}
	found := uuid.Must(uuid.NewV7()).String()
	if _, err := logger.persistScanWithCorrelation(ctx, hookRuleScan(found, scanner.Finding{
		ID: "f1", Severity: scanner.SeverityHigh, Title: "T", Scanner: "hook-rules", RuleID: "hook.cat.slug",
	}), "block", ScanCorrelation{EvaluationID: "eval-found", SessionID: "s1"}, nil); err != nil {
		t.Fatal(err)
	}
	if got := countScanResults(t, store, found); got != 1 {
		t.Fatalf("a scan with findings waited for the flush (%d rows)", got)
	}
	FlushCallWrites(ctx)
	if got := countScanResults(t, store, benign); got != 1 {
		t.Fatalf("the benign scan summary was not committed by the flush (%d rows)", got)
	}
	if got := transactions(); len(got) != 1 || got[0] != "hook_call_transaction" {
		t.Fatalf("transactions = %v, want one hook_call_transaction", got)
	}
	CloseCallWrites(ctx)
	outside := uuid.Must(uuid.NewV7()).String()
	if _, err := logger.persistScanWithCorrelation(ctx, hookRuleScan(outside), "allow",
		ScanCorrelation{EvaluationID: "eval-late"}, nil); err != nil {
		t.Fatal(err)
	}
	if got := countScanResults(t, store, outside); got != 1 {
		t.Fatalf("a scan after the batch closed did not commit at once (%d rows)", got)
	}
}

// GAP-1790: a runtime scan does not wait on the finding lifecycle lock, which
// only the current-state projection of an asset scan needs. Holding it around
// every hook's scan transaction queued the hooks one behind another.
func TestRuntimeScanDoesNotWaitOnTheFindingLifecycleLock(t *testing.T) {
	store, _ := newGroupCommitWriter(t)
	store.findingLifecycleMu.Lock()
	locked := true
	defer func() {
		if locked {
			store.findingLifecycleMu.Unlock()
		}
	}()
	done := make(chan error, 1)
	go func() {
		_, err := store.PersistScanLifecycle(scanner.ScanSummaryParams{
			ScanID: uuid.Must(uuid.NewV7()).String(), Scanner: "hook-rules", Target: "claudecode:PreToolUse",
			TargetType: "tool_call", Timestamp: time.Now().UTC(), Verdict: "allow", EvaluationID: "eval-1",
		}, nil, scanner.ScanFindingMeta{EvaluationID: "eval-1"})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		store.findingLifecycleMu.Unlock()
		locked = false
		<-done
		t.Fatal("a runtime scan waited on the finding lifecycle lock")
	}
}
