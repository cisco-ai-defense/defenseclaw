// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// fakeInserter is a counting, blockable JudgeBodyInserter used to
// exercise the async queue without involving SQLite. The hold field
// lets a test pin the worker in its INSERT path so we can saturate
// the queue deterministically.
//
// failEveryNthInsert / failCommit are the post-review fault-injection
// knobs added so tests can exercise the partial-batch and commit-
// failure paths in flushBatch without standing up a real (failing)
// SQLite store.
type fakeInserter struct {
	mu                 sync.Mutex
	inserts            int
	commits            int
	begins             int
	insertErrors       int
	committedRows      int // rows whose tx.Insert returned nil
	hold               chan struct{}
	failEveryNthInsert int // 0 = never fail
	failCommit         bool
	beginErr           error
}

type fakeBatch struct {
	parent     *fakeInserter
	insertSeen int
}

var errFakeInsert = errors.New("fakeInserter: synthetic insert failure")
var errFakeCommit = errors.New("fakeInserter: synthetic commit failure")

func (f *fakeInserter) InsertJudgeResponse(_ audit.JudgeResponse) error {
	f.mu.Lock()
	f.inserts++
	hold := f.hold
	f.mu.Unlock()
	if hold != nil {
		<-hold
	}
	return nil
}

func (f *fakeInserter) BeginJudgeBatch(_ context.Context) (JudgeBatch, error) {
	f.mu.Lock()
	f.begins++
	beginErr := f.beginErr
	f.mu.Unlock()
	if beginErr != nil {
		return nil, beginErr
	}
	return &fakeBatch{parent: f}, nil
}

func (b *fakeBatch) InsertJudgeResponse(r audit.JudgeResponse) error {
	b.parent.mu.Lock()
	b.parent.inserts++
	b.insertSeen++
	hold := b.parent.hold
	fail := b.parent.failEveryNthInsert
	b.parent.mu.Unlock()
	if hold != nil {
		<-hold
	}
	if fail > 0 && b.insertSeen%fail == 0 {
		b.parent.mu.Lock()
		b.parent.insertErrors++
		b.parent.mu.Unlock()
		return errFakeInsert
	}
	b.parent.mu.Lock()
	b.parent.committedRows++
	b.parent.mu.Unlock()
	_ = r
	return nil
}

func (b *fakeBatch) Commit() error {
	b.parent.mu.Lock()
	failCommit := b.parent.failCommit
	if !failCommit {
		b.parent.commits++
	}
	b.parent.mu.Unlock()
	if failCommit {
		return errFakeCommit
	}
	return nil
}

func (b *fakeBatch) Rollback() error { return nil }

func (f *fakeInserter) snapshot() (begins, inserts, commits int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.begins, f.inserts, f.commits
}

func (f *fakeInserter) failureSnapshot() (insertErrors, committedRows int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.insertErrors, f.committedRows
}

// makeJob is a tiny helper that returns a minimal non-empty payload
// so the queue does not no-op on the "empty raw" guard.
func makeJob(t *testing.T) (gatewaylog.JudgePayload, gatewaylog.Direction) {
	t.Helper()
	return gatewaylog.JudgePayload{
		Kind:        "injection",
		Model:       "test-model",
		LatencyMs:   1,
		Action:      "allow",
		Severity:    gatewaylog.SeverityInfo,
		RawResponse: `{"verdict":"allow"}`,
	}, gatewaylog.DirectionPrompt
}

// TestJudgeStore_DropsOnFullQueue: when the worker is blocked and
// the queue fills, additional Enqueue calls must drop (with
// telemetry) rather than blocking the caller. We freeze the worker
// in the middle of an INSERT, fill the queue, then assert the next
// submit returns without delay.
func TestJudgeStore_DropsOnFullQueue(t *testing.T) {
	fi := &fakeInserter{hold: make(chan struct{})}
	js := NewJudgeStore(fi, nil, 1)
	defer func() {
		// Release the worker so Shutdown can return cleanly.
		close(fi.hold)
		_ = js.Shutdown(context.Background())
	}()

	payload, dir := makeJob(t)

	// First enqueue: worker pulls it off and blocks on the hold gate.
	_ = js.PersistJudgeEvent(context.Background(), dir, payload, "", "", "", "")
	// Give the worker a moment to receive that first job so the
	// queue is back to zero free slots.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if begins, _, _ := fi.snapshot(); begins >= 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}

	// Second enqueue: lands in the queue (size 1).
	_ = js.PersistJudgeEvent(context.Background(), dir, payload, "", "", "", "")

	// Third onward: must DROP because the queue is full and the
	// worker is wedged. We rely on the non-blocking select default
	// path; if drop-on-full regresses, this call hangs forever and
	// the test fails on timeout.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 10; i++ {
			_ = js.PersistJudgeEvent(context.Background(), dir, payload, "", "", "", "")
		}
		close(done)
	}()
	select {
	case <-done:
		// pass
	case <-time.After(2 * time.Second):
		t.Fatal("enqueue blocked when queue was full — drop-on-full regressed")
	}
}

// TestJudgeStore_BatchesIntoSingleTx: 10 quick submits should land in
// a single transaction (one BeginJudgeBatch, one Commit). Verifies
// the worker batches instead of degenerating into 10 individual
// commits.
//
// The test pre-loads the queue by holding the worker until 10 jobs
// are queued, then releases the gate. Because the worker reads from
// the channel as fast as it can, all 10 land in one batch.
func TestJudgeStore_BatchesIntoSingleTx(t *testing.T) {
	hold := make(chan struct{})
	fi := &fakeInserter{hold: hold}
	js := NewJudgeStore(fi, nil, 64)

	// Submit synchronously: the channel is buffered (64), so these
	// all return immediately and queue up before the worker has a
	// chance to drain the first.
	payload, dir := makeJob(t)
	for i := 0; i < 10; i++ {
		_ = js.PersistJudgeEvent(context.Background(), dir, payload, "", "", "", "")
	}

	// Worker is still blocked behind the hold gate on its first
	// INSERT. Release it; the gate is one-shot so subsequent
	// INSERTS run un-blocked. We set hold to nil so the rest of the
	// batch flushes without waiting again.
	fi.mu.Lock()
	fi.hold = nil
	fi.mu.Unlock()
	close(hold)

	if err := js.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	begins, inserts, commits := fi.snapshot()
	if inserts != 10 {
		t.Fatalf("inserts=%d want 10", inserts)
	}
	if begins != 1 || commits != 1 {
		// Batching failed if we observe more than one tx for 10
		// rows queued before the worker drained.
		t.Fatalf("expected 1 tx (begin/commit), got begins=%d commits=%d", begins, commits)
	}
}

// TestJudgeStore_ShutdownDrains: enqueue 50 jobs, call Shutdown, and
// assert every single one made it to the inserter before Shutdown
// returned. The bug guarded against is "Shutdown returns before the
// worker finishes the drain", which would manifest as a flaky
// e2e suite where the final judge of a run sometimes vanishes.
func TestJudgeStore_ShutdownDrains(t *testing.T) {
	fi := &fakeInserter{}
	js := NewJudgeStore(fi, nil, 1024)

	payload, dir := makeJob(t)
	const N = 50
	for i := 0; i < N; i++ {
		_ = js.PersistJudgeEvent(context.Background(), dir, payload, "", "", "", "")
	}

	if err := js.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	_, inserts, commits := fi.snapshot()
	if inserts != N {
		t.Fatalf("inserts=%d want %d (shutdown did not drain)", inserts, N)
	}
	if commits == 0 {
		t.Fatalf("expected at least 1 commit, got 0")
	}
}

// TestJudgeStore_EmptyRawSkipsQueue: payload with empty RawResponse
// must short-circuit before touching the channel — otherwise a
// "retention off" deployment would silently fill the queue with
// no-op rows.
func TestJudgeStore_EmptyRawSkipsQueue(t *testing.T) {
	fi := &fakeInserter{}
	js := NewJudgeStore(fi, nil, 16)
	defer func() { _ = js.Shutdown(context.Background()) }()

	empty := gatewaylog.JudgePayload{
		Kind:        "injection",
		Model:       "test",
		RawResponse: "",
	}
	_ = js.PersistJudgeEvent(context.Background(), gatewaylog.DirectionPrompt, empty, "", "", "", "")

	// Give the worker a moment to (not) process anything.
	time.Sleep(50 * time.Millisecond)

	if begins, inserts, _ := fi.snapshot(); begins != 0 || inserts != 0 {
		t.Fatalf("empty raw must skip queue: begins=%d inserts=%d", begins, inserts)
	}
}

// TestJudgeStore_PostShutdownDropsAccounted: submits after Shutdown
// must drop with telemetry (reason=shutdown) instead of panicking on
// a closed channel.
func TestJudgeStore_PostShutdownDropsAccounted(t *testing.T) {
	fi := &fakeInserter{}
	js := NewJudgeStore(fi, nil, 8)
	if err := js.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	payload, dir := makeJob(t)
	// Multiple post-shutdown submits — none should panic.
	for i := 0; i < 5; i++ {
		_ = js.PersistJudgeEvent(context.Background(), dir, payload, "", "", "", "")
	}
}

// TestJudgeStore_ShutdownTimeoutHonored is a backstop for the
// bounded-wait contract: a wedged worker (hold gate pinned) must
// not block Shutdown forever. We expect a timeout error within ~5s.
func TestJudgeStore_ShutdownTimeoutHonored(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping shutdown-timeout test in -short mode (takes ~5s)")
	}
	hold := make(chan struct{})
	defer close(hold)
	fi := &fakeInserter{hold: hold}
	js := NewJudgeStore(fi, nil, 8)

	payload, dir := makeJob(t)
	_ = js.PersistJudgeEvent(context.Background(), dir, payload, "", "", "", "")

	start := time.Now()
	err := js.Shutdown(context.Background())
	if err == nil {
		t.Fatal("expected timeout error from wedged worker, got nil")
	}
	if elapsed := time.Since(start); elapsed > 7*time.Second {
		t.Fatalf("shutdown took %s (>7s); timeout not honored", elapsed)
	}
}

// TestJudgeStore_NilSafePaths covers the API guards: nil store, nil
// JudgeStore, and empty RawResponse must never panic.
func TestJudgeStore_NilSafePaths(t *testing.T) {
	if js := NewJudgeStore(nil, nil, 16); js != nil {
		t.Fatalf("NewJudgeStore(nil) must return nil")
	}

	var nilJS *JudgeStore
	_ = nilJS.PersistJudgeEvent(context.Background(), gatewaylog.DirectionPrompt,
		gatewaylog.JudgePayload{RawResponse: "x"}, "", "", "", "")
	_ = nilJS.Shutdown(context.Background())
}

// TestJudgeStore_RoundTrip is the integration smoke: hand an actual
// audit.Store to the queue, enqueue a row, drain, and read it back
// via ListJudgeResponses. Belt-and-suspenders test for the wiring
// between the gateway worker and audit.Store.BeginJudgeBatch.
func TestJudgeStore_RoundTrip(t *testing.T) {
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	js := NewJudgeStoreFromAudit(store)
	payload, dir := makeJob(t)
	ctx := ContextWithRequestID(context.Background(), "req-roundtrip")
	if err := js.PersistJudgeEvent(ctx, dir, payload, "tool", "tid", "pol", "dest"); err != nil {
		t.Fatalf("PersistJudgeEvent: %v", err)
	}
	if err := js.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	rows, err := store.ListJudgeResponses(5)
	if err != nil {
		t.Fatalf("ListJudgeResponses: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%d want 1", len(rows))
	}
	if rows[0].RequestID != "req-roundtrip" {
		t.Fatalf("request_id=%q want req-roundtrip", rows[0].RequestID)
	}
}

// TestJudgeStore_ConcurrentEnqueue stresses the non-blocking submit
// path. Multiple producers must coexist without races on the
// internal channel; the race detector is the enforcer here. We also
// verify the worker still drains everything on Shutdown.
func TestJudgeStore_ConcurrentEnqueue(t *testing.T) {
	fi := &fakeInserter{}
	js := NewJudgeStore(fi, nil, 2048)
	const (
		producers     = 8
		jobsPerWorker = 100
	)
	var wg sync.WaitGroup
	for i := 0; i < producers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload, dir := makeJob(t)
			for j := 0; j < jobsPerWorker; j++ {
				_ = js.PersistJudgeEvent(context.Background(), dir, payload, "", "", "", "")
			}
		}()
	}
	wg.Wait()
	if err := js.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	_, inserts, _ := fi.snapshot()
	// We expect every job to land; the queue is sized larger than
	// the total submission count so there is no legitimate drop.
	if inserts != producers*jobsPerWorker {
		t.Fatalf("inserts=%d want %d", inserts, producers*jobsPerWorker)
	}
}

// TestJudgeStore_QueueDepthMonotonicAfterDrain: the QueueDepth
// helper must return zero once the queue has been fully drained.
// Used by Phase 4 e2e checks; the test gives us early warning if a
// future refactor leaks a slot.
func TestJudgeStore_QueueDepthMonotonicAfterDrain(t *testing.T) {
	fi := &fakeInserter{}
	js := NewJudgeStore(fi, nil, 8)
	payload, dir := makeJob(t)
	for i := 0; i < 5; i++ {
		_ = js.PersistJudgeEvent(context.Background(), dir, payload, "", "", "", "")
	}
	if err := js.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if d := js.QueueDepth(); d != 0 {
		t.Fatalf("queue depth after shutdown = %d, want 0", d)
	}
	// Silence the unused atomic if it ever creeps in.
	_ = atomic.LoadInt32(new(int32))
}

// installTestProvider wires a ManualReader-backed telemetry provider
// as the package-level global so RecordSQLiteBusy / RecordJudgePersist*
// emit into a snapshot we can collect at the end of the test. The
// returned reader is the one to Collect() against; the cleanup
// restores whatever provider was installed before so we don't leak
// state into the next test.
func installTestProvider(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	tp, err := telemetry.NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("telemetry.NewProviderForTest: %v", err)
	}
	prev := telemetry.InstallGlobalForTest(tp)
	t.Cleanup(func() {
		telemetry.InstallGlobalForTest(prev)
		_ = tp.Shutdown(context.Background())
	})
	return reader
}

// dropReasonCount sums the int64 drop counter filtered by attribute
// reason=<r>. Used to assert that each failure mode in flushBatch
// surfaces under the correct, low-cardinality reason label.
func dropReasonCount(t *testing.T, rm metricdata.ResourceMetrics, reason string) int64 {
	t.Helper()
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "defenseclaw.judge.persist.drops" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				continue
			}
			var total int64
			for _, dp := range sum.DataPoints {
				if v, ok := dp.Attributes.Value("reason"); ok && v.AsString() == reason {
					total += dp.Value
				}
			}
			return total
		}
	}
	return 0
}

// queueDepthSeenNonZero reports whether the queue-depth gauge ever
// emitted a positive sample. The gauge is a Last-Value instrument so
// the snapshot may show zero if the worker fully drained before
// Collect ran, but the gauge must have emitted something during the
// test (the in-flight enqueue/dequeue events).
func queueDepthSeenNonZero(rm metricdata.ResourceMetrics) bool {
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "defenseclaw.judge.persist.queue_depth" {
				continue
			}
			switch d := m.Data.(type) {
			case metricdata.Gauge[int64]:
				for _, dp := range d.DataPoints {
					if dp.Value > 0 {
						return true
					}
				}
			case metricdata.Sum[int64]:
				for _, dp := range d.DataPoints {
					if dp.Value > 0 {
						return true
					}
				}
			}
		}
	}
	return false
}

// batchSizeHistogramCount returns the total number of recorded
// histogram observations for defenseclaw.judge.persist.batch_size.
// One observation == one tx successfully committed.
func batchSizeHistogramCount(rm metricdata.ResourceMetrics) uint64 {
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "defenseclaw.judge.persist.batch_size" {
				continue
			}
			hist, ok := m.Data.(metricdata.Histogram[int64])
			if !ok {
				continue
			}
			var total uint64
			for _, dp := range hist.DataPoints {
				total += dp.Count
			}
			return total
		}
	}
	return 0
}

// TestJudgeStore_PartialInsertFailureCountsDrops covers the H1 fix:
// when some — but not all — rows in a batch fail to INSERT, the
// worker must
//
//  1. record exactly one "insert_failed" drop per failed row,
//  2. commit the rows that *did* INSERT successfully, and
//  3. NOT fan out an audit summary for the failed rows (otherwise
//     SIEM rows can exist without a matching judge_responses body —
//     the very correlation invariant the design depends on).
//
// We drive 10 jobs through a fake that fails every 3rd insert (rows
// 3, 6, 9 — three drops, seven committed) and assert all three
// post-conditions.
func TestJudgeStore_PartialInsertFailureCountsDrops(t *testing.T) {
	reader := installTestProvider(t)

	auditDir := t.TempDir()
	auditStore, err := audit.NewStore(filepath.Join(auditDir, "audit.db"))
	if err != nil {
		t.Fatalf("audit.NewStore: %v", err)
	}
	t.Cleanup(func() { _ = auditStore.Close() })
	if err := auditStore.Init(); err != nil {
		t.Fatalf("audit.Init: %v", err)
	}
	logger := audit.NewLogger(auditStore)
	t.Cleanup(func() { logger.Close() })

	fi := &fakeInserter{failEveryNthInsert: 3}
	// queueDepth must be large enough that ALL ten enqueues land in
	// the worker as one batch (otherwise the round-trip can split
	// into two batches and the per-batch failure cadence shifts).
	js := NewJudgeStore(fi, logger, 128)

	// Hold-gate the worker so all ten enqueues land before the
	// first INSERT runs — guarantees a single batch.
	hold := make(chan struct{})
	fi.mu.Lock()
	fi.hold = hold
	fi.mu.Unlock()

	payload, dir := makeJob(t)
	const N = 10
	for i := 0; i < N; i++ {
		_ = js.PersistJudgeEvent(context.Background(), dir, payload, "", "", "", "")
	}
	// Release the gate AFTER all jobs are queued so they batch together.
	fi.mu.Lock()
	fi.hold = nil
	fi.mu.Unlock()
	close(hold)

	if err := js.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	insertErrors, committedRows := fi.failureSnapshot()
	wantFailed := N / 3 // rows 3,6,9 -> 3 failed
	if insertErrors != wantFailed {
		t.Fatalf("fake insert errors = %d, want %d", insertErrors, wantFailed)
	}
	if got := N - wantFailed; committedRows != got {
		t.Fatalf("fake committedRows = %d, want %d", committedRows, got)
	}

	rm := metricdata.ResourceMetrics{}
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("reader.Collect: %v", err)
	}
	if got := dropReasonCount(t, rm, "insert_failed"); got != int64(wantFailed) {
		t.Fatalf("drops(reason=insert_failed) = %d, want %d (regression: H1 partial-batch lost rows)", got, wantFailed)
	}

	// The audit logger should have received exactly one
	// `llm-judge-response` row per *committed* row — never per job.
	// This is the SIEM-vs-body parity invariant the H1 fix protects.
	fanoutCount := countAuditAction(t, auditStore, "llm-judge-response")
	if fanoutCount != N-wantFailed {
		t.Fatalf("audit_events fan-out rows = %d, want %d (regression: fan-out emitted for uncommitted jobs)",
			fanoutCount, N-wantFailed)
	}
}

// countAuditAction returns how many audit_events rows have the given
// action. Walks ListEvents (the public surface) so the test stays
// off the internal *sql.DB handle.
func countAuditAction(t *testing.T, s *audit.Store, action string) int {
	t.Helper()
	events, err := s.ListEvents(1024)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	n := 0
	for _, e := range events {
		if e.Action == action {
			n++
		}
	}
	return n
}

// TestJudgeStore_CommitFailureRollsBackEntireBatch covers the partial-
// commit-failure path in flushBatch: when tx.Commit returns an error
// the WHOLE batch is lost (SQLite rolled back per the API contract).
// Every job must record a "tx_commit_failed" drop AND no audit
// fan-out may fire — otherwise SIEM dashboards show verdicts whose
// supporting body was never persisted.
func TestJudgeStore_CommitFailureRollsBackEntireBatch(t *testing.T) {
	reader := installTestProvider(t)

	auditDir := t.TempDir()
	auditStore, err := audit.NewStore(filepath.Join(auditDir, "audit.db"))
	if err != nil {
		t.Fatalf("audit.NewStore: %v", err)
	}
	t.Cleanup(func() { _ = auditStore.Close() })
	if err := auditStore.Init(); err != nil {
		t.Fatalf("audit.Init: %v", err)
	}
	logger := audit.NewLogger(auditStore)
	t.Cleanup(func() { logger.Close() })

	fi := &fakeInserter{failCommit: true}
	js := NewJudgeStore(fi, logger, 32)
	payload, dir := makeJob(t)
	const N = 4
	for i := 0; i < N; i++ {
		_ = js.PersistJudgeEvent(context.Background(), dir, payload, "", "", "", "")
	}
	if err := js.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	rm := metricdata.ResourceMetrics{}
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("reader.Collect: %v", err)
	}
	if got := dropReasonCount(t, rm, "tx_commit_failed"); got != int64(N) {
		t.Fatalf("drops(reason=tx_commit_failed) = %d, want %d", got, N)
	}

	if fanoutCount := countAuditAction(t, auditStore, "llm-judge-response"); fanoutCount != 0 {
		t.Fatalf("fan-out fired despite commit failure: %d rows (SIEM/body parity broken)", fanoutCount)
	}
}

// TestJudgeStore_BeginFailureAccountsAllJobs guards the third failure
// mode: BeginJudgeBatch itself errored. Every job must record a
// "tx_begin_failed" drop. The audit fan-out is unreachable since the
// whole batch never made it past the begin call.
func TestJudgeStore_BeginFailureAccountsAllJobs(t *testing.T) {
	reader := installTestProvider(t)

	fi := &fakeInserter{beginErr: errors.New("synthetic begin failure")}
	js := NewJudgeStore(fi, nil, 16)
	payload, dir := makeJob(t)
	const N = 5
	for i := 0; i < N; i++ {
		_ = js.PersistJudgeEvent(context.Background(), dir, payload, "", "", "", "")
	}
	if err := js.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	rm := metricdata.ResourceMetrics{}
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("reader.Collect: %v", err)
	}
	if got := dropReasonCount(t, rm, "tx_begin_failed"); got != int64(N) {
		t.Fatalf("drops(reason=tx_begin_failed) = %d, want %d", got, N)
	}
}

// TestJudgeStore_ShutdownHonorsCtxCancel covers the M3 fix: a cancel-
// only context (no Deadline) must abort Shutdown within the
// scheduler-tick range — not silently fall through to the 5 s
// judgePersistShutdownTimeout. A wedged worker simulates the
// production SIGTERM-driven shutdown that motivated the fix.
func TestJudgeStore_ShutdownHonorsCtxCancel(t *testing.T) {
	hold := make(chan struct{})
	defer close(hold)
	fi := &fakeInserter{hold: hold}
	js := NewJudgeStore(fi, nil, 8)

	payload, dir := makeJob(t)
	_ = js.PersistJudgeEvent(context.Background(), dir, payload, "", "", "", "")

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel from another goroutine after the worker is wedged.
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	err := js.Shutdown(ctx)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected context.Canceled error from Shutdown, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	// Must return well before judgePersistShutdownTimeout (5 s).
	if elapsed > time.Second {
		t.Fatalf("Shutdown ignored ctx.Done(); elapsed=%s (regression: M3)", elapsed)
	}
	// And IsClosed must still be false — the worker is wedged.
	if js.IsClosed() {
		t.Fatal("IsClosed reported true after cancellation, but worker should still be running")
	}
}

// TestJudgeStore_IsClosedReportsLifecycle pins the H2 contract: the
// sidecar uses IsClosed() to decide whether it's safe to close the
// underlying DB after Shutdown returns. The function must report
// false while the worker is alive and true only after doneCh closes.
func TestJudgeStore_IsClosedReportsLifecycle(t *testing.T) {
	hold := make(chan struct{})
	fi := &fakeInserter{hold: hold}
	js := NewJudgeStore(fi, nil, 4)
	payload, dir := makeJob(t)
	_ = js.PersistJudgeEvent(context.Background(), dir, payload, "", "", "", "")

	if js.IsClosed() {
		t.Fatal("IsClosed = true before Shutdown; expected false")
	}

	// Cancel-only Shutdown leaves the worker alive ⇒ IsClosed stays false.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := js.Shutdown(ctx); err == nil {
		t.Fatal("expected error from cancelled Shutdown")
	}
	if js.IsClosed() {
		t.Fatal("IsClosed = true after cancelled Shutdown; worker is still inside the hold gate")
	}

	// Release the hold; the worker must finish quickly.
	close(hold)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if js.IsClosed() {
			break
		}
		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}
	if !js.IsClosed() {
		t.Fatal("IsClosed never returned true after worker drained")
	}
}

// TestJudgeStore_NoSendAfterWorkerExit covers the M5 race: producers
// and Shutdown run concurrently; no enqueue may silently leak a job
// past the worker's exit. The race detector also enforces the
// supporting concurrency contract on the RWMutex+closed pair.
//
// Test layout: spawn ~16 producer goroutines that PersistJudgeEvent
// in tight loops for the test duration. After a short warm-up, call
// Shutdown. Once Shutdown returns we drain any final samples; then
// we assert (a) IsClosed is true, (b) no test goroutine panicked,
// (c) every observed insert has a matching "either committed or
// dropped" accounting line — i.e. inserts + shutdown drops + queue
// drops == producers' total submit count.
func TestJudgeStore_NoSendAfterWorkerExit(t *testing.T) {
	reader := installTestProvider(t)

	fi := &fakeInserter{}
	js := NewJudgeStore(fi, nil, 64)

	const (
		producers     = 16
		jobsPerWorker = 200
	)
	payload, dir := makeJob(t)

	var wg sync.WaitGroup
	var submitted atomic.Int64
	for i := 0; i < producers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < jobsPerWorker; j++ {
				_ = js.PersistJudgeEvent(context.Background(), dir, payload, "", "", "", "")
				submitted.Add(1)
			}
		}()
	}

	// Race Shutdown with producers: don't wait for them to finish.
	time.Sleep(5 * time.Millisecond)
	if err := js.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	wg.Wait()
	if !js.IsClosed() {
		t.Fatal("IsClosed = false after Shutdown returned")
	}

	// Accounting: every submitted job is either inserted, dropped on
	// shutdown, or dropped because the queue was full. Nothing may
	// be silently lost.
	rm := metricdata.ResourceMetrics{}
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("reader.Collect: %v", err)
	}
	shutdownDrops := dropReasonCount(t, rm, "shutdown")
	queueFullDrops := dropReasonCount(t, rm, "queue_full")
	_, inserts, _ := fi.snapshot()
	total := int64(inserts) + shutdownDrops + queueFullDrops
	if total != submitted.Load() {
		t.Fatalf("accounting mismatch: inserts=%d shutdown_drops=%d queue_full_drops=%d total=%d submitted=%d (regression: M5 leaked sends)",
			inserts, shutdownDrops, queueFullDrops, total, submitted.Load())
	}
}

// TestJudgeStore_QueueDepthGaugeEmits guards against silent
// regressions of the queue_depth telemetry. The gauge MUST observe
// at least one positive value during a burst — otherwise operator
// dashboards that watch saturation flatline without anyone
// noticing.
//
// Test layout (the timing matters):
//  1. Enqueue one job → producer records gauge=1, worker grabs it
//     and records gauge=0, then arms the 100 ms flush timer.
//  2. Sleep until the timer fires and the worker enters
//     InsertJudgeResponse, where it blocks on the hold gate. While
//     it's blocked it cannot dequeue further work.
//  3. Enqueue 3 more jobs → producer records gauge=1, 2, 3 with the
//     worker held. The last RECORD wins for an Int64Gauge, so the
//     ManualReader snapshot now reads 3.
//
// Without step 2 the worker races the producer records and can
// emit a final Record(0) that masks the producer's positive
// values. The synchronization makes the assertion deterministic.
func TestJudgeStore_QueueDepthGaugeEmits(t *testing.T) {
	reader := installTestProvider(t)

	hold := make(chan struct{})
	defer close(hold)
	fi := &fakeInserter{hold: hold}
	js := NewJudgeStore(fi, nil, 16)

	payload, dir := makeJob(t)
	_ = js.PersistJudgeEvent(context.Background(), dir, payload, "", "", "", "")

	// Wait for the timer-driven flush to start and the worker to
	// enter (and block in) the first InsertJudgeResponse. The fake
	// records begins++ on BeginJudgeBatch and the flush timer fires
	// every judgePersistFlushInterval (100 ms).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if begins, _, _ := fi.snapshot(); begins >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if begins, _, _ := fi.snapshot(); begins == 0 {
		t.Fatal("worker never started the flush; test timing assumption broken")
	}

	// Worker is now wedged inside InsertJudgeResponse on the hold
	// gate. Producer records will be the most recent gauge writes.
	for i := 0; i < 3; i++ {
		_ = js.PersistJudgeEvent(context.Background(), dir, payload, "", "", "", "")
	}

	rm := metricdata.ResourceMetrics{}
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("reader.Collect: %v", err)
	}
	if !queueDepthSeenNonZero(rm) {
		t.Fatal("queue_depth gauge never observed a positive value (regression: telemetry silently disconnected)")
	}
}

// TestJudgeStore_BatchSizeHistogramEmits separates the histogram
// assertion from the gauge timing dance: every successful commit
// records one batch_size observation. We push five jobs, drain
// cleanly, then assert the histogram count is non-zero. This is the
// deterministic backstop for the operator dashboards that watch
// commit cadence (median should climb toward 32 under burst load,
// stay low when idle).
func TestJudgeStore_BatchSizeHistogramEmits(t *testing.T) {
	reader := installTestProvider(t)

	fi := &fakeInserter{}
	js := NewJudgeStore(fi, nil, 16)

	payload, dir := makeJob(t)
	for i := 0; i < 5; i++ {
		_ = js.PersistJudgeEvent(context.Background(), dir, payload, "", "", "", "")
	}
	if err := js.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	rm := metricdata.ResourceMetrics{}
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("reader.Collect: %v", err)
	}
	if got := batchSizeHistogramCount(rm); got == 0 {
		t.Fatal("batch_size histogram never recorded a sample (regression: commit telemetry disconnected)")
	}
}
