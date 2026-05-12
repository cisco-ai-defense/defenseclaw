// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

// fakeInserter is a counting, blockable JudgeBodyInserter used to
// exercise the async queue without involving SQLite. The hold field
// lets a test pin the worker in its INSERT path so we can saturate
// the queue deterministically.
type fakeInserter struct {
	mu      sync.Mutex
	inserts int
	commits int
	begins  int
	hold    chan struct{}
}

type fakeBatch struct {
	parent *fakeInserter
}

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
	f.mu.Unlock()
	return &fakeBatch{parent: f}, nil
}

func (b *fakeBatch) InsertJudgeResponse(r audit.JudgeResponse) error {
	return b.parent.InsertJudgeResponse(r)
}

func (b *fakeBatch) Commit() error {
	b.parent.mu.Lock()
	b.parent.commits++
	b.parent.mu.Unlock()
	return nil
}

func (b *fakeBatch) Rollback() error { return nil }

func (f *fakeInserter) snapshot() (begins, inserts, commits int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.begins, f.inserts, f.commits
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
