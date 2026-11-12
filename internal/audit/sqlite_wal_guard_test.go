// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
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
		_, err := store.CheckpointWALIfLarge(t.Context(), math.MaxInt64, testWALWriterBudget)
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
	// Only liveness is checked here: once the connection is released the
	// size check must finish. A loaded Windows runner can take more than a
	// second to schedule it, so the bound is generous; a check that never
	// gets the connection still fails.
	select {
	case err := <-guardDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("WAL size check did not finish after checkpoint connection was released")
	}
}

const testWALWriterBudget = 200 * time.Millisecond

// overLimitTestHoldCap is a bounded hold long enough for any test disk to copy
// and sync a test log under the writer; the pass ends when the copy does.
const overLimitTestHoldCap = 30 * time.Second

func logWALGuardEvents(t *testing.T, store *Store, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := store.LogEvent(Event{Action: "hook_decision", Target: "wal-guard", Severity: "INFO", SessionID: "s"}); err != nil {
			t.Fatalf("LogEvent: %v", err)
		}
	}
}

func walFileSize(t *testing.T, store *Store) int64 {
	t.Helper()
	info, err := os.Stat(store.dbPath + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

func countWALGuardEvents(t *testing.T, store *Store) int {
	t.Helper()
	var count int
	if err := store.db.QueryRow(`SELECT count(*) FROM audit_events WHERE target = 'wal-guard'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// writeDuringEveryCopy makes every copy pass on the checkpoint connection see
// a commit while it runs, the shape of a hook flood: the copy never reaches
// the end of the log by itself.
func writeDuringEveryCopy(t *testing.T, store *Store) *atomic.Int64 {
	t.Helper()
	var writes atomic.Int64
	original := walCopyPhaseHook
	walCopyPhaseHook = func(context.Context) {
		if err := store.LogEvent(Event{Action: "hook_decision", Target: "wal-guard", Severity: "INFO", SessionID: "s"}); err != nil {
			t.Errorf("LogEvent during the copy: %v", err)
		}
		writes.Add(1)
	}
	t.Cleanup(func() { walCopyPhaseHook = original })
	return &writes
}

// catchUpLimit is a WAL limit that the store's current log is over half of
// (so a pass catches it up) but under (so the catch-up is not bounded).
func catchUpLimit(t *testing.T, store *Store) int64 {
	t.Helper()
	return walFileSize(t, store) * 3 / 2
}

// countWriterPhases counts the passes that take the writer connection.
func countWriterPhases(t *testing.T) *atomic.Int64 {
	t.Helper()
	var count atomic.Int64
	original := walWriterPhaseHook
	walWriterPhaseHook = func(context.Context) { count.Add(1) }
	t.Cleanup(func() { walWriterPhaseHook = original })
	return &count
}

func TestCheckpointWALIfLargeTruncatesTheLogOnlyWhenItIsLong(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	logWALGuardEvents(t, store, 200)
	grown := walFileSize(t, store)
	if grown < 1<<20 {
		t.Fatalf("WAL did not grow without a checkpoint: %d bytes", grown)
	}
	ctx := context.Background()
	pass, err := store.CheckpointWALIfLarge(ctx, grown+1, testWALWriterBudget)
	if err != nil || pass.Truncated || pass.LogBytes == 0 || pass.FileBytes != grown || !pass.Restarted {
		t.Fatalf("below the limit: %+v, %v; want the log copied and the file kept", pass, err)
	}
	pass, err = store.CheckpointWALIfLarge(ctx, grown/2, testWALWriterBudget)
	if err != nil || !pass.Truncated || pass.FileBytes != 0 {
		t.Fatalf("over the limit: %+v, %v; want the WAL file truncated", pass, err)
	}
	// The next writes start the log again from an empty file.
	logWALGuardEvents(t, store, 50)
	if size := walFileSize(t, store); size >= grown {
		t.Fatalf("WAL is %d bytes after the truncation, want under %d", size, grown)
	}
	if count := countWALGuardEvents(t, store); count != 250 {
		t.Fatalf("events after the truncation = %d; want 250", count)
	}
}

// An idle gateway never restarts the log, so a fully copied WAL kept its peak
// size on disk until a manual TRUNCATE (rel-1-0-2:GAP-0709). The pass after
// the last write trims it.
func TestCheckpointWALIfLargeTrimsAnIdleOversizedFile(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	logWALGuardEvents(t, store, 200)
	grown := walFileSize(t, store)
	original := walIdleTrimBytes
	walIdleTrimBytes = grown / 2
	t.Cleanup(func() { walIdleTrimBytes = original })
	// The log is longer than a trickle's.
	originalTrickle := walTrickleFrames
	walTrickleFrames = 16
	t.Cleanup(func() { walTrickleFrames = originalTrickle })
	ctx := context.Background()
	pass, err := store.CheckpointWALIfLarge(ctx, math.MaxInt64, testWALWriterBudget)
	if err != nil || pass.Truncated || pass.WriterHeld != 0 || pass.FileBytes != grown {
		t.Fatalf("first pass after the writes: %+v, %v; want the copy only", pass, err)
	}
	pass, err = store.CheckpointWALIfLarge(ctx, math.MaxInt64, testWALWriterBudget)
	if err != nil || !pass.Truncated || pass.FileBytes != 0 {
		t.Fatalf("idle oversized WAL: %+v, %v; want it truncated", pass, err)
	}
}

// A trickle of background writes after a flood restarts the log, so the
// store is never quiet for a whole pass. The file is still trimmed once the
// log in use is short and copied.
func TestCheckpointWALIfLargeTrimsAnOversizedFileUnderATrickleOfWrites(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	ctx := context.Background()
	logWALGuardEvents(t, store, 200)
	grown := walFileSize(t, store)
	original := walIdleTrimBytes
	walIdleTrimBytes = grown / 2
	t.Cleanup(func() { walIdleTrimBytes = original })
	if _, err := store.CheckpointWALIfLarge(ctx, math.MaxInt64, testWALWriterBudget); err != nil {
		t.Fatal(err)
	}
	// One write restarts the fully copied log; the file keeps its size.
	logWALGuardEvents(t, store, 1)
	if size := walFileSize(t, store); size != grown {
		t.Fatalf("WAL file after the trickle write = %d bytes, want %d", size, grown)
	}
	pass, err := store.CheckpointWALIfLarge(ctx, math.MaxInt64, testWALWriterBudget)
	if err != nil || !pass.Truncated || pass.FileBytes != 0 {
		t.Fatalf("oversized file under a trickle: %+v, %v; want it truncated", pass, err)
	}
}

// SQLite's journal_size_limit leaves a restarted WAL at exactly the trim
// threshold. That boundary must be reclaimed after a flood too (GAP-0351).
func TestCheckpointWALIfLargeTrimsAtTheIdleThreshold(t *testing.T) {
	for _, trickle := range []bool{false, true} {
		for _, offset := range []int64{-1, 0, 1} {
			t.Run(fmt.Sprintf("trickle=%t/threshold-offset=%d", trickle, offset), func(t *testing.T) {
				store, cleanup := newTestStore(t)
				defer cleanup()
				logWALGuardEvents(t, store, 200)
				grown := walFileSize(t, store)
				original, originalTrickle := walIdleTrimBytes, walTrickleFrames
				walIdleTrimBytes, walTrickleFrames = grown+offset, 16
				t.Cleanup(func() { walIdleTrimBytes, walTrickleFrames = original, originalTrickle })
				// This regression checks the size boundary, not the writer's
				// deadline. Allow shared CI to deschedule a completed truncate.
				const budget = 10 * time.Second
				if _, err := store.CheckpointWALIfLarge(t.Context(), math.MaxInt64, budget); err != nil {
					t.Fatal(err)
				}
				if trickle {
					walTrickleFrames = originalTrickle
					logWALGuardEvents(t, store, 1)
				}
				pass, err := store.CheckpointWALIfLarge(t.Context(), math.MaxInt64, budget)
				wantTrim := offset <= 0
				if err != nil || pass.Truncated != wantTrim || (wantTrim && pass.FileBytes != 0) || (!wantTrim && pass.FileBytes != grown) {
					t.Fatalf("pass = %+v, %v; want trimmed=%t", pass, err, wantTrim)
				}
				wantEvents := 200
				if trickle {
					wantEvents++
				}
				if got := countWALGuardEvents(t, store); got != wantEvents {
					t.Fatalf("events = %d, want %d", got, wantEvents)
				}
			})
		}
	}
}

// rel-1-0-3 GAP-0247, GAP-0136: under sustained hook writes the WAL file stays
// over walIdleTrimBytes, and the idle trim took the writer connection for a
// sync on every pass. A pass with writes since the previous pass and a log
// under the limit only copies.
func TestCheckpointWALIfLargeDoesNotHoldTheWriterForAnOversizedFileUnderWrites(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	logWALGuardEvents(t, store, 200)
	original := walIdleTrimBytes
	walIdleTrimBytes = walFileSize(t, store) / 4
	t.Cleanup(func() { walIdleTrimBytes = original })
	// A flood writes more between two passes than a trickle.
	originalTrickle := walTrickleFrames
	walTrickleFrames = 16
	t.Cleanup(func() { walTrickleFrames = originalTrickle })
	phases := countWriterPhases(t)
	ctx := context.Background()
	for pass := range 5 {
		logWALGuardEvents(t, store, 20)
		result, err := store.CheckpointWALIfLarge(ctx, math.MaxInt64, testWALWriterBudget)
		if err != nil || result.Truncated || result.WriterHeld != 0 || phases.Load() != 0 {
			t.Fatalf("pass %d under writes: %+v, %v, writer phases %d; want the copy only", pass, result, err, phases.Load())
		}
		if result.FileBytes <= walIdleTrimBytes {
			t.Fatalf("pass %d: WAL file %d bytes is not over the trim size %d", pass, result.FileBytes, walIdleTrimBytes)
		}
	}
	// The pass after the writes stop trims the file.
	result, err := store.CheckpointWALIfLarge(ctx, math.MaxInt64, testWALWriterBudget)
	if err != nil || !result.Truncated || result.FileBytes != 0 || phases.Load() != 1 {
		t.Fatalf("pass after the writes stopped: %+v, %v, writer phases %d; want one trim", result, err, phases.Load())
	}
}

// rel-1-0-3 GAP-0186, GAP-0247, GAP-0136: a long log under writes is brought
// to its end by a PASSIVE copy while the writer is held in an idle gap, never
// by a RESTART on the writer, and SQLite restarts it at the next write. The
// file keeps its space for the writes that follow and no record is lost.
func TestCheckpointWALIfLargeCatchesUpALongLogUnderWritesWithoutARestartOnTheWriter(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	ctx := context.Background()
	logWALGuardEvents(t, store, 200)
	// This checks the hold, not how the backlog settles before it.
	overrideWALDuration(t, &walSettledSpan, time.Hour)
	writes := writeDuringEveryCopy(t, store)
	phases := countWriterPhases(t)
	pass, err := store.CheckpointWALIfLarge(ctx, catchUpLimit(t, store), testWALWriterBudget)
	if err != nil || !pass.Restarted || pass.Truncated || pass.WriterDeferred || pass.Bounded || pass.FileBytes == 0 || phases.Load() != 1 {
		t.Fatalf("long log under writes: %+v, %v, writer phases %d; want one catch-up that keeps the file", pass, err, phases.Load())
	}
	if pass.WriterHeld <= 0 || pass.WriterHeld > walSettledHoldCap+50*time.Millisecond {
		t.Fatalf("catch-up held the writer for %v; want more than zero and at most the %v cap", pass.WriterHeld, walSettledHoldCap)
	}
	if store.WALOverLimit() {
		t.Fatal("a pass that brought the log to its end left the store marked over the WAL limit")
	}
	walCopyPhaseHook = nil
	logWALGuardEvents(t, store, 1)
	next, err := store.CheckpointWALIfLarge(ctx, math.MaxInt64, testWALWriterBudget)
	if err != nil || next.LogBytes <= 0 || next.LogBytes >= pass.LogBytes/10 {
		t.Fatalf("log after the catch-up and one write = %+v, %v; want it started again (was %d bytes)", next, err, pass.LogBytes)
	}
	if count, want := countWALGuardEvents(t, store), 201+int(writes.Load()); count != want {
		t.Fatalf("events after the catch-up = %d; want %d", count, want)
	}
}

// The catch-up gives the writer back at walSettledHoldCap even when the copy
// under it takes longer: a hook that waits for the writer gets it within the cap,
// the copy goes on without the writer, and the pass reports the real hold.
func TestCheckpointWALIfLargeCatchUpGivesTheWriterBackAtItsCap(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	logWALGuardEvents(t, store, 200)
	overrideWALDuration(t, &walSettledSpan, time.Hour)
	writeDuringEveryCopy(t, store)
	entered := make(chan struct{})
	var once sync.Once
	original := walWriterPhaseHook
	walWriterPhaseHook = func(context.Context) {
		once.Do(func() { close(entered) })
		time.Sleep(10 * walSettledHoldCap)
	}
	t.Cleanup(func() { walWriterPhaseHook = original })
	type outcome struct {
		pass WALCheckpoint
		err  error
	}
	passDone := make(chan outcome, 1)
	limit := catchUpLimit(t, store)
	go func() {
		pass, err := store.CheckpointWALIfLarge(context.Background(), limit, testWALWriterBudget)
		passDone <- outcome{pass, err}
	}()
	<-entered
	started := time.Now()
	if err := store.LogEvent(Event{Action: "hook_decision", Target: "during-catch-up"}); err != nil {
		t.Fatalf("hook audit append during the catch-up: %v", err)
	}
	// The copy under the writer takes ten times the cap. The append waits for
	// the rest of the cap plus its own write, which -race on a busy box can
	// make slow, but not for the copy.
	if waited := time.Since(started); waited > 5*walSettledHoldCap {
		t.Fatalf("hook audit append waited %v for the catch-up, cap %v", waited, walSettledHoldCap)
	}
	got := <-passDone
	if got.err != nil || got.pass.Restarted || !got.pass.WriterDeferred {
		t.Fatalf("capped catch-up: %+v, %v; want deferred, not restarted", got.pass, got.err)
	}
	if got.pass.WriterHeld < walSettledHoldCap || got.pass.WriterHeld > walSettledHoldCap+100*time.Millisecond {
		t.Fatalf("capped catch-up held the writer for %v; want about the %v cap", got.pass.WriterHeld, walSettledHoldCap)
	}
	if store.WALOverLimit() {
		t.Fatal("a log under the limit is marked over it")
	}
}

// fakeWALClock stands in for the settle rounds' clock (walClock): it moves
// only when a test advances it, so a test scripts each round's span without
// sleeping.
type fakeWALClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeWALClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeWALClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func useFakeWALClock(t *testing.T) *fakeWALClock {
	t.Helper()
	clock := &fakeWALClock{now: time.Unix(1_800_000_000, 0)}
	original := walClock
	walClock = clock.Now
	t.Cleanup(func() { walClock = original })
	return clock
}

// rel-1-0-6:GAP-0267: a hook commit never waits on the checkpoint work of a
// pass under the limit. A hook call commits during every copy and every sync
// of the pass, on the pass's own goroutine (the phase hooks), so a pass that
// held the writer connection there would never get past its own hook. The
// pass takes the writer only once a settle round's span (a sync plus the copy
// before it, scripted with a fake clock, no sleeps) is within walSettledSpan,
// and then copies only the commits made since that round's copy began. A
// backlog whose span does not shorten walSettleStalls rounds in a row, or does
// not settle within walSettleRounds, is left to the next pass, and the writer
// is never taken.
func TestCheckpointWALIfLargeHookCommitDoesNotWaitOnTheCheckpoint(t *testing.T) {
	span := walSettledSpan
	slow := make([]time.Duration, walSettleRounds+1)
	for i := range slow {
		slow[i] = time.Duration(100-i) * span
	}
	for _, tc := range []struct {
		name    string
		spans   []time.Duration
		settled bool
	}{
		{name: "settles", spans: []time.Duration{4 * span, 2 * span, span / 2}, settled: true},
		{name: "first sync settled", spans: []time.Duration{span / 2}, settled: true},
		{name: "one stall then settles", spans: []time.Duration{3 * span, 4 * span, 2 * span, span / 2}, settled: true},
		{name: "stops shrinking", spans: []time.Duration{3 * span, 3 * span, 3 * span}},
		{name: "grows", spans: []time.Duration{2 * span, 3 * span, 5 * span}},
		{name: "does not settle within the rounds", spans: slow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, cleanup := newTestStore(t)
			defer cleanup()
			logWALGuardEvents(t, store, 200)
			// This case pins phase order and hook commits during each copy and
			// sync. The production writer cap is covered by the budget tests;
			// give the final copy room on slower CI disks.
			overrideWALDuration(t, &walSettledHoldCap, overLimitTestHoldCap)
			clock := useFakeWALClock(t)
			var steps []string
			var hookCommits int
			hookCall := func(step string) {
				if err := store.LogEvent(Event{Action: "hook_decision", Target: "wal-guard", Severity: "INFO", SessionID: "s"}); err != nil {
					t.Errorf("hook commit during the %s: %v", step, err)
				}
				hookCommits++
				steps = append(steps, step)
			}
			syncs := 0
			originalCopy, originalSync, originalWriter := walCopyPhaseHook, walSyncPhaseHook, walWriterPhaseHook
			t.Cleanup(func() {
				walCopyPhaseHook, walSyncPhaseHook, walWriterPhaseHook = originalCopy, originalSync, originalWriter
			})
			walCopyPhaseHook = func(context.Context) { hookCall("copy") }
			walSyncPhaseHook = func(context.Context) {
				if syncs >= len(tc.spans) {
					t.Errorf("sync %d: the script has %d spans", syncs+1, len(tc.spans))
				} else {
					clock.Advance(tc.spans[syncs])
				}
				syncs++
				hookCall("sync")
			}
			walWriterPhaseHook = func(context.Context) { steps = append(steps, "writer") }
			pass, err := store.CheckpointWALIfLarge(context.Background(), catchUpLimit(t, store), overLimitTestHoldCap)
			if err != nil {
				t.Fatal(err)
			}
			var want []string
			for range tc.spans {
				want = append(want, "copy", "sync")
			}
			if tc.settled {
				want = append(want, "writer")
			}
			if !slices.Equal(steps, want) {
				t.Fatalf("pass steps = %v; want %v", steps, want)
			}
			if pass.Syncs != len(tc.spans) || pass.SyncLongest != slices.Max(tc.spans) || pass.Bounded {
				t.Fatalf("pass = %+v; want %d syncs, the longest %v, not bounded", pass, len(tc.spans), slices.Max(tc.spans))
			}
			if tc.settled {
				if !pass.Restarted || pass.WriterDeferred || pass.WriterHeld <= 0 {
					t.Fatalf("settled backlog: %+v; want one hold that restarts the log", pass)
				}
			} else if pass.Restarted || !pass.WriterDeferred || pass.WriterHeld != 0 {
				t.Fatalf("unsettled backlog: %+v; want the pass deferred without the writer", pass)
			}
			if count := countWALGuardEvents(t, store); count != 200+hookCommits {
				t.Fatalf("events = %d; want %d (every hook commit kept)", count, 200+hookCommits)
			}
			if store.WALOverLimit() {
				t.Fatal("a log under the limit is marked over it")
			}
		})
	}
}

// floodWrite is one audit write of floodTheStore: when it started and how long
// LogEvent took.
type floodWrite struct {
	started time.Time
	took    time.Duration
}

// floodTheStore commits an audit row every walFloodInterval until the
// returned stop runs, so the store never has an idle gap. writes returns
// every write made.
func floodTheStore(t *testing.T, store *Store) (stop func(), writes func() []floodWrite) {
	t.Helper()
	done := make(chan struct{})
	var mu sync.Mutex
	var made []floodWrite
	var flood sync.WaitGroup
	flood.Add(1)
	go func() {
		defer flood.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			started := time.Now()
			if err := store.LogEvent(Event{Action: "hook_decision", Target: "wal-guard", Severity: "INFO", SessionID: "s"}); err != nil {
				t.Errorf("flood LogEvent: %v", err)
				return
			}
			took := time.Since(started)
			mu.Lock()
			made = append(made, floodWrite{started: started, took: took})
			mu.Unlock()
			time.Sleep(walFloodInterval)
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done); flood.Wait() }) }, func() []floodWrite {
		mu.Lock()
		defer mu.Unlock()
		return append([]floodWrite(nil), made...)
	}
}

// walFloodInterval paces floodTheStore at about 100 commits a second, so the
// store never has an idle gap. One
// flood commit is one audit row, about 17 WAL frames; a hook call writes
// about 163 (hookAuditWALFramesPerCall), so this flood writes about as much
// log a second as the 10 Hz hook flood GAP-1303 sizes the emergency hold for.
const walFloodInterval = 10 * time.Millisecond

// longestFloodWrite is the longest of writes that started in [from, to].
func longestFloodWrite(writes []floodWrite, from, to time.Time) time.Duration {
	var longest time.Duration
	for _, write := range writes {
		if !write.started.Before(from) && !write.started.After(to) {
			longest = max(longest, write.took)
		}
	}
	return longest
}

// withoutDiskFlushes turns SQLite's syncs off (PRAGMA synchronous = OFF) on
// the store's writer and checkpoint connections, the two a WAL guard pass and
// the hooks use, for a test that times a pass against the fixed 1 s
// emergency hold. With them on, the hold also contained the runner's own
// flushes: the copy under the writer syncs the log and the database file, and
// the first commit after the restart syncs the new log header. A Windows disk
// gives those flushes the time the other processes' I/O sets, not the time of
// this store's pages: natively under concurrent disk load they took 0.9-5.4 s
// after the modelled copy, also with every page synced beforehand, so the
// hold deferred on every pass (r106 CI, GAP-0024). The modelled copy
// (walWriterPhaseHook) is the slow final copy and sync the hold is sized for;
// a disk too slow even for the hold is GAP-1303's documented limit. Each pool
// has one connection, so requireNoDiskFlushes can confirm the setting held.
func withoutDiskFlushes(t *testing.T, store *Store) {
	t.Helper()
	for _, db := range walGuardConns(t, store) {
		if _, err := db.Exec(`PRAGMA synchronous = OFF`); err != nil {
			t.Fatal(err)
		}
	}
}

// requireNoDiskFlushes fails when a connection withoutDiskFlushes set up was
// replaced by one that syncs again.
func requireNoDiskFlushes(t *testing.T, store *Store) {
	t.Helper()
	for _, db := range walGuardConns(t, store) {
		var level int
		if err := db.QueryRow(`PRAGMA synchronous`).Scan(&level); err != nil {
			t.Fatal(err)
		}
		if level != 0 {
			t.Fatalf("a WAL guard connection runs with synchronous=%d; want the fixture's OFF through the pass", level)
		}
	}
}

func walGuardConns(t *testing.T, store *Store) []*sql.DB {
	t.Helper()
	checkpointDB, err := store.checkpointConn()
	if err != nil {
		t.Fatal(err)
	}
	return []*sql.DB{store.db, checkpointDB}
}

// GAP-1303: a persistent final copy three times slower than the ordinary hold
// must restart the WAL under continuous hook writes before the hard limit.
// The copy is modelled; the runner's disk flushes are kept out of the timed
// hold (withoutDiskFlushes).
func TestCheckpointWALIfLargeBoundsALogOverTheLimitUnderAFlood(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	withoutDiskFlushes(t, store)
	// What an ordinary commit takes on this runner under this flood, before
	// any WAL pass runs, over about a hundred commits.
	stopOrdinary, ordinaryWrites := floodTheStore(t, store)
	time.Sleep(time.Second)
	stopOrdinary()
	ordinary := longestFloodWrite(ordinaryWrites(), time.Time{}, time.Now())
	logWALGuardEvents(t, store, 200)
	// Scale the measured frames to the production band between the emergency
	// arm and the 256 MiB alarm without allocating a 176 MiB fixture.
	frames := (walFileSize(t, store) - 32) / (4096 + 24)
	if frames <= 0 {
		t.Fatal("no WAL frames to scale")
	}
	originalFrameBytes := walFrameBytes
	walFrameBytes = (WALEmergencyArmBytes + 8<<20) / frames
	t.Cleanup(func() { walFrameBytes = originalFrameBytes })
	writes := writeDuringEveryCopy(t, store)
	slowCopy := 3 * walCatchUpCap
	original := walWriterPhaseHook
	walWriterPhaseHook = func(context.Context) { time.Sleep(slowCopy) }
	t.Cleanup(func() { walWriterPhaseHook = original })
	stop, floodWrites := floodTheStore(t, store)
	defer stop()
	passStarted := time.Now()
	pass, err := store.CheckpointWALIfLarge(context.Background(), 0, testWALWriterBudget)
	if pass.LogBytes < WALEmergencyArmBytes || pass.LogBytes >= WALHardLimitBytes {
		t.Fatalf("measured log = %d bytes; want emergency hold armed before the %d-byte ceiling at %d bytes", pass.LogBytes, WALHardLimitBytes, WALEmergencyArmBytes)
	}
	held := pass.WriterHeld
	// A runner too slow to finish even this copy inside the emergency cap gets
	// the writer back at the cap, and the next over-limit pass retries
	// (walEmergencyCatchUpCap). Allow that one retry, and only when the
	// deferred pass gave the writer back at the cap plus the measured
	// scheduling slack of one commit (T11b PR CI: a hosted Windows runner
	// deferred at 1.0004s). The retry must restart the log.
	if err == nil && pass.Bounded && pass.WriterDeferred && pass.WriterHeld >= walEmergencyCatchUpCap {
		if slack := max(ordinary, 100*time.Millisecond); pass.WriterHeld > walEmergencyCatchUpCap+slack {
			t.Fatalf("deferred emergency catch-up held the writer for %v; want it back at the %v cap plus %v slack", pass.WriterHeld, walEmergencyCatchUpCap, slack)
		}
		t.Logf("first pass deferred at the cap (%+v); retrying once", pass)
		pass, err = store.CheckpointWALIfLarge(context.Background(), 0, testWALWriterBudget)
		held = max(held, pass.WriterHeld)
	}
	passEnded := time.Now()
	stop()
	requireNoDiskFlushes(t, store)
	if err != nil || !pass.Bounded || !pass.Restarted || pass.WriterDeferred {
		t.Fatalf("log over the limit under a flood: %+v, %v; want a bounded catch-up that restarts the log", pass, err)
	}
	if pass.WriterHeld < slowCopy || pass.WriterHeld >= 500*time.Millisecond {
		t.Fatalf("emergency catch-up held the writer for %v; want the %v copy inside the 500 ms writer bound", pass.WriterHeld, slowCopy)
	}
	// The contract: a hook write that arrives during the pass waits for the
	// writer hold the pass reports (inside the emergency cap, checked above)
	// plus its own commit and at most one commit queued ahead of it. A commit
	// is the longest ordinary one measured above, never under 100ms
	// (GAP-2407: a fixed 500ms total failed on a slow Windows runner whose
	// commits, not the hold, took the time). A write that waits for more than
	// one hold, or for the copy itself, still fails.
	duringPass := longestFloodWrite(floodWrites(), passStarted, passEnded)
	t.Logf("writer held %v; longest write during the pass %v, longest ordinary %v", held, duringPass, ordinary)
	if allowed := held + 2*max(ordinary, 100*time.Millisecond); duringPass >= allowed {
		t.Fatalf("hook audit write waited %v during the pass; want under %v (writer held %v, longest ordinary commit %v)", duringPass, allowed, held, ordinary)
	}
	if store.WALOverLimit() {
		t.Fatal("a bounded catch-up that restarted the log left the store marked over the WAL limit")
	}
	walCopyPhaseHook = nil
	walWriterPhaseHook = original
	logWALGuardEvents(t, store, 1)
	next, err := store.CheckpointWALIfLarge(context.Background(), math.MaxInt64, testWALWriterBudget)
	if err != nil || next.LogBytes <= 0 || next.LogBytes >= pass.LogBytes/10 {
		t.Fatalf("log after the bounded catch-up and one write = %+v, %v; want it started again (was %d bytes)", next, err, pass.LogBytes)
	}
	var count int
	if err := store.db.QueryRow(`SELECT count(*) FROM audit_events WHERE target = 'wal-guard'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count < 201+int(writes.Load()) {
		t.Fatalf("events after the bounded catch-up = %d; want at least %d", count, 201+int(writes.Load()))
	}
}

func TestGAP0245EmergencyCopyYieldsWriterWithinBound(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	withoutDiskFlushes(t, store)
	logWALGuardEvents(t, store, 200)
	frames := (walFileSize(t, store) - 32) / (4096 + 24)
	if frames <= 0 {
		t.Fatal("no WAL frames to scale")
	}
	originalFrameBytes := walFrameBytes
	walFrameBytes = (WALEmergencyArmBytes + 8<<20) / frames
	t.Cleanup(func() { walFrameBytes = originalFrameBytes })
	writeDuringEveryCopy(t, store)
	originalPhase := walWriterPhaseHook
	walWriterPhaseHook = func(context.Context) { time.Sleep(700 * time.Millisecond) }
	t.Cleanup(func() { walWriterPhaseHook = originalPhase })

	pass, err := store.CheckpointWALIfLarge(context.Background(), 0, testWALWriterBudget)
	if err != nil || !pass.Bounded || !pass.WriterDeferred || pass.WriterHeld <= 0 ||
		pass.WriterHeld >= 500*time.Millisecond {
		t.Fatalf("slow emergency copy held the writer: %+v, %v; want a yield inside 500 ms", pass, err)
	}
	// A normal append still commits after the guard yields its connection.
	if err := store.LogEvent(Event{Action: "hook_decision", Target: "after-emergency-yield"}); err != nil {
		t.Fatalf("ordinary append after guard yield: %v", err)
	}
	requireNoDiskFlushes(t, store)
}

func TestGAP0245IntermediateEmergencyCopyRestartsWAL(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	withoutDiskFlushes(t, store)
	logWALGuardEvents(t, store, 200)
	frames := (walFileSize(t, store) - 32) / (4096 + 24)
	if frames <= 0 {
		t.Fatal("no WAL frames to scale")
	}
	originalFrameBytes := walFrameBytes
	walFrameBytes = (WALEmergencyArmBytes + 8<<20) / frames
	t.Cleanup(func() { walFrameBytes = originalFrameBytes })
	writeDuringEveryCopy(t, store)
	originalPhase := walWriterPhaseHook
	walWriterPhaseHook = func(context.Context) { time.Sleep(450 * time.Millisecond) }
	t.Cleanup(func() { walWriterPhaseHook = originalPhase })
	for attempt := 0; attempt < 2; attempt++ {
		pass, err := store.CheckpointWALIfLarge(context.Background(), 0, testWALWriterBudget)
		if err != nil {
			t.Fatal(err)
		}
		if pass.Restarted {
			if !pass.Bounded || pass.WriterDeferred || pass.WriterHeld >= 500*time.Millisecond {
				t.Fatalf("intermediate emergency copy exceeded the writer bound: %+v", pass)
			}
			return
		}
	}
	t.Fatal("intermediate emergency copy did not restart the WAL")
}

// The bounded catch-up still gives the writer back at walCatchUpCap: a
// copy that takes longer goes on without the writer and the next pass tries
// again.
func TestCheckpointWALIfLargeBoundedCatchUpGivesTheWriterBackAtItsCap(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	logWALGuardEvents(t, store, 200)
	writeDuringEveryCopy(t, store)
	originalCap := walCatchUpCap
	walCatchUpCap = 40 * time.Millisecond
	t.Cleanup(func() { walCatchUpCap = originalCap })
	original := walWriterPhaseHook
	walWriterPhaseHook = func(context.Context) { time.Sleep(5 * walCatchUpCap) }
	t.Cleanup(func() { walWriterPhaseHook = original })
	pass, err := store.CheckpointWALIfLarge(context.Background(), 0, testWALWriterBudget)
	if err != nil || !pass.Bounded || pass.Restarted || !pass.WriterDeferred {
		t.Fatalf("capped bounded catch-up: %+v, %v; want deferred, not restarted", pass, err)
	}
	if pass.WriterHeld < walCatchUpCap || pass.WriterHeld > testWALWriterBudget {
		t.Fatalf("capped bounded catch-up held the writer for %v; want about the %v cap inside the budget", pass.WriterHeld, walCatchUpCap)
	}
	if !store.WALOverLimit() {
		t.Fatal("a log the bounded catch-up could not bring to its end is not marked over the WAL limit")
	}
}

// The gateway starts catch-up at 176 MiB. A measured log in the real band
// between that trigger and the emergency arm must use the 100 ms hold.
func TestCheckpointWALIfLargeAtProductionTriggerUsesOrdinaryHold(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	const productionTrigger = int64(176 << 20)
	if _, err := store.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
	originalFrameBytes := walFrameBytes
	t.Cleanup(func() { walFrameBytes = originalFrameBytes })
	originalCopy := walCopyPhaseHook
	walCopyPhaseHook = func(context.Context) {
		if err := store.LogEvent(Event{Action: "hook_decision", Target: "wal-guard"}); err != nil {
			t.Errorf("write during the copy: %v", err)
			return
		}
		frames := (walFileSize(t, store) - 32) / (4096 + 24)
		if frames <= 0 {
			t.Error("no WAL frames to scale")
			return
		}
		walFrameBytes = (productionTrigger + 8<<20) / frames
	}
	t.Cleanup(func() { walCopyPhaseHook = originalCopy })
	entered := make(chan struct{}, 1)
	originalWriter := walWriterPhaseHook
	outrun := outrunTheHold(t, store)
	walWriterPhaseHook = func(ctx context.Context) {
		entered <- struct{}{}
		outrun(ctx)
	}
	t.Cleanup(func() { walWriterPhaseHook = originalWriter })
	finished := make(chan struct {
		pass WALCheckpoint
		err  error
	}, 1)
	go func() {
		pass, err := store.CheckpointWALIfLarge(context.Background(), productionTrigger, testWALWriterBudget)
		finished <- struct {
			pass WALCheckpoint
			err  error
		}{pass, err}
	}()
	select {
	case <-entered:
	case got := <-finished:
		t.Fatalf("catch-up ended before its writer phase: %+v, %v", got.pass, got.err)
	case <-time.After(30 * time.Second):
		t.Fatal("bounded catch-up did not reach its writer phase")
	}
	started := time.Now()
	if err := store.LogEvent(Event{Action: "hook_decision", Target: "during-over-limit-catch-up"}); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(started)
	got := <-finished
	if elapsed > 500*time.Millisecond {
		t.Fatalf("ordinary catch-up delayed a hook audit write for %v: %+v", elapsed, got.pass)
	}
	if got.err != nil || got.pass.LogBytes <= productionTrigger || got.pass.LogBytes >= WALEmergencyArmBytes || !got.pass.Bounded || !got.pass.WriterDeferred || got.pass.Restarted {
		t.Fatalf("catch-up: %+v, %v; want a deferred hold between trigger and emergency arm", got.pass, got.err)
	}
	if got.pass.HoldCap != walCatchUpCap || got.pass.WriterHeld > testWALWriterBudget || !store.WALOverLimit() {
		t.Fatalf("ordinary catch-up: %+v; want a %v cap inside the writer budget and WAL pressure", got.pass, walCatchUpCap)
	}
}

// outrunTheHold stands in for a copy under the writer that is still running
// when the catch-up's hold ends (the hook gets the hold's context). It returns
// only once the pass gave the writer connection back. Returning when the hold
// ends raced the pass's cap timer, which fires at the same instant: the copy
// that followed could finish first and count as a completed catch-up (seen on
// the Windows runner, whose timers fire in coarser steps).
func outrunTheHold(t *testing.T, store *Store) func(context.Context) {
	t.Helper()
	return func(hold context.Context) {
		<-hold.Done()
		wait, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := store.db.Conn(wait)
		if err != nil {
			t.Errorf("the writer connection did not come back after the hold: %v", err)
			return
		}
		_ = conn.Close()
	}
}

// overrideWALDuration sets one of the guard's timing variables for a test.
func overrideWALDuration(t *testing.T, variable *time.Duration, value time.Duration) {
	t.Helper()
	original := *variable
	*variable = value
	t.Cleanup(func() { *variable = original })
}

// Repeated misses keep the writer hold short. Once the slow copy clears,
// passive copying plus the short catch-up can restart the log.
func TestCheckpointWALIfLargeBoundedCatchUpKeepsTheHoldShortAfterEachMiss(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	logWALGuardEvents(t, store, 200)
	writeDuringEveryCopy(t, store)
	overrideWALDuration(t, &walCatchUpCap, 40*time.Millisecond)
	original := walWriterPhaseHook
	walWriterPhaseHook = outrunTheHold(t, store)
	t.Cleanup(func() { walWriterPhaseHook = original })
	for miss := range 3 {
		pass, err := store.CheckpointWALIfLarge(context.Background(), 0, testWALWriterBudget)
		if err != nil || !pass.Bounded {
			t.Fatalf("pass %d over the limit: %+v, %v; want a bounded catch-up", miss, pass, err)
		}
		if pass.HoldCap != walCatchUpCap || pass.WriterHeld > testWALWriterBudget {
			t.Fatalf("pass %d held %v with cap %v; want a %v cap inside %v", miss,
				pass.WriterHeld, pass.HoldCap, walCatchUpCap, testWALWriterBudget)
		}
		if pass.Restarted || !pass.WriterDeferred || !store.WALOverLimit() {
			t.Fatalf("pass %d gave the writer back early: %+v, over limit %t; want deferred and over the limit", miss, pass, store.WALOverLimit())
		}
	}
	walWriterPhaseHook = original
	if pass, err := store.CheckpointWALIfLarge(context.Background(), 0, testWALWriterBudget); err != nil || !pass.Restarted || store.WALOverLimit() {
		t.Fatalf("pass after the slow copy cleared: %+v, %v; over limit %t", pass, err, store.WALOverLimit())
	}
}

// Review of G-flood-wal round 2 (P1): a bounded catch-up that found no free
// writer within its wait gave up, and the next pass waited no longer. Each
// miss now doubles the wait, so a pass gets the writer once the hooks let it
// go, and the log restarts.
func TestCheckpointWALIfLargeBoundedCatchUpWaitsLongerForABusyWriter(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	logWALGuardEvents(t, store, 200)
	// Commits from another connection during every copy keep the copies
	// short of the end of the log while the store's writer is taken.
	other, err := sql.Open("sqlite", store.dbPath+"?_pragma=busy_timeout(5000)&_pragma=wal_autocheckpoint(0)")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.Exec(`CREATE TABLE zz_wal_guard_flood (n INTEGER)`); err != nil {
		t.Fatal(err)
	}
	original := walCopyPhaseHook
	walCopyPhaseHook = func(ctx context.Context) {
		if _, err := other.ExecContext(ctx, `INSERT INTO zz_wal_guard_flood VALUES (1)`); err != nil {
			t.Errorf("write during the copy: %v", err)
		}
	}
	t.Cleanup(func() { walCopyPhaseHook = original })
	overrideWALDuration(t, &walBoundedAcquireWait, 20*time.Millisecond)
	overrideWALDuration(t, &walBoundedAcquireMax, 10*time.Second)
	writer, err := store.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for miss := range 2 {
		pass, err := store.CheckpointWALIfLarge(context.Background(), 0, testWALWriterBudget)
		if err != nil || !pass.Bounded || pass.Restarted || !pass.WriterDeferred || pass.WriterHeld != 0 {
			t.Fatalf("miss %d with the writer taken: %+v, %v; want a deferred bounded catch-up that never held it", miss, pass, err)
		}
	}
	if policy := store.boundedCatchUpPolicy(testWALWriterBudget); policy.acquire != 4*walBoundedAcquireWait || policy.hold != walCatchUpCap {
		t.Fatalf("policy after two misses %+v; want the wait doubled twice and the hold unchanged", policy)
	}
	released := make(chan struct{})
	time.AfterFunc(150*time.Millisecond, func() {
		_ = writer.Close()
		close(released)
	})
	defer func() { <-released }()
	for pass := range 8 {
		got, err := store.CheckpointWALIfLarge(context.Background(), 0, testWALWriterBudget)
		if err != nil || !got.Bounded {
			t.Fatalf("pass %d: %+v, %v", pass, got, err)
		}
		if got.Restarted {
			store.walGuardMu.Lock()
			misses := store.walBoundedMisses
			store.walGuardMu.Unlock()
			if misses != 0 {
				t.Fatalf("misses after the restart = %d, want 0", misses)
			}
			return
		}
	}
	t.Fatal("no bounded catch-up restarted the log after the writer was free")
}

func TestWALEscalatedDoublesUpToItsCeiling(t *testing.T) {
	for misses, want := range []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second} {
		if got := walEscalated(2*time.Second, 30*time.Second, misses); got != want {
			t.Fatalf("walEscalated(2s, 30s, %d) = %v, want %v", misses, got, want)
		}
	}
	if got := walEscalated(time.Second, 10*time.Second, walBoundedMissesMax); got != 10*time.Second {
		t.Fatalf("walEscalated at the miss ceiling = %v, want 10s", got)
	}
}

// rel-1-0-2:GAP-0709: the copy on the dedicated connection is not bounded by
// the writer budget. A deadline loses all of a checkpoint's progress, so a
// copy that takes longer than the budget must still finish.
func TestCheckpointWALIfLargeCopyIsNotBoundByTheWriterBudget(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	logWALGuardEvents(t, store, 200)
	original := walCopyPhaseHook
	walCopyPhaseHook = func(context.Context) { time.Sleep(3 * testWALWriterBudget) }
	t.Cleanup(func() { walCopyPhaseHook = original })
	pass, err := store.CheckpointWALIfLarge(context.Background(), 0, testWALWriterBudget)
	if err != nil || !pass.Restarted {
		t.Fatalf("slow copy: %+v, %v; want the log brought to its end", pass, err)
	}
}

// The idle trim gives the writer connection back within its budget, the pass
// reports how long it really held it, and the connection keeps its busy
// timeout afterwards.
func TestCheckpointWALIfLargeWriterPhaseYieldsWithinBudget(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	logWALGuardEvents(t, store, 200)
	ctx := context.Background()
	if _, err := store.CheckpointWALIfLarge(ctx, math.MaxInt64, testWALWriterBudget); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	original := walWriterPhaseHook
	walWriterPhaseHook = func(ctx context.Context) {
		close(entered)
		<-ctx.Done()
	}
	t.Cleanup(func() { walWriterPhaseHook = original })
	type outcome struct {
		pass WALCheckpoint
		err  error
	}
	passDone := make(chan outcome, 1)
	go func() {
		pass, err := store.CheckpointWALIfLarge(ctx, 0, testWALWriterBudget)
		passDone <- outcome{pass, err}
	}()
	<-entered
	started := time.Now()
	if err := store.LogEvent(Event{Action: "hook_decision", Target: "during-writer-phase"}); err != nil {
		t.Fatalf("hook audit append during the writer phase: %v", err)
	}
	if elapsed := time.Since(started); elapsed > testWALWriterBudget+time.Second {
		t.Fatalf("hook audit append waited %s for the writer phase, budget %s", elapsed, testWALWriterBudget)
	}
	got := <-passDone
	if !errors.Is(got.err, context.DeadlineExceeded) {
		t.Fatalf("writer phase error = %v, want a deadline", got.err)
	}
	// rel-1-0-3 GAP-0288: a pass that yields still reports its real hold.
	if got.pass.WriterHeld < testWALWriterBudget {
		t.Fatalf("yielded pass reports a writer hold of %v; want at least the %v budget", got.pass.WriterHeld, testWALWriterBudget)
	}
	walWriterPhaseHook = original
	var timeout int
	if err := store.db.QueryRow(`PRAGMA busy_timeout`).Scan(&timeout); err != nil || timeout != auditBusyTimeoutMillis {
		t.Fatalf("writer busy_timeout after the pass = %d, %v; want %d", timeout, err, auditBusyTimeoutMillis)
	}
}

// While the last pass left the WAL over its limit, background writers wait
// (bounded) for a pass to bring it back, and ANALYZE waits for its next
// interval. Hook writes do not wait.
func TestBackgroundWritersWaitWhileTheWALIsOverItsLimit(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	originalWait, originalPoll := walBackgroundWait, walBackgroundPoll
	walBackgroundWait, walBackgroundPoll = 150*time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { walBackgroundWait, walBackgroundPoll = originalWait, originalPoll })
	ctx := context.Background()
	started := time.Now()
	if err := store.awaitWALHeadroom(ctx); err != nil || time.Since(started) > 50*time.Millisecond {
		t.Fatalf("headroom wait without WAL pressure took %v, %v; want none", time.Since(started), err)
	}
	store.walPressure.Store(true)
	started = time.Now()
	if err := store.awaitWALHeadroom(ctx); err != nil || time.Since(started) < walBackgroundWait {
		t.Fatalf("headroom wait under WAL pressure took %v, %v; want the %v bound", time.Since(started), err, walBackgroundWait)
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		store.walPressure.Store(false)
	}()
	started = time.Now()
	if err := store.awaitWALHeadroom(ctx); err != nil || time.Since(started) >= walBackgroundWait {
		t.Fatalf("headroom wait that the guard released took %v, %v; want it to end early", time.Since(started), err)
	}
	store.walPressure.Store(true)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := store.awaitWALHeadroom(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("headroom wait with a cancelled context = %v; want context.Canceled", err)
	}
	started = time.Now()
	if err := store.LogEvent(Event{Action: "hook_decision", Target: "under-pressure"}); err != nil || time.Since(started) >= walBackgroundWait {
		t.Fatalf("hook audit append under WAL pressure took %v, %v; want no wait", time.Since(started), err)
	}
	logWALGuardEvents(t, store, plannerStatsMinRows+1)
	if ran, err := store.RefreshPlannerStatistics(ctx); err != nil || ran {
		t.Fatalf("ANALYZE under WAL pressure ran=%v, %v; want it skipped", ran, err)
	}
	store.walPressure.Store(false)
	if ran, err := store.RefreshPlannerStatistics(ctx); err != nil || !ran {
		t.Fatalf("ANALYZE after the pressure ran=%v, %v; want it taken", ran, err)
	}
}

func TestAuditConnectionsBoundTheWALFile(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	var limit int64
	if err := store.db.QueryRow(`PRAGMA journal_size_limit`).Scan(&limit); err != nil || limit != auditWALJournalSizeLimitBytes {
		t.Fatalf("journal_size_limit = %d, %v; want %d", limit, err, auditWALJournalSizeLimitBytes)
	}
}

// walGuardSteps records the order of a pass's copies on the checkpoint
// connection (each with a commit during it, as in a hook flood), its syncs of
// the database file off the writer (each taking syncTakes) and its writer
// phase.
func walGuardSteps(t *testing.T, store *Store) func() []string {
	t.Helper()
	var mu sync.Mutex
	var steps []string
	record := func(step string) {
		mu.Lock()
		defer mu.Unlock()
		steps = append(steps, step)
	}
	originalCopy, originalSync, originalWriter := walCopyPhaseHook, walSyncPhaseHook, walWriterPhaseHook
	walCopyPhaseHook = func(context.Context) {
		if err := store.LogEvent(Event{Action: "hook_decision", Target: "wal-guard", Severity: "INFO", SessionID: "s"}); err != nil {
			t.Errorf("LogEvent during the copy: %v", err)
		}
		record("copy")
	}
	walSyncPhaseHook = func(context.Context) { record("sync") }
	walWriterPhaseHook = func(context.Context) { record("writer") }
	t.Cleanup(func() {
		walCopyPhaseHook, walSyncPhaseHook, walWriterPhaseHook = originalCopy, originalSync, originalWriter
	})
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(steps)
	}
}

// A round within walSettledSpan leaves the copy under the writer only a few
// pages, so the pass takes the writer right after its sync.
func TestCheckpointWALIfLargeTakesTheWriterAfterOneFastSync(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	logWALGuardEvents(t, store, 200)
	overrideWALDuration(t, &walSettledSpan, time.Hour)
	limit := catchUpLimit(t, store)
	steps := walGuardSteps(t, store)
	pass, err := store.CheckpointWALIfLarge(context.Background(), limit, testWALWriterBudget)
	if err != nil || !pass.Restarted || pass.Syncs != 1 {
		t.Fatalf("pass with a fast sync: %+v, %v; want one sync and the log brought to its end", pass, err)
	}
	if got, want := steps(), []string{"copy", "sync", "writer"}; !slices.Equal(got, want) {
		t.Fatalf("pass steps = %v; want %v", got, want)
	}
}

// Review of G-flood-wal round 3 (P1): on a slow audit disk the syncs before
// the catch-up took 8-26 s each, so a pass over the limit could spend its time
// on copies and syncs off the writer and run out of it before its bounded hold
// while the hooks kept appending. Over the limit the pass goes to the bounded
// catch-up right after the copy that found it over: no more copies, no syncs.
func TestCheckpointWALIfLargeOverTheLimitHoldsTheWriterWithoutSettling(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	logWALGuardEvents(t, store, 200)
	overrideWALDuration(t, &walSettledSpan, 5*time.Millisecond)
	// What this test pins is the order of the pass (one copy, no sync, then
	// the writer), not how fast a disk copies and syncs the ~15 MiB log under
	// the writer. With the 100 ms production cap that copy and sync missed the
	// cap on a Windows CI runner (100.7 ms held, WriterDeferred, no restart:
	// rel-1-0-6:GAP-0410), so the bounded hold here gets room to finish.
	overrideWALDuration(t, &walCatchUpCap, overLimitTestHoldCap)
	// A reader on an older snapshot keeps every copy off the writer more than
	// walCopyTargetFrames short of the end of the log, and each sync is
	// slower than walSettledSpan: under the limit that is six copies and
	// settle rounds before the writer. The reader ends once the writer is held.
	reader, err := openSQLite(store.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	snapshot, err := reader.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Rollback()
	var events int
	if err := snapshot.QueryRow(`SELECT count(*) FROM audit_events`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	var copies, syncs atomic.Int64
	originalCopy, originalSync, originalWriter := walCopyPhaseHook, walSyncPhaseHook, walWriterPhaseHook
	t.Cleanup(func() {
		walCopyPhaseHook, walSyncPhaseHook, walWriterPhaseHook = originalCopy, originalSync, originalWriter
	})
	walCopyPhaseHook = func(context.Context) {
		copies.Add(1)
		logWALGuardEvents(t, store, 100)
	}
	walSyncPhaseHook = func(context.Context) {
		syncs.Add(1)
		time.Sleep(4 * walSettledSpan)
	}
	var endSnapshot sync.Once
	walWriterPhaseHook = func(context.Context) {
		endSnapshot.Do(func() { _ = snapshot.Rollback() })
	}
	pass, err := store.CheckpointWALIfLarge(context.Background(), 0, 2*overLimitTestHoldCap)
	if err != nil || !pass.Bounded || !pass.Restarted || pass.Syncs != 0 {
		t.Fatalf("pass over the limit: %+v, %v; want a bounded catch-up with no sync before it that restarts the log", pass, err)
	}
	if copies.Load() != 1 || syncs.Load() != 0 {
		t.Fatalf("pass over the limit ran %d copies and %d syncs off the writer; want 1 and 0", copies.Load(), syncs.Load())
	}
}

// A missed bounded pass remains over the limit. Its next pass must still
// attempt the writer promptly: a slow off-writer sync in this branch used to
// consume the pass deadline while hooks kept appending frames.
func TestCheckpointWALIfLargeRepeatedOverLimitPassesNeverSettleBeforeTheWriter(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	logWALGuardEvents(t, store, 200)
	writeDuringEveryCopy(t, store)
	overrideWALDuration(t, &walCatchUpCap, 40*time.Millisecond)
	originalWriter, originalSync := walWriterPhaseHook, walSyncPhaseHook
	walWriterPhaseHook = outrunTheHold(t, store)
	var syncs atomic.Int64
	walSyncPhaseHook = func(context.Context) { syncs.Add(1) }
	t.Cleanup(func() { walWriterPhaseHook, walSyncPhaseHook = originalWriter, originalSync })
	for passNumber := range 3 {
		pass, err := store.CheckpointWALIfLarge(context.Background(), 0, testWALWriterBudget)
		if err != nil || !pass.Bounded || !pass.WriterDeferred || pass.Syncs != 0 || syncs.Load() != 0 {
			t.Fatalf("over-limit pass %d: %+v, %v; sync hooks %d, want immediate bounded catch-up", passNumber, pass, err, syncs.Load())
		}
		if !store.WALOverLimit() || pass.WriterHeld > testWALWriterBudget {
			t.Fatalf("over-limit pass %d lost pressure or exceeded writer budget: %+v", passNumber, pass)
		}
	}
}

// manualDeadlineContext is a pass context whose deadline passes when a test
// says so, so that a test of a pass that ran out of time does not depend on how
// long the copies before the point it targets take.
type manualDeadlineContext struct {
	context.Context
	done chan struct{}
	once sync.Once
}

func newManualDeadlineContext() *manualDeadlineContext {
	return &manualDeadlineContext{Context: context.Background(), done: make(chan struct{})}
}

func (c *manualDeadlineContext) Done() <-chan struct{} { return c.done }

func (c *manualDeadlineContext) Err() error {
	select {
	case <-c.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func (c *manualDeadlineContext) expire() { c.once.Do(func() { close(c.done) }) }

// Review of G-flood-wal round 3 (P1): a pass that ran out of time while the
// log was over the limit cleared the store's over-the-limit mark and left the
// bounded catch-up's misses as they were, so background writers went on and
// the next pass waited and held no longer. Its outcome is recorded now: the
// store stays marked and the next bounded catch-up waits and holds longer,
// also after a pass that failed before it measured the log.
func TestCheckpointWALIfLargePassThatRunsOutOfTimeKeepsThePressureAndEscalates(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	logWALGuardEvents(t, store, 200)
	writeDuringEveryCopy(t, store)
	overrideWALDuration(t, &walCatchUpCap, 40*time.Millisecond)
	// The pass's deadline passes only once the copy under the writer has
	// outrun its cap, never during the copies before it: a wall-clock deadline
	// raced the first copy on a slow runner.
	ctx := newManualDeadlineContext()
	original := walWriterPhaseHook
	walWriterPhaseHook = func(hold context.Context) {
		<-hold.Done()
		ctx.expire()
		<-ctx.Done()
	}
	t.Cleanup(func() { walWriterPhaseHook = original })
	pass, err := store.CheckpointWALIfLarge(ctx, 0, testWALWriterBudget)
	if !errors.Is(err, context.DeadlineExceeded) || !pass.Bounded || pass.Restarted {
		t.Fatalf("pass that ran out of time: %+v, %v; want a bounded catch-up cut by the deadline", pass, err)
	}
	if !store.WALOverLimit() {
		t.Fatal("a pass that ran out of time over the limit cleared the store's over-the-limit mark")
	}
	if policy := store.boundedCatchUpPolicy(testWALWriterBudget); policy.acquire != 2*walBoundedAcquireWait || policy.hold != walCatchUpCap {
		t.Fatalf("policy after a pass that ran out of time: %+v; want the wait doubled and the hold unchanged", policy)
	}
	walWriterPhaseHook = original
	cancelled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if _, err := store.CheckpointWALIfLarge(cancelled, 0, testWALWriterBudget); err == nil {
		t.Fatal("pass with a cancelled context succeeded")
	}
	if !store.WALOverLimit() || store.boundedCatchUpPolicy(testWALWriterBudget).acquire != 4*walBoundedAcquireWait || store.boundedCatchUpPolicy(testWALWriterBudget).hold != walCatchUpCap {
		t.Fatalf("after a pass that failed before measuring the log: over limit %t, policy %+v; want more acquisition time without a longer hold", store.WALOverLimit(), store.boundedCatchUpPolicy(testWALWriterBudget))
	}
}

// Review of G-flood-wal round 3 (P1): the bounded catch-up held the store's
// writer connection, which holds off the store's own hooks only. Another
// store or process with audit.db open that committed during every copy under
// the writer kept the copy short of the end of the log. Catch-up takes
// SQLite's write lock while it has the writer, and repeated passes must keep
// the hold short, retain all writes, and restart after the flood stops.
//
// GAP-2124: the other writer commits at fixed points (before each pass and
// during every copy before the catch-up) and tries to commit during every
// copy under the writer, through a connection that does not wait for a lock.
// A free-running flood goroutine and a 50 ms timer made the result depend on
// the runner's disk: on Windows a flood commit could hold SQLite's lock past
// the catch-up's lock wait (the pass then defers, as designed), and the timer
// sat inside the measured hold.
//
// rel-1-0-6:GAP-0246: the hold also contained the runner's own disk flushes
// (the copy under the writer syncs the log and the database file). On hosted
// Windows runners they set the hold, not this store's pages: restarted passes
// held the writer 508-514 ms against the 500 ms bound and one pass deferred
// at the 1 s cap (CI jobs 121366931387, 121981091285, 121986419185,
// 122736071620). As in the flood test (GAP-0024), the store's writer and
// checkpoint connections run without flushes (withoutDiskFlushes), so the
// bound times the catch-up and its lock, and requireNoDiskFlushes confirms
// the setting held through the passes.
func TestCheckpointWALIfLargeBoundedCatchUpHoldsOffAnotherWriter(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	withoutDiskFlushes(t, store)
	logWALGuardEvents(t, store, 200)
	originalFrameBytes := walFrameBytes
	walFrameBytes = 512 << 10 // each flooded pass crosses the hard ceiling without allocating it
	t.Cleanup(func() { walFrameBytes = originalFrameBytes })
	other, err := openSQLite(store.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.Exec(`CREATE TABLE zz_wal_guard_other (n INTEGER)`); err != nil {
		t.Fatal(err)
	}
	var inserted atomic.Int64
	insert := func() error {
		if _, err := other.Exec(`INSERT INTO zz_wal_guard_other VALUES (1)`); err != nil {
			return err
		}
		inserted.Add(1)
		return nil
	}
	// Under the writer a probe connection with busy_timeout 0 tries one
	// insert: SQLITE_BUSY means the catch-up held the other writer off, a
	// commit means it did not.
	probeDB, err := openSQLite(store.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer probeDB.Close()
	probe, err := probeDB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if _, err := probe.ExecContext(context.Background(), `PRAGMA busy_timeout = 0`); err != nil {
		t.Fatal(err)
	}
	originalCopy, originalWriter := walCopyPhaseHook, walWriterPhaseHook
	t.Cleanup(func() { walCopyPhaseHook, walWriterPhaseHook = originalCopy, originalWriter })
	// It commits during every copy before the catch-up, so no copy without
	// the lock reaches the end of the log, and tries to during every copy
	// under the writer.
	var flooding atomic.Bool
	flooding.Store(true)
	walCopyPhaseHook = func(context.Context) {
		if !flooding.Load() {
			return
		}
		if err := insert(); err != nil {
			t.Errorf("other writer during a copy: %v", err)
		}
	}
	var heldOff, committed atomic.Int64
	walWriterPhaseHook = func(context.Context) {
		if !flooding.Load() {
			return
		}
		_, err := probe.ExecContext(context.Background(), `INSERT INTO zz_wal_guard_other VALUES (1)`)
		switch {
		case err == nil:
			inserted.Add(1)
			committed.Add(1)
		case isSQLiteBusy(err):
			heldOff.Add(1)
		default:
			t.Errorf("other writer during the catch-up: %v", err)
		}
	}
	const passes = 4
	for i := range passes {
		logWALGuardEvents(t, store, 50)
		for range 20 {
			if err := insert(); err != nil {
				t.Fatalf("other writer before pass %d: %v", i, err)
			}
		}
		pass, err := store.CheckpointWALIfLarge(context.Background(), 0, testWALWriterBudget)
		if err != nil || !pass.Bounded || !pass.Restarted || pass.WriterDeferred || pass.HoldCap != walEmergencyCatchUpCap || pass.WriterHeld >= 500*time.Millisecond {
			t.Fatalf("pass %d with another writer flooding audit.db: %+v, %v; want a restart on every pass with a short observed writer hold", i, pass, err)
		}
	}
	requireNoDiskFlushes(t, store)
	flooding.Store(false)
	if committed.Load() != 0 || heldOff.Load() < passes {
		t.Fatalf("the other writer committed %d times under the writer and was held off %d times; want no commits under the writer and a lock on every pass", committed.Load(), heldOff.Load())
	}
	pass, err := store.CheckpointWALIfLarge(context.Background(), 0, testWALWriterBudget)
	if err != nil || !pass.Restarted {
		t.Fatalf("catch-up after the other writer stopped: %+v, %v; want a restarted log", pass, err)
	}
	var rows int64
	if err := other.QueryRow(`SELECT count(*) FROM zz_wal_guard_other`).Scan(&rows); err != nil || rows != inserted.Load() {
		t.Fatalf("other writer rows = %d, %v; want all %d it wrote", rows, err, inserted.Load())
	}
	if store.WALOverLimit() {
		t.Fatal("catch-up after the other writer stopped left the store marked over the WAL limit")
	}
}

// rel-1-0-3 GAP-0247, GAP-0136: audit.db is never memory-mapped on Windows,
// where a sync of a mapped database grew with its size and kept the log from
// being restarted. rel-1-0-6 GAP-0327: nor elsewhere, where the pages read
// through the map stayed resident and the gateway's RSS grew with the store.
// A Secure Client store keeps main's map (256 MiB off Windows, #1092) on
// every connection it opens, the judge-body store too.
func TestAuditConnectionsNeverMapTheDatabaseOutsideSecureClient(t *testing.T) {
	scWant := int64(256 << 20)
	if runtime.GOOS == "windows" {
		scWant = 0
	}
	for _, tc := range []struct {
		name string
		opts []StoreOption
		want int64
	}{{"standalone", nil, 0}, {"secure-client", []StoreOption{WithSecureClientSchema()}, scWant}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			store, err := NewStore(filepath.Join(dir, "audit.db"), tc.opts...)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if err := store.Init(); err != nil {
				t.Fatal(err)
			}
			checkpointDB, err := store.checkpointConn()
			if err != nil {
				t.Fatal(err)
			}
			durableDB, err := store.durableConn()
			if err != nil {
				t.Fatal(err)
			}
			bodies, err := NewJudgeBodyStoreForCutover(filepath.Join(dir, "judge_bodies.db"), store.StoreOptions()...)
			if err != nil {
				t.Fatal(err)
			}
			defer bodies.Close()
			for name, db := range map[string]*sql.DB{"writer": store.db, "checkpoint": checkpointDB, "durable": durableDB, "judge-body": bodies.db} {
				var size int64
				if err := db.QueryRow(`PRAGMA mmap_size`).Scan(&size); err != nil || size != tc.want {
					t.Fatalf("%s connection mmap_size = %d, %v; want %d", name, size, err, tc.want)
				}
			}
		})
	}
}

// rel-1-0-6 GAP-0273: after a flood on a per-user RHEL host the WAL file
// stayed at 52 MiB through ten idle minutes. Its log was fully copied, but
// the file was under the 64 MiB idle threshold, and a restart cuts it back
// only to journal_size_limit, so nothing ever shrank it. With the production
// threshold, an idle pass trims a file between the trickle size and
// journal_size_limit to zero, and keeps every event.
func TestCheckpointWALIfLargeTrimsAnIdleFileUnderTheJournalSizeLimit(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	details := string(make([]byte, 64<<10))
	written := 0
	// Past the trickle log (about 8 MiB), well under journal_size_limit.
	for walFileSize(t, store) <= int64(walTrickleFrames)*walFrameBytes+(1<<20) {
		if err := store.LogEvent(Event{Action: "hook_decision", Target: "wal-guard", Severity: "INFO", SessionID: "s", Details: details}); err != nil {
			t.Fatal(err)
		}
		written++
	}
	grown := walFileSize(t, store)
	if grown >= auditWALJournalSizeLimitBytes {
		t.Fatalf("WAL grew to %d bytes, want it under journal_size_limit", grown)
	}
	ctx := context.Background()
	pass, err := store.CheckpointWALIfLarge(ctx, math.MaxInt64, testWALWriterBudget)
	if err != nil || !pass.Restarted || pass.FileBytes != grown {
		t.Fatalf("first pass after the flood: %+v, %v; want the log copied and the file kept", pass, err)
	}
	pass, err = store.CheckpointWALIfLarge(ctx, math.MaxInt64, testWALWriterBudget)
	if err != nil || !pass.Truncated || pass.FileBytes != 0 {
		t.Fatalf("idle pass with a %d-byte WAL: %+v, %v; want it trimmed to zero", grown, pass, err)
	}
	if got := countWALGuardEvents(t, store); got != written {
		t.Fatalf("events after the trim = %d, want %d", got, written)
	}
	// A short log is left alone: its file is not trimmed on every pass.
	logWALGuardEvents(t, store, 3)
	small := walFileSize(t, store)
	if _, err := store.CheckpointWALIfLarge(ctx, math.MaxInt64, testWALWriterBudget); err != nil {
		t.Fatal(err)
	}
	pass, err = store.CheckpointWALIfLarge(ctx, math.MaxInt64, testWALWriterBudget)
	if err != nil || pass.Truncated || pass.FileBytes != small {
		t.Fatalf("idle pass with a short %d-byte WAL: %+v, %v; want it kept", small, pass, err)
	}
	if walIdleTrimBytes >= auditWALJournalSizeLimitBytes || walIdleTrimBytes < int64(walTrickleFrames)*walFrameBytes {
		t.Fatalf("idle trim threshold %d, want at least the trickle log (%d) and under journal_size_limit (%d)",
			walIdleTrimBytes, int64(walTrickleFrames)*walFrameBytes, auditWALJournalSizeLimitBytes)
	}
}
