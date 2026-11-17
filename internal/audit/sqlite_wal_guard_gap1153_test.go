// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"math"
	"sync/atomic"
	"testing"
	"time"
)

// rel-1-0-10:GAP-1153: under a 50-100 calls/s hook flood on a per-user Mac
// the WAL grew from 114 to 5786 MiB in two minutes, and every guard pass held
// the hooks for the full 470 ms emergency hold without restarting the log.
// SQLite syncs audit.db only at the end of a copy that reached the live end
// of the log, which a copy off the writer never does under a flood, so the
// copy under the writer synced every page that the copies since the last
// restart had written. A pass over the limit took the writer without syncing
// first, so that work grew with every pass and never fit in the hold.
//
// The model: the copy under the writer costs walGAP1153PerCopy for each copy
// off the writer whose pages are not yet synced (a sync of the database file
// off the writer resets the count), and one more for its own. A flood keeps
// every copy off the writer short of the end of the log; three passes under
// the limit leave three copies unsynced, as a flood that has been running
// does. Each over-limit pass must then restart the log inside the ordinary
// bounded hold, and no audit row is lost.
const walGAP1153PerCopy = 30 * time.Millisecond

func TestGAP1153OverLimitPassSyncsOffTheWriterSoTheLogRestartsUnderAFlood(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	logWALGuardEvents(t, store, 200)
	writes := writeDuringEveryCopy(t, store)
	flood, originalSync, originalWriter := walCopyPhaseHook, walSyncPhaseHook, walWriterPhaseHook
	t.Cleanup(func() { walSyncPhaseHook, walWriterPhaseHook = originalSync, originalWriter })
	var unsynced atomic.Int64
	walCopyPhaseHook = func(ctx context.Context) {
		flood(ctx)
		unsynced.Add(1)
	}
	walSyncPhaseHook = func(context.Context) { unsynced.Store(0) }
	walWriterPhaseHook = func(hold context.Context) {
		timer := time.NewTimer(walGAP1153PerCopy * time.Duration(unsynced.Load()+1))
		defer timer.Stop()
		select {
		case <-timer.C:
			// The copy reached the end of the log and synced audit.db.
			unsynced.Store(0)
		case <-hold.Done():
		}
	}
	for pass := range 3 {
		got, err := store.CheckpointWALIfLarge(context.Background(), math.MaxInt64, testWALWriterBudget)
		if err != nil || got.Restarted || got.WriterHeld != 0 {
			t.Fatalf("flood pass %d under the limit: %+v, %v; want a copy off the writer that does not reach the end", pass, got, err)
		}
	}
	if unsynced.Load() != 3 {
		t.Fatalf("copies off the writer left unsynced = %d; want 3", unsynced.Load())
	}
	hold := min(walCatchUpCap, testWALWriterBudget/2)
	if walGAP1153PerCopy*5 <= hold {
		t.Fatalf("model: four unsynced copies must outlast the %v hold", hold)
	}
	for pass := range 4 {
		got, err := store.CheckpointWALIfLarge(context.Background(), 0, testWALWriterBudget)
		if err != nil || !got.Bounded || got.HoldCap != hold {
			t.Fatalf("over-limit pass %d: %+v, %v; want a bounded catch-up with the %v hold", pass, got, err, hold)
		}
		if !got.Restarted || got.WriterDeferred || got.Syncs == 0 {
			t.Fatalf("over-limit pass %d under a flood: %+v (copies unsynced at the writer phase: %d); "+
				"want a sync off the writer, then a restart inside the hold", pass, got, unsynced.Load())
		}
		if store.WALOverLimit() {
			t.Fatalf("over-limit pass %d restarted the log but left the store marked over the limit", pass)
		}
		logWALGuardEvents(t, store, 20)
		for range 3 {
			if _, err := store.CheckpointWALIfLarge(context.Background(), math.MaxInt64, testWALWriterBudget); err != nil {
				t.Fatal(err)
			}
		}
	}
	if got, want := countWALGuardEvents(t, store), 200+4*20+int(writes.Load()); got != want {
		t.Fatalf("audit rows after the passes = %d; want all %d written", got, want)
	}
}

// rel-1-0-10:GAP-1153, a disk slower than the hooks' page writes: every
// bounded hold reaches its cap without restarting the log. After
// walCappedHoldsBeforeBackoff of them the passes leave the writer alone for
// a rest that doubles with each further capped hold, and the first restart
// ends it, so a disk that catches up again gets a hold on every pass.
func TestGAP1153CappedHoldsBackOffUntilTheLogRestarts(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	logWALGuardEvents(t, store, 200)
	writes := writeDuringEveryCopy(t, store)
	overrideWALDuration(t, &walCatchUpCap, 40*time.Millisecond)
	now := time.Now()
	originalClock, originalWriter := walClock, walWriterPhaseHook
	t.Cleanup(func() { walClock, walWriterPhaseHook = originalClock, originalWriter })
	walClock = func() time.Time { return now }
	walWriterPhaseHook = outrunTheHold(t, store)
	pass := func(label string) WALCheckpoint {
		t.Helper()
		got, err := store.CheckpointWALIfLarge(context.Background(), 0, testWALWriterBudget)
		if err != nil || !got.Bounded || !got.WriterDeferred || got.Restarted {
			t.Fatalf("%s: %+v, %v; want a bounded pass that does not restart the log", label, got, err)
		}
		return got
	}
	for index := range walCappedHoldsBeforeBackoff {
		if got := pass("capped hold"); got.HoldBackoff || got.WriterHeld < got.HoldCap {
			t.Fatalf("pass %d: %+v; want a hold that reaches its cap", index, got)
		}
	}
	for index := range 3 {
		if got := pass("rest"); !got.HoldBackoff || got.WriterHeld != 0 {
			t.Fatalf("pass %d after %d capped holds: %+v; want the writer left alone", index, walCappedHoldsBeforeBackoff, got)
		}
	}
	now = now.Add(walHoldBackoffBase)
	if got := pass("after the first rest"); got.HoldBackoff || got.WriterHeld < got.HoldCap {
		t.Fatalf("pass after the rest: %+v; want one more capped hold", got)
	}
	now = now.Add(walHoldBackoffBase)
	if got := pass("inside the doubled rest"); !got.HoldBackoff {
		t.Fatalf("pass inside the doubled rest: %+v; want the writer left alone", got)
	}
	// The disk catches up: the next hold restarts the log and ends the rest.
	walWriterPhaseHook = originalWriter
	now = now.Add(walHoldBackoffBase)
	got, err := store.CheckpointWALIfLarge(context.Background(), 0, testWALWriterBudget)
	if err != nil || got.HoldBackoff || !got.Restarted {
		t.Fatalf("pass after the disk caught up: %+v, %v; want a hold that restarts the log", got, err)
	}
	logWALGuardEvents(t, store, 20)
	if got, err := store.CheckpointWALIfLarge(context.Background(), 0, testWALWriterBudget); err != nil || got.HoldBackoff || got.WriterHeld == 0 {
		t.Fatalf("pass after the restart: %+v, %v; want a hold again without a rest", got, err)
	}
	if got, want := countWALGuardEvents(t, store), 220+int(writes.Load()); got != want {
		t.Fatalf("audit rows after the passes = %d; want all %d written", got, want)
	}
}
