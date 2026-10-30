// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The planner statistics are taken once the history is long enough and again
// each time it has doubled, so ledger lookups keep using the selective index
// as the database grows (GAP-0233).
func TestRefreshPlannerStatisticsFollowsTheHistory(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	ctx := context.Background()
	logEvents := func(n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if err := store.LogEvent(Event{Action: "hook_decision", Target: "planner-stats", Severity: "INFO", SessionID: "s"}); err != nil {
				t.Fatalf("LogEvent: %v", err)
			}
		}
	}
	refresh := func(want bool, when string) {
		t.Helper()
		if ran, err := store.RefreshPlannerStatistics(ctx); err != nil || ran != want {
			t.Fatalf("%s: ran=%v err=%v, want ran=%v", when, ran, err, want)
		}
	}
	statRows := func() (n int) {
		t.Helper()
		if err := store.db.QueryRow("SELECT COUNT(*) FROM sqlite_stat1").Scan(&n); err != nil {
			t.Fatalf("sqlite_stat1: %v", err)
		}
		return n
	}

	refresh(false, "empty history")
	logEvents(plannerStatsMinRows)
	refresh(true, "history reached the minimum")
	first := statRows()
	if first == 0 {
		t.Fatal("ANALYZE ran but left no statistics")
	}
	logEvents(100)
	refresh(false, "history grew by a tenth")
	logEvents(plannerStatsMinRows)
	refresh(true, "history doubled")
}

// A gateway start does not take the statistics again when an earlier process
// took them for a history of about this size: ANALYZE counts every index
// entry on the store's one connection, which on a multi-gigabyte store with a
// cold page cache closed the hooks of the first half minute after a start
// (GAP-1790). Once the history has doubled from what the statistics counted,
// they are taken again, with every index and index-less table covered.
func TestPlannerStatisticsFromAnEarlierProcessStayCurrentAcrossAStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	ctx := context.Background()
	open := func() *Store {
		t.Helper()
		store, err := NewStore(path)
		if err != nil {
			t.Fatalf("NewStore: %v", err)
		}
		if err := store.Init(); err != nil {
			t.Fatalf("Init: %v", err)
		}
		return store
	}
	logEvents := func(store *Store, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if err := store.LogEvent(Event{Action: "hook_decision", Target: "planner-stats", Severity: "INFO", SessionID: "s"}); err != nil {
				t.Fatalf("LogEvent: %v", err)
			}
		}
	}
	first := open()
	logEvents(first, plannerStatsMinRows)
	if ran, err := first.RefreshPlannerStatistics(ctx); err != nil || !ran {
		t.Fatalf("first process: ran=%v err=%v, want the statistics taken", ran, err)
	}
	logEvents(first, plannerStatsMinRows/2)
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	restarted := open()
	defer restarted.Close()
	if ran, err := restarted.RefreshPlannerStatistics(ctx); err != nil || ran {
		t.Fatalf("after a start with current statistics: ran=%v err=%v, want no ANALYZE", ran, err)
	}
	logEvents(restarted, plannerStatsMinRows/2)
	if ran, err := restarted.RefreshPlannerStatistics(ctx); err != nil || !ran {
		t.Fatalf("history doubled from the stored statistics: ran=%v err=%v, want them taken", ran, err)
	}
	statKeys := func() map[string]bool {
		t.Helper()
		rows, err := restarted.db.QueryContext(ctx, "SELECT tbl, COALESCE(idx, '') FROM sqlite_stat1")
		if err != nil {
			t.Fatalf("sqlite_stat1: %v", err)
		}
		defer rows.Close()
		keys := map[string]bool{}
		for rows.Next() {
			var tbl, idx string
			if err := rows.Scan(&tbl, &idx); err != nil {
				t.Fatalf("scan sqlite_stat1: %v", err)
			}
			keys[tbl+"/"+idx] = true
		}
		return keys
	}
	perTarget := statKeys()
	if len(perTarget) == 0 {
		t.Fatal("the refresh left no statistics")
	}
	if _, err := restarted.db.ExecContext(ctx, "ANALYZE"); err != nil {
		t.Fatalf("full ANALYZE: %v", err)
	}
	full := statKeys()
	for key := range full {
		if !perTarget[key] {
			t.Errorf("a full ANALYZE writes statistics for %s that the refresh did not", key)
		}
	}
}

// Measuring the history reads one end of each history table, never the whole
// table: it runs at every start and every 30 s on the store's one connection.
func TestPlannerStatisticsSizeQueryReadsOnlyTheEndsOfTheHistory(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	rows, err := store.db.Query("EXPLAIN QUERY PLAN " + plannerStatsSizeQuery())
	if err != nil {
		t.Fatalf("EXPLAIN QUERY PLAN: %v", err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatalf("scan plan: %v", err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("plan rows: %v", err)
	}
	for _, step := range plan {
		for _, table := range plannerStatsTables {
			if strings.HasPrefix(step, "SCAN "+table) {
				t.Fatalf("history size query scans %s: plan %q", table, plan)
			}
		}
	}
}

// An upgrade from 1.0.2, 1.0.3 or 1.0.4 rebuilds the sparse-key indexes
// (migrateSparseKeyIndexes), and DROP INDEX deletes their statistics while
// every other index keeps its own. The stored statistics still count as
// current, so the first pass after the start takes the statistics of just
// the rebuilt indexes: without them SQLite prefers a rebuilt index over the
// selective analyzed one (the GAP-0233 misplan). RV-ha7-1 of GAP-1790.
func TestPlannerStatisticsCoverIndexesAMigrationRebuilt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	ctx := context.Background()
	open := func() *Store {
		t.Helper()
		store, err := NewStore(path)
		if err != nil {
			t.Fatalf("NewStore: %v", err)
		}
		if err := store.Init(); err != nil {
			t.Fatalf("Init: %v", err)
		}
		return store
	}
	first := open()
	for i := 0; i < plannerStatsMinRows; i++ {
		if err := first.LogEvent(Event{Action: "hook_decision", Target: "planner-stats", Severity: "INFO", SessionID: "s",
			RunID: "run-" + strings.Repeat("x", i%7), RequestID: "req-" + strings.Repeat("y", i%5)}); err != nil {
			t.Fatalf("LogEvent: %v", err)
		}
	}
	if ran, err := first.RefreshPlannerStatistics(ctx); err != nil || !ran {
		t.Fatalf("first process: ran=%v err=%v, want the statistics taken", ran, err)
	}
	// The migration of an older store: each sparse-key index is dropped and
	// created again (here from the partial form through the full one).
	if err := setSparseKeyIndexForm(first.db, false); err != nil {
		t.Fatalf("rebuild full: %v", err)
	}
	if err := setSparseKeyIndexForm(first.db, true); err != nil {
		t.Fatalf("rebuild partial: %v", err)
	}
	statKeys := func(store *Store) map[string]bool {
		t.Helper()
		rows, err := store.db.QueryContext(ctx, "SELECT tbl, COALESCE(idx, '') FROM sqlite_stat1")
		if err != nil {
			t.Fatalf("sqlite_stat1: %v", err)
		}
		defer rows.Close()
		keys := map[string]bool{}
		for rows.Next() {
			var tbl, idx string
			if err := rows.Scan(&tbl, &idx); err != nil {
				t.Fatalf("scan sqlite_stat1: %v", err)
			}
			keys[tbl+"/"+idx] = true
		}
		return keys
	}
	if keys := statKeys(first); keys["audit_events/idx_audit_run_id"] {
		t.Fatal("fixture: the rebuild kept the statistics of idx_audit_run_id")
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	restarted := open()
	defer restarted.Close()
	if _, err := restarted.RefreshPlannerStatistics(ctx); err != nil {
		t.Fatalf("after the start: %v", err)
	}
	after := statKeys(restarted)
	for _, key := range []string{"audit_events/idx_audit_run_id", "audit_events/idx_audit_request_id"} {
		if !after[key] {
			t.Errorf("after the first pass of the new process %s has no statistics", key)
		}
	}
	if _, err := restarted.db.ExecContext(ctx, "ANALYZE"); err != nil {
		t.Fatalf("full ANALYZE: %v", err)
	}
	for key := range statKeys(restarted) {
		if !after[key] {
			t.Errorf("a full ANALYZE writes statistics for %s that the first pass did not", key)
		}
	}
	// Once covered, a later pass of the same history takes nothing.
	if ran, err := restarted.RefreshPlannerStatistics(ctx); err != nil || ran {
		t.Fatalf("second pass: ran=%v err=%v, want no ANALYZE", ran, err)
	}
}

// GAP-1790: ANALYZE gives the store's one connection back to a hook write
// that waits for it, instead of holding it for the whole read of an index
// (tens of seconds on a cold multi-gigabyte store, while every hook queued
// behind it). The statistics are taken at the next pass.
func TestPlannerStatisticsYieldTheConnectionToAWaitingWrite(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	ctx := context.Background()
	logEvents := func(n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if err := store.LogEvent(Event{Action: "hook_decision", Target: "planner-yield", Severity: "INFO", SessionID: "s"}); err != nil {
				t.Fatalf("LogEvent: %v", err)
			}
		}
	}
	// The first statistics, then a history that has doubled since: the
	// refresh is the pass that yields.
	logEvents(plannerStatsMinRows + 10)
	if ran, err := store.RefreshPlannerStatistics(ctx); err != nil || !ran {
		t.Fatalf("first statistics = (%t, %v), want taken", ran, err)
	}
	logEvents(2 * (plannerStatsMinRows + 10))
	held := make(chan struct{})
	var calls atomic.Int32
	previous := plannerStatsAnalyzePhaseHook
	plannerStatsAnalyzePhaseHook = func(ctx context.Context) {
		if calls.Add(1) != 1 {
			return
		}
		close(held)
		// A slow cold read of a large index.
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
	t.Cleanup(func() { plannerStatsAnalyzePhaseHook = previous })
	type refresh struct {
		ran bool
		err error
	}
	first := make(chan refresh, 1)
	go func() {
		ran, err := store.RefreshPlannerStatistics(ctx)
		first <- refresh{ran, err}
	}()
	select {
	case <-held:
	case <-time.After(10 * time.Second):
		t.Fatal("ANALYZE never started")
	}
	started := time.Now()
	if err := store.LogEvent(Event{Action: "hook_decision", Target: "planner-yield-hook", Severity: "INFO", SessionID: "s"}); err != nil {
		t.Fatalf("hook write: %v", err)
	}
	if waited := time.Since(started); waited > 2*time.Second {
		t.Fatalf("a hook write waited %s behind ANALYZE", waited)
	}
	got := <-first
	if got.err != nil || got.ran {
		t.Fatalf("interrupted refresh = (%t, %v), want (false, nil)", got.ran, got.err)
	}
	if ran, err := store.RefreshPlannerStatistics(ctx); err != nil || !ran {
		t.Fatalf("next refresh = (%t, %v), want the statistics taken", ran, err)
	}
	if next := store.plannerStatsNext.Load(); next != 0 {
		t.Fatalf("a complete pass left the resume point at target %d", next)
	}
}

// GAP-1790 (rc.10, managed RHEL, 6.8 GB store): the statements that queued
// for the connection together with ANALYZE, and were still waiting once it
// took it, are not new pool waits. The refresh kept the connection for 13 s
// with five of them waiting, because it only looked for waits that started
// after it held the connection, and the hook caller limit was full so none
// did. ANALYZE now yields to them as well.
func TestPlannerStatisticsYieldToStatementsQueuedBeforeIt(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	ctx := context.Background()
	rows := 0
	logEvents := func(n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if err := store.LogEvent(Event{Action: "hook_decision", Target: "planner-queued", Severity: "INFO", SessionID: "s"}); err != nil {
				t.Fatalf("LogEvent: %v", err)
			}
		}
		rows += n
	}
	logEvents(plannerStatsMinRows + 10)
	if ran, err := store.RefreshPlannerStatistics(ctx); err != nil || !ran {
		t.Fatalf("first statistics = (%t, %v), want taken", ran, err)
	}
	const queued = 16
	previousConn, previousPhase := plannerStatsBeforeConnHook, plannerStatsAnalyzePhaseHook
	t.Cleanup(func() {
		plannerStatsBeforeConnHook, plannerStatsAnalyzePhaseHook = previousConn, previousPhase
	})
	// database/sql gives the released connection to any one waiter, so
	// ANALYZE may be served last, with nobody left waiting: then the trial
	// shows nothing and runs again.
	for trial := 0; trial < 4; trial++ {
		logEvents(rows)
		var pending atomic.Int32
		drained := make(chan struct{})
		var connCalls, phaseCalls atomic.Int32
		plannerStatsBeforeConnHook = func() {
			if connCalls.Add(1) != 1 {
				return
			}
			holder, err := store.db.Conn(ctx)
			if err != nil {
				t.Errorf("hold the connection: %v", err)
				return
			}
			base := store.db.Stats().WaitCount
			pending.Store(queued)
			for i := 0; i < queued; i++ {
				go func() {
					if err := store.LogEvent(Event{Action: "hook_decision", Target: "planner-queued-hook", Severity: "INFO", SessionID: "s"}); err != nil {
						t.Errorf("queued hook write: %v", err)
					}
					if pending.Add(-1) == 0 {
						close(drained)
					}
				}()
			}
			for store.db.Stats().WaitCount < base+queued {
				time.Sleep(time.Millisecond)
			}
			// Release once ANALYZE has queued with them.
			go func() {
				for store.db.Stats().WaitCount < base+queued+1 {
					time.Sleep(time.Millisecond)
				}
				_ = holder.Close()
			}()
		}
		held := make(chan int32, 1)
		plannerStatsAnalyzePhaseHook = func(ctx context.Context) {
			if phaseCalls.Add(1) != 1 {
				return
			}
			held <- pending.Load()
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
			}
		}
		type refresh struct {
			ran bool
			err error
		}
		first := make(chan refresh, 1)
		go func() {
			ran, err := store.RefreshPlannerStatistics(ctx)
			first <- refresh{ran, err}
		}()
		var waiting int32
		select {
		case waiting = <-held:
		case <-time.After(10 * time.Second):
			t.Fatal("ANALYZE never started")
		}
		started := time.Now()
		select {
		case <-drained:
		case <-time.After(10 * time.Second):
			t.Fatal("queued hook writes never finished")
		}
		waited := time.Since(started)
		got := <-first
		if waiting == 0 {
			continue
		}
		if waited > 2*time.Second {
			t.Fatalf("%d hook writes queued with ANALYZE waited %s behind it", waiting, waited)
		}
		if got.err != nil || got.ran {
			t.Fatalf("interrupted refresh = (%t, %v), want (false, nil)", got.ran, got.err)
		}
		plannerStatsBeforeConnHook, plannerStatsAnalyzePhaseHook = previousConn, previousPhase
		if ran, err := store.RefreshPlannerStatistics(ctx); err != nil || !ran {
			t.Fatalf("next refresh = (%t, %v), want the statistics taken", ran, err)
		}
		return
	}
	t.Fatal("ANALYZE was served last in every trial; no statement was queued with it")
}

// GAP-2505: the first statistics of a history (a store from before 1.0.3)
// also give the store's one connection back to a hook write that waits for
// it. On a 3.9 GB managed RHEL store that pass ran about 100 s, and while it
// kept the connection nearly every benign hook was denied as "did not answer
// in time". The hooks' lookups do not need the statistics to plan their
// seeks (TestHookLedgerLookupsSeekTheFullKeyWithoutPlannerStatistics).
func TestFirstPlannerStatisticsYieldTheConnectionToAWaitingWrite(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	ctx := context.Background()
	for i := 0; i < plannerStatsMinRows+10; i++ {
		if err := store.LogEvent(Event{Action: "hook_decision", Target: "planner-first", Severity: "INFO", SessionID: "s"}); err != nil {
			t.Fatalf("LogEvent: %v", err)
		}
	}
	held := make(chan struct{})
	var calls atomic.Int32
	previous := plannerStatsAnalyzePhaseHook
	plannerStatsAnalyzePhaseHook = func(ctx context.Context) {
		if calls.Add(1) != 1 {
			return
		}
		close(held)
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
	t.Cleanup(func() { plannerStatsAnalyzePhaseHook = previous })
	type refresh struct {
		ran bool
		err error
	}
	first := make(chan refresh, 1)
	go func() {
		ran, err := store.RefreshPlannerStatistics(ctx)
		first <- refresh{ran, err}
	}()
	select {
	case <-held:
	case <-time.After(10 * time.Second):
		t.Fatal("ANALYZE never started")
	}
	started := time.Now()
	if err := store.LogEvent(Event{Action: "hook_decision", Target: "planner-first-hook", Severity: "INFO", SessionID: "s"}); err != nil {
		t.Fatalf("hook write: %v", err)
	}
	if waited := time.Since(started); waited > 2*time.Second {
		t.Fatalf("a hook write waited %s behind the first ANALYZE", waited)
	}
	got := <-first
	if got.err != nil || got.ran {
		t.Fatalf("interrupted first statistics = (%t, %v), want (false, nil)", got.ran, got.err)
	}
	if ran, err := store.RefreshPlannerStatistics(ctx); err != nil || !ran {
		t.Fatalf("next pass = (%t, %v), want the statistics taken", ran, err)
	}
	var stats int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM sqlite_stat1").Scan(&stats); err != nil || stats == 0 {
		t.Fatalf("sqlite_stat1 rows = %d (%v), want the first statistics", stats, err)
	}
}

// GAP-2505 (RV-ha8-2505): a first pass that yielded part way, then a gateway
// restart (rpm upgrade, reboot). The history tables now have statistics, so
// the new process takes the pass for the targets that have none, and that
// pass gives the store's connection back to a waiting hook write as well.
// Before, it kept the connection for the rest of the targets, the share of
// the ~100 s first statistics of a multi-gigabyte store from 1.0.2 that the
// yielded pass left.
func TestPlannerStatisticsAfterAPartialFirstPassAndARestartYieldToAWaitingWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	ctx := context.Background()
	open := func() *Store {
		t.Helper()
		store, err := NewStore(path)
		if err != nil {
			t.Fatalf("NewStore: %v", err)
		}
		if err := store.Init(); err != nil {
			t.Fatalf("Init: %v", err)
		}
		return store
	}
	logEvent := func(store *Store, target string) {
		t.Helper()
		if err := store.LogEvent(Event{Action: "hook_decision", Target: target, Severity: "INFO", SessionID: "s"}); err != nil {
			t.Fatalf("LogEvent: %v", err)
		}
	}
	previous := plannerStatsAnalyzePhaseHook
	t.Cleanup(func() { plannerStatsAnalyzePhaseHook = previous })
	// holdAt holds the n-th ANALYZE of a pass open, as a slow cold read of a
	// large index, and reports when it holds.
	holdAt := func(n int32, hold time.Duration) <-chan struct{} {
		held := make(chan struct{})
		var calls atomic.Int32
		plannerStatsAnalyzePhaseHook = func(ctx context.Context) {
			if calls.Add(1) != n {
				return
			}
			close(held)
			select {
			case <-ctx.Done():
			case <-time.After(hold):
			}
		}
		return held
	}
	type refresh struct {
		ran bool
		err error
	}
	// waitingWrite starts a pass, writes while the held ANALYZE runs and
	// returns how long the write waited.
	waitingWrite := func(store *Store, held <-chan struct{}, target string) (time.Duration, refresh) {
		t.Helper()
		pass := make(chan refresh, 1)
		go func() {
			ran, err := store.RefreshPlannerStatistics(ctx)
			pass <- refresh{ran, err}
		}()
		select {
		case <-held:
		case <-time.After(10 * time.Second):
			t.Fatal("ANALYZE never started")
		}
		started := time.Now()
		logEvent(store, target)
		waited := time.Since(started)
		return waited, <-pass
	}
	statRows := func(store *Store) int {
		t.Helper()
		var n int
		if err := store.db.QueryRow("SELECT COUNT(*) FROM sqlite_stat1").Scan(&n); err != nil {
			t.Fatalf("sqlite_stat1: %v", err)
		}
		return n
	}

	first := open()
	for i := 0; i < plannerStatsMinRows+10; i++ {
		logEvent(first, "planner-partial")
	}
	// The first statistics yield at the fourth target.
	if _, got := waitingWrite(first, holdAt(4, 5*time.Second), "planner-partial-hook"); got.err != nil || got.ran {
		t.Fatalf("yielded first pass = (%t, %v), want (false, nil)", got.ran, got.err)
	}
	partial := statRows(first)
	if partial == 0 {
		t.Fatal("fixture: the yielded first pass took no statistics")
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	restarted := open()
	defer restarted.Close()
	waited, got := waitingWrite(restarted, holdAt(1, 3*time.Second), "planner-restart-hook")
	if waited > 2*time.Second {
		t.Fatalf("after a partial first pass and a restart a hook write waited %s behind ANALYZE", waited)
	}
	if got.err != nil || got.ran {
		t.Fatalf("interrupted pass after the restart = (%t, %v), want (false, nil)", got.ran, got.err)
	}
	plannerStatsAnalyzePhaseHook = previous
	if ran, err := restarted.RefreshPlannerStatistics(ctx); err != nil || !ran {
		t.Fatalf("next pass = (%t, %v), want the missing statistics taken", ran, err)
	}
	missing, err := restarted.plannerStatsMissingTargets(ctx, mustPlannerStatsTargets(t, restarted))
	if err != nil {
		t.Fatalf("missing targets: %v", err)
	}
	if len(missing) != 0 || statRows(restarted) <= partial {
		t.Fatalf("after the pass %d targets still have no statistics (%d rows, %d before)", len(missing), statRows(restarted), partial)
	}
}

func mustPlannerStatsTargets(t *testing.T, store *Store) []string {
	t.Helper()
	targets, err := store.plannerStatsTargets(context.Background())
	if err != nil {
		t.Fatalf("planner statistics targets: %v", err)
	}
	return targets
}
