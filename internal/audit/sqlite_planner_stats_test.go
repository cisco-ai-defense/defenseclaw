// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
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
