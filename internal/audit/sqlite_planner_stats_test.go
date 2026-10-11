// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
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
