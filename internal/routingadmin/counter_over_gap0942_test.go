// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingadmin

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestGAP0942OverKeysReadOnlyTheBudgetWindow (RV6 P5): 300 over-limit keys
// of a daily budget, each with 35 days of history. The by-key read with
// Over returns one row per key (today's), not every day of the keep window
// (23 per key before), so over keys never push a read toward its page
// limit. A key this process holds still reads every day of the window.
func TestGAP0942OverKeysReadOnlyTheBudgetWindow(t *testing.T) {
	lc := NewLocalCounter(t.TempDir())
	defer lc.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	const keys, days = 300, 35
	var rows []SeedRow
	for k := 0; k < keys; k++ {
		for d := 0; d < days; d++ {
			rows = append(rows, SeedRow{Day: now.AddDate(0, 0, -d).Format(time.DateOnly), Key: fmt.Sprintf("actor:daily:%016x", k), USD: 1})
		}
	}
	if err := lc.Push(ctx, "epoch-other-replica", rows); err != nil {
		t.Fatal(err)
	}
	since := KeepSince(now)
	today := now.Truncate(24 * time.Hour)
	over := []OverQuery{{Prefix: "actor:daily:", Since: today, Limit: 0.5, Max: 4096}}
	got, err := lc.TotalsPage(ctx, "epoch-mine-000", since, TotalsQuery{ByKey: true, Over: over})
	if err != nil {
		t.Fatal(err)
	}
	day := today.Format(time.DateOnly)
	for _, r := range got {
		if r.Day != day {
			t.Fatalf("over key row %+v outside the budget window (%s)", r, day)
		}
	}
	if len(got) != keys {
		t.Fatalf("over keys: %d rows, want %d (one per key)", len(got), keys)
	}
	held := fmt.Sprintf("actor:daily:%016x", 7)
	got, err = lc.TotalsPage(ctx, "epoch-mine-000", since, TotalsQuery{ByKey: true, Keys: []string{held}, Over: over})
	if err != nil {
		t.Fatal(err)
	}
	var heldRows int
	for _, r := range got {
		if r.Key == held {
			heldRows++
		}
	}
	window := int(today.Sub(since.UTC().Truncate(24*time.Hour)).Hours()/24) + 1
	if heldRows != window || len(got) != keys-1+window {
		t.Fatalf("held key: %d rows (want %d, the keep window), total %d (want %d)", heldRows, window, len(got), keys-1+window)
	}
}
