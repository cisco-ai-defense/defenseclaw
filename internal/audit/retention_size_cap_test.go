// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// seedSizedAuditRows writes count audit rows of about 1 KiB, one a minute,
// the newest at newest.
func seedSizedAuditRows(t *testing.T, store *Store, prefix string, count int, newest time.Time) {
	t.Helper()
	tx, err := store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	statement, err := tx.Prepare(`INSERT INTO audit_events
		(id, timestamp, action, actor, details, severity) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		t.Fatal(err)
	}
	padding := strings.Repeat("x", 1024)
	for index := 0; index < count; index++ {
		at := newest.Add(-time.Duration(count-1-index) * time.Minute)
		if _, err := statement.Exec(fmt.Sprintf("%s-%05d", prefix, index), at.Format(time.RFC3339Nano),
			"scan", "operator", padding, "LOW"); err != nil {
			t.Fatal(err)
		}
	}
	_ = statement.Close()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func noRetentionYield(context.Context) error { return nil }

func usedStoreBytes(t *testing.T, store *Store) int64 {
	t.Helper()
	var pages, free, size int64
	if err := store.db.QueryRow(`SELECT (SELECT page_count FROM pragma_page_count()),
		(SELECT freelist_count FROM pragma_freelist_count()),
		(SELECT page_size FROM pragma_page_size())`).Scan(&pages, &free, &size); err != nil {
		t.Fatal(err)
	}
	return (pages - free) * size
}

func countAuditRows(t *testing.T, store *Store, where string, args ...any) int {
	t.Helper()
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE `+where, args...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// #1384: max_store_mb is off by default. Set, a run over the cap deletes the
// oldest history, through the same batches as day retention, until the used
// pages are under the cap, never the newest hour; under the cap it deletes
// nothing more.
func TestRetentionSizeCapDeletesOldestHistoryUntilUnderTheCap(t *testing.T) {
	store, judge := newRetentionStores(t)
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	seedSizedAuditRows(t, store, "old", 4000, now.Add(-2*time.Hour))
	seedSizedAuditRows(t, store, "recent", 20, now.Add(-time.Minute))
	before := usedStoreBytes(t, store)
	if before < 4<<20 {
		t.Fatalf("seeded store uses %d bytes, want over 4 MiB", before)
	}

	// Off by default: everything is inside the 7-day window and stays.
	reaper := newRetentionReaperAt(t, store, judge, 7, now, RetentionOptions{}, retentionHooks{yield: noRetentionYield})
	if reaper.MaxStoreMB() != 0 {
		t.Fatalf("default max_store_mb = %d, want 0", reaper.MaxStoreMB())
	}
	result, err := reaper.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if result.SizeCapped || result.RowsDeleted[RetentionAuditEvents] != 0 {
		t.Fatalf("days-only run: capped %t, deleted %d; want nothing", result.SizeCapped, result.RowsDeleted[RetentionAuditEvents])
	}

	capMiB := int64(before>>20) / 2
	if err := reaper.UpdateMaxStoreMB(capMiB); err != nil {
		t.Fatal(err)
	}
	result, err = reaper.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !result.SizeCapped || result.RowsDeleted[RetentionAuditEvents] == 0 || !result.Backlog {
		t.Fatalf("capped run: capped %t, deleted %d, backlog %t; want the oldest rows deleted",
			result.SizeCapped, result.RowsDeleted[RetentionAuditEvents], result.Backlog)
	}
	// The cutoff is an estimate: a run left over the cap asks for a
	// follow-up run (Backlog), which gets the store under it.
	deleted := result.RowsDeleted[RetentionAuditEvents]
	for runs := 1; result.Backlog && usedStoreBytes(t, store) > capMiB<<20; runs++ {
		if runs > 5 {
			t.Fatalf("store still uses %d bytes after %d capped runs, cap %d", usedStoreBytes(t, store), runs, capMiB<<20)
		}
		if result, err = reaper.Run(t.Context()); err != nil {
			t.Fatal(err)
		}
		deleted += result.RowsDeleted[RetentionAuditEvents]
	}
	if used := usedStoreBytes(t, store); used > capMiB<<20 {
		t.Fatalf("store uses %d bytes after the capped runs, cap %d", used, capMiB<<20)
	}
	if kept := countAuditRows(t, store, `id LIKE ?`, "recent-%"); kept != 20 {
		t.Fatalf("newest-hour rows kept %d, want all 20", kept)
	}
	var oldestKept string
	if err := store.db.QueryRow(`SELECT MIN(id) FROM audit_events WHERE id LIKE ?`, "old-%").Scan(&oldestKept); err != nil {
		t.Fatal(err)
	}
	if oldestKept != fmt.Sprintf("old-%05d", deleted) {
		t.Fatalf("oldest kept row %s after %d deletions, want the oldest rows deleted first", oldestKept, deleted)
	}

	// Under the cap now: the next run deletes nothing and leaves no backlog.
	result, err = reaper.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if result.SizeCapped || result.RowsDeleted[RetentionAuditEvents] != 0 || result.Backlog {
		t.Fatalf("run under the cap: capped %t, deleted %d, backlog %t", result.SizeCapped, result.RowsDeleted[RetentionAuditEvents], result.Backlog)
	}
}

// A size cap with retention_days 0 still runs, and never deletes the newest
// hour even when only that is over the cap.
func TestRetentionSizeCapWithoutDaysKeepsTheNewestHour(t *testing.T) {
	store, judge := newRetentionStores(t)
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	seedSizedAuditRows(t, store, "recent", 50, now)
	reaper := newRetentionReaperAt(t, store, judge, 0, now, RetentionOptions{}, retentionHooks{yield: noRetentionYield})
	if err := reaper.UpdateMaxStoreMB(1); err != nil {
		t.Fatal(err)
	}
	seedSizedAuditRows(t, store, "old", 3000, now.Add(-2*time.Hour))
	result, err := reaper.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if result.Disabled || !result.SizeCapped {
		t.Fatalf("days 0 with a cap: disabled %t, capped %t", result.Disabled, result.SizeCapped)
	}
	if kept := countAuditRows(t, store, `id LIKE ?`, "recent-%"); kept != 50 {
		t.Fatalf("newest-hour rows kept %d, want all 50", kept)
	}
	for _, bad := range []int64{-1, RetentionMaxStoreMB + 1} {
		if err := reaper.UpdateMaxStoreMB(bad); err == nil {
			t.Fatalf("max_store_mb %d accepted", bad)
		}
	}
}
