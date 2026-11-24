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
	seedSizedAuditRowsWithSpacing(t, store, prefix, count, newest, time.Minute)
}

func seedSizedAuditRowsWithSpacing(
	t *testing.T, store *Store, prefix string, count int, newest time.Time, spacing time.Duration,
) {
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
		at := newest.Add(-time.Duration(count-1-index) * spacing)
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
// pages are under the cap; under the cap it deletes nothing more.
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
	for runs := 1; result.Backlog && usedStoreBytes(t, store) > retentionSizeCapStart(capMiB<<20); runs++ {
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
		t.Fatalf("newest rows kept %d, want all 20 (oldest first)", kept)
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
	if result.CapNotReached || result.StoreSizeBytes != 0 || result.StoreCapBytes != 0 || result.CapReason != "" {
		t.Fatalf("run under the cap reported a shortfall: %+v", result)
	}
}

// A completed cap pass may leave more than the cap when no row is older than
// the cutoff it computed (here every row shares one instant). The result must
// report the measured used pages rather than treating a successful SQL run as
// success against the size target.
func TestRetentionSizeCapReportsWhenThePassStopsAboveTheCap(t *testing.T) {
	store, judge := newRetentionStores(t)
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	seedSizedAuditRowsWithSpacing(t, store, "recent", 2000, now, 0)
	reaper := newRetentionReaperAt(t, store, judge, 7, now, RetentionOptions{}, retentionHooks{yield: noRetentionYield})
	if err := reaper.UpdateMaxStoreMB(1); err != nil {
		t.Fatal(err)
	}
	result, err := reaper.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !result.CapNotReached || result.StoreSizeBytes != usedStoreBytes(t, store) ||
		result.StoreCapBytes != 1<<20 || result.CapReason != RetentionCapRetainedHistory {
		t.Fatalf("cap shortfall = %+v; used=%d", result, usedStoreBytes(t, store))
	}
	if result.RowsDeleted[RetentionAuditEvents] != 0 {
		t.Fatalf("rows at the cutoff instant deleted: %d", result.RowsDeleted[RetentionAuditEvents])
	}
}

func TestRetentionSizeCapNamesActiveCorrelationState(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyDefenseClaw)
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	// The edges of the live session are inside the 7-day window: an edge
	// past it goes even on a live session (rel-1-0-10:GAP-0034), one inside
	// it stays under the size cap, so the cap is not reached.
	old := now.Add(-2 * 24 * time.Hour)
	link := func(tx *CorrelationTx, event CorrelationEvent) {
		if _, err := tx.PutRelationship(t.Context(), CorrelationRelationshipInput{
			FromKind: CorrelationNodeSemanticEvent, FromID: string(event.SemanticEventID),
			ToKind: CorrelationNodeSession, ToID: "active-session", Type: CorrelationBelongsTo,
			Method: CorrelationMethodReported, RuleID: "membership", RuleVersion: "v1",
			Status: CorrelationRelationshipActive, ObservedAt: old,
		}); err != nil {
			t.Fatal(err)
		}
	}
	seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: old, mutate: func(tx *CorrelationTx, event CorrelationEvent) {
		if err := tx.PutCursor(t.Context(), CorrelationCursor{
			ConnectorInstanceID: instance.ConnectorInstanceID, SessionID: "active-session", AgentID: "active-agent",
			Phase: "active", Sequence: 1, LastSemanticEventID: event.SemanticEventID,
			ProfileVersion: instance.ProfileVersion, Active: true, UpdatedAt: now.Add(-time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		link(tx, event)
	}})
	for range 400 {
		seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: old, mutate: link})
	}
	reaper := newRetentionReaperAt(t, store, nil, 7, now, RetentionOptions{}, retentionHooks{yield: noRetentionYield})
	if err := reaper.UpdateMaxStoreMB(1); err != nil {
		t.Fatal(err)
	}
	result, err := reaper.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !result.CapNotReached || result.CapReason != RetentionCapActiveCorrelation ||
		result.StoreSizeBytes <= result.StoreCapBytes || result.StoreSizeBytes != usedStoreBytes(t, store) {
		t.Fatalf("active-state shortfall = %+v", result)
	}
	if result.RowsDeleted[RetentionCorrelationRelationships] != 0 ||
		countRetentionRows(t, store.db, "correlation_relationships") != 401 {
		t.Fatalf("active relationships were removed or not seeded: %+v", result.RowsDeleted)
	}
}

// A size cap with retention_days 0 still runs, and the cap wins over the
// newest hour (substrate-1:GAP-0570): when that hour alone is over the cap,
// its oldest rows go, down to seven tenths of the cap.
func TestRetentionSizeCapWithoutDaysDeletesInsideTheNewestHour(t *testing.T) {
	store, judge := newRetentionStores(t)
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	reaper := newRetentionReaperAt(t, store, judge, 0, now, RetentionOptions{}, retentionHooks{yield: noRetentionYield})
	if err := reaper.UpdateMaxStoreMB(1); err != nil {
		t.Fatal(err)
	}
	seedSizedAuditRowsWithSpacing(t, store, "hour", 3000, now, time.Second)
	if used := usedStoreBytes(t, store); used <= 1<<20 {
		t.Fatalf("seeded store uses %d bytes, want over the 1 MiB cap", used)
	}
	result, err := reaper.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if result.Disabled || !result.SizeCapped || result.RowsDeleted[RetentionAuditEvents] == 0 {
		t.Fatalf("days 0 with a cap: disabled %t, capped %t, deleted %d", result.Disabled, result.SizeCapped,
			result.RowsDeleted[RetentionAuditEvents])
	}
	for runs := 1; result.Backlog && usedStoreBytes(t, store) > 1<<20; runs++ {
		if runs > 5 {
			t.Fatalf("store still uses %d bytes after %d capped runs", usedStoreBytes(t, store), runs)
		}
		if result, err = reaper.Run(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if used := usedStoreBytes(t, store); used > 1<<20 || result.CapNotReached {
		t.Fatalf("store uses %d bytes after the capped runs (shortfall %t), cap 1 MiB", used, result.CapNotReached)
	}
	if kept := countAuditRows(t, store, `id = ?`, "hour-02999"); kept != 1 {
		t.Fatal("the newest row was deleted; the cap deletes oldest first")
	}
	for _, bad := range []int64{-1, RetentionMaxStoreMB + 1} {
		if err := reaper.UpdateMaxStoreMB(bad); err == nil {
			t.Fatalf("max_store_mb %d accepted", bad)
		}
	}
}

// substrate-1:GAP-0538 (b): the controller's size check reads page counts
// only; it says a pass is due once the used pages pass nine tenths of the
// cap, the size at which a pass starts deleting.
func TestRetentionStoreOverCapStartReadsTheUsedPages(t *testing.T) {
	store, judge := newRetentionStores(t)
	now := time.Date(2026, 11, 17, 21, 0, 0, 0, time.UTC)
	reaper := newRetentionReaperAt(t, store, judge, 7, now, RetentionOptions{}, retentionHooks{yield: noRetentionYield})
	if over, err := reaper.StoreOverCapStart(t.Context()); err != nil || over {
		t.Fatalf("no cap: over %t, err %v", over, err)
	}
	seedSizedAuditRows(t, store, "load", 3000, now)
	used := usedStoreBytes(t, store)
	for _, c := range []struct {
		capBytes int64
		want     bool
	}{
		{capBytes: used * 2, want: false},
		{capBytes: used, want: true},
		{capBytes: used * 100 / 89, want: false},
		{capBytes: used * 100 / 91, want: true},
	} {
		reaper.maxStoreBytes.Store(c.capBytes)
		over, err := reaper.StoreOverCapStart(t.Context())
		if err != nil || over != c.want {
			t.Fatalf("used %d, cap %d: over %t (err %v), want %t", used, c.capBytes, over, err, c.want)
		}
	}
	// The check deleted nothing.
	if kept := countAuditRows(t, store, `id LIKE ?`, "load-%"); kept != 3000 {
		t.Fatalf("the size check changed the store: %d rows", kept)
	}
}
