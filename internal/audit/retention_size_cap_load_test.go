// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"fmt"
	"testing"
	"time"
)

// substrate-1:GAP-0570: under 50 actors a Substrate gateway replica wrote
// about 4 GiB of audit store in an hour, four times its 1 GiB cap, and the
// cap never deleted the newest hour, so the store filled its 4 GiB volume and
// every hook failed closed. Here an hour of rows is about twice an 8 MiB cap;
// a pass every simulated minute must keep the used pages under the cap, and
// the file inside the twice-the-cap volume the chart requires, deleting
// oldest first.
func TestRetentionSizeCapHoldsWhenAnHourOfRowsExceedsTheCap(t *testing.T) {
	const (
		capMiB        = 8
		rowsPerMinute = 150
		minutes       = 75
	)
	store, judge := newRetentionStores(t)
	clock := time.Date(2026, 11, 17, 21, 0, 0, 0, time.UTC)
	reaper, err := newRetentionReaperWithHooks(store, judge, 7, RetentionOptions{}, retentionHooks{
		now: func() time.Time { return clock }, yield: noRetentionYield,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := reaper.UpdateMaxStoreMB(capMiB); err != nil {
		t.Fatal(err)
	}
	capBytes := int64(capMiB) << 20
	var tenMinuteBytes, peak, deletes int64
	for minute := range minutes {
		clock = clock.Add(time.Minute)
		seedSizedAuditRowsWithSpacing(t, store, fmt.Sprintf("m%03d", minute), rowsPerMinute,
			clock, time.Minute/rowsPerMinute)
		if minute == 9 && deletes == 0 {
			tenMinuteBytes = usedStoreBytes(t, store)
		}
		result, err := reaper.Run(t.Context())
		if err != nil {
			t.Fatalf("minute %d: %v", minute, err)
		}
		deletes += result.RowsDeleted[RetentionAuditEvents]
		used := usedStoreBytes(t, store)
		peak = max(peak, used)
		if used > capBytes || result.CapNotReached {
			t.Fatalf("minute %d: the store uses %d bytes after a pass, cap %d (deleted %d rows so far, shortfall %t, reason %q)",
				minute, used, capBytes, deletes, result.CapNotReached, result.CapReason)
		}
		var pages, pageSize int64
		if err := store.db.QueryRow(`SELECT (SELECT page_count FROM pragma_page_count()),
			(SELECT page_size FROM pragma_page_size())`).Scan(&pages, &pageSize); err != nil {
			t.Fatal(err)
		}
		if file := pages * pageSize; file > 2*capBytes {
			t.Fatalf("minute %d: audit.db is %d bytes, over twice the cap", minute, file)
		}
	}
	if hour := 6 * tenMinuteBytes; hour <= capBytes {
		t.Fatalf("an hour of rows is about %d bytes, not over the %d byte cap; the test does not load the store enough", hour, capBytes)
	}
	if deletes == 0 {
		t.Fatal("the cap deleted nothing")
	}
	// Oldest first: the newest minute is all there.
	if kept := countAuditRows(t, store, `id LIKE ?`, fmt.Sprintf("m%03d-%%", minutes-1)); kept != rowsPerMinute {
		t.Fatalf("newest minute kept %d rows, want %d", kept, rowsPerMinute)
	}
	t.Logf("cap %d MiB: peak used %d bytes, %d rows deleted over %d minutes", capMiB, peak, deletes, minutes)
}
