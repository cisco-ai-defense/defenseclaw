// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A store first opened under Secure Client records the rejected_records
// migration without the table; opened later as a standalone store it gets
// the table, and the opt-in store can write (GAP-0072).
func TestSecureClientStoreOpenedStandaloneGetsTheRejectedRecordsTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	secureClient, err := NewStore(path, WithSecureClientSchema())
	if err != nil {
		t.Fatal(err)
	}
	if err := secureClient.Init(); err != nil {
		t.Fatal(err)
	}
	if present, err := tableExists(secureClient.db, "rejected_records"); err != nil || present {
		t.Fatalf("Secure Client store has rejected_records=%v err=%v", present, err)
	}
	if err := secureClient.Close(); err != nil {
		t.Fatal(err)
	}

	standalone, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := standalone.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = standalone.Close() })
	if present, err := tableExists(standalone.db, "rejected_records"); err != nil || !present {
		t.Fatalf("standalone reopen of a Secure Client store: rejected_records=%v err=%v", present, err)
	}
	if err := standalone.InsertRejectedRecords(t.Context(), []RejectedRecordRow{rejectedTestRow(time.Now(), "reopened")}, RejectedRecordsDefaultRows); err != nil {
		t.Fatalf("insert after the standalone reopen: %v", err)
	}
	if count, err := standalone.CountRejectedRecords(t.Context()); err != nil || count != 1 {
		t.Fatalf("rows=%d err=%v, want 1", count, err)
	}
	// Init stays idempotent on a store that already has the table.
	if err := standalone.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := again.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = again.Close() })
	if count, err := again.CountRejectedRecords(t.Context()); err != nil || count != 1 {
		t.Fatalf("rows after a second Init=%d err=%v, want 1", count, err)
	}
}

// A trim of a table under its cap is a read only: it takes no write turn, so
// the writer's trim after every batch does not wait behind another writer
// while the store is not full (GAP-0072). Over the cap it still trims.
func TestTrimRejectedRecordsUnderTheCapTakesNoWriteTurn(t *testing.T) {
	store, _ := newRetentionStores(t)
	base := time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)
	rows := make([]RejectedRecordRow, 0, RejectedRecordMaxBatch)
	for index := 0; index < RejectedRecordMaxBatch; index++ {
		rows = append(rows, rejectedTestRow(base.Add(time.Duration(index)*time.Second), "under"))
	}
	if err := store.InsertRejectedRecords(t.Context(), rows, RejectedRecordsMinRows); err != nil {
		t.Fatal(err)
	}

	turn, err := store.writeBaton.acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	started := time.Now()
	deleted, more, trimErr := store.TrimRejectedRecords(ctx, RejectedRecordsMinRows, RejectedRecordTrimBatch)
	cancel()
	turn()
	if trimErr != nil || deleted != 0 || more {
		t.Fatalf("trim under the cap with the write turn held: deleted=%d more=%v err=%v after %s, want a read-only no-op",
			deleted, more, trimErr, time.Since(started))
	}

	// An empty table is under every cap too.
	empty, _ := newRetentionStores(t)
	if deleted, more, err := empty.TrimRejectedRecords(t.Context(), RejectedRecordsMinRows, RejectedRecordTrimBatch); err != nil || deleted != 0 || more {
		t.Fatalf("trim of an empty table: deleted=%d more=%v err=%v", deleted, more, err)
	}

	for batch := 0; batch < 7; batch++ {
		if err := store.InsertRejectedRecords(t.Context(), rows, RejectedRecordsMinRows); err != nil {
			t.Fatal(err)
		}
	}
	deleted, more, err = store.TrimRejectedRecords(t.Context(), RejectedRecordsMinRows, RejectedRecordTrimBatch)
	if err != nil || deleted != 8*RejectedRecordMaxBatch-RejectedRecordsMinRows || more {
		t.Fatalf("trim over the cap: deleted=%d more=%v err=%v", deleted, more, err)
	}
	if count, _ := store.CountRejectedRecords(t.Context()); count != RejectedRecordsMinRows {
		t.Fatalf("rows after trim=%d, want %d", count, RejectedRecordsMinRows)
	}
}

// The under-cap check reads the two ends of the rowid, never the whole table
// (review of GAP-0072: MAX(id) - MIN(id) in one SELECT is a full scan).
func TestRejectedRecordsSpanQueryReadsOnlyTheRowidEnds(t *testing.T) {
	store, _ := newRetentionStores(t)
	rows, err := store.db.QueryContext(t.Context(), "EXPLAIN QUERY PLAN "+rejectedRecordsSpanQuery)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close() //nolint:errcheck
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(plan) == 0 {
		t.Fatal("no query plan")
	}
	for _, detail := range plan {
		if strings.HasPrefix(strings.TrimSpace(detail), "SCAN") {
			t.Fatalf("span query plan %q scans the table", plan)
		}
	}
}
