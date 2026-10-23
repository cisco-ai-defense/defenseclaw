// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// journalRows is a journal bound of rows rows and room for any test
// occurrence.
func journalRows(rows int) HookDeliveryJournalLimits {
	return HookDeliveryJournalLimits{Rows: rows, OccurrenceBytes: 1 << 20, Bytes: 1 << 30}
}

// journalIDs reads the whole journal in batches of size and returns the
// row ids in the order read.
func journalIDs(t *testing.T, store *Store, size int) []string {
	t.Helper()
	var ids []string
	var after HookDeliveryJournalEntry
	for {
		entries, err := store.HookDeliveries(t.Context(), after, size)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) > size {
			t.Fatalf("a read of at most %d rows returned %d", size, len(entries))
		}
		for _, entry := range entries {
			ids = append(ids, entry.ProcessID+"/"+entry.ID)
			after = entry
		}
		if len(entries) < size {
			return ids
		}
	}
}

// The journal keeps every process's rows, oldest first, survives a reopen
// of the store, and tolerates a store that never journaled a call.
func TestHookDeliveryJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	store := openTestStore(t, path)
	ctx := t.Context()

	// A store that never journaled a call has no table: nothing to recover,
	// nothing to record or forget.
	if entries, err := store.HookDeliveries(ctx, HookDeliveryJournalEntry{}, 10); err != nil || len(entries) != 0 {
		t.Fatalf("journal of a fresh store = %v, %v; want empty", entries, err)
	}
	if found, err := store.RecordHookDeliveryVerdict(ctx, "missing", []byte(`{}`), journalRows(10)); err != nil || found {
		t.Fatalf("verdict on a fresh store = %t, %v; want no row and no error", found, err)
	}
	if err := store.ForgetHookDelivery(ctx, "missing"); err != nil {
		t.Fatalf("forget on a fresh store: %v", err)
	}
	if exists, err := tableExists(store.db, "hook_delivery_journal"); err != nil || exists {
		t.Fatalf("journal table on a fresh store = %t, %v; want none until first use", exists, err)
	}

	for _, row := range []struct{ id, process string }{{"a", "dead"}, {"b", "live"}, {"c", "dead"}} {
		if err := store.JournalHookDelivery(ctx, row.id, row.process, []byte(`{"ID":"`+row.id+`"}`), journalRows(10)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.JournalHookDelivery(ctx, "a", "dead", []byte(`{}`), journalRows(10)); err == nil {
		t.Fatal("a second row under one id was journaled")
	}
	for _, bad := range []struct {
		id, process, occurrence string
		limits                  HookDeliveryJournalLimits
	}{
		{"", "p", "{}", journalRows(10)}, {"x", "", "{}", journalRows(10)}, {"x", "p", "", journalRows(10)},
		{"x", "p", "{}", journalRows(0)}, {"x", "p", "{}", HookDeliveryJournalLimits{Rows: 10, Bytes: 1 << 20}},
		{"x", "p", "{}", HookDeliveryJournalLimits{Rows: 10, OccurrenceBytes: 1 << 10}},
	} {
		if err := store.JournalHookDelivery(ctx, bad.id, bad.process, []byte(bad.occurrence), bad.limits); err == nil {
			t.Fatalf("journaled an incomplete row %+v", bad)
		}
	}
	if entry, found, err := store.HookDelivery(ctx, "missing"); err != nil || found {
		t.Fatalf("missing journal row = %+v, %t, %v", entry, found, err)
	}
	if found, err := store.RecordHookDeliveryVerdict(ctx, "c", []byte(`{"ID":"c","Decided":{}}`), journalRows(10)); err != nil || !found {
		t.Fatalf("verdict of row c = %t, %v; want recorded", found, err)
	}
	if found, err := store.RecordHookDeliveryVerdict(ctx, "missing", []byte(`{}`), journalRows(10)); err != nil || found {
		t.Fatalf("verdict of a missing row = %t, %v; want no row and no error", found, err)
	}

	_ = store.Close()
	store = openTestStore(t, path)
	if entry, found, err := store.HookDelivery(ctx, "c"); err != nil || !found ||
		string(entry.Occurrence) != `{"ID":"c","Decided":{}}` {
		t.Fatalf("recorded journal row after reopen = %+v, %t, %v", entry, found, err)
	}
	entries, err := store.HookDeliveries(ctx, HookDeliveryJournalEntry{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || entries[0].ID != "a" || entries[1].ProcessID != "live" ||
		string(entries[2].Occurrence) != `{"ID":"c","Decided":{}}` {
		t.Fatalf("journal after a reopen = %+v, want a, b of live, and c with its verdict", entries)
	}
	if err := store.ForgetHookDelivery(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(journalIDs(t, store, 10), ","); got != "live/b,dead/c" {
		t.Fatalf("journal after forgetting a = %s, want live/b,dead/c", got)
	}

	_ = store.Close()
	if err := store.JournalHookDelivery(ctx, "d", "live", []byte(`{}`), journalRows(10)); err == nil {
		t.Fatal("a closed store journaled a call")
	}
	if _, err := store.RecordHookDeliveryVerdict(ctx, "b", []byte(`{}`), journalRows(10)); err == nil {
		t.Fatal("a closed store recorded a verdict")
	}
	if _, err := store.HookDeliveries(ctx, HookDeliveryJournalEntry{}, 10); err == nil {
		t.Fatal("a closed store listed its journal")
	}
}

// A journal at its limit refuses the next row, so rows whose records cannot
// be written never grow it without bound; a forgotten row makes room again.
// A read returns at most its limit, and batches read after one another
// return every row once.
func TestHookDeliveryJournalIsBounded(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "audit.db"))
	ctx := t.Context()
	const limit = 5
	for _, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		if err := store.JournalHookDelivery(ctx, id, "p", []byte(`{}`), journalRows(limit)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.JournalHookDelivery(ctx, "r6", "p", []byte(`{}`), journalRows(limit)); !errors.Is(err, ErrHookDeliveryJournalFull) {
		t.Fatalf("row past the limit = %v, want ErrHookDeliveryJournalFull", err)
	}
	if got := strings.Join(journalIDs(t, store, 2), ","); got != "p/r1,p/r2,p/r3,p/r4,p/r5" {
		t.Fatalf("journal read in batches of 2 = %s, want r1..r5 once each", got)
	}
	if _, err := store.HookDeliveries(ctx, HookDeliveryJournalEntry{}, 0); err == nil {
		t.Fatal("an unbounded read was served")
	}
	if err := store.ForgetHookDelivery(ctx, "r2"); err != nil {
		t.Fatal(err)
	}
	if err := store.JournalHookDelivery(ctx, "r6", "p", []byte(`{}`), journalRows(limit)); err != nil {
		t.Fatalf("row after one was forgotten: %v", err)
	}
	if got := strings.Join(journalIDs(t, store, 3), ","); got != "p/r1,p/r3,p/r4,p/r5,p/r6" {
		t.Fatalf("journal = %s, want r1, r3..r6", got)
	}
}

// The journal is bounded in bytes too, so large hook fields cannot fill the
// audit volume during an outage: an occurrence over its own limit is
// refused, a row that would take the journal past its total is refused as
// full, and a recorded verdict keeps to both limits, leaving the row as it
// was when it does not fit.
func TestHookDeliveryJournalBoundsItsBytes(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "audit.db"))
	ctx := t.Context()
	limits := HookDeliveryJournalLimits{Rows: 100, OccurrenceBytes: 64, Bytes: 100}
	occurrence := func(size int) []byte { return []byte(strings.Repeat("x", size)) }

	if err := store.JournalHookDelivery(ctx, "huge", "p", occurrence(65), limits); !errors.Is(err, ErrHookDeliveryOccurrenceTooLarge) {
		t.Fatalf("occurrence over its limit = %v, want ErrHookDeliveryOccurrenceTooLarge", err)
	}
	for _, id := range []string{"b1", "b2"} {
		if err := store.JournalHookDelivery(ctx, id, "p", occurrence(40), limits); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.JournalHookDelivery(ctx, "b3", "p", occurrence(40), limits); !errors.Is(err, ErrHookDeliveryJournalFull) {
		t.Fatalf("row past the byte limit = %v, want ErrHookDeliveryJournalFull", err)
	}
	if err := store.JournalHookDelivery(ctx, "b3", "p", occurrence(20), limits); err != nil {
		t.Fatalf("row that fits the byte limit exactly: %v", err)
	}
	if got := strings.Join(journalIDs(t, store, 10), ","); got != "p/b1,p/b2,p/b3" {
		t.Fatalf("journal = %s, want b1, b2, b3 and no refused row", got)
	}

	if found, err := store.RecordHookDeliveryVerdict(ctx, "b1", occurrence(41), limits); !found || !errors.Is(err, ErrHookDeliveryJournalFull) {
		t.Fatalf("verdict past the byte limit = %t, %v; want the row and ErrHookDeliveryJournalFull", found, err)
	}
	if _, err := store.RecordHookDeliveryVerdict(ctx, "b1", occurrence(65), limits); !errors.Is(err, ErrHookDeliveryOccurrenceTooLarge) {
		t.Fatalf("verdict over the occurrence limit = %v, want ErrHookDeliveryOccurrenceTooLarge", err)
	}
	entries, err := store.HookDeliveries(ctx, HookDeliveryJournalEntry{}, 1)
	if err != nil || len(entries) != 1 || len(entries[0].Occurrence) != 40 {
		t.Fatalf("row b1 after refused verdicts = %+v, %v; want its 40-byte occurrence", entries, err)
	}
	if found, err := store.RecordHookDeliveryVerdict(ctx, "b1", occurrence(30), limits); !found || err != nil {
		t.Fatalf("verdict within the limits = %t, %v; want recorded", found, err)
	}
	if found, err := store.RecordHookDeliveryVerdict(ctx, "missing", occurrence(10), limits); found || err != nil {
		t.Fatalf("verdict of a missing row = %t, %v; want no row and no error", found, err)
	}
}
