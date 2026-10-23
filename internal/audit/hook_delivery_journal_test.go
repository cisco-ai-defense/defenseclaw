// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"path/filepath"
	"testing"
)

// The journal keeps each process's rows apart, survives a reopen of the
// store, and tolerates a store that never journaled a call.
func TestHookDeliveryJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	store := openTestStore(t, path)
	ctx := t.Context()

	// A store that never journaled a call has no table: nothing to recover,
	// nothing to forget.
	if entries, err := store.UnauditedHookDeliveries(ctx, "live"); err != nil || len(entries) != 0 {
		t.Fatalf("journal of a fresh store = %v, %v; want empty", entries, err)
	}
	if err := store.ForgetHookDelivery(ctx, "missing"); err != nil {
		t.Fatalf("forget on a fresh store: %v", err)
	}
	if exists, err := tableExists(store.db, "hook_delivery_journal"); err != nil || exists {
		t.Fatalf("journal table on a fresh store = %t, %v; want none until first use", exists, err)
	}

	for _, row := range []struct{ id, process string }{{"a", "dead"}, {"b", "live"}, {"c", "dead"}} {
		if err := store.JournalHookDelivery(ctx, row.id, row.process, []byte(`{"ID":"`+row.id+`"}`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.JournalHookDelivery(ctx, "a", "dead", []byte(`{}`)); err == nil {
		t.Fatal("a second row under one id was journaled")
	}
	for _, bad := range []struct{ id, process, occurrence string }{{"", "p", "{}"}, {"x", "", "{}"}, {"x", "p", ""}} {
		if err := store.JournalHookDelivery(ctx, bad.id, bad.process, []byte(bad.occurrence)); err == nil {
			t.Fatalf("journaled an incomplete row %+v", bad)
		}
	}

	_ = store.Close()
	store = openTestStore(t, path)
	entries, err := store.UnauditedHookDeliveries(ctx, "live")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].ID != "a" || entries[1].ID != "c" || string(entries[1].Occurrence) != `{"ID":"c"}` {
		t.Fatalf("rows other processes left = %+v, want a and c with their occurrences", entries)
	}
	if err := store.ForgetHookDelivery(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	entries, err = store.UnauditedHookDeliveries(ctx, "dead")
	if err != nil || len(entries) != 1 || entries[0].ID != "b" {
		t.Fatalf("rows other than the dead process's after forgetting a = %+v, %v; want b", entries, err)
	}

	_ = store.Close()
	if err := store.JournalHookDelivery(ctx, "d", "live", []byte(`{}`)); err == nil {
		t.Fatal("a closed store journaled a call")
	}
	if _, err := store.UnauditedHookDeliveries(ctx, "live"); err == nil {
		t.Fatal("a closed store listed its journal")
	}
}
