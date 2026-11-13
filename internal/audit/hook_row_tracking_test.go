// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// hookRowForTest inserts one hook row with an explicit column list, the way
// any writer does. sid "" leaves the projected record without a semantic
// event; pad grows the record past a page.
func hookRowForTest(t *testing.T, db *sql.DB, id, action, sid string, pad int) {
	t.Helper()
	record := map[string]any{"body": map[string]any{"pad": strings.Repeat("x", pad)}}
	if sid != "" {
		record["correlation"] = map[string]any{"semantic_event_id": sid}
	}
	projected, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO audit_events (id, timestamp, action, details, severity, connector,
		event_name, projected_record_json) VALUES (?, ?, ?, 'hook row', 'INFO', 'claudecode', ?, ?)`,
		id, time.Now().UTC().Format(time.RFC3339Nano), action, action, string(projected)); err != nil {
		t.Fatal(err)
	}
}

// trackForTest runs the gateway's own bookkeeping for one written row
// (trackHookRowTx), lone or not, in its own transaction.
func trackForTest(t *testing.T, store *Store, action, id, sid string, lone bool) {
	t.Helper()
	trackModeForTest(t, store, action, id, sid, map[bool]string{true: "record", false: ""}[lone])
}

// trackModeForTest: mode "record" (row of record), "awaiting" (fail-mode
// decision), "report" (a failure-report connector-hook row), "" plain.
func trackModeForTest(t *testing.T, store *Store, action, id, sid, mode string) {
	t.Helper()
	ctx := context.Background()
	switch mode {
	case "record":
		ctx = WithLoneHookDecision(ctx)
	case "awaiting":
		ctx = WithLoneHookDecisionAwaitingReport(ctx)
	case "report":
		ctx = withHookFailureReport(ctx)
	}
	tx, err := store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.trackHookRowTx(ctx, tx, action, id, sid); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func loneHookDecisionIDsForTest(t *testing.T, db *sql.DB, tracked bool) []string {
	t.Helper()
	rows, err := db.Query(`SELECT id FROM audit_events WHERE ` + LoneHookDecisionSQL("", tracked))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	sort.Strings(ids)
	return ids
}

func newHookRowTrackingStoreForTest(t *testing.T, options ...StoreOption) *Store {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"), options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	return store
}

func explainForTest(t *testing.T, db *sql.DB, query string) string {
	t.Helper()
	rows, err := db.Query(`EXPLAIN QUERY PLAN ` + query)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var steps []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		steps = append(steps, detail)
	}
	return strings.Join(steps, " | ")
}

// TestLoneHookDecisionsComeFromTheLoneTable: the store keeps
// audit_hook_lone; the lone rule reads it by key and agrees with the
// projected-record rule when the writer lists exactly the rows it wrote
// alone; a connector-hook row written later for the same semantic event
// (the failure report) removes the entry; retention on a connection without
// foreign_keys=ON removes the entry of a deleted row; a stale entry whose
// row is gone never counts (rel-1-0-10:GAP-0316).
func TestLoneHookDecisionsComeFromTheLoneTable(t *testing.T) {
	store := newHookRowTrackingStoreForTest(t)
	if tracked, err := HookRowsTracked(store.db); err != nil || !tracked {
		t.Fatalf("HookRowsTracked = %t, %v; the store must keep audit_hook_lone", tracked, err)
	}
	write := func(id, action, sid string, lone bool) {
		hookRowForTest(t, store.db, id, action, sid, 0)
		trackForTest(t, store, action, id, sid, lone)
	}
	write("lone", hookDecisionEventName, "sid-lone", true)
	write("pair-ch", string(ActionConnectorHook), "sid-pair", false)
	write("pair-hd", hookDecisionEventName, "sid-pair", false)
	write("stop-syn", string(ActionConnectorHookSynthetic), "sid-stop", false)
	write("stop-hd", hookDecisionEventName, "sid-stop", false)
	hookRowForTest(t, store.db, "late-hd", hookDecisionEventName, "sid-late", 0)
	trackModeForTest(t, store, hookDecisionEventName, "late-hd", "sid-late", "awaiting")
	for _, tracked := range []bool{true, false} {
		if got := loneHookDecisionIDsForTest(t, store.db, tracked); fmt.Sprint(got) != "[late-hd lone]" {
			t.Fatalf("lone rows (tracked %t) = %v, want [late-hd lone]", tracked, got)
		}
	}
	// The failure report writes the call's connector-hook row afterwards.
	hookRowForTest(t, store.db, "late-report", string(ActionConnectorHook), "sid-late", 0)
	trackModeForTest(t, store, string(ActionConnectorHook), "late-report", "sid-late", "report")
	for _, tracked := range []bool{true, false} {
		if got := loneHookDecisionIDsForTest(t, store.db, tracked); fmt.Sprint(got) != "[lone]" {
			t.Fatalf("lone rows after the report (tracked %t) = %v, want [lone]", tracked, got)
		}
	}

	plain, err := sql.Open("sqlite", "file:"+store.dbPath+"?_pragma=foreign_keys(0)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plain.Exec(`DELETE FROM audit_events WHERE id = 'lone'`); err != nil {
		t.Fatal(err)
	}
	_ = plain.Close()
	var left int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_hook_lone`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatalf("audit_hook_lone keeps %d entries after its rows were deleted or paired, want 0", left)
	}
	if _, err := store.db.Exec(`INSERT INTO audit_hook_lone VALUES ('gone', NULL)`); err != nil {
		t.Fatal(err)
	}
	if got := loneHookDecisionIDsForTest(t, store.db, true); len(got) != 0 {
		t.Fatalf("a stale entry counted: %v", got)
	}

	plan := explainForTest(t, store.db, `SELECT COUNT(*) FROM audit_events WHERE `+LoneHookDecisionSQL("", true))
	if !strings.Contains(plan, "hook_lone") || !strings.Contains(plan, "PRIMARY KEY") || strings.Contains(plan, "LIST SUBQUERY") {
		t.Fatalf("lone rule plan %q, want a key lookup in audit_hook_lone", plan)
	}
}

// TestNonLoneHookRowsWriteNothing: a hook_decision row written without the
// lone mark and a connector-hook row of a semantic event with no entry
// leave audit_hook_lone empty: the managed path and every paired decision
// pay no insert.
func TestNonLoneHookRowsWriteNothing(t *testing.T) {
	store := newHookRowTrackingStoreForTest(t)
	// A connector-hook row that is not the failure report's leaves a listed
	// fail-mode decision alone: only the report pairs it.
	hookRowForTest(t, store.db, "wait-hd", hookDecisionEventName, "sid-wait", 0)
	trackModeForTest(t, store, hookDecisionEventName, "wait-hd", "sid-wait", "awaiting")
	trackForTest(t, store, string(ActionConnectorHook), "other-ch", "sid-wait", false)
	if got := loneHookDecisionIDsForTest(t, store.db, true); fmt.Sprint(got) != "[wait-hd]" {
		t.Fatalf("lone rows = %v, want [wait-hd]", got)
	}
	if _, err := store.db.Exec(`DELETE FROM audit_events WHERE id = 'wait-hd'`); err != nil {
		t.Fatal(err)
	}
	trackForTest(t, store, string(ActionConnectorHook), "ch", "sid-1", false)
	trackForTest(t, store, hookDecisionEventName, "hd", "sid-1", false)
	trackForTest(t, store, hookDecisionEventName, "no-sid", "", true)
	var entries int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_hook_lone`).Scan(&entries); err != nil {
		t.Fatal(err)
	}
	if entries != 0 {
		t.Fatalf("audit_hook_lone has %d entries, want 0", entries)
	}
}

// TestLoneHookDecisionCountDoesNotReadTheRecords: the lone count costs the
// same with 100 B or 32 KB records (several overflow pages), because it
// reads audit_hook_lone only (rel-1-0-10:GAP-0316). The projected-record
// rule parsed every hook row's record.
func TestLoneHookDecisionCountDoesNotReadTheRecords(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a 70 MB store")
	}
	const pairs = 1000
	timeLone := func(pad int) time.Duration {
		store := newHookRowTrackingStoreForTest(t)
		tx, err := store.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		filler := strings.Repeat("x", pad)
		for index := range pairs {
			sid := fmt.Sprintf("sid-%06d", index)
			for _, action := range []string{string(ActionConnectorHook), hookDecisionEventName} {
				record := fmt.Sprintf(`{"correlation":{"semantic_event_id":%q},"body":{"pad":%q}}`, sid, filler)
				if _, err := tx.Exec(`INSERT INTO audit_events (id, timestamp, action, details, severity, connector,
					event_name, projected_record_json) VALUES (?, ?, ?, 'hook row', 'INFO', 'claudecode', ?, ?)`,
					sid+"-"+action, "2026-11-13T00:00:00Z", action, action, record); err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		best := time.Duration(1 << 62)
		for range 5 {
			started := time.Now()
			if got := loneHookDecisionIDsForTest(t, store.db, true); len(got) != 0 {
				t.Fatalf("lone rows in a store of pairs = %d, want 0", len(got))
			}
			best = min(best, time.Since(started))
		}
		return best
	}
	small, big := timeLone(100), timeLone(32<<10)
	t.Logf("lone count over %d pairs: 100 B records %v, 32 KB records %v", pairs, small, big)
	if big > 3*small+20*time.Millisecond {
		t.Fatalf("the lone count took %v with 32 KB records vs %v with 100 B: it reads the records", big, small)
	}
}

// TestSecureClientStoreHasNoLoneTable: a Secure Client store keeps main's
// schema (#1092) and every connector-hook row: no audit_hook_lone, no
// trigger, and the bookkeeping writes nothing.
func TestSecureClientStoreHasNoLoneTable(t *testing.T) {
	store := newHookRowTrackingStoreForTest(t, WithSecureClientSchema())
	if tracked, err := HookRowsTracked(store.db); err != nil || tracked {
		t.Fatalf("HookRowsTracked on a Secure Client store = %t, %v; want false", tracked, err)
	}
	var triggers int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name = ?`,
		hookLoneTrigger).Scan(&triggers); err != nil {
		t.Fatal(err)
	}
	if triggers != 0 {
		t.Fatal("a Secure Client store has the lone-row trigger")
	}
	trackForTest(t, store, hookDecisionEventName, "hd", "sid-1", true)
}

// TestRowOfRecordEntryIsItsKeyAlone: a row of record's entry stores no
// semantic event and adds nothing to the partial index, so it costs its key
// alone (the benign PreToolUse budget, hookStoreBudgetPerBenignPreToolUse).
func TestRowOfRecordEntryIsItsKeyAlone(t *testing.T) {
	store := newHookRowTrackingStoreForTest(t)
	hookRowForTest(t, store.db, "of-record", hookDecisionEventName, "sid-r", 0)
	trackForTest(t, store, hookDecisionEventName, "of-record", "sid-r", true)
	var sid sql.NullString
	if err := store.db.QueryRow(`SELECT semantic_event_id FROM audit_hook_lone WHERE audit_event_id = 'of-record'`).Scan(&sid); err != nil {
		t.Fatal(err)
	}
	if sid.Valid {
		t.Fatalf("a row of record's entry stores semantic event %q, want NULL", sid.String)
	}
}
