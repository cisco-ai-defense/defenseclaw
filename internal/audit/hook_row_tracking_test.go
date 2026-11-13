// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// hookRowForTest inserts one hook row the way any writer does, with an
// explicit column list (a 1.0.9 binary writes the same columns). sid ""
// leaves the projected record without a semantic event; pad grows the
// projected record past a page so a reader that parses it pays overflow I/O.
func hookRowForTest(t *testing.T, store *Store, id, action, sid string, pad int) {
	t.Helper()
	record := map[string]any{"body": map[string]any{"pad": strings.Repeat("x", pad)}}
	if sid != "" {
		record["correlation"] = map[string]any{"semantic_event_id": sid}
	}
	projected, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	eventName := "legacy.audit.connector.hook"
	if action == hookDecisionEventName {
		eventName = hookDecisionEventName
	}
	if _, err := store.db.Exec(`INSERT INTO audit_events (id, timestamp, action, details, severity, connector,
		event_name, payload_json, projected_record_json)
		VALUES (?, ?, ?, 'hook row', 'INFO', 'claudecode', ?, NULL, ?)`,
		id, time.Now().UTC().Format(time.RFC3339Nano), action, eventName, string(projected)); err != nil {
		t.Fatal(err)
	}
}

func loneHookDecisionIDsForTest(t *testing.T, store *Store, tracked bool) []string {
	t.Helper()
	rows, err := store.db.Query(`SELECT id FROM audit_events WHERE ` + LoneHookDecisionSQL("", tracked))
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

// TestLoneHookDecisionsComeFromTheHookRowTable: a store keeps
// audit_hook_rows, so the lone hook_decision rule is two index lookups per
// row and the same rows as the projected-record rule, in every order the
// rows of a decision are written; a deleted audit row takes its hook row
// with it (retention), and a row written with a plain INSERT, as a 1.0.9
// binary writes it, is tracked too (rel-1-0-10:GAP-0316).
func TestLoneHookDecisionsComeFromTheHookRowTable(t *testing.T) {
	store := newHookRowTrackingStoreForTest(t)
	if tracked, err := HookRowsTracked(store.db); err != nil || !tracked {
		t.Fatalf("HookRowsTracked = %t, %v; the store must keep audit_hook_rows", tracked, err)
	}
	hookRowForTest(t, store, "lone", hookDecisionEventName, "sid-lone", 0)
	hookRowForTest(t, store, "pair-ch", string(ActionConnectorHook), "sid-pair", 0)
	hookRowForTest(t, store, "pair-hd", hookDecisionEventName, "sid-pair", 0)
	// The failure report writes the connector-hook row of a call after its
	// fail-mode hook_decision row.
	hookRowForTest(t, store, "late-hd", hookDecisionEventName, "sid-late", 0)
	hookRowForTest(t, store, "late-report", string(ActionConnectorHook), "sid-late", 0)
	hookRowForTest(t, store, "stop-syn", string(ActionConnectorHookSynthetic), "sid-stop", 0)
	hookRowForTest(t, store, "stop-hd", hookDecisionEventName, "sid-stop", 0)
	hookRowForTest(t, store, "no-semantic", hookDecisionEventName, "", 0)
	want := []string{"lone"}
	for _, tracked := range []bool{true, false} {
		if got := loneHookDecisionIDsForTest(t, store, tracked); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("lone hook_decision rows (tracked %t) = %v, want %v", tracked, got, want)
		}
	}

	if _, err := store.db.Exec(`DELETE FROM audit_events WHERE id = 'lone'`); err != nil {
		t.Fatal(err)
	}
	var left int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_hook_rows WHERE audit_event_id = 'lone'`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatalf("a deleted audit row left %d hook rows", left)
	}

	// The plan: the hook row table by its keys, never the hook rows'
	// records (the projected-record rule built its set from every
	// connector-hook record and parsed every hook_decision record).
	plan := explainForTest(t, store, `SELECT COUNT(*) FROM audit_events WHERE `+LoneHookDecisionSQL("", true))
	if !strings.Contains(plan, "audit_hook_rows") || strings.Contains(plan, "LIST SUBQUERY") ||
		strings.Contains(plan, "hook_sibling USING INDEX idx_audit_action") {
		t.Fatalf("lone rule plan %q, want lookups in audit_hook_rows only", plan)
	}

	// Opening the store again keeps the table and its rows.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewStore(store.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.Init(); err != nil {
		t.Fatal(err)
	}
	hookRowForTest(t, reopened, "lone-2", hookDecisionEventName, "sid-lone-2", 0)
	if got := loneHookDecisionIDsForTest(t, reopened, true); fmt.Sprint(got) != "[lone-2]" {
		t.Fatalf("lone rows after a reopen = %v, want [lone-2]", got)
	}
}

func explainForTest(t *testing.T, store *Store, query string) string {
	t.Helper()
	rows, err := store.db.Query(`EXPLAIN QUERY PLAN ` + query)
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

// TestLoneHookDecisionCountDoesNotReadTheRecords: the lone count costs the
// same whether each hook row's projected record is 100 B or 32 KB (several
// overflow pages), because it reads audit_hook_rows only
// (rel-1-0-10:GAP-0316). The projected-record rule parsed every hook row's
// record, so on a grown store (3.3-3.6 KB records, 325,000 hook rows) it read
// about 1.1 GB with a cold cache.
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
			if got := loneHookDecisionIDsForTest(t, store, true); len(got) != 0 {
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

// TestSecureClientStoreHasNoHookRowTable: a Secure Client store keeps main's
// schema (#1092) and every connector-hook row, so it has no audit_hook_rows
// and no trigger, and the export falls back to the record rule.
func TestSecureClientStoreHasNoHookRowTable(t *testing.T) {
	store := newHookRowTrackingStoreForTest(t, WithSecureClientSchema())
	if tracked, err := HookRowsTracked(store.db); err != nil || tracked {
		t.Fatalf("HookRowsTracked on a Secure Client store = %t, %v; want false", tracked, err)
	}
	var triggers int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name = ?`,
		hookRowsTrigger).Scan(&triggers); err != nil {
		t.Fatal(err)
	}
	if triggers != 0 {
		t.Fatal("a Secure Client store has the hook row trigger")
	}
}
