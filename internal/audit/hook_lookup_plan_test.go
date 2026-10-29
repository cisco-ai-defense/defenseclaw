// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"database/sql"
	"strconv"
	"strings"
	"testing"
)

// The hooks' identifier-ledger lookups plan a full-key seek without planner
// statistics. A store from before 1.0.3 has none until its first ANALYZE
// ends, and on a multi-gigabyte store that pass takes the store's connection
// for about 100 s: with the connector as a lone index prefix every hook read
// the connector's whole identifier ledger meanwhile, and nearly every benign
// hook of those 100 s was denied as "did not answer in time" (GAP-2505,
// managed RHEL, the GAP-0233 misplan).
func TestHookLedgerLookupsSeekTheFullKeyWithoutPlannerStatistics(t *testing.T) {
	store, _ := newCorrelationTestStore(t)
	var stats int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM sqlite_schema WHERE name='sqlite_stat1'`).Scan(&stats); err != nil {
		t.Fatal(err)
	}
	if stats != 0 {
		if _, err := store.db.Exec(`DELETE FROM sqlite_stat1`); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.Exec(`ANALYZE sqlite_schema`); err != nil {
			t.Fatal(err)
		}
	}
	assertHookLedgerLookupPlans(t, store, "no statistics")

	// A first pass that yielded part way (and a restart) leaves statistics
	// for the indexes before the one it yielded at: here the unique keys of
	// the identifier ledger, which describe the connector prefix as every
	// row, and none for idx_correlation_identifiers_event. The lookups keep
	// their seeks, so the passes that finish the statistics may yield too
	// (RV-ha8-2505).
	if _, err := store.db.Exec(`ANALYZE sqlite_schema`); err != nil {
		t.Fatal(err)
	}
	indexes, err := store.db.Query(`SELECT name FROM sqlite_schema WHERE type='index' AND tbl_name='correlation_identifiers' AND name<>'idx_correlation_identifiers_event'`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for indexes.Next() {
		var name string
		if err := indexes.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	if err := indexes.Close(); err != nil {
		t.Fatal(err)
	}
	if len(names) == 0 {
		t.Fatal("fixture: correlation_identifiers has no other index")
	}
	const ledgerRows = 1000000
	for _, name := range names {
		var columns int
		if err := store.db.QueryRow(`SELECT COUNT(*) FROM pragma_index_info(?)`, name).Scan(&columns); err != nil {
			t.Fatal(err)
		}
		stat := []string{strconv.Itoa(ledgerRows), strconv.Itoa(ledgerRows)}
		for i := 1; i < columns; i++ {
			rows := ledgerRows
			for j := 0; j < i; j++ {
				rows /= 100
			}
			stat = append(stat, strconv.Itoa(max(rows, 1)))
		}
		if _, err := store.db.Exec(`INSERT INTO sqlite_stat1(tbl, idx, stat) VALUES ('correlation_identifiers', ?, ?)`, name, strings.Join(stat, " ")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.db.Exec(`ANALYZE sqlite_schema`); err != nil {
		t.Fatal(err)
	}
	assertHookLedgerLookupPlans(t, store, "partial statistics")
}

func assertHookLedgerLookupPlans(t *testing.T, store *Store, state string) {
	t.Helper()
	plan := func(query string, args ...any) []string {
		t.Helper()
		rows, err := store.db.Query(`EXPLAIN QUERY PLAN `+query, args...)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var lines []string
		for rows.Next() {
			var id, parent, unused int
			var detail sql.NullString
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatal(err)
			}
			lines = append(lines, detail.String)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return lines
	}
	connector := ConnectorInstanceID(strings.Repeat("c", 36))
	digest := strings.Repeat("d", 64)
	identifiers := []CorrelationMatchIdentifier{
		{Namespace: "claudecode", Kind: "session", ValueDigest: digest},
		{Namespace: "claudecode", Kind: "tool_invocation", ValueDigest: digest},
		{Namespace: "claudecode", Kind: "turn", ValueDigest: digest},
	}
	for _, mirror := range []*CorrelationMirrorCompatibility{nil, {Rail: "native_otlp", EventName: "tool_call"}} {
		from, args := correlationIdentifierMatchFrom(connector, identifiers, mirror)
		for _, tail := range []string{` LIMIT 1`, ` AND event.logical_group_id<>? LIMIT 1`,
			` ORDER BY event.received_time_unix_nano, event.semantic_event_id LIMIT 1`} {
			queryArgs := args
			if strings.Contains(tail, "<>?") {
				queryArgs = append(append([]any(nil), args...), "group")
			}
			lines := plan(`SELECT event.semantic_event_id `+from+tail, queryArgs...)
			seeks := 0
			for _, line := range lines {
				if !strings.Contains(line, " identifier ") {
					continue
				}
				if !strings.Contains(line, "connector_instance_id=? AND namespace=? AND identifier_kind=? AND value_digest=?") {
					t.Fatalf("%s: identifier match (mirror %v, %q) does not seek the full key: %q", state, mirror != nil, tail, lines)
				}
				seeks++
			}
			if seeks != len(identifiers) {
				t.Fatalf("%s: identifier match (mirror %v, %q) seeks %d identifiers, want %d: %q", state, mirror != nil, tail, seeks, len(identifiers), lines)
			}
		}
	}
	lines := plan(toolChainSessionDigestSQL, "event", string(connector))
	if len(lines) == 0 || !strings.Contains(lines[0], "idx_correlation_identifiers_event (semantic_event_id=?)") {
		t.Fatalf("%s: tool-chain session lookup does not seek the event's identifiers: %q", state, lines)
	}
}
