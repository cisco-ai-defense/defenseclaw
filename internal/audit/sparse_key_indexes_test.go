// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sparseIndexDefinition(t *testing.T, store *Store, name string) string {
	t.Helper()
	var definition string
	if err := store.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='index' AND name=?`, name).Scan(&definition); err != nil {
		t.Fatalf("index %s: %v", name, err)
	}
	return definition
}

// TestSparseKeyIndexesUpgradeFromEarlierStores opens stores at the schema of
// 1.0.2 and 1.0.3 (both end at the migration before 1.0.4's record digest)
// and of 1.0.4, with rows in place, and upgrades them: the sparse-key
// indexes become partial, the launcher sees the migration as pending, and
// every row stays and is still found through its index (GAP-1303).
func TestSparseKeyIndexesUpgradeFromEarlierStores(t *testing.T) {
	recordDigest := -1
	for index, candidate := range migrations {
		if candidate.description == configChangeRecordDigestMigrationDescription {
			recordDigest = index
		}
	}
	if recordDigest < 0 {
		t.Fatal("1.0.4 record digest migration not found")
	}
	for _, release := range []struct {
		name    string
		applied int
	}{
		{"1.0.2 and 1.0.3", recordDigest},
		{"1.0.4", recordDigest + 1},
	} {
		t.Run(release.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.db")
			store, err := NewStore(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.db.Exec(`CREATE TABLE schema_version (
				version INTEGER PRIMARY KEY, applied_at DATETIME NOT NULL)`); err != nil {
				t.Fatal(err)
			}
			for index := 0; index < release.applied; index++ {
				if err := store.applyMigration(index+1, migrations[index]); err != nil {
					t.Fatalf("apply migration %d: %v", index+1, err)
				}
			}
			for _, row := range []struct{ id, runID, requestID any }{
				{"with-keys", "run-1", "request-1"},
				{"without-keys", nil, nil},
			} {
				if _, err := store.db.Exec(`INSERT INTO audit_events (id, timestamp, action, actor, details, severity, run_id, request_id)
					VALUES (?, '2026-10-01T12:00:00Z', 'scan', 'test', 'row', 'INFO', ?, ?)`,
					row.id, row.runID, row.requestID); err != nil {
					t.Fatal(err)
				}
			}
			if !strings.Contains(sparseIndexDefinition(t, store, "idx_audit_run_id"), "audit_events") {
				t.Fatal("the earlier schema has no run_id index")
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			pending, err := PendingMigrations(path)
			if err != nil {
				t.Fatal(err)
			}
			if want := len(migrations) - release.applied; pending != want {
				t.Fatalf("pending migrations = %d, want %d", pending, want)
			}

			store, err = NewStore(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })
			if err := store.Init(); err != nil {
				t.Fatal(err)
			}
			for _, index := range sparseKeyIndexes {
				if definition := sparseIndexDefinition(t, store, index.name); !strings.HasSuffix(definition, " WHERE "+index.key+" IS NOT NULL") {
					t.Errorf("%s after the upgrade: %s", index.name, definition)
				}
			}
			var rows int
			if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id IN ('with-keys', 'without-keys')`).Scan(&rows); err != nil || rows != 2 {
				t.Fatalf("rows after the upgrade = %d, %v", rows, err)
			}
			var id string
			if err := store.db.QueryRow(`SELECT id FROM audit_events WHERE run_id = ?`, "run-1").Scan(&id); err != nil || id != "with-keys" {
				t.Fatalf("run_id lookup after the upgrade = %q, %v", id, err)
			}
			if pending, err := PendingMigrations(path); err != nil || pending != 0 {
				t.Fatalf("pending after the upgrade = %d, %v", pending, err)
			}
			// A second start finds the partial form and changes nothing.
			if err := setSparseKeyIndexForm(store.db, true); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestSparseKeyIndexesServeTheirQueries is the query inventory of the
// partial indexes: each reader's lookup still uses its index.
func TestSparseKeyIndexesServeTheirQueries(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	plan := func(query string, args ...any) string {
		rows, err := store.db.Query(`EXPLAIN QUERY PLAN `+query, args...)
		if err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		defer rows.Close()
		var lines []string
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatal(err)
			}
			lines = append(lines, detail)
		}
		return strings.Join(lines, "; ")
	}
	for _, index := range sparseKeyIndexes {
		query := `SELECT rowid FROM ` + index.table + ` WHERE ` + index.key + ` = ?`
		if got := plan(query, "x"); !strings.Contains(got, index.name) {
			t.Errorf("%s does not use %s: %s", query, index.name, got)
		}
	}
	// The production statements themselves (GAP-1793): a drift in their SQL
	// that loses the index fails here.
	anchor := func(set func(*CorrelationAnchor)) (string, []any) {
		var value CorrelationAnchor
		set(&value)
		return correlationAnchorStatement(value, CorrelationPageRequest{}, 10)
	}
	type reader struct {
		index, name string
		query       string
		args        []any
	}
	readers := []reader{}
	add := func(index, name string, query string, args []any) {
		readers = append(readers, reader{index: index, name: name, query: query, args: args})
	}
	for _, c := range []struct {
		index string
		set   func(*CorrelationAnchor)
	}{
		{"idx_correlation_observations_turn", func(a *CorrelationAnchor) { a.TurnID = "x" }},
		{"idx_correlation_observations_agent", func(a *CorrelationAnchor) { a.AgentID = "x" }},
		{"idx_correlation_observations_lifecycle", func(a *CorrelationAnchor) { a.LifecycleID = "x" }},
		{"idx_correlation_observations_execution", func(a *CorrelationAnchor) { a.ExecutionID = "x" }},
		{"idx_correlation_observations_model_request", func(a *CorrelationAnchor) { a.ModelRequestID = "x" }},
		{"idx_correlation_observations_model_response", func(a *CorrelationAnchor) { a.ModelResponseID = "x" }},
		{"idx_correlation_observations_trace", func(a *CorrelationAnchor) { a.TraceID, a.SpanID = "x", "y" }},
	} {
		query, args := anchor(c.set)
		add(c.index, "anchorEventIDs", query, args)
	}
	add("idx_correlation_observations_trace", "matchTraceSpan", correlationTraceSpanMatchSQL, []any{"c", "x", "y"})
	similarity, similarityArgs := correlationSimilarityMatchStatement("c", CorrelationSimilarityHint{
		EventName: "e", AgentID: "x", Around: time.Unix(1, 0), Window: time.Second,
	})
	// matchSimilarity seeks the connector time window; agent_id only filters it.
	add("idx_correlation_events_connector", "matchSimilarity", similarity, similarityArgs)
	add("idx_audit_evaluation_id", "enforcementBlockCompatibility", enforcementBlockEvaluationSQL, []any{"x", "y"})
	for _, r := range readers {
		if got := plan(r.query, r.args...); !strings.Contains(got, r.index) {
			t.Errorf("%s does not use %s: %s\n%s", r.name, r.index, got, r.query)
		}
	}
	// The Python readers (cli/defenseclaw/db.py, tui/panels/audit.py) are run
	// here as written there; the predicate each relies on must still be in
	// that source, so a drift there fails this test too.
	for _, py := range []struct{ index, file, predicate, query string }{
		{"idx_audit_run_id", "../../cli/defenseclaw/tui/panels/audit.py", "WHERE run_id = ?",
			`SELECT id FROM audit_events WHERE run_id = ? ORDER BY timestamp DESC LIMIT 50`},
		{"idx_audit_request_id", "../../cli/defenseclaw/db.py",
			"LEFT JOIN audit_events AS h ON COALESCE(f.request_id, '') <> '' AND h.request_id = f.request_id",
			`SELECT f.id, h.id FROM audit_events AS f
			LEFT JOIN audit_events AS h ON COALESCE(f.request_id, '') <> '' AND h.request_id = f.request_id
			WHERE f.id IN (?, ?)`},
		{"idx_audit_enforcement_action_id", "../../cli/defenseclaw/db.py",
			"ON a.enforcement_action_id = f.enforcement_action_id AND a.id <> f.id",
			`SELECT f.id FROM audit_events AS f
			JOIN audit_events AS a ON a.enforcement_action_id = f.enforcement_action_id AND a.id <> f.id
			WHERE f.id = ?`},
	} {
		source, err := os.ReadFile(py.file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(source), py.predicate) {
			t.Errorf("%s no longer has %q: update this reader", py.file, py.predicate)
		}
		if got := plan(py.query, "x", "y"); !strings.Contains(got, py.index) {
			t.Errorf("%s reader does not use %s: %s", py.file, py.index, got)
		}
	}
}

// TestSecureClientStoreKeepsFullSparseKeyIndexes: a Secure Client store keeps
// main's schema.
func TestSecureClientStoreKeepsFullSparseKeyIndexes(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"), WithSecureClientSchema())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	for _, index := range sparseKeyIndexes {
		if definition := sparseIndexDefinition(t, store, index.name); strings.Contains(definition, " WHERE ") {
			t.Errorf("Secure Client %s: %s", index.name, definition)
		}
	}
}
