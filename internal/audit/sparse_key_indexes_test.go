// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"path/filepath"
	"strings"
	"testing"
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
	for _, reader := range []struct{ index, query string }{
		// The correlation graph anchors (CorrelationRepository.anchorEventIDs).
		{"idx_correlation_observations_turn", `SELECT DISTINCT event.semantic_event_id, event.received_time_unix_nano
			FROM correlation_events AS event JOIN correlation_observations AS observation
			ON observation.semantic_event_id=event.semantic_event_id WHERE observation.turn_id=?`},
		{"idx_correlation_observations_trace", `SELECT DISTINCT event.semantic_event_id
			FROM correlation_events AS event JOIN correlation_observations AS observation
			ON observation.semantic_event_id=event.semantic_event_id WHERE observation.trace_id=? AND observation.span_id=?`},
		// The TUI audit panel by run (cli/defenseclaw/tui/panels/audit.py).
		{"idx_audit_run_id", `SELECT id FROM audit_events WHERE run_id = ? ORDER BY timestamp DESC LIMIT 50`},
		// The finding-to-hook join (cli/defenseclaw/db.py).
		{"idx_audit_request_id", `SELECT f.id, h.id FROM audit_events AS f
			LEFT JOIN audit_events AS h ON COALESCE(f.request_id, '') <> '' AND h.request_id = f.request_id
			WHERE f.id IN (?, ?)`},
		// The quarantine target join (cli/defenseclaw/db.py).
		{"idx_audit_enforcement_action_id", `SELECT f.id FROM audit_events AS f
			JOIN audit_events AS a ON a.enforcement_action_id = f.enforcement_action_id AND a.id <> f.id
			WHERE f.id = ?`},
		// The enforcement block compatibility lookup (event_history_v8.go).
		{"idx_audit_evaluation_id", `SELECT target FROM audit_events WHERE evaluation_id = ? AND event_name = ?`},
	} {
		if got := plan(reader.query, "x", "y"); !strings.Contains(got, reader.index) {
			t.Errorf("reader does not use %s: %s\n%s", reader.index, got, reader.query)
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
