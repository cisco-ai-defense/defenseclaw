// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

// legacySchemaWithoutRunID is the pre-migration-2 schema (no run_id on audit_events / scan_results).
const legacySchemaWithoutRunID = `
	CREATE TABLE audit_events (
		id TEXT PRIMARY KEY,
		timestamp DATETIME NOT NULL,
		action TEXT NOT NULL,
		target TEXT,
		actor TEXT NOT NULL DEFAULT 'defenseclaw',
		details TEXT,
		severity TEXT
	);

	CREATE TABLE scan_results (
		id TEXT PRIMARY KEY,
		scanner TEXT NOT NULL,
		target TEXT NOT NULL,
		timestamp DATETIME NOT NULL,
		duration_ms INTEGER,
		finding_count INTEGER,
		max_severity TEXT,
		raw_json TEXT
	);
	`

func TestStoreInitMigratesRunIDColumns(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	if _, err := db.Exec(legacySchemaWithoutRunID); err != nil {
		t.Fatalf("create old schema: %v", err)
	}
	_ = db.Close()

	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	for _, spec := range []struct {
		table  string
		column string
	}{
		{table: "audit_events", column: "run_id"},
		{table: "audit_events", column: "trace_id"},
		{table: "scan_results", column: "run_id"},
	} {
		ok, err := store.hasColumn(spec.table, spec.column)
		if err != nil {
			t.Fatalf("hasColumn(%s, %s): %v", spec.table, spec.column, err)
		}
		if !ok {
			t.Fatalf("expected %s.%s to exist after migration", spec.table, spec.column)
		}
	}
}

func TestLogEventRoundTripIncludesTraceID(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	if err := store.LogEvent(Event{
		Action:   "guardrail-inspection",
		Target:   "gpt-4",
		Details:  "trace-bearing event",
		Severity: "HIGH",
		TraceID:  "trace-123",
	}); err != nil {
		t.Fatalf("LogEvent: %v", err)
	}

	events, err := store.ListEvents(10)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("ListEvents returned %d rows, want 1", len(events))
	}
	if got := events[0].TraceID; got != "trace-123" {
		t.Fatalf("TraceID = %q, want %q", got, "trace-123")
	}
}

func TestStoreLogEventUsesEnvRunID(t *testing.T) {
	t.Setenv("DEFENSECLAW_RUN_ID", "unit-run-store")

	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	if err := store.LogEvent(Event{
		Action:   "test-action",
		Target:   "target",
		Severity: "INFO",
	}); err != nil {
		t.Fatalf("LogEvent: %v", err)
	}

	events, err := store.ListEvents(10)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if got := events[0].RunID; got != "unit-run-store" {
		t.Fatalf("RunID = %q, want %q", got, "unit-run-store")
	}
}

func TestStoreInsertScanResultUsesEnvRunID(t *testing.T) {
	t.Setenv("DEFENSECLAW_RUN_ID", "unit-run-scan")

	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	if err := store.InsertScanResult(
		"scan-1",
		"skill-scanner",
		"/tmp/skill",
		time.Now().UTC(),
		100,
		1,
		"HIGH",
		`{"scanner":"skill-scanner"}`,
	); err != nil {
		t.Fatalf("InsertScanResult: %v", err)
	}

	var runID sql.NullString
	if err := store.db.QueryRow(`SELECT run_id FROM scan_results WHERE id = ?`, "scan-1").Scan(&runID); err != nil {
		t.Fatalf("select run_id: %v", err)
	}
	if got := runID.String; got != "unit-run-scan" {
		t.Fatalf("run_id = %q, want %q", got, "unit-run-scan")
	}
}

func TestSchemaVersionTracking(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	want := len(migrations)
	got, err := store.SchemaVersion()
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if got != want {
		t.Errorf("SchemaVersion() = %d, want %d (len(migrations))", got, want)
	}

	verifyDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open verify: %v", err)
	}
	defer verifyDB.Close()

	var tableCount int
	if err := verifyDB.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_version'`,
	).Scan(&tableCount); err != nil {
		t.Fatalf("schema_version table check: %v", err)
	}
	if tableCount != 1 {
		t.Errorf("schema_version table exists: got count %d, want 1", tableCount)
	}

	var rowCount int
	if err := verifyDB.QueryRow(`SELECT COUNT(*) FROM schema_version`).Scan(&rowCount); err != nil {
		t.Fatalf("COUNT schema_version: %v", err)
	}
	if rowCount != want {
		t.Errorf("schema_version rows = %d, want %d", rowCount, want)
	}
}

func TestInitIdempotent(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	if err := store.Init(); err != nil {
		t.Fatalf("first Init: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Errorf("second Init: %v", err)
	}

	want := len(migrations)
	got, err := store.SchemaVersion()
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if got != want {
		t.Errorf("SchemaVersion() after second Init = %d, want %d", got, want)
	}

	verifyDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open verify: %v", err)
	}
	defer verifyDB.Close()

	var rowCount int
	if err := verifyDB.QueryRow(`SELECT COUNT(*) FROM schema_version`).Scan(&rowCount); err != nil {
		t.Fatalf("COUNT schema_version: %v", err)
	}
	if rowCount != want {
		t.Errorf("schema_version rows after Init x2 = %d, want %d (not duplicated)", rowCount, want)
	}
}

func TestAcknowledgeAlertsRemainInAuditHistoryButNotAlerts(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	if err := store.LogEvent(Event{
		Action:   "scan",
		Target:   "skill/test-skill",
		Details:  "found suspicious behavior",
		Severity: "HIGH",
	}); err != nil {
		t.Fatalf("LogEvent alert: %v", err)
	}

	n, err := store.AcknowledgeAlerts("all")
	if err != nil {
		t.Fatalf("AcknowledgeAlerts: %v", err)
	}
	if n != 1 {
		t.Fatalf("RowsAffected = %d, want 1", n)
	}

	alerts, err := store.ListAlerts(10)
	if err != nil {
		t.Fatalf("ListAlerts: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatalf("ListAlerts returned %d rows after acknowledgement, want 0", len(alerts))
	}

	events, err := store.ListEvents(10)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("ListEvents returned %d rows, want 2", len(events))
	}

	foundAck := false
	for _, event := range events {
		if event.Action == "acknowledge-alerts" {
			foundAck = true
			if event.Severity != "ACK" {
				t.Fatalf("acknowledge-alerts severity = %q, want ACK", event.Severity)
			}
		}
	}
	if !foundAck {
		t.Fatal("expected acknowledge-alerts event to remain in audit history")
	}
}

func TestMigrationFromFreshDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	wantTables := []string{
		"actions",
		"audit_events",
		"findings",
		"network_egress_events",
		"scan_results",
		"schema_version",
		"target_snapshots",
	}
	verifyDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open verify: %v", err)
	}
	defer verifyDB.Close()

	for _, name := range wantTables {
		var n int
		err := verifyDB.QueryRow(
			`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name,
		).Scan(&n)
		if err != nil {
			t.Fatalf("table %q lookup: %v", name, err)
		}
		if n != 1 {
			t.Errorf("table %q: want 1 match in sqlite_master, got %d", name, n)
		}
	}

	want := len(migrations)
	got, err := store.SchemaVersion()
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if got != want {
		t.Errorf("SchemaVersion() = %d, want %d", got, want)
	}

	ok, err := store.hasColumn("audit_events", "run_id")
	if err != nil {
		t.Fatalf("hasColumn(audit_events, run_id): %v", err)
	}
	if !ok {
		t.Errorf("hasColumn(audit_events, run_id) = false, want true")
	}
}

func TestMigrationFromV1Schema(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit-v1.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := db.Exec(legacySchemaWithoutRunID); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	if _, err := db.Exec(`
		CREATE TABLE schema_version (
			version INTEGER PRIMARY KEY,
			applied_at DATETIME NOT NULL
		);
		INSERT INTO schema_version (version, applied_at) VALUES (1, '2020-01-01T00:00:00Z');
	`); err != nil {
		t.Fatalf("create schema_version v1: %v", err)
	}
	_ = db.Close()

	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	want := len(migrations)
	got, err := store.SchemaVersion()
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if got != want {
		t.Errorf("SchemaVersion() = %d, want %d", got, want)
	}

	verifyDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open verify: %v", err)
	}
	defer verifyDB.Close()

	var rowCount int
	if err := verifyDB.QueryRow(`SELECT COUNT(*) FROM schema_version`).Scan(&rowCount); err != nil {
		t.Fatalf("COUNT schema_version: %v", err)
	}
	if rowCount != want {
		t.Errorf("schema_version rows = %d, want %d (v1 pre-seeded + migration %d only)", rowCount, want, want)
	}

	ok, err := store.hasColumn("audit_events", "run_id")
	if err != nil {
		t.Fatalf("hasColumn(audit_events, run_id): %v", err)
	}
	if !ok {
		t.Errorf("hasColumn(audit_events, run_id) = false, want true after migration 2 only")
	}
}

func TestMigrationTransactional(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	verifyDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("second connection sql.Open: %v", err)
	}
	defer verifyDB.Close()

	rows, err := verifyDB.Query(`SELECT version FROM schema_version ORDER BY version`)
	if err != nil {
		t.Fatalf("query schema_version: %v", err)
	}
	defer rows.Close()

	var versions []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			t.Fatalf("scan version: %v", err)
		}
		versions = append(versions, v)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	if len(versions) != len(migrations) {
		t.Fatalf("schema_version rows = %d, want %d (len(migrations))", len(versions), len(migrations))
	}
	for i, v := range versions {
		want := i + 1
		if v != want {
			t.Fatalf("schema_version[%d] = %d, want consecutive starting at 1 (got %d)", i, v, want)
		}
	}

	for _, v := range versions {
		var n int
		if err := verifyDB.QueryRow(
			`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='audit_events'`,
		).Scan(&n); err != nil {
			t.Fatalf("audit_events table check: %v", err)
		}
		if n != 1 {
			t.Errorf("version %d recorded but audit_events table missing or duplicate", v)
		}
		if v >= 2 {
			ok, err := store.hasColumn("audit_events", "run_id")
			if err != nil {
				t.Fatalf("hasColumn after version %d: %v", v, err)
			}
			if !ok {
				t.Errorf("version %d in schema_version but audit_events.run_id missing (migration not atomic with version bump)", v)
			}
		}
	}
}

func TestMigrationApplyUsesTransaction(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	wantCount := len(migrations)
	var rowCount int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM schema_version`).Scan(&rowCount); err != nil {
		t.Fatalf("COUNT schema_version: %v", err)
	}
	if rowCount != wantCount {
		t.Fatalf("schema_version rows = %d, want %d", rowCount, wantCount)
	}

	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer rawDB.Close()

	ok, err := store.hasColumn("audit_events", "run_id")
	if err != nil {
		t.Fatalf("hasColumn(audit_events, run_id): %v", err)
	}
	if !ok {
		t.Fatal("expected audit_events.run_id after migration 2")
	}

	var v1, v2 int
	if err := rawDB.QueryRow(`SELECT COUNT(*) FROM schema_version WHERE version = 1`).Scan(&v1); err != nil {
		t.Fatalf("count version 1: %v", err)
	}
	if err := rawDB.QueryRow(`SELECT COUNT(*) FROM schema_version WHERE version = 2`).Scan(&v2); err != nil {
		t.Fatalf("count version 2: %v", err)
	}
	if wantCount >= 1 && v1 != 1 {
		t.Errorf("version 1 rows = %d, want 1", v1)
	}
	if wantCount >= 2 && v2 != 1 {
		t.Errorf("version 2 rows = %d, want 1", v2)
	}
}
