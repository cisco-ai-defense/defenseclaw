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

func TestStoreInitMigratesRunIDColumns(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	oldSchema := `
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
	if _, err := db.Exec(oldSchema); err != nil {
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
