// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// TestStoreV7SchemaColumnsPresent asserts that the v7 provenance
// quartet (schema_version / content_hash / generation /
// binary_version) plus the three-tier agent identity columns
// (agent_id / agent_instance_id / sidecar_instance_id) exist on
// audit_events, judge_responses, and scan_results after Init. These
// columns are the shared substrate parallel tracks rely on; if
// Track 0 drops one, every downstream writer fails at runtime with
// an opaque "no such column" error.
func TestStoreV7SchemaColumnsPresent(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
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
		// provenance quartet
		{"audit_events", "schema_version"},
		{"audit_events", "content_hash"},
		{"audit_events", "generation"},
		{"audit_events", "binary_version"},
		{"judge_responses", "schema_version"},
		{"judge_responses", "content_hash"},
		{"judge_responses", "generation"},
		{"judge_responses", "binary_version"},
		{"scan_results", "schema_version"},
		{"scan_results", "content_hash"},
		{"scan_results", "generation"},
		{"scan_results", "binary_version"},
		// three-tier agent identity
		{"audit_events", "agent_id"},
		{"audit_events", "sidecar_instance_id"},
		{"judge_responses", "agent_id"},
		{"judge_responses", "sidecar_instance_id"},
		{"judge_responses", "session_id"},
		{"judge_responses", "agent_instance_id"},
		{"scan_results", "agent_id"},
		{"scan_results", "sidecar_instance_id"},
		// scan_results new columns from Track 1/2/3
		{"scan_results", "verdict"},
		{"scan_results", "exit_code"},
		{"scan_results", "error"},
		// findings rule_id / line_number
		{"findings", "rule_id"},
		{"findings", "line_number"},
		{"findings", "agent_id"},
	} {
		ok, err := store.hasColumn(spec.table, spec.column)
		if err != nil {
			t.Fatalf("hasColumn(%s, %s): %v", spec.table, spec.column, err)
		}
		if !ok {
			t.Errorf("expected %s.%s column after migrations", spec.table, spec.column)
		}
	}
}

// TestStoreV7TablesPresent asserts the three new v7 tables were
// created by migrations 7-9. Parallel tracks rely on these being
// ready; see Track 0 docs.
func TestStoreV7TablesPresent(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	for _, name := range []string{"scan_findings", "activity_events", "sink_health"} {
		var count int
		err := db.QueryRow(
			`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name,
		).Scan(&count)
		if err != nil {
			t.Fatalf("sqlite_master for %s: %v", name, err)
		}
		if count != 1 {
			t.Errorf("table %s missing after v7 migrations", name)
		}
	}
}

// TestStoreV7SchemaVersionFinal pins the schema version at
// len(migrations) so out-of-band migrations added in a rebase are
// caught loudly instead of silently advancing.
func TestStoreV7SchemaVersionFinal(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	got, err := store.SchemaVersion()
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if got != len(migrations) {
		t.Errorf("SchemaVersion = %d, want %d", got, len(migrations))
	}
	if got < 11 {
		t.Errorf("expected at least 11 migrations after v7 pre-allocation, got %d", got)
	}
}
