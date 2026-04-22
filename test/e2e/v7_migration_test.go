// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	_ "modernc.org/sqlite"
)

func TestMigration_FromV0_FreshInstall(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "fresh.db")
	st, err := audit.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer st.Close()
	if err := st.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	assertV7Columns(t, dbPath)
	v, err := st.SchemaVersion()
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if v < 11 {
		t.Fatalf("SchemaVersion = %d, want >= 11", v)
	}
}

func TestMigration_FromV5(t *testing.T) {
	t.Parallel()
	src := filepath.Join("testdata", "v5_audit.sqlite")
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	dbPath := filepath.Join(t.TempDir(), "fromv5.db")
	if err := os.WriteFile(dbPath, b, 0o600); err != nil {
		t.Fatalf("write db: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	_, err = db.Exec(`INSERT INTO audit_events (id, timestamp, action, target, actor, details, severity)
		VALUES ('legacy-row', datetime('now'), 'legacy-action', 't', 'defenseclaw', 'keep-me', 'INFO')`)
	if err != nil {
		_ = db.Close()
		t.Fatalf("seed legacy row: %v", err)
	}
	_ = db.Close()

	st, err := audit.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer st.Close()
	if err := st.Init(); err != nil {
		t.Fatalf("Init from v5: %v", err)
	}
	assertV7Columns(t, dbPath)

	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()
	var details string
	err = db.QueryRow(`SELECT details FROM audit_events WHERE id = 'legacy-row'`).Scan(&details)
	if err != nil {
		t.Fatalf("legacy row: %v", err)
	}
	if details != "keep-me" {
		t.Fatalf("details = %q, want keep-me", details)
	}
}

func TestMigration_Idempotent(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "idempotent.db")
	st, err := audit.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer st.Close()
	if err := st.Init(); err != nil {
		t.Fatalf("Init 1: %v", err)
	}
	v1, _ := st.SchemaVersion()
	if err := st.Init(); err != nil {
		t.Fatalf("Init 2: %v", err)
	}
	v2, err := st.SchemaVersion()
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if v1 != v2 {
		t.Fatalf("schema version changed: %d vs %d", v1, v2)
	}
}

func assertV7Columns(t *testing.T, dbPath string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()
	for _, col := range []string{
		"schema_version", "content_hash", "generation", "binary_version",
		"agent_id", "agent_instance_id", "sidecar_instance_id",
	} {
		var n int
		err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('audit_events') WHERE name=?`, col).Scan(&n)
		if err != nil {
			t.Fatalf("pragma audit_events %s: %v", col, err)
		}
		if n != 1 {
			t.Errorf("audit_events.%s missing", col)
		}
	}
}
