// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	_ "modernc.org/sqlite"
)

// actionsHasColumn reports whether the actions table has the named column.
func actionsHasColumn(t *testing.T, dbPath, col string) bool {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('actions') WHERE name=?`, col,
	).Scan(&n); err != nil {
		t.Fatalf("pragma actions %s: %v", col, err)
	}
	return n == 1
}

// actionsHasIndex reports whether a named index exists on the actions table.
func actionsHasIndex(t *testing.T, dbPath, name string) bool {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND tbl_name='actions' AND name=?`, name,
	).Scan(&n); err != nil {
		t.Fatalf("index lookup %s: %v", name, err)
	}
	return n == 1
}

// TestMigration_ActionsConnector_FreshInstall verifies a from-scratch DB ends
// up with the connector column, the connector-aware uniqueness index (and not
// the legacy 2-column one), and that global vs per-connector entries on the
// same target are isolated for exact-match reads (SK-4).
func TestMigration_ActionsConnector_FreshInstall(t *testing.T) {
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

	if !actionsHasColumn(t, dbPath, "connector") {
		t.Fatal("actions.connector column missing after fresh Init")
	}
	if !actionsHasIndex(t, dbPath, "idx_actions_type_name_conn") {
		t.Fatal("idx_actions_type_name_conn missing after fresh Init")
	}
	if actionsHasIndex(t, dbPath, "idx_actions_type_name") {
		t.Fatal("legacy idx_actions_type_name should have been dropped")
	}

	v, err := st.SchemaVersion()
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if v < 17 {
		t.Fatalf("SchemaVersion = %d, want >= 17", v)
	}

	// Global block + per-connector allow on the SAME target must coexist
	// (proves the uniqueness key is connector-aware) and stay isolated.
	if err := st.SetActionField("skill", "x", "install", "block", "global block"); err != nil {
		t.Fatalf("SetActionField global: %v", err)
	}
	if err := st.SetActionFieldForConnector("skill", "x", "hermes", "install", "allow", "hermes allow"); err != nil {
		t.Fatalf("SetActionFieldForConnector hermes: %v", err)
	}

	mustHas := func(label string, got bool, gErr error, want bool) {
		t.Helper()
		if gErr != nil {
			t.Fatalf("%s: %v", label, gErr)
		}
		if got != want {
			t.Fatalf("%s = %v, want %v", label, got, want)
		}
	}
	g, gErr := st.HasAction("skill", "x", "install", "block")
	mustHas("global block", g, gErr, true)
	hBlock, hbErr := st.HasActionForConnector("skill", "x", "hermes", "install", "block")
	mustHas("hermes block (none)", hBlock, hbErr, false)
	hAllow, haErr := st.HasActionForConnector("skill", "x", "hermes", "install", "allow")
	mustHas("hermes allow", hAllow, haErr, true)

	gEntry, err := st.GetAction("skill", "x")
	if err != nil || gEntry == nil {
		t.Fatalf("GetAction global: entry=%v err=%v", gEntry, err)
	}
	if gEntry.Connector != "" || gEntry.Actions.Install != "block" {
		t.Fatalf("global entry = {connector=%q install=%q}, want {connector=\"\" install=block}", gEntry.Connector, gEntry.Actions.Install)
	}
	hEntry, err := st.GetActionForConnector("skill", "x", "hermes")
	if err != nil || hEntry == nil {
		t.Fatalf("GetActionForConnector hermes: entry=%v err=%v", hEntry, err)
	}
	if hEntry.Connector != "hermes" || hEntry.Actions.Install != "allow" {
		t.Fatalf("hermes entry = {connector=%q install=%q}, want {connector=hermes install=allow}", hEntry.Connector, hEntry.Actions.Install)
	}

	// ListActionsByType returns both; the connector-scoped list returns one.
	all, err := st.ListActionsByType("skill")
	if err != nil {
		t.Fatalf("ListActionsByType: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("ListActionsByType returned %d entries, want 2", len(all))
	}
	hermesOnly, err := st.ListActionsByTypeForConnector("skill", "hermes")
	if err != nil {
		t.Fatalf("ListActionsByTypeForConnector: %v", err)
	}
	if len(hermesOnly) != 1 || hermesOnly[0].Connector != "hermes" {
		t.Fatalf("hermes-scoped list = %+v, want exactly one hermes entry", hermesOnly)
	}
}

// TestMigration_ActionsConnector_PreservesRows verifies that an existing
// actions table holding pre-SK-4 rows (no connector column, legacy 2-column
// unique index) upgrades in place WITHOUT data loss: rows survive as global
// (connector=”), the index is swapped, and a per-connector row can then
// coexist with the preserved global one.
func TestMigration_ActionsConnector_PreservesRows(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "legacy.db")

	// Build the actions table in the pre-SK-4 shape with the legacy 2-column
	// unique index and seed two global rows. No schema_version table, so Init
	// runs every migration from scratch; CREATE TABLE/INDEX IF NOT EXISTS in
	// migration 1 are no-ops over this pre-existing table, and the seeded rows
	// survive (block_list/allow_list don't exist, so the list migration is a
	// no-op too).
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := db.Exec(`
		CREATE TABLE actions (
			id TEXT PRIMARY KEY,
			target_type TEXT NOT NULL,
			target_name TEXT NOT NULL,
			source_path TEXT,
			actions_json TEXT NOT NULL DEFAULT '{}',
			reason TEXT,
			updated_at DATETIME NOT NULL
		);
		CREATE UNIQUE INDEX idx_actions_type_name ON actions(target_type, target_name);
		INSERT INTO actions (id, target_type, target_name, source_path, actions_json, reason, updated_at)
			VALUES ('a1', 'skill', 'legacy-skill', NULL, '{"install":"block"}', 'old block', datetime('now'));
		INSERT INTO actions (id, target_type, target_name, source_path, actions_json, reason, updated_at)
			VALUES ('a2', 'mcp', 'legacy-mcp', NULL, '{"install":"allow"}', 'old allow', datetime('now'));
	`); err != nil {
		_ = db.Close()
		t.Fatalf("seed legacy actions: %v", err)
	}
	_ = db.Close()

	st, err := audit.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer st.Close()
	if err := st.Init(); err != nil {
		t.Fatalf("Init upgrade: %v", err)
	}

	// Schema upgraded.
	if !actionsHasColumn(t, dbPath, "connector") {
		t.Fatal("actions.connector column missing after upgrade")
	}
	if !actionsHasIndex(t, dbPath, "idx_actions_type_name_conn") {
		t.Fatal("idx_actions_type_name_conn missing after upgrade")
	}
	if actionsHasIndex(t, dbPath, "idx_actions_type_name") {
		t.Fatal("legacy idx_actions_type_name should have been dropped")
	}

	// Legacy rows preserved as global — nothing lost.
	block, err := st.GetAction("skill", "legacy-skill")
	if err != nil || block == nil {
		t.Fatalf("GetAction legacy block: entry=%v err=%v", block, err)
	}
	if block.Connector != "" || block.Actions.Install != "block" || block.Reason != "old block" {
		t.Fatalf("legacy block = {connector=%q install=%q reason=%q}, want {\"\" block \"old block\"}",
			block.Connector, block.Actions.Install, block.Reason)
	}
	allow, err := st.GetAction("mcp", "legacy-mcp")
	if err != nil || allow == nil {
		t.Fatalf("GetAction legacy allow: entry=%v err=%v", allow, err)
	}
	if allow.Connector != "" || allow.Actions.Install != "allow" {
		t.Fatalf("legacy allow = {connector=%q install=%q}, want {\"\" allow}", allow.Connector, allow.Actions.Install)
	}

	// Pre-existing global block stays in force.
	if has, err := st.HasAction("skill", "legacy-skill", "install", "block"); err != nil || !has {
		t.Fatalf("HasAction global block = %v (err %v), want true", has, err)
	}

	// A per-connector row for the same (type, name) coexists with the global.
	if err := st.SetActionFieldForConnector("skill", "legacy-skill", "hermes", "install", "allow", "hermes ok"); err != nil {
		t.Fatalf("SetActionFieldForConnector: %v", err)
	}
	if has, err := st.HasActionForConnector("skill", "legacy-skill", "hermes", "install", "allow"); err != nil || !has {
		t.Fatalf("HasActionForConnector hermes allow = %v (err %v), want true", has, err)
	}
	// Global block is untouched and the hermes lookup does not see it.
	if has, err := st.HasAction("skill", "legacy-skill", "install", "block"); err != nil || !has {
		t.Fatalf("global block after per-connector write = %v (err %v), want true", has, err)
	}
	if has, err := st.HasActionForConnector("skill", "legacy-skill", "hermes", "install", "block"); err != nil || has {
		t.Fatalf("hermes block = %v (err %v), want false", has, err)
	}

	// Re-running Init is a no-op: the connector-aware index stays, the legacy
	// one does not reappear, and the per-connector row survives.
	if err := st.Init(); err != nil {
		t.Fatalf("Init re-run: %v", err)
	}
	if !actionsHasIndex(t, dbPath, "idx_actions_type_name_conn") || actionsHasIndex(t, dbPath, "idx_actions_type_name") {
		t.Fatal("re-Init disturbed the actions uniqueness index")
	}
	if has, err := st.HasActionForConnector("skill", "legacy-skill", "hermes", "install", "allow"); err != nil || !has {
		t.Fatalf("per-connector row lost after re-Init: %v (err %v)", has, err)
	}
}
