// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func writeVSCodeExtensions(t *testing.T, home string, ids ...string) {
	t.Helper()
	var entries []map[string]any
	for _, id := range ids {
		folder := id + "-1.0.0"
		mustWrite(t, filepath.Join(home, ".vscode", "extensions", folder, "package.json"), `{"version":"1.0.0"}`)
		entries = append(entries, map[string]any{"identifier": map[string]string{"id": id}, "version": "1.0.0", "relativeLocation": folder})
	}
	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(home, ".vscode", "extensions", "extensions.json"), string(data))
}

// A service-context scan (managed Windows walks every profile) attributes
// each home's IDE plugins and AI editor-extension signals to the profile's
// owner, flags AI plugins from the catalog, records the list in
// inventory.db, and reports plugins that disappear as removed.
func TestIDEInventoryAttributesPluginsToProfileOwners(t *testing.T) {
	root := t.TempDir()
	alice := filepath.Join(root, "Users", "alice")
	bob := filepath.Join(root, "Users", "bob")
	writeVSCodeExtensions(t, alice, "github.copilot", "ms-python.python")
	writeVSCodeExtensions(t, bob, "github.copilot")
	catalog := []AISignature{{ID: "copilot", Name: "GitHub Copilot", Vendor: "GitHub", Category: SignalSupportedConnector, ExtensionIDs: []string{"github.copilot"}}}
	owners := []discoveryHomeOwner{
		{Home: alice, UserID: "S-1-5-21-1-2-3-1001", UserName: "alice"},
		{Home: bob, UserID: "S-1-5-21-1-2-3-1002", UserName: "bob"},
	}
	opts := AIDiscoveryOptions{Enabled: true, DataDir: filepath.Join(root, "data"), HomeDir: alice, HomeDirs: []string{alice, bob}, ScanRoots: []string{filepath.Join(root, "none")}}
	svc := NewContinuousDiscoveryServiceWithOptions(opts, catalog)
	svc.opts.homeOwners = owners
	cleanupPreparedDiscoveryService(t, svc)

	report, err := svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatal(err)
	}
	signals := map[string]bool{}
	for _, sig := range report.Signals {
		if sig.Category == SignalEditorExtension {
			signals[sig.UserName] = true
		}
	}
	if !signals["alice"] || !signals["bob"] || len(signals) != 2 {
		t.Fatalf("editor extension signals by owner = %v, want one each for alice and bob", signals)
	}
	inv := svc.IDEInventory()
	if inv == nil || len(inv.Plugins) != 3 {
		t.Fatalf("inventory = %+v", inv)
	}
	for _, p := range inv.Plugins {
		wantID := map[string]string{"alice": "S-1-5-21-1-2-3-1001", "bob": "S-1-5-21-1-2-3-1002"}[p.UserName]
		if p.UserID != wantID || p.State != AIStateNew || p.IsAI != (p.PluginID == "github.copilot") {
			t.Fatalf("plugin %+v", p)
		}
		if strings.Contains(p.PathHash, root) {
			t.Fatalf("raw path in %+v", p)
		}
	}
	if c := inv.Counts(); c.Users != 2 || c.AI != 2 || c.ByIDE["vscode"] != 3 {
		t.Fatalf("counts = %+v", c)
	}

	// Bob removes Copilot: the next full scan reports it removed, and the
	// history store holds the latest list.
	writeVSCodeExtensions(t, bob)
	report, err = svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatal(err)
	}
	if got := report.IDEInventory; got == nil || len(got.Removed) != 1 || got.Removed[0].UserName != "bob" || len(got.Plugins) != 2 {
		t.Fatalf("second scan = %+v", got)
	}
	// A process-only scan carries the list without writing it again.
	if _, err := svc.runScan(context.Background(), false, "test"); err != nil {
		t.Fatal(err)
	}
	stored, err := svc.InventoryStore().LatestIDEPlugins(context.Background())
	if err != nil || len(stored) != 2 {
		t.Fatalf("stored = %+v, %v", stored, err)
	}
	var rows int
	if err := svc.InventoryStore().db.QueryRow(`SELECT COUNT(*) FROM ide_plugins`).Scan(&rows); err != nil || rows != 5 {
		t.Fatalf("ide_plugins rows = %d, %v; want the two full scans only (3 + 2)", rows, err)
	}

	// ai_only keeps only the AI plugins.
	svc.opts.IDEInventory = config.IDEInventoryAIOnly
	if _, err := svc.runScan(context.Background(), true, "test"); err != nil {
		t.Fatal(err)
	}
	if got := svc.IDEInventory(); len(got.Plugins) != 1 || got.Plugins[0].PluginID != "github.copilot" {
		t.Fatalf("ai_only = %+v", got.Plugins)
	}
}

// A v3 inventory.db (the 1.0.0 schema) migrates to v4 in place: existing
// rows survive and the new columns and tables are there.
func TestInventoryStoreMigratesV3ToV4(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.db")
	db, err := sql.Open("sqlite", path+inventoryPragmas)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at DATETIME NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for i, m := range inventoryMigrations[:3] {
		if err := m.apply(db); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO schema_version VALUES (?, ?)`, i+1, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	for _, q := range []string{
		`INSERT INTO ai_scans VALUES ('scan-1', ?, 1, 'sidecar', 'enhanced', 'ok', 1, 1, 0)`,
		`INSERT INTO ai_signals (scan_id, fingerprint, signal_id, signature_id, name, vendor, product, category, detector, state, confidence, last_seen)
		 VALUES ('scan-1', 'fp', 'ai-1', 'codex', 'Codex', 'OpenAI', 'Codex', 'supported_connector', 'config', 'seen', 0.9, ?)`,
	} {
		if _, err := db.Exec(q, now); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	st, err := NewInventoryStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if v, _ := st.SchemaVersion(); v != 4 {
		t.Fatalf("schema version = %d, want 4", v)
	}
	var name string
	var user sql.NullString
	if err := st.db.QueryRow(`SELECT name, user_id FROM ai_signals WHERE fingerprint = 'fp'`).Scan(&name, &user); err != nil || name != "Codex" || user.Valid {
		t.Fatalf("migrated row = %q %v, %v", name, user, err)
	}
	for _, table := range []string{"ide_installations", "ide_plugins", "agent_identities"} {
		if _, err := st.db.Exec(`SELECT * FROM ` + table + ` LIMIT 1`); err != nil {
			t.Fatalf("table %s: %v", table, err)
		}
	}
	// Retention pruning removes a scan's IDE rows with it.
	if _, err := st.db.Exec(`INSERT INTO ide_installations (scan_id, install_id, ide_family, ide_product, last_seen) VALUES ('scan-1', 'ide-1', 'vscode', 'vscode', ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`INSERT INTO ai_scans VALUES ('scan-2', ?, 1, 'sidecar', 'enhanced', 'ok', 0, 0, 0)`, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PruneScanHistory(context.Background(), now.Add(30*time.Second), time.Second); err != nil {
		t.Fatal(err)
	}
	var left int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM ide_installations`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("ide rows after prune = %d, %v", left, err)
	}
	_ = os.Remove(path)
}
