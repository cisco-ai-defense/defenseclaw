// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory/ideplugins"
	"github.com/defenseclaw/defenseclaw/internal/legacyconnector"
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
	withoutMachineIDEs(t)
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

	// ai_only keeps only the AI plugins, and the non-AI rows it stops
	// collecting are not reported removed.
	svc.opts.IDEInventory = config.IDEInventoryAIOnly
	report, err = svc.runScan(context.Background(), true, "test")
	if err != nil {
		t.Fatal(err)
	}
	if got := svc.IDEInventory(); len(got.Plugins) != 1 || got.Plugins[0].PluginID != "github.copilot" || len(report.IDEInventory.Removed) != 0 {
		t.Fatalf("ai_only = %+v, removed %+v", got.Plugins, report.IDEInventory.Removed)
	}
}

// A folder name far longer than any real one (an unknown JetBrains product
// directory, a VS Code profile) is bounded by the scan, so the guardian
// still accepts the user's report with every row in it.
func TestUserScanBoundsOddIDEFolderNames(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("per-user scans run on Linux and macOS")
	}
	withoutMachineIDEs(t)
	home := t.TempDir()
	appData := filepath.Join(home, ".config")
	if runtime.GOOS == "darwin" {
		appData = filepath.Join(home, "Library", "Application Support")
	}
	if err := os.MkdirAll(filepath.Join(appData, "JetBrains", strings.Repeat("A", 60)+"2024.1"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeVSCodeExtensions(t, home, "github.copilot")
	mustWrite(t, filepath.Join(appData, "Code", "User", "profiles", strings.Repeat("p", 250), "extensions.json"),
		`[{"identifier":{"id":"github.copilot"},"version":"1.0.0","relativeLocation":"github.copilot-1.0.0"}]`)
	report := ScanUserHome(context.Background(), home, "alice", os.Getuid(), UserScanOptions{}, nil)
	if err := SanitizeUserScanReport(&report, nil, false, false); err != nil {
		t.Fatalf("SanitizeUserScanReport: %v", err)
	}
	if ide := report.IDEInventory; ide == nil || len(ide.Installations) != 2 || len(ide.Plugins) != 2 || ide.Partial {
		t.Fatalf("IDE inventory = %+v, want the JetBrains and VS Code installations and both plugin rows", ide)
	}
}

// A marketplace AI extension creates a signature outside the curated
// catalog; the guardian must still accept the full user report.
func TestUserScanAcceptsMarketplaceAISignal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("per-user scans run on Linux and macOS")
	}
	withoutMachineIDEs(t)
	home := t.TempDir()
	writeVSCodeExtensions(t, home, "augment.vscode-augment")
	report := ScanUserHome(context.Background(), home, "alice", os.Getuid(), UserScanOptions{}, nil)
	if len(report.Signals) != 1 || report.Signals[0].SignatureID != "ide-augment.vscode-augment" {
		t.Fatalf("marketplace signals = %+v", report.Signals)
	}
	if err := SanitizeUserScanReport(&report, nil, false, false); err != nil {
		t.Fatalf("SanitizeUserScanReport: %v", err)
	}
}

// GAP-0396: the guardian's per-user scan runs as the home's owner, but a
// link that owner planted toward another readable home must not put the
// other account's plugins in this account's managed inventory.
func TestUserScanFollowsNoLinkOutOfTheHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("per-user scans run on Linux and macOS")
	}
	withoutMachineIDEs(t)
	home, other := t.TempDir(), t.TempDir()
	writeVSCodeExtensions(t, home, "github.copilot")
	writeVSCodeExtensions(t, other, "secretco.internal-ai-assistant")
	if err := os.Symlink(filepath.Join(other, ".vscode"), filepath.Join(home, ".cursor")); err != nil {
		t.Fatal(err)
	}
	report := ScanUserHome(context.Background(), home, "alice", os.Getuid(), UserScanOptions{}, nil)
	ide := report.IDEInventory
	if ide == nil || len(ide.Plugins) != 1 || ide.Plugins[0].PluginID != "github.copilot" {
		t.Fatalf("IDE inventory = %+v, want only the home's own plugin", ide)
	}
}

// An upgrade from 1.0.0 keeps an editor-extension signal's fingerprint:
// the stored row below is the Continue signal of a 1.0.0 per-user install
// (dc-win2, GAP-0297), keyed on the extension id, and the first full scan
// after the upgrade reports that same signal as seen since it was stored.
func TestUpgradeFrom100KeepsTheEditorExtensionFingerprint(t *testing.T) {
	withoutMachineIDEs(t)
	home := t.TempDir()
	writeVSCodeExtensions(t, home, "continue.continue")
	catalog, err := LoadAISignatures()
	if err != nil {
		t.Fatal(err)
	}
	service := &ContinuousDiscoveryService{
		catalog: catalog,
		opts:    AIDiscoveryOptions{Mode: "passive", HomeDir: home, HomeDirs: []string{home}},
		store:   NewAIStateStore(filepath.Join(t.TempDir(), "state.json")),
	}
	const fingerprint100 = "sha256:ff641fd7415804e6b4d636aefdbda5e88ea62e87ff81136104b5d51b2c9dd2a4"
	firstSeen := time.Date(2026, 10, 7, 23, 40, 0, 0, time.UTC)
	prev := aiStateFile{Signals: map[string]aiStoredSignal{fingerprint100: {AISignal: AISignal{
		Fingerprint: fingerprint100, SignatureID: "continue", Category: SignalEditorExtension,
		Detector: "editor_extension", FirstSeen: firstSeen, State: AIStateSeen,
	}}}}
	signals, _ := service.detectEditorExtensions()
	stats := scanStats{DetectorErrors: map[string]string{}, DetectorDurations: map[string]int{}}
	report := service.classifyAndPersist("full-1", "test", time.Now(), signals, stats, prev, true)
	if len(report.Signals) != 1 || report.Signals[0].Fingerprint != fingerprint100 ||
		report.Signals[0].State != AIStateSeen || !report.Signals[0].FirstSeen.Equal(firstSeen) {
		t.Fatalf("signals = %+v, want the 1.0.0 signal, seen since it was stored", report.Signals)
	}
}

// The Devin vendor's plugins keep pre-rename ids that the catalog does not
// spell; the AI index still flags them as Devin plugins.
func TestIDEAIIndexFlagsPreRenameDevinPlugins(t *testing.T) {
	idx := newIDEAIIndex([]AISignature{{ID: legacyconnector.Replacement}})
	for family, id := range map[string]string{
		ideplugins.FamilyVSCode:    legacyconnector.VSCodeExtensionIDs[0],
		ideplugins.FamilyJetBrains: legacyconnector.JetBrainsPluginIDs[0],
		ideplugins.FamilyVim:       legacyconnector.VimPlugins[0],
	} {
		if sig, ok := idx.match(family, id); !ok || sig.ID != legacyconnector.Replacement {
			t.Fatalf("%s %s matched %+v, %t", family, id, sig, ok)
		}
	}
}

func TestMarketplaceAIExtensionsIncludeDescribedAndKnownProducts(t *testing.T) {
	index := newIDEAIIndex(nil)
	for _, id := range []string{
		"augment.vscode-augment", "kilocode.kilo-code", "rjmacarthy.twinny",
		"genieai.chatgpt-vscode", "gitlab.gitlab-workflow",
		"google.gemini-cli-vscode-ide-companion", "sst-dev.opencode",
		"visualstudioexptteam.vscodeintellicode",
	} {
		if _, ok := index.matchPlugin(ideplugins.FamilyVSCode, ideplugins.Plugin{ID: id}); !ok {
			t.Fatalf("%s was not flagged AI", id)
		}
	}
	if _, ok := index.matchPlugin(ideplugins.FamilyVSCode, ideplugins.Plugin{
		ID: "newvendor.assistant", Description: "AI coding assistant for editors",
	}); !ok {
		t.Fatal("description-based AI coding rule missed a new extension")
	}
	if _, ok := index.matchPlugin(ideplugins.FamilyVSCode, ideplugins.Plugin{
		ID: "plain.theme", Description: "A colorful theme",
	}); ok {
		t.Fatal("ordinary extension was flagged AI")
	}
}

// The built-in catalog flags JetBrains' own AI Assistant plugin as AI.
func TestIDEAIIndexFlagsJetBrainsAIAssistant(t *testing.T) {
	catalog, err := LoadAISignatures()
	if err != nil {
		t.Fatal(err)
	}
	if sig, ok := newIDEAIIndex(catalog).match(ideplugins.FamilyJetBrains, "com.intellij.ml.llm"); !ok || sig.ID != "jetbrains-ai" {
		t.Fatalf("com.intellij.ml.llm matched %+v, %t", sig, ok)
	}
}

// A v3 inventory.db migrates in place: existing
// rows survive and the new columns and tables are there.
func TestInventoryStoreMigratesV3ToV6(t *testing.T) {
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
	// A pre-upgrade store may already have counted agent sessions.
	if _, err := db.Exec(`CREATE TABLE agent_identity_sessions (
		agent_id TEXT NOT NULL, session_id TEXT NOT NULL, first_seen TEXT NOT NULL,
		PRIMARY KEY (agent_id, session_id)) WITHOUT ROWID`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO agent_identity_sessions VALUES ('agt-old', 'session-old', ?)`, now.Format(agentIdentityTimeLayout)); err != nil {
		t.Fatal(err)
	}
	db.Close()

	st, err := NewInventoryStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if v, _ := st.SchemaVersion(); v != 6 {
		t.Fatalf("schema version = %d, want 6", v)
	}
	var sessionLastSeen string
	if err := st.db.QueryRow(`SELECT last_seen FROM agent_identity_sessions WHERE agent_id = 'agt-old'`).Scan(&sessionLastSeen); err != nil || sessionLastSeen != now.Format(agentIdentityTimeLayout) {
		t.Fatalf("migrated session last_seen = %q, err %v", sessionLastSeen, err)
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

// withoutMachineIDEs keeps a test's scan off the host's machine-wide IDE
// installations (a Windows runner ships Visual Studio).
func withoutMachineIDEs(t *testing.T) {
	t.Helper()
	previous := programFilesDirs
	programFilesDirs = func() []string { return nil }
	t.Cleanup(func() { programFilesDirs = previous })
}

func TestUserPluginCapPreservesLaterInstallationBaseline(t *testing.T) {
	now := time.Now().UTC()
	first := IDEInstallation{InstallID: "first", Family: ideplugins.FamilyVSCode, Product: "vscode", PathHash: hashPath("/first")}
	later := IDEInstallation{InstallID: "later", Family: ideplugins.FamilyJetBrains, Product: "intellij", PathHash: hashPath("/later")}
	inv := &IDEInventory{Scope: config.IDEInventoryAll, Installations: []IDEInstallation{first, later}}
	for i := 0; i < MaxIDEPluginsPerUser; i++ {
		inv.Plugins = append(inv.Plugins, IDEPlugin{Fingerprint: fmt.Sprintf("first-%d", i), InstallID: first.InstallID, Family: first.Family, Product: first.Product, PluginID: fmt.Sprintf("example.%d", i), Enabled: ideplugins.EnabledOn})
	}
	old := IDEPlugin{Fingerprint: "later-plugin", InstallID: later.InstallID, Family: later.Family, Product: later.Product, PluginID: "example.plugin", Enabled: ideplugins.EnabledOn}
	inv.Plugins = append(inv.Plugins, old)
	boundUserScanIDE(inv)
	svc := &ContinuousDiscoveryService{ideBaseline: map[string]IDEPlugin{old.Fingerprint: old}, opts: AIDiscoveryOptions{IDEInventory: config.IDEInventoryAll}}
	got := svc.finishIDEInventory(inv, true, now)
	// Publishing the retained row re-sorts the installations (GAP-0594).
	laterPartial := false
	for _, inst := range got.Installations {
		laterPartial = laterPartial || inst.InstallID == later.InstallID && inst.Partial
	}
	if len(got.Removed) != 0 || !laterPartial {
		t.Fatalf("capped later installation: removed=%v partial=%v", got.Removed, laterPartial)
	}
	for _, p := range got.Plugins {
		if p.Fingerprint == old.Fingerprint {
			return
		}
	}
	t.Fatal("later installation baseline missing from the published inventory")
}

// A capped IDE scan cannot prove that an AI extension missing beyond the cap
// was removed while the IDE inventory still retains that plugin.
func TestPartialIDEInventoryKeepsEditorExtensionSignal(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".vscode", "extensions")
	sig := AISignature{ID: "copilot", Name: "GitHub Copilot", Category: SignalSupportedConnector, ExtensionIDs: []string{"github.copilot"}}
	svc := &ContinuousDiscoveryService{
		opts:  AIDiscoveryOptions{IDEInventory: config.IDEInventoryAll, HomeDir: home},
		store: NewAIStateStore(filepath.Join(t.TempDir(), "state.json")),
	}
	old := svc.signalFromValue(sig, SignalEditorExtension, "editor_extension", "github.copilot")
	firstSeen := time.Now().Add(-time.Hour).UTC()
	old.FirstSeen = firstSeen
	prior := aiStateFile{Signals: map[string]aiStoredSignal{
		old.Fingerprint: {AISignal: old, StoredEvidence: old.Evidence},
	}}
	index := newIDEAIIndex([]AISignature{sig})
	complete := &IDEInventory{Scope: config.IDEInventoryAll}
	plugin := ideplugins.Plugin{ID: "github.copilot", Enabled: ideplugins.EnabledOn}
	install := ideplugins.Install{Family: ideplugins.FamilyVSCode, Product: "vscode", Root: root, Plugins: []ideplugins.Plugin{plugin}}
	complete.add([]ideplugins.Install{install}, ideOwner{}, index, time.Now())
	svc.ideBaseline = map[string]IDEPlugin{complete.Plugins[0].Fingerprint: complete.Plugins[0]}
	install.Partial = true
	install.Plugins = nil
	partial := &IDEInventory{Scope: config.IDEInventoryAll}
	partial.add([]ideplugins.Install{install}, ideOwner{}, index, time.Now())
	stats := scanStats{ideInventory: partial, DetectorErrors: map[string]string{}, DetectorDurations: map[string]int{}}
	report := svc.classifyAndPersist("partial", "test", time.Now(), nil, stats, prior, true)
	if report.Summary.GoneSignals != 0 || report.Summary.ActiveSignals != 1 || len(report.Signals) != 1 ||
		report.Signals[0].State != AIStateSeen || !report.Signals[0].FirstSeen.Equal(firstSeen) {
		t.Fatalf("partial editor signals = %+v, summary = %+v", report.Signals, report.Summary)
	}
	if report.IDEInventory == nil || len(report.IDEInventory.Plugins) != 1 {
		t.Fatalf("partial IDE inventory = %+v", report.IDEInventory)
	}
}
