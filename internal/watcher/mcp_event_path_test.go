// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestGAP0034EventPathDistinguishesScopeTuples(t *testing.T) {
	base := t.TempDir()
	project := filepath.Join(base, "project")
	first := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: base, Project: project}
	second := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: base + "@claudecode#" + project}
	if MCPEventPath(first) == MCPEventPath(second) {
		t.Fatal("different home and project tuples share a snapshot key")
	}

	values := []string{"", "notes", "@", "#", ":", "@claudecode#", "notes@claudecode:/tmp"}
	seen := make(map[string]config.MCPServerEntry)
	for _, name := range values {
		for _, connector := range values {
			for _, home := range values {
				for _, project := range values {
					server := config.MCPServerEntry{Name: name, Connector: connector, Home: home, Project: project}
					key := MCPEventPath(server)
					if previous, ok := seen[key]; ok {
						t.Fatalf("scope tuples %+v and %+v share key %q", previous, server, key)
					}
					seen[key] = server
				}
			}
		}
	}
}

func TestGAP0034DistinctSnapshotKeysPreserveCompletedFailure(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.MCP.TakeAction = true
	cfg.Scanners.MCPScanner.UnverifiedServer = "warn"
	home := filepath.Join(t.TempDir(), "account")
	project := t.TempDir()
	failed := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: home,
		Project: project, SourceScope: "project", Command: "npx", Args: []string{"-y", "."}}
	ordinary := config.MCPServerEntry{Name: "notes", Connector: "claudecode",
		Home: home + "@claudecode#" + project, Command: "npx", Args: []string{"-y", "."}}
	servers := []config.MCPServerEntry{failed}
	w := New(cfg, nil, nil, store, logger, nil, nil)
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return servers, nil })
	w.firstCycleDone.Store(true)
	w.scannerFactory = func(InstallEvent) scanner.Scanner {
		return &failingScanner{countingScanner{name: "mcp-scanner"}}
	}
	w.AdmitAddedMCPServers([]string{failed.Name})
	w.admitAddedMCPServers(context.Background())
	failedQuery := MCPAdmissionQuery{Connector: failed.Connector, Server: failed.Name, Home: failed.Home, CWD: project}
	if got := w.MCPAdmissionStatus(failedQuery); !got.Failed {
		t.Fatalf("failed scan was not stored: %+v", got)
	}

	servers = []config.MCPServerEntry{ordinary, failed}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &countingScanner{name: "mcp-scanner"} }
	w.AdmitAddedMCPServers([]string{ordinary.Name})
	w.admitAddedMCPServers(context.Background())
	if got := w.MCPAdmissionStatus(failedQuery); !got.Failed {
		t.Fatalf("ordinary server replaced the completed failure: %+v", got)
	}
	ordinaryQuery := MCPAdmissionQuery{Connector: ordinary.Connector, Server: ordinary.Name, Home: ordinary.Home, CWD: t.TempDir()}
	if got := w.MCPAdmissionStatus(ordinaryQuery); got.Failed || got.Pending {
		t.Fatalf("admitted ordinary server inherited the failure: %+v", got)
	}
}

func TestGAP0034LegacyUnscopedHomeIsNeverSplit(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.MCP.TakeAction = true
	baseHome := filepath.Join(t.TempDir(), "account")
	project := t.TempDir()
	failedHome := baseHome + "@claudecode#" + project
	legacyPath := "notes@claudecode:" + failedHome
	if err := store.SetTargetSnapshot(string(InstallMCP), legacyPath, "hash", "{}",
		`{"mcp.servers.notes":"hash"}`, "[]", "", "fingerprint"+mcpScanFailedMark); err != nil {
		t.Fatal(err)
	}
	cold := New(cfg, nil, nil, store, logger, nil, nil)
	cold.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return nil, errors.New("source list unavailable") })
	cold.firstCycleDone.Store(true)
	for _, tc := range []struct {
		name   string
		query  MCPAdmissionQuery
		failed bool
	}{
		{"failed account", MCPAdmissionQuery{Connector: "claudecode", Server: "notes", Home: failedHome, CWD: t.TempDir()}, true},
		{"unresolved home", MCPAdmissionQuery{Connector: "claudecode", Server: "notes", CWD: t.TempDir()}, true},
		{"ordinary other account", MCPAdmissionQuery{Connector: "claudecode", Server: "notes", Home: baseHome, CWD: project}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := cold.MCPAdmissionStatus(tc.query)
			if got.Failed != tc.failed || got.Unavailable == tc.failed {
				t.Fatalf("legacy state = %+v, want failed=%v", got, tc.failed)
			}
		})
	}
}

func TestGAP0034LegacyPathOnlyNameDoesNotAcquireProjectScope(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.MCP.TakeAction = true
	project := t.TempDir()
	legacyName := "notes@claudecode#" + project
	if err := store.SetTargetSnapshot(string(InstallMCP), legacyName, "hash", "{}", "{}", "[]", "", "fingerprint"+mcpScanFailedMark); err != nil {
		t.Fatal(err)
	}
	cold := New(cfg, nil, nil, store, logger, nil, nil)
	cold.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return nil, errors.New("source list unavailable") })
	cold.firstCycleDone.Store(true)
	if got := cold.MCPAdmissionStatus(MCPAdmissionQuery{Connector: "claudecode", Server: "notes", CWD: project}); got.Failed || !got.Unavailable {
		t.Fatalf("ordinary server inherited legacy name failure: %+v", got)
	}
	if got := cold.MCPAdmissionStatus(MCPAdmissionQuery{Connector: "claudecode", Server: legacyName}); !got.Failed {
		t.Fatalf("named server lost its completed failure: %+v", got)
	}
}

func TestGAP0034LegacySnapshotMigratesOnFirstWrite(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.MCP.TakeAction = true
	server := config.MCPServerEntry{Name: "notes", Connector: "claudecode",
		Home: filepath.Join(t.TempDir(), "account@claudecode#literal"), Command: "npx", Args: []string{"-y", "."}}
	hash, err := mcpDefinitionHash(server)
	if err != nil {
		t.Fatal(err)
	}
	oldPath := legacyMCPEventPath(server)
	identity, err := json.Marshal(mcpIdentityForServer(server))
	if err != nil {
		t.Fatal(err)
	}
	hashes, err := json.Marshal(map[string]string{"mcp.servers.notes": hash, mcpSnapshotIdentityKey: string(identity)})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetTargetSnapshot(string(InstallMCP), oldPath, hash, "{}",
		string(hashes), "[]", "", "fingerprint"+mcpScanFailedMark); err != nil {
		t.Fatal(err)
	}
	w := New(cfg, nil, nil, store, logger, nil, nil)
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return []config.MCPServerEntry{server}, nil })
	w.firstCycleDone.Store(true)
	query := MCPAdmissionQuery{Connector: server.Connector, Server: server.Name, Home: server.Home}
	if got := w.MCPAdmissionStatus(query); !got.Failed {
		t.Fatalf("legacy failed scan was not read: %+v", got)
	}
	evt := InstallEvent{Type: InstallMCP, Name: server.Name, Path: MCPEventPath(server), Connector: server.Connector}
	snap, err := w.snapshotMCPServer(evt)
	if err != nil {
		t.Fatal(err)
	}
	w.persistSnapshot(evt, snap, "scan-clean", "fingerprint")
	if _, err := store.GetTargetSnapshot(string(InstallMCP), oldPath); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("old snapshot remains after versioned write: %v", err)
	}
	if got := w.MCPAdmissionStatus(query); got.Failed || got.Pending || got.Unavailable {
		t.Fatalf("clean versioned snapshot did not replace old failure: %+v", got)
	}
}

func TestGAP0034AccountJournalKeepsLiteralHomeAndProjectSeparate(t *testing.T) {
	home := filepath.Join(t.TempDir(), "account")
	project := t.TempDir()
	projectServer := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: home, Project: project}
	literalHomeServer := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: home + "@claudecode#" + project}
	projectKey := MCPJournalName(projectServer)
	literalKey := MCPJournalName(literalHomeServer)
	if projectKey == literalKey {
		t.Fatal("different account scopes share a journal key")
	}
	projectCall := MCPAdmissionQuery{Connector: "claudecode", Server: "notes", Home: home, CWD: project}
	literalCall := MCPAdmissionQuery{Connector: "claudecode", Server: "notes", Home: literalHomeServer.Home, CWD: t.TempDir()}
	if !MCPAccountJournalServes(projectKey, projectCall) || MCPAccountJournalServes(projectKey, literalCall) {
		t.Fatal("project row matched the literal-home account")
	}
	if !MCPAccountJournalServes(literalKey, literalCall) || MCPAccountJournalServes(literalKey, projectCall) {
		t.Fatal("literal-home row matched the project account")
	}
}

func TestGAP0034StructuredLegacyProjectSnapshotMigrates(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.MCP.TakeAction = true
	server := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: t.TempDir(),
		Project: t.TempDir(), Command: "npx", Args: []string{"-y", "."}}
	hash, err := mcpDefinitionHash(server)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := json.Marshal(mcpIdentityForServer(server))
	if err != nil {
		t.Fatal(err)
	}
	hashes, err := json.Marshal(map[string]string{"mcp.servers.notes": hash, mcpSnapshotIdentityKey: string(identity)})
	if err != nil {
		t.Fatal(err)
	}
	oldPath := legacyMCPEventPath(server)
	if err := store.SetTargetSnapshot(string(InstallMCP), oldPath, hash, "{}", string(hashes), "[]", "", "fingerprint"+mcpScanFailedMark); err != nil {
		t.Fatal(err)
	}
	w := New(cfg, nil, nil, store, logger, nil, nil)
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return []config.MCPServerEntry{server}, nil })
	w.firstCycleDone.Store(true)
	query := MCPAdmissionQuery{Connector: server.Connector, Server: server.Name, Home: server.Home, CWD: server.Project}
	if got := w.MCPAdmissionStatus(query); !got.Failed {
		t.Fatalf("structured legacy failure was not read: %+v", got)
	}
	evt := InstallEvent{Type: InstallMCP, Name: server.Name, Path: MCPEventPath(server), Connector: server.Connector}
	snap, err := w.snapshotMCPServer(evt)
	if err != nil {
		t.Fatal(err)
	}
	w.persistSnapshot(evt, snap, "scan-clean", "fingerprint")
	if _, err := store.GetTargetSnapshot(string(InstallMCP), oldPath); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("old project snapshot remains after versioned write: %v", err)
	}
	if got := w.MCPAdmissionStatus(query); got.Failed || got.Pending || got.Unavailable {
		t.Fatalf("clean versioned snapshot did not replace old project failure: %+v", got)
	}
}

func TestGAP0034LegacyAccountJournalClearsAfterCleanReadmission(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.MCP.TakeAction = true
	server := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: t.TempDir(),
		Project: t.TempDir(), Command: "npx", Args: []string{"-y", "."}}
	hash, err := mcpDefinitionHash(server)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := json.Marshal(mcpIdentityForServer(server))
	if err != nil {
		t.Fatal(err)
	}
	hashes, err := json.Marshal(map[string]string{"mcp.servers.notes": hash, mcpSnapshotIdentityKey: string(identity)})
	if err != nil {
		t.Fatal(err)
	}
	oldPath := legacyMCPEventPath(server)
	if err := store.SetTargetSnapshot(string(InstallMCP), oldPath, hash, "{}", string(hashes), "[]", "", "fingerprint"+mcpScanFailedMark); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActionForConnector(string(InstallMCP), oldPath, server.Connector, oldPath,
		audit.ActionState{Install: "block", Runtime: "disable"}, scanFailureReason+"previous scan"); err != nil {
		t.Fatal(err)
	}
	w := New(cfg, nil, nil, store, logger, nil, nil)
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return []config.MCPServerEntry{server}, nil })
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &countingScanner{name: "mcp-scanner"} }
	w.firstCycleDone.Store(true)
	evt := InstallEvent{Type: InstallMCP, Name: server.Name, Path: MCPEventPath(server), Connector: server.Connector}
	if result := w.runAdmission(context.Background(), evt); result.Verdict != VerdictClean {
		t.Fatalf("clean readmission: %+v", result)
	}
	old, err := store.GetActionForConnector(string(InstallMCP), oldPath, server.Connector)
	if err != nil || old != nil {
		t.Fatalf("legacy action remains after clean readmission: %+v, %v", old, err)
	}
	current, err := store.GetActionForConnector(string(InstallMCP), MCPJournalName(server), server.Connector)
	if err != nil || current != nil && (current.Actions.Install == "block" || current.Actions.Runtime == "disable") {
		t.Fatalf("clean account still refused: %+v, %v", current, err)
	}
}

func TestGAP0034LegacyJournalMigrationKeepsOtherScope(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	home := filepath.Join(t.TempDir(), "account")
	project := t.TempDir()
	failed := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: home,
		Project: project, Command: "npx"}
	ordinary := config.MCPServerEntry{Name: "notes", Connector: "claudecode",
		Home: home + "@claudecode#" + project, Command: "npx"}
	oldPath := legacyMCPEventPath(failed)
	if oldPath != legacyMCPEventPath(ordinary) {
		t.Fatal("fixture must share the old key")
	}
	hash, err := mcpDefinitionHash(failed)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := json.Marshal(mcpIdentityForServer(failed))
	if err != nil {
		t.Fatal(err)
	}
	hashes, err := json.Marshal(map[string]string{"mcp.servers.notes": hash, mcpSnapshotIdentityKey: string(identity)})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetTargetSnapshot(string(InstallMCP), oldPath, hash, "{}", string(hashes), "[]", "", "fingerprint"+mcpScanFailedMark); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActionForConnector(string(InstallMCP), oldPath, failed.Connector, oldPath,
		audit.ActionState{Runtime: "disable"}, scanFailureReason+"previous scan"); err != nil {
		t.Fatal(err)
	}
	w := New(cfg, nil, nil, store, logger, nil, nil)
	ordinaryEvent := InstallEvent{Type: InstallMCP, Name: ordinary.Name, Path: MCPEventPath(ordinary), Connector: ordinary.Connector}
	if err := w.migrateLegacyMCPJournal(ordinaryEvent); err != nil {
		t.Fatal(err)
	}
	if row, err := store.GetActionForConnector(string(InstallMCP), oldPath, failed.Connector); err != nil || row == nil || row.Actions.Runtime != "disable" {
		t.Fatalf("another scope moved the old block: %+v, %v", row, err)
	}
	if row, err := store.GetActionForConnector(string(InstallMCP), ordinaryEvent.Path, ordinary.Connector); err != nil || row != nil {
		t.Fatalf("ordinary scope inherited the old block: %+v, %v", row, err)
	}
	failedEvent := InstallEvent{Type: InstallMCP, Name: failed.Name, Path: MCPEventPath(failed), Connector: failed.Connector}
	if err := w.migrateLegacyMCPJournal(failedEvent); err != nil {
		t.Fatal(err)
	}
	if row, err := store.GetActionForConnector(string(InstallMCP), failedEvent.Path, failed.Connector); err != nil || row == nil || row.Actions.Runtime != "disable" {
		t.Fatalf("failed scope lost its block: %+v, %v", row, err)
	}
	if row, err := store.GetActionForConnector(string(InstallMCP), oldPath, failed.Connector); err != nil || row != nil {
		t.Fatalf("old key remained after scoped move: %+v, %v", row, err)
	}
}

func TestGAP0034PreIdentityProjectRowDoesNotMoveToLiteralHome(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	home := filepath.Join(t.TempDir(), "alice")
	project := t.TempDir()
	failed := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: home,
		Project: project, SourceScope: "project", Command: "npx", Args: []string{"-y", "."}}
	ordinary := config.MCPServerEntry{Name: "notes", Connector: "claudecode",
		Home: home + "@claudecode#" + project, Command: "npx", Args: []string{"-y", "."}}
	oldPath := legacyMCPEventPath(failed)
	if oldPath != legacyMCPEventPath(ordinary) {
		t.Fatal("fixture does not share the legacy path")
	}
	hash, err := mcpDefinitionHash(failed)
	if err != nil {
		t.Fatal(err)
	}
	hashes, err := json.Marshal(map[string]string{"mcp.servers.notes": hash})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetTargetSnapshot(string(InstallMCP), oldPath, hash, "{}", string(hashes), "[]", "", "fingerprint"+mcpScanFailedMark); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActionForConnector(string(InstallMCP), oldPath, failed.Connector, oldPath,
		audit.ActionState{Runtime: "disable"}, scanFailureReason+"previous scan"); err != nil {
		t.Fatal(err)
	}
	w := New(cfg, nil, nil, store, logger, nil, nil)
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return []config.MCPServerEntry{ordinary}, nil })
	evt := InstallEvent{Type: InstallMCP, Name: ordinary.Name, Path: MCPEventPath(ordinary), Connector: ordinary.Connector}
	if err := w.migrateLegacyMCPJournal(evt); err != nil {
		t.Fatal(err)
	}
	if row, err := store.GetActionForConnector(string(InstallMCP), evt.Path, evt.Connector); err != nil || row != nil {
		t.Fatalf("other account inherited the legacy action: row=%+v err=%v", row, err)
	}
	snap, err := w.snapshotMCPServer(evt)
	if err != nil {
		t.Fatal(err)
	}
	w.persistSnapshot(evt, snap, "scan-clean", "fingerprint")
	if row, err := store.GetTargetSnapshot(string(InstallMCP), oldPath); err != nil || row == nil || !mcpSnapshotFailed(row) {
		t.Fatalf("other account retired the failed snapshot: row=%+v err=%v", row, err)
	}
	if row, err := store.GetActionForConnector(string(InstallMCP), oldPath, failed.Connector); err != nil || row == nil || row.Actions.Runtime != "disable" {
		t.Fatalf("other account retired the failed action: row=%+v err=%v", row, err)
	}
	old, err := store.GetTargetSnapshot(string(InstallMCP), oldPath)
	if err != nil {
		t.Fatal(err)
	}
	protectedCall := MCPAdmissionQuery{Connector: failed.Connector, Server: failed.Name, Home: home, CWD: project}
	ordinaryCall := MCPAdmissionQuery{Connector: ordinary.Connector, Server: ordinary.Name, Home: ordinary.Home, CWD: t.TempDir()}
	if !MCPAccountJournalServesSnapshot(oldPath, old, protectedCall) || MCPAccountJournalServesSnapshot(oldPath, old, ordinaryCall) {
		t.Fatal("remaining legacy action crossed account scopes")
	}
}

func TestGAP0034AmbiguousPreIdentityScopesStayUnmovedEvenWithEqualHash(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	project := t.TempDir()
	projectServer := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: home,
		Project: project, Command: "npx"}
	literalServer := config.MCPServerEntry{Name: "notes", Connector: "claudecode",
		Home: home + "@claudecode#" + project, Command: "npx"}
	path := legacyMCPEventPath(projectServer)
	if path != legacyMCPEventPath(literalServer) {
		t.Fatal("fixture does not share the legacy path")
	}
	hash, err := mcpDefinitionHash(projectServer)
	if err != nil {
		t.Fatal(err)
	}
	otherHash, err := mcpDefinitionHash(literalServer)
	if err != nil || otherHash != hash {
		t.Fatalf("fixture does not share the old definition hash: %s %s %v", hash, otherHash, err)
	}
	hashes, err := json.Marshal(map[string]string{"mcp.servers.notes": hash})
	if err != nil {
		t.Fatal(err)
	}
	row := &audit.SnapshotRow{ContentHash: hash, ConfigHashes: string(hashes)}
	for _, server := range []config.MCPServerEntry{projectServer, literalServer} {
		if mcpLegacySnapshotCanMove(path, row, server, hash) {
			t.Fatalf("ambiguous pre-identity scope moved: %+v", server)
		}
	}
}

func TestGAP0034LiteralLegacyHomeJournalUsesStoredIdentity(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	project := t.TempDir()
	server := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: home + "@claudecode#" + project}
	path := legacyMCPEventPath(server)
	identity, err := json.Marshal(mcpIdentityForServer(server))
	if err != nil {
		t.Fatal(err)
	}
	hashes, err := json.Marshal(map[string]string{"mcp.servers.notes": "hash", mcpSnapshotIdentityKey: string(identity)})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := &audit.SnapshotRow{ContentHash: "hash", ConfigHashes: string(hashes)}
	protected := MCPAdmissionQuery{Connector: "claudecode", Server: "notes", Home: server.Home, CWD: t.TempDir()}
	ordinary := MCPAdmissionQuery{Connector: "claudecode", Server: "notes", Home: home, CWD: project}
	if !MCPAccountJournalServesSnapshot(path, snapshot, protected) || MCPAccountJournalServesSnapshot(path, snapshot, ordinary) {
		t.Fatal("stored identity did not keep the legacy action with its account")
	}
}

func TestGAP0034PathOnlyVersionedSpellingRemainsLiteral(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	const literalName = "mcp:v2:5:6e6f74657310:636c61756465636f64650:0:"
	cold := New(cfg, nil, nil, store, logger, nil, nil)
	cold.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return nil, errors.New("source list unavailable") })
	cold.firstCycleDone.Store(true)
	for _, hashes := range []string{"{}", `{"mcp.servers.` + literalName + `":"hash"}`} {
		if err := store.SetTargetSnapshot(string(InstallMCP), literalName, "hash", "{}", hashes, "[]", "",
			"fingerprint"+mcpScanFailedMark); err != nil {
			t.Fatal(err)
		}
		if got := cold.MCPAdmissionStatus(MCPAdmissionQuery{Connector: "claudecode", Server: "notes"}); got.Failed || !got.Unavailable {
			t.Fatalf("literal name became another server's failure with %s: %+v", hashes, got)
		}
		if got := cold.MCPAdmissionStatus(MCPAdmissionQuery{Connector: "claudecode", Server: literalName}); !got.Failed {
			t.Fatalf("literal server lost its failure with %s: %+v", hashes, got)
		}
	}
}
