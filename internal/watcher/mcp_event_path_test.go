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
					if decoded, ok := decodeMCPEventPath(key); !ok || decoded != mcpIdentityForServer(server) {
						t.Fatalf("scope key %q did not round trip: %+v", key, decoded)
					}
					if previous, ok := seen[key]; ok {
						t.Fatalf("scope tuples %+v and %+v share key %q", previous, server, key)
					}
					seen[key] = server
				}
			}
		}
	}
	for _, key := range []string{"notes@claudecode", "mcp:v2:5:6e6f746573", "mcp:v2:05:6e6f7465730:0:0:", MCPEventPath(first) + "suffix"} {
		if _, ok := decodeMCPEventPath(key); ok {
			t.Fatalf("invalid scope key %q was accepted", key)
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

func TestGAP0034UpgradePreIdentityRowsRescanOnce(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.MCP.TakeAction = true
	cfg.Scanners.MCPScanner.UnverifiedServer = "warn"
	home := filepath.Join(t.TempDir(), "account")
	project := t.TempDir()
	failed := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: home + "@claudecode#" + project, Command: "npx"}
	ordinary := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: home, Project: project, Command: "npx"}
	oldPath := "notes@claudecode:" + failed.Home
	if oldPath != "notes@claudecode:"+ordinary.Home+"@claudecode#"+ordinary.Project {
		t.Fatal("old scope keys did not collide")
	}
	hash, err := mcpDefinitionHash(failed)
	if err != nil {
		t.Fatal(err)
	}
	otherHash, err := mcpDefinitionHash(ordinary)
	if err != nil || hash != otherHash {
		t.Fatalf("old definition hashes differ: %s %s %v", hash, otherHash, err)
	}
	hashes, err := json.Marshal(map[string]string{"mcp.servers.notes": hash})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetTargetSnapshot(string(InstallMCP), oldPath, hash, "{}", string(hashes), "[]", "", "fingerprint"+mcpScanFailedMark); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActionFieldForConnector(string(InstallMCP), oldPath, "claudecode", "runtime", "disable", "previous scan"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = audit.NewStore(cfg.AuditDB)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	logger = audit.NewLogger(store)
	logger.SetRuntimeV8Emitter(&watcherTestRuntime{})
	if MCPAccountJournalServes(oldPath, MCPAdmissionQuery{Connector: "claudecode", Server: "notes", Home: failed.Home}) ||
		MCPAccountJournalServes(oldPath, MCPAdmissionQuery{Connector: "claudecode", Server: "notes", Home: ordinary.Home, CWD: project}) {
		t.Fatal("pre-identity action was served to an account")
	}
	servers := []config.MCPServerEntry{failed, ordinary}
	w := New(cfg, nil, nil, store, logger, nil, nil)
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return servers, nil })
	w.firstCycleDone.Store(true)
	failedCall := MCPAdmissionQuery{Connector: "claudecode", Server: "notes", Home: failed.Home, CWD: t.TempDir()}
	ordinaryCall := MCPAdmissionQuery{Connector: "claudecode", Server: "notes", Home: ordinary.Home, CWD: project}
	for _, query := range []MCPAdmissionQuery{failedCall, ordinaryCall} {
		if got := w.MCPAdmissionStatus(query); !got.Pending || got.Failed {
			t.Fatalf("old row was served instead of fresh admission: %+v", got)
		}
	}
	failedScanner := &failingScanner{countingScanner{name: "mcp-scanner"}}
	ordinaryScanner := &countingScanner{name: "mcp-scanner"}
	w.scannerFactory = func(evt InstallEvent) scanner.Scanner {
		if evt.Path == MCPEventPath(failed) {
			return failedScanner
		}
		return ordinaryScanner
	}
	w.admitAddedMCPServers(context.Background())
	if failedScanner.calls != 1 || ordinaryScanner.calls != 1 {
		t.Fatalf("upgrade scans: failed=%d ordinary=%d, want one each", failedScanner.calls, ordinaryScanner.calls)
	}
	if got := w.MCPAdmissionStatus(failedCall); !got.Failed || got.Pending {
		t.Fatalf("new failed admission was not retained: %+v", got)
	}
	if got := w.MCPAdmissionStatus(ordinaryCall); got.Failed || got.Pending || got.Unavailable {
		t.Fatalf("clean account inherited a failed admission: %+v", got)
	}
	for _, server := range servers {
		if row, err := mcpSnapshotForServer(store, server); err != nil || row == nil {
			t.Fatalf("versioned snapshot for %+v: %+v, %v", server, row, err)
		}
	}
	w.AdmitAddedMCPServers([]string{"notes"})
	w.admitAddedMCPServers(context.Background())
	if failedScanner.calls != 1 || ordinaryScanner.calls != 1 {
		t.Fatalf("unchanged server scanned twice: failed=%d ordinary=%d", failedScanner.calls, ordinaryScanner.calls)
	}
	cold := New(cfg, nil, nil, store, logger, nil, nil)
	cold.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return nil, errors.New("source list unavailable") })
	cold.firstCycleDone.Store(true)
	if got := cold.MCPAdmissionStatus(failedCall); !got.Failed || got.Unavailable {
		t.Fatalf("new failed admission lost after restart: %+v", got)
	}
	if got := cold.MCPAdmissionStatus(ordinaryCall); got.Failed || !got.Unavailable {
		t.Fatalf("ordinary account inherited failure after restart: %+v", got)
	}
}

func TestGAP0034VersionedSnapshotRequiresStoredIdentity(t *testing.T) {
	_, store, _, _ := setupTestEnv(t)
	server := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: t.TempDir(), Command: "npx"}
	hash, err := mcpDefinitionHash(server)
	if err != nil {
		t.Fatal(err)
	}
	path := MCPEventPath(server)
	if err := store.SetTargetSnapshot(string(InstallMCP), path, hash, "{}", `{"mcp.servers.notes":"`+hash+`"}`, "[]", "", "fingerprint"+mcpScanFailedMark); err != nil {
		t.Fatal(err)
	}
	if row, err := mcpSnapshotForServer(store, server); row != nil || !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unstructured snapshot was accepted: %+v, %v", row, err)
	}
	identity, err := json.Marshal(mcpIdentityForServer(server))
	if err != nil {
		t.Fatal(err)
	}
	hashes, err := json.Marshal(map[string]string{"mcp.servers.notes": hash, mcpSnapshotIdentityKey: string(identity)})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetTargetSnapshot(string(InstallMCP), path, hash, "{}", string(hashes), "[]", "", "fingerprint"+mcpScanFailedMark); err != nil {
		t.Fatal(err)
	}
	if row, err := mcpSnapshotForServer(store, server); err != nil || row == nil {
		t.Fatalf("structured versioned snapshot was lost: %+v, %v", row, err)
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
	oldPath := "notes@claudecode:" + literalHomeServer.Home
	if MCPAccountJournalServes(oldPath, projectCall) || MCPAccountJournalServes(oldPath, literalCall) {
		t.Fatal("old account journal row was assigned to an account")
	}
}

func TestGAP0034PreIdentityCollisionBothDirectionsNeedAdmission(t *testing.T) {
	home := filepath.Join(t.TempDir(), "account")
	project := t.TempDir()
	projectServer := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: home, Project: project, Command: "npx"}
	literalServer := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: home + "@claudecode#" + project, Command: "npx"}
	oldPath := "notes@claudecode:" + literalServer.Home
	for _, tc := range []struct {
		name                         string
		failedServer, ordinaryServer config.MCPServerEntry
	}{
		{"literal home failed", literalServer, projectServer},
		{"project failed", projectServer, literalServer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, store, logger, _ := setupTestEnv(t)
			cfg.Gateway.Watcher.MCP.TakeAction = true
			hash, err := mcpDefinitionHash(tc.failedServer)
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
			w := New(cfg, nil, nil, store, logger, nil, nil)
			w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) {
				return []config.MCPServerEntry{tc.failedServer, tc.ordinaryServer}, nil
			})
			w.firstCycleDone.Store(true)
			for _, server := range []config.MCPServerEntry{tc.failedServer, tc.ordinaryServer} {
				query := MCPAdmissionQuery{Connector: server.Connector, Server: server.Name, Home: server.Home, CWD: server.Project}
				if got := w.MCPAdmissionStatus(query); !got.Pending || got.Failed {
					t.Fatalf("old row selected scope %+v: %+v", server, got)
				}
			}
		})
	}
}

func TestGAP0034StructuredOldKeyNeedsFreshAdmission(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.MCP.TakeAction = true
	server := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: t.TempDir(), Command: "npx"}
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
	oldPath := "notes@claudecode:" + server.Home
	if err := store.SetTargetSnapshot(string(InstallMCP), oldPath, hash, "{}", string(hashes), "[]", "", "fingerprint"+mcpScanFailedMark); err != nil {
		t.Fatal(err)
	}
	w := New(cfg, nil, nil, store, logger, nil, nil)
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return []config.MCPServerEntry{server}, nil })
	w.firstCycleDone.Store(true)
	query := MCPAdmissionQuery{Connector: server.Connector, Server: server.Name, Home: server.Home}
	if got := w.MCPAdmissionStatus(query); !got.Pending || got.Failed {
		t.Fatalf("old key was accepted despite its stored identity: %+v", got)
	}
	cold := New(cfg, nil, nil, store, logger, nil, nil)
	cold.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return nil, errors.New("source list unavailable") })
	cold.firstCycleDone.Store(true)
	if got := cold.MCPAdmissionStatus(query); got.Failed || !got.Unavailable {
		t.Fatalf("old key was served during source outage: %+v", got)
	}
}

// The decision of a completed failed scan holds from the moment admission
// records it: before its snapshot is stored, and if storing it fails.
// Only a snapshot an earlier release left under the key makes a row old.
func TestGAP0034FreshAccountDecisionHoldsWithoutSnapshot(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.MCP.TakeAction = true
	cfg.Scanners.MCPScanner.UnverifiedServer = "block"
	server := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: filepath.Join(t.TempDir(), "account"),
		Command: "npx", Args: []string{"-y", "."}}
	w := New(cfg, nil, nil, store, logger, nil, nil)
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return []config.MCPServerEntry{server}, nil })
	w.firstCycleDone.Store(true)
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &failingScanner{countingScanner{name: "mcp-scanner"}} }
	key := MCPEventPath(server)
	evt := InstallEvent{Type: InstallMCP, Name: server.Name, Path: key, Connector: server.Connector}
	w.runAdmission(context.Background(), evt)
	row, err := store.GetActionForConnector(string(InstallMCP), MCPJournalName(server), "claudecode")
	if err != nil || row == nil || row.Actions.Runtime != "disable" || row.SourcePath != key {
		t.Fatalf("failed admission was not recorded: row=%+v err=%v", row, err)
	}
	snapshot, err := store.GetTargetSnapshot(string(InstallMCP), key)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("snapshot already stored: %+v %v", snapshot, err)
	}
	owner := MCPAdmissionQuery{Connector: server.Connector, Server: server.Name, Home: server.Home}
	ordinary := MCPAdmissionQuery{Connector: server.Connector, Server: server.Name, Home: filepath.Join(t.TempDir(), "ordinary")}
	if !MCPAccountJournalServesSnapshot(row.TargetName, snapshot, owner) ||
		MCPAccountJournalServesSnapshot(row.TargetName, snapshot, ordinary) {
		t.Fatal("decision without a stored snapshot did not stay with its account")
	}
	current, err := w.snapshotForEvent(evt)
	if err != nil {
		t.Fatal(err)
	}
	w.persistSnapshot(evt, current, "", "fingerprint"+mcpScanFailedMark)
	if snapshot, err = store.GetTargetSnapshot(string(InstallMCP), key); err != nil ||
		!MCPAccountJournalServesSnapshot(row.TargetName, snapshot, owner) {
		t.Fatalf("stored snapshot released the decision: %+v %v", snapshot, err)
	}
	old := &audit.SnapshotRow{ContentHash: "hash", ConfigHashes: `{"mcp.servers.` + key + `":"hash"}`}
	if MCPAccountJournalServesSnapshot(row.TargetName, old, owner) {
		t.Fatal("snapshot of an earlier release was taken as current provenance")
	}
}
