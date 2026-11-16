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
	cfg, store, _, _ := setupTestEnv(t)
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
	logger := audit.NewLogger(store)
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
// records it, whatever the snapshot table holds under the key: nothing, a
// snapshot an earlier release left there (a server literally named like the
// key), or the new snapshot. The provenance is on the decision row itself.
func TestGAP0034FreshAccountDecisionCarriesItsProvenance(t *testing.T) {
	for _, preIdentitySnapshot := range []bool{false, true} {
		cfg, store, logger, _ := setupTestEnv(t)
		cfg.Gateway.Watcher.MCP.TakeAction = true
		cfg.Scanners.MCPScanner.UnverifiedServer = "block"
		server := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: filepath.Join(t.TempDir(), "account"),
			Command: "npx", Args: []string{"-y", "."}}
		key := MCPEventPath(server)
		if preIdentitySnapshot {
			hashes, err := json.Marshal(map[string]string{"mcp.servers." + key: "oldhash"})
			if err != nil {
				t.Fatal(err)
			}
			if err := store.SetTargetSnapshot(string(InstallMCP), key, "oldhash", "{}", string(hashes), "[]", "", "fingerprint"); err != nil {
				t.Fatal(err)
			}
		}
		w := New(cfg, nil, nil, store, logger, nil, nil)
		w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return []config.MCPServerEntry{server}, nil })
		w.firstCycleDone.Store(true)
		w.scannerFactory = func(InstallEvent) scanner.Scanner { return &failingScanner{countingScanner{name: "mcp-scanner"}} }
		evt := InstallEvent{Type: InstallMCP, Name: server.Name, Path: key, Connector: server.Connector}
		w.runAdmission(context.Background(), evt)
		owner := MCPAdmissionQuery{Connector: server.Connector, Server: server.Name, Home: server.Home}
		ordinary := MCPAdmissionQuery{Connector: server.Connector, Server: server.Name, Home: filepath.Join(t.TempDir(), "ordinary")}
		served := func(stage string) {
			t.Helper()
			row, err := store.GetActionForConnector(MCPJournalType(server), MCPJournalName(server), "claudecode")
			if err != nil || row == nil || row.SourcePath != key || !MCPAccountRuntimeDisabled(*row) ||
				!MCPAccountJournalServes(row.TargetName, owner) || MCPAccountJournalServes(row.TargetName, ordinary) {
				t.Fatalf("pre-identity snapshot %v, %s: decision not in force for its account only: row=%+v err=%v",
					preIdentitySnapshot, stage, row, err)
			}
		}
		served("before its snapshot")
		current, err := w.snapshotForEvent(evt)
		if err != nil {
			t.Fatal(err)
		}
		w.persistSnapshot(evt, current, "", "fingerprint"+mcpScanFailedMark)
		served("after its snapshot")
	}
}

// A runtime disable an earlier release wrote under a key (here an old server
// literally named like the versioned key) has no provenance, with or without
// its old snapshot; a later plain runtime write drops the provenance too.
func TestGAP0034RuntimeDisableWithoutProvenanceIsNotAnAccountDecision(t *testing.T) {
	_, store, _, _ := setupTestEnv(t)
	key := MCPEventPath(config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: filepath.Join(t.TempDir(), "account")})
	row := func() audit.ActionEntry {
		t.Helper()
		entry, err := store.GetActionForConnector(AccountMCPJournalType, key, "claudecode")
		if err != nil || entry == nil {
			t.Fatalf("row: %+v %v", entry, err)
		}
		return *entry
	}
	if err := store.SetActionFieldForConnector(AccountMCPJournalType, key, "claudecode", "runtime", "disable", "old literal server"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSourcePathForConnector(AccountMCPJournalType, key, "claudecode", key); err != nil {
		t.Fatal(err)
	}
	if MCPAccountRuntimeDisabled(row()) {
		t.Fatal("a runtime disable without provenance was taken as the account decision")
	}
	if err := store.SetRuntimeDisableForConnector(AccountMCPJournalType, key, "claudecode", key, "fresh admission failed"); err != nil {
		t.Fatal(err)
	}
	if !MCPAccountRuntimeDisabled(row()) {
		t.Fatal("the account decision lost its provenance")
	}
	if err := store.SetActionFieldForConnector(AccountMCPJournalType, key, "claudecode", "runtime", "disable", "plain write"); err != nil {
		t.Fatal(err)
	}
	if MCPAccountRuntimeDisabled(row()) {
		t.Fatal("a later runtime write kept the provenance of an earlier one")
	}
	literal := MCPEventPath(config.MCPServerEntry{Name: key, Connector: "claudecode"})
	if err := store.SetRuntimeDisableForConnector(AccountMCPJournalType, key, "claudecode", literal, "literal server failed"); err != nil {
		t.Fatal(err)
	}
	if MCPAccountRuntimeDisabled(row()) {
		t.Fatal("the decision of a server literally named like the key became the account decision")
	}
}

// An account-less server named exactly like an enrolled account server key
// (its versioned event path) shares no journal row with that account: its
// failed scan does not replace the account decision and its clean scan does
// not release it, whether or not the account snapshot exists yet. The
// account own clean scan still releases the account row, and the literal
// server own row follows its own scans.
func TestGAP0034LiteralServerNamedLikeAccountKeyKeepsApartInBothDirections(t *testing.T) {
	for _, withSnapshot := range []bool{false, true} {
		cfg, store, logger, _ := setupTestEnv(t)
		cfg.Gateway.Watcher.MCP.TakeAction = true
		cfg.Scanners.MCPScanner.UnverifiedServer = "block"
		account := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: filepath.Join(t.TempDir(), "account"),
			Command: "npx", Args: []string{"-y", "."}}
		key := MCPEventPath(account)
		literal := config.MCPServerEntry{Name: key, Connector: "claudecode", Command: "npx", Args: []string{"-y", "."}}
		literalPath := MCPEventPath(literal)
		verdict := map[string]string{key: "failed", literalPath: "failed"}
		w := New(cfg, nil, nil, store, logger, nil, nil)
		w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return []config.MCPServerEntry{account, literal}, nil })
		w.firstCycleDone.Store(true)
		w.scannerFactory = func(evt InstallEvent) scanner.Scanner {
			if verdict[evt.Path] == "failed" {
				return &failingScanner{countingScanner{name: "mcp-scanner"}}
			}
			return &countingScanner{name: "mcp-scanner"}
		}
		accountEvt := InstallEvent{Type: InstallMCP, Name: account.Name, Path: key, Connector: account.Connector}
		literalEvt := InstallEvent{Type: InstallMCP, Name: literal.Name, Path: literalPath, Connector: literal.Connector}
		held := func(stage string) {
			t.Helper()
			row, err := store.GetActionForConnector(MCPJournalType(account), MCPJournalName(account), "claudecode")
			if err != nil || row == nil || row.SourcePath != key || row.Actions.Install != "block" || !MCPAccountRuntimeDisabled(*row) {
				t.Fatalf("snapshot %v, %s: the account decision is gone: row=%+v err=%v", withSnapshot, stage, row, err)
			}
		}
		own := func() *audit.ActionEntry {
			t.Helper()
			row, err := store.GetActionForConnector(MCPJournalType(literal), MCPJournalName(literal), "claudecode")
			if err != nil {
				t.Fatal(err)
			}
			return row
		}

		w.runAdmission(context.Background(), accountEvt)
		if withSnapshot {
			current, err := w.snapshotForEvent(accountEvt)
			if err != nil {
				t.Fatal(err)
			}
			w.persistSnapshot(accountEvt, current, "", "fingerprint"+mcpScanFailedMark)
		}
		held("after the account admission")

		w.runAdmission(context.Background(), literalEvt)
		held("after the failed scan of the literal server")
		if row := own(); row == nil || row.Actions.Runtime != "disable" || row.SourcePath != literalPath {
			t.Fatalf("snapshot %v: the literal server failed scan left no row of its own: %+v", withSnapshot, row)
		}

		verdict[literalPath] = "clean"
		w.runAdmission(context.Background(), literalEvt)
		held("after the clean scan of the literal server")
		if row := own(); row != nil && (row.Actions.Runtime != "" || row.Actions.Install != "") {
			t.Fatalf("snapshot %v: the clean scan did not release the literal server: %+v", withSnapshot, row)
		}

		verdict[key] = "clean"
		w.runAdmission(context.Background(), accountEvt)
		row, err := store.GetActionForConnector(MCPJournalType(account), MCPJournalName(account), "claudecode")
		if err != nil || (row != nil && (row.Actions.Runtime != "" || row.Actions.Install != "")) {
			t.Fatalf("snapshot %v: the account own clean scan did not release it: %+v %v", withSnapshot, row, err)
		}
	}
}
