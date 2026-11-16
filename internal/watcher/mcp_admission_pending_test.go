// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// GAP-0112: Claude Code started a project's server and called its tool
// before the discovery poll had admitted it, so a server with no admission
// outcome is pending and its admission runs at once. The hook selects its
// pending behavior by tier. A rejected verdict records a runtime disable.
func TestMCPServerWithoutAdmissionIsPendingUntilAdmitted(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.MCP.TakeAction = true
	cfg.Admission.MCP.Actions.High = &config.AdmissionAction{Shorthand: config.AdmissionActionQuarantine}
	project := filepath.Join(t.TempDir(), "decoy-proj")
	server := config.MCPServerEntry{Name: "gb05-decoy", Command: "npx", Args: []string{"-y", "."},
		Connector: "claudecode", Project: project, SourceScope: "project"}
	var admitted []AdmissionResult
	w := New(cfg, nil, nil, store, logger, nil, func(r AdmissionResult) { admitted = append(admitted, r) })
	w.scannerFactory = func(InstallEvent) scanner.Scanner {
		return &countingScanner{name: "mcp-scanner", findings: []scanner.Finding{{
			ID: "f1", RuleID: "MCP-001", Severity: scanner.SeverityHigh, Title: "credential harvesting",
		}}}
	}
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return []config.MCPServerEntry{server}, nil })
	w.firstCycleDone.Store(true)

	query := MCPAdmissionQuery{Connector: "claudecode", Server: "gb05-decoy", CWD: filepath.Join(project, "src")}
	if name, pending := w.MCPAdmissionPending(query); !pending || name != "gb05-decoy" {
		t.Fatalf("MCPAdmissionPending = %q, %v; want gb05-decoy pending", name, pending)
	}
	// The pending call queued the admission; the added-server loop runs it.
	w.admitAddedMCPServers(context.Background())
	if len(admitted) != 1 || admitted[0].Verdict != VerdictRejected {
		t.Fatalf("admitted %+v, want gb05-decoy rejected", admitted)
	}
	if _, pending := w.MCPAdmissionPending(query); pending {
		t.Fatal("a server with an admission outcome is still pending")
	}
	entry, err := store.GetActionForConnector("mcp", "gb05-decoy", "claudecode")
	if err != nil || entry == nil || entry.Actions.Runtime != "disable" {
		t.Fatalf("journal %+v (err %v), want the rejected server disabled at runtime", entry, err)
	}
}

func TestGAP0034WatcherDistinguishesPendingFromCompletedFailure(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.MCP.TakeAction = true
	cfg.Scanners.MCPScanner.UnverifiedServer = "warn"
	server := config.MCPServerEntry{Name: "notes", Command: "npx", Args: []string{"-y", "."},
		Connector: "claudecode", Project: filepath.Join(t.TempDir(), "proj"), SourceScope: "project"}
	w := New(cfg, nil, nil, store, logger, nil, nil)
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return []config.MCPServerEntry{server}, nil })
	w.firstCycleDone.Store(true)
	query := MCPAdmissionQuery{Connector: "claudecode", Server: "notes", CWD: server.Project}
	initial := w.MCPAdmissionStatus(query)
	if !initial.Pending || initial.Failed || initial.Name != "notes" || initial.RetryAfter <= 0 || initial.RetryAfter > defaultScanTimeout {
		t.Fatalf("pending status: %+v", initial)
	}
	path := MCPEventPath(server)
	w.mcpClaims = map[string]time.Time{path: time.Now().Add(-2 * time.Minute)}
	inProgress := w.MCPAdmissionStatus(query)
	if inProgress.RetryAfter < 3*time.Minute-time.Second || inProgress.RetryAfter > 3*time.Minute {
		t.Fatalf("scan progress was not reflected in the retry time: %+v", inProgress)
	}
	w.releaseMCP(path)
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &failingScanner{countingScanner{name: "mcp-scanner"}} }
	w.admitAddedMCPServers(context.Background())
	failed := w.MCPAdmissionStatus(query)
	if !failed.Failed || failed.Pending || failed.Name != "notes" {
		t.Fatalf("completed scan failure was reported as pending or clean: %+v", failed)
	}
	if _, pending := w.MCPAdmissionPending(query); pending {
		t.Fatal("a completed scan failure was reported as pending")
	}
	server.Args = []string{"-y", "changed"}
	changed := w.MCPAdmissionStatus(query)
	if !changed.Pending || changed.Failed {
		t.Fatalf("a changed definition kept the prior scan outcome: %+v", changed)
	}
}

func TestGAP0034FailedScanSurvivesServerListOutage(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.MCP.TakeAction = true
	cfg.Scanners.MCPScanner.UnverifiedServer = "warn"
	server := config.MCPServerEntry{Name: "notes", Command: "npx", Args: []string{"-y", "."},
		Connector: "claudecode", Project: filepath.Join(t.TempDir(), "proj"), SourceScope: "project"}
	unavailable := false
	w := New(cfg, nil, nil, store, logger, nil, nil)
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) {
		if unavailable {
			return nil, errors.New("server list temporarily unavailable")
		}
		return []config.MCPServerEntry{server}, nil
	})
	w.firstCycleDone.Store(true)
	w.scannerFactory = func(InstallEvent) scanner.Scanner {
		return &failingScanner{countingScanner{name: "mcp-scanner"}}
	}
	w.AdmitAddedMCPServers([]string{server.Name})
	w.admitAddedMCPServers(context.Background())
	query := MCPAdmissionQuery{Connector: server.Connector, Server: server.Name, CWD: server.Project}
	if status := w.MCPAdmissionStatus(query); !status.Failed {
		t.Fatalf("completed scan failure: %+v", status)
	}
	unavailable = true
	if status := w.MCPAdmissionStatus(query); !status.Failed || status.Unavailable {
		t.Fatalf("completed failure lost during list outage: %+v", status)
	}
	cold := New(cfg, nil, nil, store, logger, nil, nil)
	cold.SetMCPServerSource(func() ([]config.MCPServerEntry, error) {
		return nil, errors.New("server list temporarily unavailable")
	})
	cold.firstCycleDone.Store(true)
	if status := cold.MCPAdmissionStatus(query); !status.Failed || status.Unavailable {
		t.Fatalf("stored failure lost before the first successful list: %+v", status)
	}
	ordinary := query
	ordinary.Server = "ordinary"
	if status := cold.MCPAdmissionStatus(ordinary); status.Failed || !status.Unavailable {
		t.Fatalf("unrelated server inherited a stored failure: %+v", status)
	}
	otherProject := query
	otherProject.CWD = t.TempDir()
	if status := cold.MCPAdmissionStatus(otherProject); status.Failed || !status.Unavailable {
		t.Fatalf("another project inherited a stored failure: %+v", status)
	}
	scopedName := query
	scopedName.Server = config.MCPToolServerName(server.Connector, MCPEventPath(server))
	if status := cold.MCPAdmissionStatus(scopedName); status.Failed || !status.Unavailable {
		t.Fatalf("a scoped key was treated as another server's name: %+v", status)
	}
	unavailable = false
	server.Args = []string{"-y", "changed"}
	if status := w.MCPAdmissionStatus(query); !status.Pending || status.Failed {
		t.Fatalf("new definition inherited old failure: %+v", status)
	}
	unavailable = true
	if status := w.MCPAdmissionStatus(query); status.Failed || !status.Unavailable {
		t.Fatalf("old failure returned after a successful new listing: %+v", status)
	}
}

func TestGAP0034ColdOutageSnapshotScope(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	project := filepath.Join(home, "project")
	server := config.MCPServerEntry{Name: "shared", Connector: "claudecode", Home: home, Project: project}
	path := MCPEventPath(server)
	identity, ok := decodeMCPEventPath(path)
	if !ok {
		t.Fatal("versioned path did not decode")
	}
	for _, tc := range []struct {
		name  string
		query MCPAdmissionQuery
		want  bool
	}{
		{"same account and project", MCPAdmissionQuery{Connector: "CLAUDECODE", Server: "shared", Home: home, CWD: filepath.Join(project, "src")}, true},
		{"equivalent home with separator", MCPAdmissionQuery{Connector: "claudecode", Server: "shared", Home: home + string(filepath.Separator), CWD: project}, true},
		{"equivalent home with dot", MCPAdmissionQuery{Connector: "claudecode", Server: "shared", Home: filepath.Join(home, ".") + string(filepath.Separator) + ".", CWD: project}, true},
		{"other account", MCPAdmissionQuery{Connector: "claudecode", Server: "shared", Home: home + "2", CWD: project}, false},
		{"other project", MCPAdmissionQuery{Connector: "claudecode", Server: "shared", Home: home, CWD: filepath.Join(home, "other")}, false},
		{"other connector", MCPAdmissionQuery{Connector: "codex", Server: "shared", Home: home, CWD: project}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mcpServerServesQuery(identity.server(), tc.query); got != tc.want {
				t.Fatalf("stored scope matched=%v, want %v", got, tc.want)
			}
		})
	}
	other := config.MCPServerEntry{Name: "shared@claudecode#decoy", Connector: "claudecode"}
	otherIdentity, ok := decodeMCPEventPath(MCPEventPath(other))
	if !ok || mcpServerServesQuery(otherIdentity.server(), MCPAdmissionQuery{Connector: "claudecode", Server: "shared"}) {
		t.Fatal("a different server name was read as the ordinary server's scope")
	}
}

func TestGAP0034ColdFailedSnapshotUsesStoredIdentityAndNormalizedHome(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.MCP.TakeAction = true
	cfg.Scanners.MCPScanner.UnverifiedServer = "warn"
	home := filepath.Join(t.TempDir(), "account")
	project := filepath.Join(home, "project")
	failed := config.MCPServerEntry{Name: "notes@claudecode#decoy", Connector: "claudecode",
		Command: "npx", Args: []string{"-y", "."}, Home: home, Project: project, SourceScope: "project"}
	ordinary := config.MCPServerEntry{Name: "notes", Connector: "claudecode",
		Command: "npx", Args: []string{"-y", "."}, Home: home}
	admitted := New(cfg, nil, nil, store, logger, nil, nil)
	admitted.SetMCPServerSource(func() ([]config.MCPServerEntry, error) {
		return []config.MCPServerEntry{failed, ordinary}, nil
	})
	admitted.firstCycleDone.Store(true)
	admitted.scannerFactory = func(InstallEvent) scanner.Scanner {
		return &failingScanner{countingScanner{name: "mcp-scanner"}}
	}
	admitted.AdmitAddedMCPServers([]string{failed.Name})
	admitted.admitAddedMCPServers(context.Background())
	if status := admitted.MCPAdmissionStatus(MCPAdmissionQuery{
		Connector: failed.Connector, Server: config.MCPToolServerName(failed.Connector, failed.Name), Home: home, CWD: project,
	}); !status.Failed {
		t.Fatalf("setup: failed scan was not recorded: %+v", status)
	}

	cold := New(cfg, nil, nil, store, logger, nil, nil)
	cold.SetMCPServerSource(func() ([]config.MCPServerEntry, error) {
		return nil, errors.New("server list temporarily unavailable")
	})
	cold.firstCycleDone.Store(true)
	for _, homeVariant := range []string{home, home + string(filepath.Separator), home + string(filepath.Separator) + "."} {
		q := MCPAdmissionQuery{Connector: failed.Connector,
			Server: config.MCPToolServerName(failed.Connector, failed.Name), Home: homeVariant, CWD: project}
		if status := cold.MCPAdmissionStatus(q); !status.Failed || status.Unavailable {
			t.Errorf("stored failure for equivalent home %q: %+v", homeVariant, status)
		}
	}
	q := MCPAdmissionQuery{Connector: ordinary.Connector, Server: ordinary.Name, Home: home, CWD: project}
	if status := cold.MCPAdmissionStatus(q); status.Failed || !status.Unavailable {
		t.Fatalf("ordinary server inherited another failure: %+v", status)
	}
}

func TestGAP0034ColdFailedScanUsesStructuredScope(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.MCP.TakeAction = true
	cfg.Scanners.MCPScanner.UnverifiedServer = "warn"
	home := filepath.Join(t.TempDir(), "alice")
	project := t.TempDir()
	failed := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: home,
		Project: project, SourceScope: "project", Command: "npx", Args: []string{"-y", "."}}
	admitted := New(cfg, nil, nil, store, logger, nil, nil)
	admitted.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return []config.MCPServerEntry{failed}, nil })
	admitted.firstCycleDone.Store(true)
	admitted.scannerFactory = func(InstallEvent) scanner.Scanner {
		return &failingScanner{countingScanner{name: "mcp-scanner"}}
	}
	admitted.AdmitAddedMCPServers([]string{failed.Name})
	admitted.admitAddedMCPServers(context.Background())

	cold := New(cfg, nil, nil, store, logger, nil, nil)
	cold.SetMCPServerSource(func() ([]config.MCPServerEntry, error) {
		return nil, errors.New("source list unavailable")
	})
	cold.firstCycleDone.Store(true)
	for _, tc := range []struct {
		name   string
		query  MCPAdmissionQuery
		failed bool
	}{
		{"failed account", MCPAdmissionQuery{Connector: "claudecode", Server: "notes", Home: home, CWD: project}, true},
		{"equivalent account", MCPAdmissionQuery{Connector: "claudecode", Server: "notes", Home: home + string(filepath.Separator) + ".", CWD: project}, true},
		{"different account with scope marker", MCPAdmissionQuery{Connector: "claudecode", Server: "notes", Home: home + "@claudecode#" + project + string(filepath.Separator) + ".", CWD: t.TempDir()}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := cold.MCPAdmissionStatus(tc.query)
			if got.Failed != tc.failed || got.Unavailable == tc.failed {
				t.Fatalf("cold failed scan: %+v, want failed=%v", got, tc.failed)
			}
		})
	}
}

func TestGAP0034ColdFailedHomeDelimiterWithUnresolvedCaller(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.MCP.TakeAction = true
	cfg.Scanners.MCPScanner.UnverifiedServer = "warn"
	failed := config.MCPServerEntry{Name: "notes", Connector: "claudecode",
		Home: filepath.Join(t.TempDir(), "alice@claudecode#fake"), Command: "npx", Args: []string{"-y", "."}}
	admitted := New(cfg, nil, nil, store, logger, nil, nil)
	admitted.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return []config.MCPServerEntry{failed}, nil })
	admitted.firstCycleDone.Store(true)
	admitted.scannerFactory = func(InstallEvent) scanner.Scanner {
		return &failingScanner{countingScanner{name: "mcp-scanner"}}
	}
	admitted.AdmitAddedMCPServers([]string{failed.Name})
	admitted.admitAddedMCPServers(context.Background())
	cold := New(cfg, nil, nil, store, logger, nil, nil)
	cold.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return nil, errors.New("source list unavailable") })
	cold.firstCycleDone.Store(true)
	for _, q := range []MCPAdmissionQuery{
		{Connector: "claudecode", Server: "notes", Home: failed.Home},
		{Connector: "claudecode", Server: "notes", CWD: t.TempDir()},
	} {
		if got := cold.MCPAdmissionStatus(q); !got.Failed || got.Unavailable {
			t.Errorf("stored failed scan for %+v: %+v", q, got)
		}
	}
}

func TestGAP0034UnstructuredVersionedNameIgnoredDuringOutage(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.MCP.TakeAction = true
	other := config.MCPServerEntry{Name: "notes@claudecode#" + t.TempDir()}
	hashes, err := json.Marshal(map[string]string{"mcp.servers." + other.Name: "hash"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetTargetSnapshot(string(InstallMCP), MCPEventPath(other), "hash", "{}", string(hashes), "[]", "", "fingerprint"+mcpScanFailedMark); err != nil {
		t.Fatal(err)
	}
	cold := New(cfg, nil, nil, store, logger, nil, nil)
	cold.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return nil, errors.New("source list unavailable") })
	cold.firstCycleDone.Store(true)
	if got := cold.MCPAdmissionStatus(MCPAdmissionQuery{Connector: "claudecode", Server: "notes"}); got.Failed || !got.Unavailable {
		t.Fatalf("ambiguous legacy scope selected another name: %+v", got)
	}
	if got := cold.MCPAdmissionStatus(MCPAdmissionQuery{Connector: "claudecode", Server: other.Name}); got.Failed || !got.Unavailable {
		t.Fatalf("unstructured versioned row was served: %+v", got)
	}
}

func TestGAP0034UnstructuredVersionedProjectIgnoredDuringOutage(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.MCP.TakeAction = true
	server := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Home: t.TempDir(), Project: t.TempDir()}
	if err := store.SetTargetSnapshot(string(InstallMCP), MCPEventPath(server), "hash", "{}", `{"mcp.servers.notes":"hash"}`, "[]", "", "fingerprint"+mcpScanFailedMark); err != nil {
		t.Fatal(err)
	}
	cold := New(cfg, nil, nil, store, logger, nil, nil)
	cold.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return nil, errors.New("source list unavailable") })
	cold.firstCycleDone.Store(true)
	for _, cwd := range []string{server.Project, t.TempDir()} {
		got := cold.MCPAdmissionStatus(MCPAdmissionQuery{Connector: "claudecode", Server: "notes", CWD: cwd})
		if got.Failed || !got.Unavailable {
			t.Errorf("unstructured project row at %q was served: %+v", cwd, got)
		}
	}
}

func TestMCPAdmissionPendingKeepsOtherCallsAsBefore(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.MCP.TakeAction = true
	project := filepath.Join(t.TempDir(), "proj")
	servers := []config.MCPServerEntry{
		{Name: "notes", Command: "npx", Args: []string{"notes"}, Connector: "claudecode", Project: project, SourceScope: "project"},
		{Name: "time", Command: "uvx", Args: []string{"mcp-server-time"}, Connector: "codex", Home: "/home/u1"},
		{Name: "bundled", Command: "npx", Args: []string{"b"}, Connector: "claudecode", Bundled: true},
	}
	w := New(cfg, nil, nil, store, logger, nil, nil)
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return servers, nil })

	// Before the watcher listed the servers present at start, nothing is
	// known to be new.
	if _, pending := w.MCPAdmissionPending(MCPAdmissionQuery{Connector: "claudecode", Server: "notes"}); pending {
		t.Fatal("pending before the startup listing")
	}
	// A server the first cycle lists at start stays with that cycle.
	w.recordStartupMCP([]InstallEvent{{Type: InstallMCP, Name: "notes", Path: MCPEventPath(servers[0])}})
	if _, pending := w.MCPAdmissionPending(MCPAdmissionQuery{Connector: "claudecode", Server: "notes"}); pending {
		t.Fatal("a server listed at start is pending during the first cycle")
	}
	w.firstCycleDone.Store(true)
	for _, tc := range []struct {
		name  string
		query MCPAdmissionQuery
	}{
		{"another project", MCPAdmissionQuery{Connector: "claudecode", Server: "notes", CWD: filepath.Join(t.TempDir(), "other")}},
		{"another connector", MCPAdmissionQuery{Connector: "codex", Server: "notes"}},
		{"another account", MCPAdmissionQuery{Connector: "codex", Server: "time", Home: "/home/u2"}},
		{"a bundled server", MCPAdmissionQuery{Connector: "claudecode", Server: "bundled"}},
		{"an unknown server", MCPAdmissionQuery{Connector: "claudecode", Server: "nowhere"}},
	} {
		if _, pending := w.MCPAdmissionPending(tc.query); pending {
			t.Errorf("%s: pending", tc.name)
		}
	}
	if _, pending := w.MCPAdmissionPending(MCPAdmissionQuery{Connector: "codex", Server: "time", Home: "/home/u1"}); !pending {
		t.Fatal("the caller's own unadmitted server is not pending")
	}
	cfg.Gateway.Watcher.MCP.TakeAction = false
	if _, pending := w.MCPAdmissionPending(MCPAdmissionQuery{Connector: "codex", Server: "time", Home: "/home/u1"}); pending {
		t.Fatal("pending although the watcher does not enforce MCP admission")
	}
}

// GAP-0134: an MCP server whose scan failed left an asset_not_scanned issue
// that nothing removed after its project and configuration were deleted, so
// status and verify kept warning about it. Discovery forgets the issues of
// servers no longer configured.
func TestRemovedMCPServerLeavesNoAdmissionIssue(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Scanners.MCPScanner.UnverifiedServer = "block" // the strict tier blocks a server whose scan failed (GAP-1195)
	servers := []config.MCPServerEntry{{Name: "gone", Command: "npx", Args: []string{"-y", "."},
		Connector: "claudecode", Project: filepath.Join(t.TempDir(), "proj"), SourceScope: "project"}}
	w := New(cfg, nil, nil, store, logger, nil, nil)
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return &failingScanner{countingScanner{name: "mcp-scanner"}} }
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return servers, nil })
	w.SetMCPDiscoveryPoll(true)
	w.firstCycleDone.Store(true)
	w.AdmitAddedMCPServers([]string{"gone"})
	w.admitAddedMCPServers(context.Background())
	if issues, _ := ReadAdmissionIssues(cfg.DataDir); len(issues) != 1 || issues[0].Kind != AdmissionUnscanned {
		t.Fatalf("issues after the failed scan: %+v", issues)
	}
	w.discoverAddedMCPServers()
	if issues, _ := ReadAdmissionIssues(cfg.DataDir); len(issues) != 1 {
		t.Fatalf("a configured server lost its issue: %+v", issues)
	}
	servers = nil
	w.discoverAddedMCPServers()
	if issues, _ := ReadAdmissionIssues(cfg.DataDir); len(issues) != 0 {
		t.Fatalf("issues after the server was removed: %+v", issues)
	}
}

// GAP-0216: a verdict is for a server's definition, not its name. An
// enrolled account's admitted server whose arguments changed under the same
// name kept the old outcome, so its calls reached the new program before any
// scan. A changed server is pending until admission has run on the new
// definition, that admission runs at once and its baseline is kept, and
// another account's same-name server keeps its own outcome.
func TestChangedMCPServerDefinitionIsPendingUntilReadmitted(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.MCP.TakeAction = true
	cfg.Admission.MCP.Actions.High = &config.AdmissionAction{Shorthand: config.AdmissionActionQuarantine}
	base := t.TempDir()
	servers := []config.MCPServerEntry{enrolledMCPServer(base, "1001", "benign"), enrolledMCPServer(base, "1002", "benign")}
	rejected := map[string]bool{}
	var admitted []AdmissionResult
	w := New(cfg, nil, nil, store, logger, nil, func(r AdmissionResult) { admitted = append(admitted, r) })
	w.scannerFactory = func(evt InstallEvent) scanner.Scanner {
		if rejected[evt.Path] {
			return &countingScanner{name: "mcp-scanner", findings: []scanner.Finding{{
				ID: "f1", RuleID: "MCP-001", Severity: scanner.SeverityHigh, Title: "credential harvesting",
			}}}
		}
		return &countingScanner{name: "mcp-scanner"}
	}
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return servers, nil })
	w.firstCycleDone.Store(true)
	ctx := context.Background()
	query := func(server config.MCPServerEntry) MCPAdmissionQuery {
		return MCPAdmissionQuery{Connector: "claudecode", Server: server.Name, Home: server.Home, CWD: server.Project}
	}
	runtime := func(server config.MCPServerEntry) string {
		t.Helper()
		entry, err := store.GetActionForConnector(MCPJournalType(server), MCPJournalName(server), "claudecode")
		if err != nil {
			t.Fatal(err)
		}
		if entry == nil {
			return ""
		}
		return entry.Actions.Runtime
	}

	w.AdmitAddedMCPServers([]string{"gb05-benign"})
	w.admitAddedMCPServers(ctx)
	if len(admitted) != 2 {
		t.Fatalf("first admissions: %+v, want both accounts' servers", admitted)
	}
	for _, server := range servers {
		if _, pending := w.MCPAdmissionPending(query(server)); pending {
			t.Fatalf("%s: an admitted server is pending", server.Home)
		}
	}

	// The first account's server now runs another program under the same
	// name, in the same project.
	servers[0].Args = []string{"-y", "decoy"}
	rejected[MCPEventPath(servers[0])] = true
	if _, pending := w.MCPAdmissionPending(query(servers[0])); !pending {
		t.Fatal("a server whose definition changed kept the verdict of the old definition")
	}
	if _, pending := w.MCPAdmissionPending(query(servers[1])); pending {
		t.Fatal("the other account's unchanged same-name server is pending")
	}
	// The pending call queued the admission; the added-server loop runs it.
	w.admitAddedMCPServers(ctx)
	if len(admitted) != 3 || admitted[2].Verdict != VerdictRejected || admitted[2].Event.Path != MCPEventPath(servers[0]) {
		t.Fatalf("admissions after the change: %+v, want the changed server rejected", admitted)
	}
	if _, pending := w.MCPAdmissionPending(query(servers[0])); pending {
		t.Fatal("still pending after its admission: the new baseline was not kept")
	}
	if runtime(servers[0]) != "disable" || runtime(servers[1]) != "" {
		t.Fatalf("runtime: changed %q, other account %q; want the changed server disabled, the other not",
			runtime(servers[0]), runtime(servers[1]))
	}
	// Unchanged definitions are not admitted again.
	w.AdmitAddedMCPServers([]string{"gb05-benign"})
	w.admitAddedMCPServers(ctx)
	if len(admitted) != 3 {
		t.Fatalf("an unchanged server was admitted again: %+v", admitted[3:])
	}
}

// GAP-0686: a definition the account's agent runs is admitted only when the
// watcher holds a server of that account with the same complete definition:
// URL, command, every argument and the environment.
func TestMCPPublishedIsPerAccountAndPerDefinition(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	longArgs := make([]string, 40)
	for i := range longArgs {
		longArgs[i] = fmt.Sprintf("a%d", i)
	}
	servers := []config.MCPServerEntry{
		{Name: "notes", URL: "http://127.0.0.1:28561/mcp", Connector: "codex", Home: "/home/u1"},
		{Name: "loop", Command: "node", Args: []string{"a.js"}, Env: map[string]string{"TARGET": "ordinary"}, Connector: "codex", Home: "/home/u1"},
		{Name: "wide", Command: "node", Args: longArgs, Connector: "codex", Home: "/home/u1"},
		{Name: "docs", URL: "https://docs.example/mcp", Connector: "codex", Home: "/home/u1", Bundled: true},
	}
	w := New(cfg, nil, nil, store, logger, nil, nil)
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return servers, nil })
	query := func(server, home string) MCPAdmissionQuery {
		return MCPAdmissionQuery{Connector: "codex", Server: server, Home: home}
	}
	for _, tc := range []struct {
		name           string
		q              MCPAdmissionQuery
		def            config.MCPServerEntry
		matched, named bool
	}{
		{"same url", query("notes", "/home/u1"), config.MCPServerEntry{URL: "http://127.0.0.1:28561/mcp"}, true, true},
		{"another url under the same name", query("notes", "/home/u1"), config.MCPServerEntry{URL: "http://127.0.0.1:28562/mcp"}, false, true},
		{"another account", query("notes", "/home/u2"), config.MCPServerEntry{URL: "http://127.0.0.1:28561/mcp"}, false, false},
		{"another connector", MCPAdmissionQuery{Connector: "claudecode", Server: "notes", Home: "/home/u1"}, config.MCPServerEntry{URL: "http://127.0.0.1:28561/mcp"}, false, false},
		{"same command and environment", query("loop", "/home/u1"), config.MCPServerEntry{Command: "node", Args: []string{"a.js"}, Env: map[string]string{"TARGET": "ordinary"}}, true, true},
		{"other arguments", query("loop", "/home/u1"), config.MCPServerEntry{Command: "node", Args: []string{"b.js"}, Env: map[string]string{"TARGET": "ordinary"}}, false, true},
		{"changed environment", query("loop", "/home/u1"), config.MCPServerEntry{Command: "node", Args: []string{"a.js"}, Env: map[string]string{"TARGET": "protected"}}, false, true},
		{"no environment", query("loop", "/home/u1"), config.MCPServerEntry{Command: "node", Args: []string{"a.js"}}, false, true},
		{"more arguments than a hook fact carries", query("wide", "/home/u1"), config.MCPServerEntry{Command: "node", Args: longArgs}, true, true},
		{"a different last argument", query("wide", "/home/u1"), config.MCPServerEntry{Command: "node", Args: append(append([]string(nil), longArgs[:39]...), "x")}, false, true},
		{"built-in server is not an admission target", query("docs", "/home/u1"), config.MCPServerEntry{URL: "https://docs.example/mcp"}, false, false},
	} {
		got := w.MCPPublished(tc.q, config.MCPLaunchDigest(tc.def))
		if got.Matched != tc.matched || got.Named != tc.named {
			t.Errorf("%s: MCPPublished = matched %v named %v, want matched %v named %v", tc.name, got.Matched, got.Named, tc.matched, tc.named)
		}
		if got.Matched && got.Entry.Name != tc.q.Server {
			t.Errorf("%s: matched entry %q, want %q", tc.name, got.Entry.Name, tc.q.Server)
		}
	}
	if got := w.MCPPublished(query("notes", "/home/u1"), ""); got.Matched || !got.Named {
		t.Errorf("no digest: matched %v named %v, want unmatched and named", got.Matched, got.Named)
	}
}

// GAP-0925: a local server a managed Linux or macOS hook reported with the
// scanner verdict taken from the complete definition is not pending: the
// admission that starts can only record the refusal, so the call that lists
// the server gets the failed status with the cause the later calls get. The
// same definition read by the watcher itself, and a server the verdict says a
// scan starts, keep the pending path.
func TestMCPStatedRefusalOfAReportedServerIsFailedOnItsFirstCall(t *testing.T) {
	for _, tc := range []struct {
		name, command, stated, issue string
		args                         []string
		failed                       bool
	}{
		{"launcher", "python3", "launcher", MCPScanIssueLauncher, []string{"server.py"}, true},
		{"arguments past the bound", "npx", "arguments", MCPScanIssueArguments, []string{"-y", "pkg"}, true},
		{"read by the watcher", "python3", "", "", []string{"server.py"}, false},
		{"stated none over a carried flag", "npx", "none", "", []string{"-c", "x"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, store, logger, _ := setupTestEnv(t)
			cfg.Gateway.Watcher.MCP.TakeAction = true
			server := config.MCPServerEntry{Name: "localsrv", Command: tc.command, Args: tc.args,
				Connector: "claudecode", Home: "/home/eng1", LocalRefusal: tc.stated}
			w := New(cfg, nil, nil, store, logger, nil, nil)
			w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return []config.MCPServerEntry{server}, nil })
			w.firstCycleDone.Store(true)
			status := w.MCPAdmissionStatus(MCPAdmissionQuery{Connector: "claudecode", Server: "localsrv", Home: "/home/eng1"})
			if tc.failed {
				if !status.Failed || status.Pending || status.Name != "localsrv" || status.ScanIssue != tc.issue {
					t.Fatalf("first call status %+v, want failed with the %q cause", status, tc.issue)
				}
				return
			}
			if status.Failed || !status.Pending {
				t.Fatalf("first call status %+v, want pending until the admission", status)
			}
		})
	}
}
