// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func enrolledMCPServer(base, account, args string) config.MCPServerEntry {
	home := filepath.Join(base, account)
	return config.MCPServerEntry{Name: "gb05-benign", Command: "npx", Args: []string{"-y", args},
		Connector: "claudecode", Home: home, Project: filepath.Join(home, "proj"), SourceScope: "project",
		RunAsSID: "S-1-5-21-1-" + account}
}

// GAP-0216: two enrolled users' MCP servers with the same name shared one
// journal row, so one user's failed scan refused the other user's clean
// server, and a rescan of the second user's server could release a block the
// first user's verdict needed. Each account's verdict now has its own row:
// both outcomes stay apart across rescans.
func TestTwoAccountsSameNameMCPServerVerdictsStayApart(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Scanners.MCPScanner.UnverifiedServer = "block" // the strict tier blocks a server whose scan failed (GAP-1195)
	cfg.Gateway.Watcher.MCP.TakeAction = true
	cfg.Admission.MCP.Actions.High = &config.AdmissionAction{Shorthand: config.AdmissionActionQuarantine}
	base := t.TempDir()
	u1 := enrolledMCPServer(base, "1001", "decoy")
	u2 := enrolledMCPServer(base, "1002", "benign")
	verdict := map[string]string{MCPEventPath(u1): "rejected", MCPEventPath(u2): "clean"}
	w := New(cfg, nil, nil, store, logger, nil, nil)
	w.scannerFactory = func(evt InstallEvent) scanner.Scanner {
		switch verdict[evt.Path] {
		case "rejected":
			return &countingScanner{name: "mcp-scanner", findings: []scanner.Finding{{
				ID: "f1", RuleID: "MCP-001", Severity: scanner.SeverityHigh, Title: "credential harvesting",
			}}}
		case "failed":
			return &failingScanner{countingScanner{name: "mcp-scanner"}}
		}
		return &countingScanner{name: "mcp-scanner"}
	}
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return []config.MCPServerEntry{u1, u2}, nil })
	w.firstCycleDone.Store(true)
	admit := func(server config.MCPServerEntry) {
		t.Helper()
		w.runAdmission(context.Background(), InstallEvent{Type: InstallMCP, Name: server.Name,
			Path: MCPEventPath(server), Connector: server.Connector})
	}
	runtime := func(server config.MCPServerEntry) string {
		t.Helper()
		entry, err := store.GetActionForConnector("mcp", MCPJournalName(server), "claudecode")
		if err != nil {
			t.Fatal(err)
		}
		if entry == nil {
			return ""
		}
		return entry.Actions.Runtime
	}

	admit(u1)
	admit(u2)
	if runtime(u1) != "disable" || runtime(u2) != "" {
		t.Fatalf("after the first admissions: u1 runtime %q, u2 runtime %q; want u1 disabled, u2 not", runtime(u1), runtime(u2))
	}
	if bare, err := store.GetActionForConnector("mcp", "gb05-benign", "claudecode"); err != nil || bare != nil {
		t.Fatalf("a bare-name row %+v (err %v) would refuse every account's server", bare, err)
	}
	// Rescans of the clean server never release the rejected one.
	admit(u2)
	admit(u2)
	if runtime(u1) != "disable" {
		t.Fatalf("u2's rescans released u1's rejected server (runtime %q)", runtime(u1))
	}
	// A failed scan of u2's server blocks only u2's, and u2's clean rescan
	// releases only u2's.
	verdict[MCPEventPath(u2)] = "failed"
	admit(u2)
	if runtime(u2) != "disable" || runtime(u1) != "disable" {
		t.Fatalf("after u2's failed scan: u1 %q, u2 %q; want both disabled", runtime(u1), runtime(u2))
	}
	verdict[MCPEventPath(u2)] = "clean"
	admit(u2)
	if runtime(u2) != "" || runtime(u1) != "disable" {
		t.Fatalf("after u2's clean rescan: u1 %q, u2 %q; want u1 disabled, u2 released", runtime(u1), runtime(u2))
	}

	key := MCPJournalName(u1)
	for _, tc := range []struct {
		name  string
		query MCPAdmissionQuery
		want  bool
	}{
		{"the account in its project", MCPAdmissionQuery{Connector: "claudecode", Server: "gb05-benign", Home: u1.Home, CWD: filepath.Join(u1.Project, "src")}, true},
		{"the account, no working folder", MCPAdmissionQuery{Connector: "claudecode", Server: "gb05-benign", Home: u1.Home}, true},
		{"a caller whose home is not known", MCPAdmissionQuery{Connector: "claudecode", Server: "gb05-benign"}, true},
		{"another account", MCPAdmissionQuery{Connector: "claudecode", Server: "gb05-benign", Home: u2.Home, CWD: u2.Project}, false},
		{"another project of the account", MCPAdmissionQuery{Connector: "claudecode", Server: "gb05-benign", Home: u1.Home, CWD: filepath.Join(u1.Home, "other")}, false},
		{"another connector", MCPAdmissionQuery{Connector: "codex", Server: "gb05-benign", Home: u1.Home}, false},
		{"another server", MCPAdmissionQuery{Connector: "claudecode", Server: "gb05-other", Home: u1.Home}, false},
	} {
		if got := MCPAccountJournalServes(key, tc.query); got != tc.want {
			t.Errorf("%s: serves = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A per-user server keeps its bare-name row; only an enrolled account's
// server has an account key.
func TestMCPJournalNameOnlyKeysEnrolledAccounts(t *testing.T) {
	project := config.MCPServerEntry{Name: "notes", Connector: "claudecode", Project: "/work/proj"}
	user := config.MCPServerEntry{Name: "notes", Connector: "codex"}
	for _, server := range []config.MCPServerEntry{project, user} {
		if got := MCPJournalName(server); got != "notes" {
			t.Errorf("per-user %+v journaled as %q", server, got)
		}
		if IsAccountMCPJournalName(server.Name, MCPEventPath(server)) {
			t.Errorf("per-user event path %q read as an account key", MCPEventPath(server))
		}
	}
	enrolled := config.MCPServerEntry{Name: "notes", Connector: "kiro", Home: "/home/u1"}
	if got := MCPJournalName(enrolled); got != MCPEventPath(enrolled) || !IsAccountMCPJournalName("notes", got) {
		t.Errorf("enrolled server journaled as %q", got)
	}
}

// Rows an earlier version kept under the bare name for an enrolled account's
// server move to that account; rows whose account cannot be told stay and
// keep refusing by name.
func TestBareNameMCPJournalRowsMoveToTheirAccount(t *testing.T) {
	_, store, _, _ := setupTestEnv(t)
	u1 := enrolledMCPServer(t.TempDir(), "1001", "decoy")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(store.SetActionFieldForConnector("mcp", "gb05-benign", "claudecode", "install", "block", "auto-block: x"))
	must(store.SetActionFieldForConnector("mcp", "gb05-benign", "claudecode", "runtime", "disable", "auto-block: x"))
	must(store.SetSourcePathForConnector("mcp", "gb05-benign", "claudecode", MCPEventPath(u1)))
	must(store.SetActionFieldForConnector("mcp", "notes", "claudecode", "runtime", "disable", "operator"))

	moved, kept, err := MigrateAccountMCPJournal(store)
	if err != nil || moved != 1 || kept != 1 {
		t.Fatalf("moved %d kept %d err %v; want 1 moved, 1 kept", moved, kept, err)
	}
	account, err := store.GetActionForConnector("mcp", MCPJournalName(u1), "claudecode")
	if err != nil || account == nil || account.Actions.Runtime != "disable" || account.Actions.Install != "block" ||
		account.SourcePath != MCPEventPath(u1) {
		t.Fatalf("account row %+v (err %v), want the block and disable moved with the source path", account, err)
	}
	if bare, _ := store.GetActionForConnector("mcp", "gb05-benign", "claudecode"); bare != nil {
		t.Fatalf("the moved bare row stays: %+v", bare)
	}
	if notes, _ := store.GetActionForConnector("mcp", "notes", "claudecode"); notes == nil || notes.Actions.Runtime != "disable" {
		t.Fatalf("a row whose account is unknown was dropped: %+v", notes)
	}
	if moved, _, err := MigrateAccountMCPJournal(store); err != nil || moved != 0 {
		t.Fatalf("second run moved %d (err %v)", moved, err)
	}
	// An operator allow of the name also clears the accounts' runtime rows.
	must(ClearAccountMCPJournal(store, "gb05-benign", "claudecode", "runtime"))
	if account, _ := store.GetActionForConnector("mcp", MCPJournalName(u1), "claudecode"); account == nil ||
		account.Actions.Runtime != "" || account.Actions.Install != "block" {
		t.Fatalf("after the allow: %+v, want the runtime disable cleared and the install block kept", account)
	}
}
