// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// definitionChangeHarness admits MCP servers whose scan rejects a definition
// whose arguments name a decoy and passes every other one.
type definitionChangeHarness struct {
	t        *testing.T
	w        *InstallWatcher
	store    *audit.Store
	servers  []config.MCPServerEntry
	admitted []AdmissionResult
}

func newDefinitionChangeHarness(t *testing.T, servers ...config.MCPServerEntry) *definitionChangeHarness {
	t.Helper()
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.MCP.TakeAction = true
	cfg.Admission.MCP.Actions.High = &config.AdmissionAction{Shorthand: config.AdmissionActionQuarantine}
	h := &definitionChangeHarness{t: t, store: store, servers: servers}
	h.w = New(cfg, nil, nil, store, logger, nil, func(r AdmissionResult) { h.admitted = append(h.admitted, r) })
	h.w.scannerFactory = func(evt InstallEvent) scanner.Scanner {
		for _, server := range h.servers {
			if MCPEventPath(server) == evt.Path && strings.Contains(strings.Join(server.Args, " "), "decoy") {
				return &countingScanner{name: "mcp-scanner", findings: []scanner.Finding{{
					ID: "f1", RuleID: "MCP-001", Severity: scanner.SeverityHigh, Title: "credential harvesting",
				}}}
			}
		}
		return &countingScanner{name: "mcp-scanner"}
	}
	h.w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) {
		return append([]config.MCPServerEntry(nil), h.servers...), nil
	})
	h.w.SetMCPDiscoveryPoll(true)
	h.w.firstCycleDone.Store(true)
	return h
}

// poll is one discovery poll and the admissions it queued.
func (h *definitionChangeHarness) poll() []AdmissionResult {
	h.t.Helper()
	before := len(h.admitted)
	h.w.discoverAddedMCPServers()
	h.w.admitAddedMCPServers(context.Background())
	return h.admitted[before:]
}

func (h *definitionChangeHarness) pending(server config.MCPServerEntry) bool {
	_, pending := h.w.MCPAdmissionPending(MCPAdmissionQuery{
		Connector: server.Connector, Server: server.Name, Home: server.Home, CWD: server.Project,
	})
	return pending
}

func (h *definitionChangeHarness) journal(server config.MCPServerEntry) audit.ActionState {
	h.t.Helper()
	entry, err := h.store.GetActionForConnector("mcp", MCPJournalName(server), "claudecode")
	if err != nil {
		h.t.Fatal(err)
	}
	if entry == nil {
		return audit.ActionState{}
	}
	return entry.Actions
}

// GAP-0216: an admitted server changed to a decoy under the same name was
// seen only by the rescan cycle, minutes later, while its calls were allowed
// on the old verdict. The discovery poll (and, on a managed gateway, every
// change of the enrolled users' published servers) now admits a changed
// definition at once: refused until its own scan, then rejected HIGH, and
// its new baseline is kept, so the next poll does not admit it again.
func TestChangedMCPServerIsAdmittedByTheWatchNotTheRescanCycle(t *testing.T) {
	base := t.TempDir()
	h := newDefinitionChangeHarness(t, enrolledMCPServer(base, "1001", "."), enrolledMCPServer(base, "1002", "."))
	if got := h.poll(); len(got) != 2 {
		t.Fatalf("first poll admitted %+v, want both accounts' servers", got)
	}

	h.servers[0].Args = []string{"-y", ".", "--config", "decoy.json"}
	if !h.pending(h.servers[0]) {
		t.Fatal("a changed server kept the clean verdict of its old definition")
	}
	got := h.poll()
	if len(got) != 1 || got[0].Event.Path != MCPEventPath(h.servers[0]) || got[0].Verdict != VerdictRejected || got[0].MaxSeverity != "HIGH" {
		t.Fatalf("poll after the change admitted %+v, want only the changed server, rejected HIGH", got)
	}
	if h.pending(h.servers[0]) {
		t.Fatal("still pending after its admission: the new baseline was not kept")
	}
	if state := h.journal(h.servers[0]); state.Runtime != "disable" || state.Install != "block" {
		t.Fatalf("journal of the changed server %+v, want blocked and disabled", state)
	}
	if state := h.journal(h.servers[1]); !state.IsEmpty() {
		t.Fatalf("the other account's same-name server got %+v", state)
	}
	if got := h.poll(); len(got) != 0 {
		t.Fatalf("an unchanged server was admitted again: %+v", got)
	}
}

// GAP-0266: a server changed to a decoy, rejected, and then restored to its
// benign definition was admitted clean but stayed refused with the decoy's
// reason. The clean admission of the changed definition lifts the watcher's
// own rejection; the other account's server and an operator block stay as
// they are.
func TestRestoredMCPServerIsReleasedByItsCleanAdmission(t *testing.T) {
	base := t.TempDir()
	h := newDefinitionChangeHarness(t, enrolledMCPServer(base, "1001", "."), enrolledMCPServer(base, "1002", "decoy"))
	h.poll()
	if state := h.journal(h.servers[1]); state.Runtime != "disable" {
		t.Fatalf("the second account's decoy is not disabled: %+v", state)
	}

	h.servers[0].Args = []string{"-y", "decoy"}
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictRejected {
		t.Fatalf("decoy admission %+v, want rejected", got)
	}
	h.servers[0].Args = []string{"-y", "."}
	if !h.pending(h.servers[0]) {
		t.Fatal("the restored definition is not pending before its own scan")
	}
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictClean {
		t.Fatalf("restore admission %+v, want clean", got)
	}
	if state := h.journal(h.servers[0]); !state.IsEmpty() {
		t.Fatalf("the restored, clean server is still refused: %+v", state)
	}
	if h.pending(h.servers[0]) {
		t.Fatal("the restored server is pending after its clean admission")
	}
	if state := h.journal(h.servers[1]); state.Runtime != "disable" {
		t.Fatalf("the other account's rejected server was released: %+v", state)
	}
	// An operator block of the server is not the watcher's to lift.
	key := MCPJournalName(h.servers[0])
	if err := h.store.SetActionFieldForConnector("mcp", key, "claudecode", "runtime", "disable", "operator: hold"); err != nil {
		t.Fatal(err)
	}
	h.servers[0].Args = []string{"-y", ".", "--quiet"}
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictClean {
		t.Fatalf("admission after the operator block %+v, want clean", got)
	}
	if state := h.journal(h.servers[0]); state.Runtime != "disable" {
		t.Fatalf("a clean admission lifted an operator block: %+v", state)
	}
}

// GAP-1365: the scanner's verdict can recover without a change to the MCP
// definition (for example, after its rules or judge change). The recovery
// scan must apply admission, rather than only recording finding drift.
func TestMCPRecoveryRescanReleasesOnlyItsOwnRejection(t *testing.T) {
	base := t.TempDir()
	h := newDefinitionChangeHarness(t, enrolledMCPServer(base, "1001", "decoy"), enrolledMCPServer(base, "1002", "decoy"))
	h.w.cfg.Admission.MCP.Actions.High = &config.AdmissionAction{Shorthand: config.AdmissionActionQuarantine}
	if got := h.poll(); len(got) != 2 || got[0].Verdict != VerdictRejected || got[1].Verdict != VerdictRejected {
		t.Fatalf("initial admission %+v, want two rejected servers", got)
	}
	if h.journal(h.servers[0]).Runtime != "disable" || h.journal(h.servers[1]).Runtime != "disable" {
		t.Fatal("initial HIGH findings did not disable both servers")
	}

	// A scanner setting change makes the unchanged server eligible for a
	// recovery rescan. First prove a continuing HIGH verdict keeps it off.
	h.w.cfg.Scanners.MCPScanner.ScanPrompts = true
	evt := InstallEvent{Type: InstallMCP, Name: h.servers[0].Name, Path: MCPEventPath(h.servers[0]), Connector: h.servers[0].Connector}
	before := len(h.admitted)
	if got := h.w.rescanTarget(context.Background(), evt, nil); got != rescanScanned {
		t.Fatalf("continuing HIGH recovery scan = %v, want scanned", got)
	}
	if len(h.admitted) != before+1 || h.admitted[before].Verdict != VerdictRejected || h.journal(h.servers[0]).Runtime != "disable" {
		t.Fatalf("continuing HIGH admission %+v, journal %+v; want still rejected", h.admitted[before:], h.journal(h.servers[0]))
	}

	// The next scanner revision finds this same definition clean.
	h.w.cfg.Scanners.MCPScanner.ScanResources = true
	h.w.scannerFactory = func(InstallEvent) scanner.Scanner { return &countingScanner{name: "mcp-scanner"} }
	before = len(h.admitted)
	if got := h.w.rescanTarget(context.Background(), evt, nil); got != rescanScanned {
		t.Fatalf("clean recovery scan = %v, want scanned", got)
	}
	if len(h.admitted) != before+1 || h.admitted[before].Verdict != VerdictClean || !h.journal(h.servers[0]).IsEmpty() {
		t.Fatalf("clean admission %+v, journal %+v; want server restored", h.admitted[before:], h.journal(h.servers[0]))
	}
	if h.journal(h.servers[1]).Runtime != "disable" {
		t.Fatalf("another account's server was released: %+v", h.journal(h.servers[1]))
	}
	if h.pending(h.servers[0]) {
		t.Fatal("recovered server remained behind the pending gate")
	}

	// An administrator's later hold is separate from watcher enforcement.
	key := MCPJournalName(h.servers[0])
	if err := h.store.SetActionFieldForConnector("mcp", key, "claudecode", "runtime", "disable", "operator: hold"); err != nil {
		t.Fatal(err)
	}
	h.w.cfg.Scanners.MCPScanner.ScanInstructions = true
	h.w.rescanTarget(context.Background(), evt, nil)
	if h.journal(h.servers[0]).Runtime != "disable" {
		t.Fatal("clean rescan lifted the administrator's hold")
	}
}

// GAP-1365 also starts with an unfinished scan under the explicit block
// setting. Its empty-scan baseline must retry admission until a completed
// scan can release that scan-failure block for this definition alone.
func TestMCPFailedScanRecoveryReadmitsUnchangedDefinition(t *testing.T) {
	base := t.TempDir()
	h := newDefinitionChangeHarness(t, enrolledMCPServer(base, "1001", "."), enrolledMCPServer(base, "1002", "."))
	h.w.cfg.Scanners.MCPScanner.UnverifiedServer = "block"
	h.w.scannerFactory = func(InstallEvent) scanner.Scanner {
		return &failingScanner{countingScanner{name: "mcp-scanner"}}
	}
	if got := h.poll(); len(got) != 2 || got[0].Verdict != VerdictBlocked || got[1].Verdict != VerdictBlocked {
		t.Fatalf("initial scanner failures admitted %+v, want two blocks", got)
	}
	if h.journal(h.servers[0]).Runtime != "disable" || h.journal(h.servers[1]).Runtime != "disable" {
		t.Fatal("initial scanner failures did not disable both servers")
	}
	evt := InstallEvent{Type: InstallMCP, Name: h.servers[0].Name, Path: MCPEventPath(h.servers[0]), Connector: h.servers[0].Connector}
	if got := h.w.rescanTarget(context.Background(), evt, nil); got != rescanScanned {
		t.Fatalf("repeated failure recovery scan = %v, want scanned", got)
	}
	if h.journal(h.servers[0]).Runtime != "disable" {
		t.Fatalf("repeated failure released the server: %+v", h.journal(h.servers[0]))
	}
	h.w.scannerFactory = func(InstallEvent) scanner.Scanner { return &countingScanner{name: "mcp-scanner"} }
	before := len(h.admitted)
	if got := h.w.rescanTarget(context.Background(), evt, nil); got != rescanScanned {
		t.Fatalf("clean recovery scan = %v, want scanned", got)
	}
	if len(h.admitted) != before+1 || h.admitted[before].Verdict != VerdictClean || !h.journal(h.servers[0]).IsEmpty() {
		t.Fatalf("clean recovery admission %+v, journal %+v; want restored", h.admitted[before:], h.journal(h.servers[0]))
	}
	if h.journal(h.servers[1]).Runtime != "disable" {
		t.Fatalf("another account's failed server was released: %+v", h.journal(h.servers[1]))
	}
}

// A per-user gateway journals a project server under its bare name, so two
// projects' servers of one name share a row. Restoring one of them must not
// free the other's rejection.
func TestRestoredMCPServerKeepsABlockAnotherServerShares(t *testing.T) {
	root := t.TempDir()
	project := func(name, args string) config.MCPServerEntry {
		return config.MCPServerEntry{Name: "notes", Command: "npx", Args: []string{"-y", args},
			Connector: "claudecode", Project: filepath.Join(root, name), SourceScope: "project"}
	}
	h := newDefinitionChangeHarness(t, project("a", "decoy"), project("b", "."))
	h.poll()
	h.servers[1].Args = []string{"-y", "decoy"}
	h.poll()
	h.servers[1].Args = []string{"-y", "."}
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictClean {
		t.Fatalf("restore admission %+v, want clean", got)
	}
	if state := h.journal(h.servers[0]); state.Runtime != "disable" {
		t.Fatalf("project a's rejected server was freed by project b's restore: %+v", state)
	}
}
