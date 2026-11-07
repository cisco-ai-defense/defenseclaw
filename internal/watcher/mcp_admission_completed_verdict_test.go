// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/scanner"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func statusOf(h *definitionChangeHarness, server config.MCPServerEntry) MCPAdmissionStatus {
	return h.w.MCPAdmissionStatus(MCPAdmissionQuery{
		Connector: server.Connector, Server: server.Name, Home: server.Home, CWD: server.Project,
	})
}

// GAP-0775: the hook read a server whose admission had completed as a scan
// failure as still pending (and allowed its first calls) whenever the stored
// baseline was not readable for that definition. The completed verdict is
// kept from the moment it is decided, so the status is failed, never
// pending, for that exact definition, and a changed definition is pending
// again.
func TestCompletedScanFailureIsNotPendingWithoutItsBaseline(t *testing.T) {
	h, _ := newScriptedMCPHarness(t) // strict tier: a refusal is a block
	server := &h.servers[0]
	server.Command, server.Args = "node", []string{"server.js"}
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictBlocked {
		t.Fatalf("admission %+v, want a block", got)
	}
	if status := statusOf(h, *server); !status.Failed || status.Pending || status.ScanIssue != MCPScanIssueLauncher {
		t.Fatalf("after the verdict: %+v, want failed with the launcher cause", status)
	}
	// The baseline write did not land (or was lost): the verdict stands.
	if err := h.store.DeleteTargetSnapshot(string(InstallMCP), MCPEventPath(*server)); err != nil {
		t.Fatal(err)
	}
	if status := statusOf(h, *server); !status.Failed || status.Pending {
		t.Fatalf("without a baseline: %+v, want the completed failure, not pending", status)
	}
	server.Args = []string{"other.js"}
	if status := statusOf(h, *server); !status.Pending || status.Failed {
		t.Fatalf("changed definition: %+v, want pending until its own admission", status)
	}
}

// The default and permissive tiers cannot scan a launcher the scanner refuses
// and keep the server with a warning; nothing is blocked or disabled, the
// status still reports the failure and its cause so the hook can warn, and
// an ordinary npx server stays clean (the benign twin).
func TestRefusedMCPServerIsKeptWithAWarningInTheDefaultTier(t *testing.T) {
	h := newDefinitionChangeHarness(t, enrolledMCPServer(t.TempDir(), "1001", "."))
	scan := &scriptedMCPScanner{h: h}
	h.w.scannerFactory = func(InstallEvent) scanner.Scanner { return scan }
	server := &h.servers[0]
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictClean {
		t.Fatalf("ordinary server %+v, want clean", got)
	}
	if status := statusOf(h, *server); status.Failed || status.Pending {
		t.Fatalf("ordinary server status %+v", status)
	}
	server.Command, server.Args = "node", []string{"server.js"}
	got := h.poll()
	if len(got) != 1 || got[0].Verdict != VerdictScanError || !keptUnscannedMCPReason(got[0].Reason) ||
		got[0].InstallAction != "" || got[0].RuntimeAction != "" {
		t.Fatalf("refused launcher %+v, want kept with a warning and no block", got)
	}
	entry, err := h.store.GetActionForConnector(MCPJournalType(*server), MCPJournalName(*server), server.Connector)
	if err != nil || (entry != nil && (entry.Actions.Install == "block" || entry.Actions.Runtime == "disable")) {
		t.Fatalf("journal %+v (err %v), want no block or disable", entry, err)
	}
	if status := statusOf(h, *server); !status.Failed || status.Pending || status.ScanIssue != MCPScanIssueLauncher {
		t.Fatalf("status %+v, want failed with the launcher cause", status)
	}
}

func TestMCPScanIssueNamesTheRefusedDefinition(t *testing.T) {
	for _, tc := range []struct {
		server config.MCPServerEntry
		want   string
	}{
		{config.MCPServerEntry{Command: "python3", Args: []string{"s.py"}}, MCPScanIssueLauncher},
		{config.MCPServerEntry{Command: "/usr/bin/npx", Args: []string{"-y", "p"}}, MCPScanIssueLauncher},
		{config.MCPServerEntry{Command: "npx", Args: []string{"-y", "p"}}, ""},
		{config.MCPServerEntry{Command: "uvx", Args: []string{"p"}}, ""},
		{config.MCPServerEntry{URL: "http://127.0.0.1:18795/mcp"}, MCPScanIssueAddress},
		{config.MCPServerEntry{URL: "http://localhost:3000/mcp"}, MCPScanIssueAddress},
		{config.MCPServerEntry{URL: "http://10.1.2.3/mcp"}, MCPScanIssueAddress},
		{config.MCPServerEntry{URL: "http://[::1]:8080/mcp"}, MCPScanIssueAddress},
		{config.MCPServerEntry{URL: "https://docs.example.com/mcp"}, ""},
		{config.MCPServerEntry{URL: "https://8.8.8.8/mcp"}, ""},
	} {
		if got := mcpScanIssue(tc.server); got != tc.want {
			t.Errorf("%+v: issue %q, want %q", tc.server, got, tc.want)
		}
	}
}

// GAP-0778: an allow decided for a definition whose stored baseline still
// says "failed" (the admin allowed the server and the rescan admitted it, the
// baseline write has not landed) is the verdict from that moment: the next
// call is not held by the old failed baseline. Once the baseline is written
// it carries the verdict. A changed definition is pending again, and a failed
// outcome is not lost before the baseline records it (the benign twin).
func TestAllowedOutcomeReplacesTheFailedBaselineBeforeItsWrite(t *testing.T) {
	h, _ := newScriptedMCPHarness(t) // strict tier: a refusal is a block
	server := &h.servers[0]
	server.Command, server.Args = "node", []string{"server.js"}
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictBlocked {
		t.Fatalf("admission %+v, want a block", got)
	}
	if status := statusOf(h, *server); !status.Failed {
		t.Fatalf("before the allow: %+v, want failed", status)
	}
	evt := InstallEvent{Type: InstallMCP, Name: server.Name, Path: MCPEventPath(*server), Connector: server.Connector}
	snap, err := h.w.snapshotForEvent(evt)
	if err != nil {
		t.Fatal(err)
	}
	h.w.noteMCPAdmissionOutcome(evt, snap, AdmissionResult{Event: evt, Verdict: VerdictAllowed})
	if status := statusOf(h, *server); status.Failed || status.Pending {
		t.Fatalf("after the allow, before the baseline: %+v, want neither failed nor pending", status)
	}
	h.w.persistSnapshot(evt, snap, "", "allowed-fingerprint")
	if status := statusOf(h, *server); status.Failed || status.Pending {
		t.Fatalf("after the baseline write: %+v, want neither failed nor pending", status)
	}
	server.Args = []string{"other.js"}
	if status := statusOf(h, *server); !status.Pending || status.Failed {
		t.Fatalf("changed definition: %+v, want pending until its own admission", status)
	}
	// Twin: a failure noted for a definition with a clean baseline is
	// reported until the baseline is written for it.
	server.Args = []string{"server.js"}
	h.w.noteMCPAdmissionOutcome(evt, snap, AdmissionResult{Event: evt, Verdict: VerdictBlocked, Reason: scanFailureReason + "x"})
	if status := statusOf(h, *server); !status.Failed {
		t.Fatalf("a completed failure over a clean baseline: %+v, want failed", status)
	}
}

// A verdict is for the definition that was scanned. The scanner reads the
// definition by name when it runs, so a config rewrite between the snapshot
// and the scan gave a clean verdict for the new definition to the snapshot of
// the old one. When the old definition came back it read as admitted. Neither
// the outcome nor the baseline is published for a definition the snapshot does
// not name, so the server has no outcome (pending) and is admitted again.
func TestVerdictIsNotPublishedForADefinitionThatMovedDuringTheScan(t *testing.T) {
	h, scan := newScriptedMCPHarness(t)
	server := &h.servers[0]
	server.Command, server.Args = "node", []string{"server.js"}
	h.w.scannerFactory = func(InstallEvent) scanner.Scanner {
		server.Command, server.Args = "npx", []string{"-y", "."}
		return scan
	}
	h.poll()
	server.Command, server.Args = "node", []string{"server.js"}
	if status := statusOf(h, *server); !status.Failed && !status.Pending {
		t.Fatalf("the unscanned definition inherited the verdict of the one scanned: %+v", status)
	}
	if row, err := h.store.GetTargetSnapshot(string(InstallMCP), MCPEventPath(*server)); err == nil && mcpBaselineMatches(row, *server) {
		t.Fatalf("a baseline was stored for the unscanned definition: %+v", row)
	}
}

// Twin: a definition that stays as it was snapshotted keeps its verdict.
func TestVerdictIsPublishedForTheDefinitionThatWasScanned(t *testing.T) {
	h, scan := newScriptedMCPHarness(t)
	server := &h.servers[0]
	server.Command, server.Args = "npx", []string{"-y", "."}
	h.w.scannerFactory = func(InstallEvent) scanner.Scanner { return scan }
	h.poll()
	if status := statusOf(h, *server); status.Failed || status.Pending {
		t.Fatalf("a scanned, unchanged definition: %+v, want admitted", status)
	}
}
