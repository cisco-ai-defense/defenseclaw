// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func highFindingScanner() scanner.Scanner {
	return &countingScanner{name: "mcp-scanner", findings: []scanner.Finding{{
		ID: "f1", RuleID: "MCP-001", Severity: scanner.SeverityHigh, Title: "credential harvesting",
	}}}
}

// An admission enforces and releases only for the definition it was started
// for. The scanner reads a server by name, so a rewrite between the snapshot
// and the scan gave one definition a verdict found on another.

// A finding on a definition the snapshot does not name does not disable the
// ordinary definition the server goes back to.
func TestFindingOnAnotherDefinitionDoesNotDisableTheOrdinaryOne(t *testing.T) {
	h := newDefinitionChangeHarness(t, enrolledMCPServer(t.TempDir(), "1001", "."))
	h.w.cfg.Guardrail.RulePack = "balanced"
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictClean {
		t.Fatalf("initial ordinary admission: %+v", got)
	}
	server := &h.servers[0]
	server.Args = []string{"-y", "ordinary-new"}
	h.w.scannerFactory = func(InstallEvent) scanner.Scanner {
		server.Args = []string{"-y", ".", "--config", "other.json"}
		return highFindingScanner()
	}
	h.poll()
	server.Args = []string{"-y", "ordinary-new"}
	if status := statusOf(h, *server); !status.Pending && !status.Failed {
		t.Fatalf("unscanned definition inherited a completed verdict: %+v", status)
	}
	if state := h.journal(*server); state.Runtime == "disable" || state.Install == "block" || state.File != "" {
		t.Fatalf("a finding on another definition disabled the ordinary one: %+v", state)
	}
}

// A clean scan of a definition the snapshot does not name does not release the
// block an earlier finding left on the server.
func TestCleanScanOfAnotherDefinitionKeepsThePriorFindingBlock(t *testing.T) {
	h := newDefinitionChangeHarness(t, enrolledMCPServer(t.TempDir(), "1001", "decoy"))
	h.w.cfg.Guardrail.RulePack = "balanced"
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictRejected {
		t.Fatalf("initial high finding: %+v", got)
	}
	server := &h.servers[0]
	if state := h.journal(*server); state.Runtime != "disable" {
		t.Fatalf("initial finding did not disable the server: %+v", state)
	}
	server.Args = []string{"-y", "decoy-new"}
	h.w.scannerFactory = func(InstallEvent) scanner.Scanner {
		server.Args = []string{"-y", "ordinary"}
		return &countingScanner{name: "mcp-scanner"}
	}
	h.poll()
	server.Args = []string{"-y", "decoy-new"}
	if status := statusOf(h, *server); !status.Pending && !status.Failed {
		t.Fatalf("unscanned definition inherited a clean verdict: %+v", status)
	}
	if state := h.journal(*server); state.Runtime != "disable" || state.Install != "block" {
		t.Fatalf("a clean scan of another definition released the earlier block: %+v", state)
	}
}

// Twin: a definition that stays as it was snapshotted is still blocked for its
// finding, and a clean change still releases the earlier block.
func TestFindingOnTheSnapshottedDefinitionStillBlocksAndACleanChangeStillReleases(t *testing.T) {
	h := newDefinitionChangeHarness(t, enrolledMCPServer(t.TempDir(), "1001", "decoy"))
	h.w.cfg.Guardrail.RulePack = "balanced"
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictRejected {
		t.Fatalf("finding on a stable definition: %+v", got)
	}
	server := &h.servers[0]
	if state := h.journal(*server); state.Runtime != "disable" || state.Install != "block" {
		t.Fatalf("a finding on a stable definition did not block it: %+v", state)
	}
	server.Args = []string{"-y", "ordinary"}
	h.w.scannerFactory = func(InstallEvent) scanner.Scanner { return &countingScanner{name: "mcp-scanner"} }
	if got := h.poll(); len(got) != 1 || got[0].Verdict != VerdictClean {
		t.Fatalf("clean change: %+v", got)
	}
	if state := h.journal(*server); state.Runtime == "disable" || state.Install == "block" {
		t.Fatalf("a clean scan of the changed definition left the earlier block: %+v", state)
	}
}
