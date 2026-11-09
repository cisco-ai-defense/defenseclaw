// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// An MCP server the administrator allowed before any scan (an
// asset_policy.mcp.allowed rule on a server the scanner refuses) was admitted
// by the policy, not by a verdict on its definition. Removing the rule left
// that admission standing: the baseline and the outcome kept saying admitted,
// the recovery scan of a baseline without a scan id failed without recording
// anything, and the agent kept calling the server for minutes in running and
// new sessions (GAP-0920). The allow is revoked with the rule: the next call
// is pending, and the admission that follows blocks the server again.
type allowRemovalFixture struct {
	t      *testing.T
	cfg    *config.Config
	w      *InstallWatcher
	server config.MCPServerEntry
	scans  *failingScanner
}

func newAllowRemovalFixture(t *testing.T) *allowRemovalFixture {
	t.Helper()
	t.Setenv("PATH", "")
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Gateway.Watcher.MCP.TakeAction = true
	cfg.Scanners.MCPScanner.UnverifiedServer = "block"
	cfg.Watch.RescanContentGated = true
	f := &allowRemovalFixture{t: t, cfg: cfg,
		server: config.MCPServerEntry{Name: "wiki-ok2", URL: "http://127.0.0.1:28772/mcp", Connector: "codex", Home: "/home/u1"},
		scans:  &failingScanner{countingScanner{name: "mcp-scanner"}}}
	f.w = New(cfg, nil, nil, store, logger, nil, nil)
	f.w.scannerFactory = func(InstallEvent) scanner.Scanner { return f.scans }
	f.w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return []config.MCPServerEntry{f.server}, nil })
	f.w.firstCycleDone.Store(true)
	return f
}

func (f *allowRemovalFixture) status() MCPAdmissionStatus {
	return f.w.MCPAdmissionStatus(MCPAdmissionQuery{Connector: f.server.Connector, Server: f.server.Name, Home: f.server.Home})
}

func (f *allowRemovalFixture) admitQueued() {
	f.w.admitAddedMCPServers(context.Background())
}

func (f *allowRemovalFixture) blocked() bool {
	entry, err := f.w.store.GetActionForConnector(MCPJournalType(f.server), MCPJournalName(f.server), "codex")
	return err == nil && entry != nil && entry.Actions.Runtime == "disable" && entry.Actions.Install == "block"
}

// admittedByAllowRule takes the server through the failed scan, then the
// allow rule, and checks it is admitted.
func (f *allowRemovalFixture) admittedByAllowRule() {
	f.t.Helper()
	f.w.AdmitAddedMCPServers([]string{f.server.Name})
	f.admitQueued()
	if status := f.status(); !status.Failed || !f.blocked() {
		f.t.Fatalf("after the failed scan: %+v blocked=%v, want a failed, blocked server", status, f.blocked())
	}
	f.cfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: f.server.Name, URL: f.server.URL, Reason: "reviewed"}}
	f.w.runRescanCycle(context.Background())
	if status := f.status(); status.Failed || status.Pending || f.blocked() {
		f.t.Fatalf("after the allow rule: %+v blocked=%v, want an admitted server", status, f.blocked())
	}
}

func TestRemovedAllowRuleRevokesAnUnscannedMCPAdmissionAtTheNextCall(t *testing.T) {
	f := newAllowRemovalFixture(t)
	f.admittedByAllowRule()
	f.cfg.AssetPolicy.MCP.Allowed = nil
	if status := f.status(); !status.Pending {
		t.Fatalf("the call after the rule was removed: %+v, want pending, not the old allow", status)
	}
	f.admitQueued()
	if status := f.status(); !status.Failed || status.Pending || !f.blocked() {
		t.Fatalf("after the admission that followed: %+v blocked=%v, want the failed scan to block it again", status, f.blocked())
	}
}

func TestRemovedAllowRuleBlocksAnUnscannedMCPServerOnTheRescan(t *testing.T) {
	f := newAllowRemovalFixture(t)
	f.admittedByAllowRule()
	f.cfg.AssetPolicy.MCP.Allowed = nil
	f.w.runRescanCycle(context.Background())
	if status := f.status(); !status.Failed || status.Pending || !f.blocked() {
		t.Fatalf("after the rescan: %+v blocked=%v, want the failed scan to block it again", status, f.blocked())
	}
}

func TestRemovedScanOnInstallOffRevokesAnUnscannedMCPAdmission(t *testing.T) {
	f := newAllowRemovalFixture(t)
	off := false
	f.cfg.Admission.MCP.ScanOnInstall = &off
	f.w.AdmitAddedMCPServers([]string{f.server.Name})
	f.admitQueued()
	if status := f.status(); status.Failed || status.Pending || f.scans.calls != 0 {
		t.Fatalf("admitted without a scan: %+v, %d scans", status, f.scans.calls)
	}
	f.cfg.Admission.MCP.ScanOnInstall = nil
	if status := f.status(); !status.Pending {
		t.Fatalf("after the setting was turned back on: %+v, want pending", status)
	}
	f.admitQueued()
	if status := f.status(); !status.Failed || !f.blocked() {
		t.Fatalf("after its admission: %+v blocked=%v, want the failed scan to block it", status, f.blocked())
	}
}

// Benign twins: a rule that stays keeps the server admitted without another
// scan, and a server a completed scan admitted stays admitted when a rule
// that also covered it is removed.
func TestStandingAllowRuleKeepsAnUnscannedMCPAdmission(t *testing.T) {
	f := newAllowRemovalFixture(t)
	f.admittedByAllowRule()
	scans := f.scans.calls
	for range 3 {
		f.w.runRescanCycle(context.Background())
		if status := f.status(); status.Failed || status.Pending || f.blocked() || f.scans.calls != scans {
			t.Fatalf("with the rule standing: %+v blocked=%v, %d scans (was %d), want it admitted and not scanned", status, f.blocked(), f.scans.calls, scans)
		}
	}
}

func TestRemovedAllowRuleKeepsAScannedMCPAdmission(t *testing.T) {
	f := newAllowRemovalFixture(t)
	clean := &countingScanner{name: "mcp-scanner"}
	f.w.scannerFactory = func(InstallEvent) scanner.Scanner { return clean }
	f.server.URL = "https://mcp.example.test/mcp"
	f.w.AdmitAddedMCPServers([]string{f.server.Name})
	f.admitQueued()
	f.cfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: f.server.Name, Reason: "reviewed"}}
	f.w.runRescanCycle(context.Background())
	f.cfg.AssetPolicy.MCP.Allowed = nil
	f.w.runRescanCycle(context.Background())
	if status := f.status(); status.Failed || status.Pending || f.blocked() {
		t.Fatalf("scanned server after the rule was removed: %+v blocked=%v, want it still admitted", status, f.blocked())
	}
}
