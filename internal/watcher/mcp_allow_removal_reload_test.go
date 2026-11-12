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

// GAP-0088 (gas-ux-r2): on a managed gateway an administrator allowed a
// loopback MCP server the scanner refuses, the hook call admitted it, and the
// allow rule was removed again. A config reload or a gateway restart starts a
// new watcher on the same audit store: the call kept running 22 minutes later
// and after the restart. The admission the rule gave must end with the rule,
// whichever path admitted it and whichever watcher reads it.

// reloaded is the watcher a config reload or a gateway restart starts on the
// same store, with cfg as the new config.
func (f *allowRemovalFixture) reloaded(cfg *config.Config) {
	f.t.Helper()
	store, logger := f.w.store, f.w.logger
	f.cfg = cfg
	f.w = New(cfg, nil, nil, store, logger, nil, nil)
	f.w.scannerFactory = func(InstallEvent) scanner.Scanner { return f.scans }
	f.w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return []config.MCPServerEntry{f.server}, nil })
}

func (f *allowRemovalFixture) withoutAllow() *config.Config {
	next := *f.cfg
	next.AssetPolicy.MCP.Allowed = nil
	return &next
}

// admittedByHookCall takes the server through the failed scan, then the allow
// rule, and admits it as the managed hook call does: the call finds the
// failed admission and the standing rule and queues the admission.
func (f *allowRemovalFixture) admittedByHookCall() {
	f.t.Helper()
	f.server = config.MCPServerEntry{Name: "v2probe", URL: "http://127.0.0.1:19555/mcp", Connector: "claudecode", Home: "/home/u1"}
	f.w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return []config.MCPServerEntry{f.server}, nil })
	f.w.AdmitAddedMCPServers([]string{f.server.Name})
	f.admitQueued()
	if status := f.status(); !status.Failed || !f.blocked() {
		f.t.Fatalf("after the failed scan: %+v blocked=%v, want a failed, blocked server", status, f.blocked())
	}
	f.cfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: f.server.Name, URL: f.server.URL, Reason: "reviewed"}}
	f.status() // the call: failed, and the rule queues its admission
	f.admitQueued()
	if status := f.status(); status.Failed || status.Pending || f.blocked() {
		f.t.Fatalf("after the allow rule: %+v blocked=%v, want an admitted server", status, f.blocked())
	}
}

func TestGAP0088RemovedAllowRuleRevokesAHookCallAdmissionAfterAReload(t *testing.T) {
	f := newAllowRemovalFixture(t)
	f.admittedByHookCall()
	f.reloaded(f.withoutAllow())
	f.w.firstCycleDone.Store(true)
	if status := f.status(); !status.Pending && !status.Failed {
		t.Fatalf("the call after the reload without the rule: %+v, want pending or failed, not the old allow", status)
	}
	f.admitQueued()
	if status := f.status(); !status.Failed || !f.blocked() {
		t.Fatalf("after the admission that followed: %+v blocked=%v, want the failed scan to block it again", status, f.blocked())
	}
}

func TestGAP0088RemovedAllowRuleRevokesAHookCallAdmissionAfterARestart(t *testing.T) {
	f := newAllowRemovalFixture(t)
	f.admittedByHookCall()
	f.reloaded(f.withoutAllow())
	// A restarted gateway: the first cycle has not run yet.
	if status := f.status(); !status.Pending && !status.Failed {
		t.Fatalf("the first call after the restart: %+v, want pending or failed, not the old allow", status)
	}
	f.w.runRescanCycle(context.Background())
	f.admitQueued()
	if status := f.status(); !status.Failed || !f.blocked() {
		t.Fatalf("after the first cycle: %+v blocked=%v, want the failed scan to block it again", status, f.blocked())
	}
}

func TestGAP0088RemovedAllowRuleBlocksOnTheRescanOfAReloadedWatcher(t *testing.T) {
	f := newAllowRemovalFixture(t)
	f.admittedByHookCall()
	f.reloaded(f.withoutAllow())
	f.w.firstCycleDone.Store(true)
	f.w.runRescanCycle(context.Background())
	f.w.runRescanCycle(context.Background())
	if status := f.status(); !status.Failed || !f.blocked() {
		t.Fatalf("after the rescans: %+v blocked=%v, want the failed scan to block it again", status, f.blocked())
	}
}

// The rule is removed before any rescan cycle ran after the allow: the
// admission is still the rule's.
func TestGAP0088RuleRemovedBeforeAnyCycleRevokesTheAdmission(t *testing.T) {
	f := newAllowRemovalFixture(t)
	f.admittedByHookCall()
	f.cfg.AssetPolicy.MCP.Allowed = nil
	f.w.runRescanCycle(context.Background())
	f.admitQueued()
	if status := f.status(); !status.Failed || !f.blocked() {
		t.Fatalf("after the rule was removed: %+v blocked=%v, want the failed scan to block it again", status, f.blocked())
	}
}
