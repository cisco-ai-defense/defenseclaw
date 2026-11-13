// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"fmt"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// refusingScanner refuses every server as the MCP scanner refuses a loopback
// address: a refusal of the definition, not an unfinished scan.
type refusingScanner struct{ countingScanner }

func (s *refusingScanner) Scan(context.Context, string) (*scanner.ScanResult, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return nil, fmt.Errorf("%w: the MCP scanner does not connect to loopback, private, link-local or multicast addresses and http://127.0.0.1:19555/mcp is on 127.0.0.1, a loopback address, so the server was not scanned", scanner.ErrMCPScanRefused)
}

// newManagedAllowRemovalFixture is the gas-ux-r2 host: a standalone managed
// Linux gateway whose watcher lists the servers the hooks report.
func newManagedAllowRemovalFixture(t *testing.T) *allowRemovalFixture {
	t.Helper()
	f := newAllowRemovalFixture(t)
	f.cfg.DeploymentMode = "managed_enterprise"
	f.cfg.Enterprise.Profile = "standalone"
	f.cfg.Scanners.MCPScanner.UnverifiedServer = ""
	refusing := &refusingScanner{countingScanner{name: "mcp-scanner"}}
	f.w.scannerFactory = func(InstallEvent) scanner.Scanner { return refusing }
	f.server = config.MCPServerEntry{Name: "v2probe", URL: "http://127.0.0.1:19555/mcp", Transport: "http", Connector: "claudecode", Home: "/home/u1"}
	f.w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return []config.MCPServerEntry{f.server}, nil })
	return f
}

func (f *allowRemovalFixture) managedAdmittedThenRuleRemoved(cycleWithRule bool) {
	f.t.Helper()
	f.w.AdmitAddedMCPServers([]string{f.server.Name})
	f.admitQueued()
	if status := f.status(); !status.Failed || !f.blocked() {
		f.t.Fatalf("after the refused scan: %+v blocked=%v, want a failed, blocked server", status, f.blocked())
	}
	f.cfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: f.server.Name, URL: f.server.URL}}
	f.status()
	f.admitQueued()
	if status := f.status(); status.Failed || status.Pending || f.blocked() {
		f.t.Fatalf("after the allow rule: %+v blocked=%v, want an admitted server", status, f.blocked())
	}
	if cycleWithRule {
		f.w.runRescanCycle(context.Background())
	}
	f.cfg.AssetPolicy.MCP.Allowed = nil
}

func TestGAP0088ManagedRemovedAllowRuleBlocksAtTheNextCall(t *testing.T) {
	for _, cycle := range []bool{false, true} {
		f := newManagedAllowRemovalFixture(t)
		f.managedAdmittedThenRuleRemoved(cycle)
		if status := f.status(); !status.Pending && !status.Failed {
			t.Fatalf("cycle=%v: the call after the rule was removed: %+v, want pending or failed", cycle, status)
		}
		f.admitQueued()
		for range 3 {
			f.w.runRescanCycle(context.Background())
			f.admitQueued()
		}
		if status := f.status(); !status.Failed || !f.blocked() {
			t.Fatalf("cycle=%v: after admission and rescans: %+v blocked=%v, want it blocked again", cycle, status, f.blocked())
		}
	}
}

func TestGAP0088ManagedRemovedAllowRuleBlocksAfterAReloadAndRescans(t *testing.T) {
	for _, cycle := range []bool{false, true} {
		f := newManagedAllowRemovalFixture(t)
		f.managedAdmittedThenRuleRemoved(cycle)
		scans := f.w.scannerFactory
		f.reloaded(f.withoutAllow())
		f.w.scannerFactory = scans
		for range 3 {
			f.w.runRescanCycle(context.Background())
			f.admitQueued()
		}
		f.w.firstCycleDone.Store(true)
		f.status()
		f.admitQueued()
		if status := f.status(); !status.Failed || !f.blocked() {
			t.Fatalf("cycle=%v: after the reload and rescans: %+v blocked=%v, want it blocked again", cycle, status, f.blocked())
		}
	}
}
