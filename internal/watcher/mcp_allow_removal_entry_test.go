// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"fmt"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// The agent can keep its connection to an MCP server after it removes the
// entry from its config. An administrator who then takes back the allow the
// server was admitted by (or turns scan_on_install back on) revokes that
// admission for the live connection too: the next call is not decided by
// the old allow just because the config no longer lists the server
// (GAP-0920). Servers the policy never admitted without a scan, and servers
// whose allow stands, are untouched.
type removableEntryFixture struct {
	*allowRemovalFixture
	listed bool
}

func newRemovableEntryFixture(t *testing.T) *removableEntryFixture {
	t.Helper()
	f := &removableEntryFixture{allowRemovalFixture: newAllowRemovalFixture(t), listed: true}
	f.w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) {
		if !f.listed {
			return nil, nil
		}
		return []config.MCPServerEntry{f.server}, nil
	})
	f.w.firstCycleDone.Store(true)
	return f
}

func (f *removableEntryFixture) removeEntry() {
	f.t.Helper()
	f.listed = false
	// The agent config is read on the next call, as the hook does.
	if status := f.status(); status.Pending || status.Failed {
		f.t.Fatalf("a removed entry with its allow standing: %+v, want no admission state", status)
	}
}

func TestRemovedAgentEntryStillRevokesAnUnscannedAdmissionOfTheLiveConnection(t *testing.T) {
	for name, revoke := range map[string]func(*removableEntryFixture){
		"allow rule removed": func(f *removableEntryFixture) { f.cfg.AssetPolicy.MCP.Allowed = nil },
		"allow rule moved to another server": func(f *removableEntryFixture) {
			f.cfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: "other", URL: "https://other.example.test/mcp"}}
		},
		"allow rule moved to another endpoint": func(f *removableEntryFixture) {
			f.cfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: f.server.Name, URL: "https://other.example.test/mcp"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newRemovableEntryFixture(t)
			f.admittedByAllowRule()
			f.removeEntry()
			revoke(f)
			status := f.status()
			if !status.Failed || status.Name != f.server.Name || status.ScanIssue != MCPScanIssueAddress {
				t.Fatalf("the call after the allow was revoked: %+v, want the failed admission of %q with the address cause", status, f.server.Name)
			}
		})
	}
}

func TestRemovedAgentEntryStillRevokesAdmissionWithoutAScanWhenTheScanSettingIsBackOn(t *testing.T) {
	f := newRemovableEntryFixture(t)
	off := false
	f.cfg.Admission.MCP.ScanOnInstall = &off
	f.w.AdmitAddedMCPServers([]string{f.server.Name})
	f.admitQueued()
	f.removeEntry()
	f.cfg.Admission.MCP.ScanOnInstall = nil
	if status := f.status(); !status.Failed {
		t.Fatalf("after scan_on_install came back on: %+v, want the failed admission", status)
	}
}

// Benign twins.
func TestRemovedAgentEntryKeepsAnUnscannedAdmissionWhileItsAllowStands(t *testing.T) {
	f := newRemovableEntryFixture(t)
	f.admittedByAllowRule()
	f.removeEntry()
	for range 3 {
		if status := f.status(); status.Pending || status.Failed {
			t.Fatalf("with the URL-pinned allow standing: %+v, want the removed server left alone", status)
		}
	}
}

func TestRemovedAgentEntryOfAScannedServerIsLeftAlone(t *testing.T) {
	f := newRemovableEntryFixture(t)
	f.w.scannerFactory = func(InstallEvent) scanner.Scanner { return &countingScanner{name: "mcp-scanner"} }
	f.server.URL = "https://mcp.example.test/mcp"
	f.w.AdmitAddedMCPServers([]string{f.server.Name})
	f.admitQueued()
	f.removeEntry()
	f.cfg.AssetPolicy.MCP.Allowed = nil
	if status := f.status(); status.Pending || status.Failed {
		t.Fatalf("a scanned server whose entry was removed: %+v, want no admission state", status)
	}
}

func TestNeverSeenMCPServerHasNoAdmissionState(t *testing.T) {
	f := newRemovableEntryFixture(t)
	f.admittedByAllowRule()
	f.cfg.AssetPolicy.MCP.Allowed = nil
	f.removeEntryWithoutCheck()
	status := f.w.MCPAdmissionStatus(MCPAdmissionQuery{Connector: f.server.Connector, Server: "never-seen", Home: f.server.Home})
	if status.Pending || status.Failed {
		t.Fatalf("a name no listing had: %+v, want no admission state", status)
	}
}

func (f *removableEntryFixture) removeEntryWithoutCheck() { f.listed = false; f.status() }

func TestRestoredAgentEntryIsJudgedAsAListedServerAgain(t *testing.T) {
	f := newRemovableEntryFixture(t)
	f.admittedByAllowRule()
	f.removeEntry()
	f.cfg.AssetPolicy.MCP.Allowed = nil
	if status := f.status(); !status.Failed {
		t.Fatalf("revoked and removed: %+v, want failed", status)
	}
	f.listed = true
	if status := f.status(); !status.Pending {
		t.Fatalf("the entry is back: %+v, want the listed server pending its admission", status)
	}
	f.w.mcpAdmissionMu.RLock()
	held := len(f.w.mcpAdmissionDeparted)
	f.w.mcpAdmissionMu.RUnlock()
	if held != 0 {
		t.Fatalf("%d departed servers held after the entry was listed again, want none", held)
	}
}

func TestDepartedMCPServersAreBounded(t *testing.T) {
	w := &InstallWatcher{}
	var prev []mcpKnownDefinition
	for i := 0; i < mcpDepartedMax+40; i++ {
		server := config.MCPServerEntry{Name: fmt.Sprintf("s%d", i), Connector: "codex"}
		prev = append(prev, mcpKnownDefinition{server: server, path: MCPEventPath(server)})
	}
	w.mcpAdmissionMu.Lock()
	w.rememberDepartedMCP(prev, nil)
	held := len(w.mcpAdmissionDeparted)
	w.mcpAdmissionMu.Unlock()
	if held != mcpDepartedMax {
		t.Fatalf("held %d departed servers, want the bound %d", held, mcpDepartedMax)
	}
}
