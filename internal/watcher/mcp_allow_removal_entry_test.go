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
	// extra are other entries the agent config lists.
	extra []config.MCPServerEntry
}

func newRemovableEntryFixture(t *testing.T) *removableEntryFixture {
	t.Helper()
	f := &removableEntryFixture{allowRemovalFixture: newAllowRemovalFixture(t), listed: true}
	f.w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) {
		servers := append([]config.MCPServerEntry(nil), f.extra...)
		if f.listed {
			servers = append(servers, f.server)
		}
		return servers, nil
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

func ordinaryMCPEntries(prefix string, n int, f *removableEntryFixture) []config.MCPServerEntry {
	entries := make([]config.MCPServerEntry, 0, n)
	for i := 0; i < n; i++ {
		entries = append(entries, config.MCPServerEntry{Name: fmt.Sprintf("%s%d", prefix, i),
			URL: fmt.Sprintf("https://ordinary%d.example.test/mcp", i), Connector: f.server.Connector, Home: f.server.Home})
	}
	return entries
}

// Entries the agent adds and removes over time are not admissions anyone
// revoked: however many there are, they cannot push the revoked live
// connection out of the departed servers.
func TestOrdinaryRemovedEntriesDoNotDropARevokedLiveAdmission(t *testing.T) {
	f := newRemovableEntryFixture(t)
	f.admittedByAllowRule()
	f.removeEntry()
	f.cfg.AssetPolicy.MCP.Allowed = nil
	if status := f.status(); !status.Failed {
		t.Fatalf("revoked and removed: %+v, want failed", status)
	}
	for batch := 0; batch < 3; batch++ {
		f.extra = ordinaryMCPEntries(fmt.Sprintf("b%d-", batch), mcpDepartedMax, f)
		f.status()
		f.extra = nil
		if status := f.status(); !status.Failed || status.Name != f.server.Name {
			t.Fatalf("after %d batches of removed ordinary entries: %+v, want the failed admission of %q", batch+1, status, f.server.Name)
		}
	}
	f.w.mcpAdmissionMu.RLock()
	held, lost := len(f.w.mcpAdmissionDeparted), len(f.w.mcpAdmissionLost)
	f.w.mcpAdmissionMu.RUnlock()
	if held != 1 || lost != 0 {
		t.Fatalf("held %d departed servers (lost=%v) after ordinary churn, want only the revoked one", held, lost)
	}
}

// Benign twin: the same churn with the allow standing leaves every call alone.
func TestOrdinaryRemovedEntriesLeaveAStandingAllowAlone(t *testing.T) {
	f := newRemovableEntryFixture(t)
	f.admittedByAllowRule()
	f.removeEntry()
	f.extra = ordinaryMCPEntries("c-", mcpDepartedMax+10, f)
	f.status()
	f.extra = nil
	if status := f.status(); status.Pending || status.Failed {
		t.Fatalf("with the allow standing after churn: %+v, want no admission state", status)
	}
}

// A departed server that does not fit is not allowed by default: a call that
// names no listed and no held server fails like any unscanned admission, a
// call to a listed or held server is decided as before.
func TestDepartedMCPServersBeyondTheBoundFailTheCallsNoServerStandsFor(t *testing.T) {
	f := newRemovableEntryFixture(t)
	f.admittedByAllowRule()
	var prev []mcpKnownDefinition
	for i := 0; i < mcpDepartedMax+1; i++ {
		server := config.MCPServerEntry{Name: fmt.Sprintf("held%d", i), Connector: f.server.Connector, Home: f.server.Home}
		prev = append(prev, mcpKnownDefinition{server: server, path: MCPEventPath(server)})
	}
	f.w.mcpAdmissionMu.Lock()
	f.w.rememberDepartedMCP(prev, nil, nil)
	held, lost := len(f.w.mcpAdmissionDeparted), len(f.w.mcpAdmissionLost)
	f.w.mcpAdmissionMu.Unlock()
	if held != mcpDepartedMax || lost != 1 {
		t.Fatalf("held %d departed servers (%d lost scopes), want the bound %d and the overflow noted once", held, lost, mcpDepartedMax)
	}
	unknown := f.w.MCPAdmissionStatus(MCPAdmissionQuery{Connector: f.server.Connector, Server: "never-seen", Home: f.server.Home})
	if !unknown.Failed || unknown.Name != "never-seen" {
		t.Fatalf("a name no listing has, after overflow: %+v, want the failed admission", unknown)
	}
	if status := f.status(); status.Pending || status.Failed {
		t.Fatalf("the listed server whose allow stands, after overflow: %+v, want no admission state", status)
	}
}

func TestSettledDepartedMCPServersAreNotHeld(t *testing.T) {
	f := newRemovableEntryFixture(t)
	f.extra = ordinaryMCPEntries("s", 3, f)
	f.status()
	f.extra = nil
	f.status()
	f.w.mcpAdmissionMu.RLock()
	held := len(f.w.mcpAdmissionDeparted)
	f.w.mcpAdmissionMu.RUnlock()
	if held != 0 {
		t.Fatalf("%d departed servers held for entries nothing admitted without a scan, want none", held)
	}
}

// The agent can edit an entry and then drop it while the live connection
// keeps the first definition. The admission the policy gave that definition
// stays revocable through both (GAP-0920).
func TestEditedThenRemovedAgentEntryStillRevokesAnUnscannedAdmissionOfTheLiveConnection(t *testing.T) {
	f := newRemovableEntryFixture(t)
	original := f.server
	f.admittedByAllowRule()
	f.server.URL = "https://replacement.example.test/mcp"
	if status := f.status(); !status.Pending {
		t.Fatalf("the edited definition: %+v, want it pending its own admission", status)
	}
	f.listed = false
	f.status()
	f.cfg.AssetPolicy.MCP.Allowed = nil
	status := f.w.MCPAdmissionStatus(MCPAdmissionQuery{Connector: original.Connector, Server: original.Name, Home: original.Home})
	if !status.Failed || status.Name != original.Name || status.ScanIssue != MCPScanIssueAddress {
		t.Fatalf("the call after edit, removal and revocation: %+v, want the failed admission of %q", status, original.Name)
	}
}

// Benign twins: the same edit and removal with the allow standing, and an
// edit back to the first definition, leave every call alone.
func TestEditedThenRemovedAgentEntryLeavesAStandingAllowAlone(t *testing.T) {
	f := newRemovableEntryFixture(t)
	f.admittedByAllowRule()
	f.server.URL = "https://replacement.example.test/mcp"
	f.status()
	f.removeEntry()
	if status := f.status(); status.Pending || status.Failed {
		t.Fatalf("with the allow standing: %+v, want no admission state", status)
	}
}

// The agent can keep its first connection after the entry is edited. A
// replacement that stays listed and is admitted, by a new allow pinned to it
// or by a clean scan, decides for itself and does not stand for the earlier
// unscanned definition once the allow of that one is revoked.
func TestListedReplacementDoesNotClearTheRevokedAdmissionOfTheEarlierConnection(t *testing.T) {
	for _, mode := range []string{"a new allow pinned to the replacement", "a clean scan of the replacement"} {
		t.Run(mode, func(t *testing.T) {
			f := newRemovableEntryFixture(t)
			original := f.server
			f.admittedByAllowRule()
			f.server.URL = "https://replacement.example.test/mcp"
			if status := f.status(); !status.Pending {
				t.Fatalf("the edited definition: %+v, want it pending its own admission", status)
			}
			if mode == "a clean scan of the replacement" {
				f.w.scannerFactory = func(InstallEvent) scanner.Scanner { return &countingScanner{name: "mcp-scanner"} }
				f.admitQueued()
				if status := f.status(); status.Pending || status.Failed || status.Unavailable {
					t.Fatalf("the scanned replacement with the first allow standing: %+v, want no admission state", status)
				}
				f.cfg.AssetPolicy.MCP.Allowed = nil
			} else {
				f.cfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: f.server.Name, URL: f.server.URL, Reason: "replacement reviewed"}}
				f.w.runRescanCycle(context.Background())
			}
			f.w.mcpAdmissionMu.RLock()
			held := len(f.w.mcpAdmissionDeparted)
			f.w.mcpAdmissionMu.RUnlock()
			if held != 1 {
				t.Fatalf("%d departed definitions held, want the unscanned first one", held)
			}
			status := f.w.MCPAdmissionStatus(MCPAdmissionQuery{Connector: original.Connector, Server: original.Name, Home: original.Home})
			if !status.Failed || status.Name != original.Name || status.ScanIssue != MCPScanIssueAddress {
				t.Fatalf("the call with the replacement listed and the first allow revoked: %+v, want the failed admission of %q", status, original.Name)
			}
		})
	}
}

// Benign twin: with the allow of the first definition standing, the listed
// and admitted replacement leaves every call alone.
func TestListedReplacementLeavesAStandingAllowOfTheEarlierConnectionAlone(t *testing.T) {
	f := newRemovableEntryFixture(t)
	original := f.server
	f.admittedByAllowRule()
	f.server.URL = "https://replacement.example.test/mcp"
	f.status()
	f.cfg.AssetPolicy.MCP.Allowed = append(f.cfg.AssetPolicy.MCP.Allowed,
		config.AssetPolicyRule{Name: f.server.Name, URL: f.server.URL, Reason: "replacement reviewed"})
	f.w.runRescanCycle(context.Background())
	if status := f.w.MCPAdmissionStatus(MCPAdmissionQuery{Connector: original.Connector, Server: original.Name, Home: original.Home}); status.Pending || status.Failed {
		t.Fatalf("with both allows standing: %+v, want no admission state", status)
	}
}

func TestEditedAgentEntryRestoredIsJudgedAsListedAgain(t *testing.T) {
	f := newRemovableEntryFixture(t)
	f.admittedByAllowRule()
	original := f.server
	f.server.URL = "https://replacement.example.test/mcp"
	f.status()
	f.w.mcpAdmissionMu.RLock()
	held := len(f.w.mcpAdmissionDeparted)
	f.w.mcpAdmissionMu.RUnlock()
	if held != 1 {
		t.Fatalf("%d departed definitions after the edit, want the first one held", held)
	}
	f.server = original
	f.status()
	f.w.mcpAdmissionMu.RLock()
	held = len(f.w.mcpAdmissionDeparted)
	f.w.mcpAdmissionMu.RUnlock()
	if held != 0 {
		t.Fatalf("%d departed definitions after the entry was restored, want none", held)
	}
}

// Overflow of the departed servers of one account describes only the calls
// of that account and connector, and ends when the definitions list again.
func TestDepartedMCPOverflowFailsOnlyTheAccountItCameFrom(t *testing.T) {
	f := newRemovableEntryFixture(t)
	f.admittedByAllowRule()
	f.extra = make([]config.MCPServerEntry, mcpDepartedMax+1)
	for i := range f.extra {
		server := config.MCPServerEntry{Name: fmt.Sprintf("held-%d", i), URL: "https://held.example.test/mcp",
			Connector: f.server.Connector, Home: f.server.Home}
		f.extra[i] = server
		hash, err := mcpDefinitionHash(server)
		if err != nil {
			t.Fatal(err)
		}
		f.w.mcpAdmissionMu.Lock()
		if f.w.mcpOutcomes == nil {
			f.w.mcpOutcomes = map[string]mcpAdmissionOutcome{}
		}
		f.w.mcpOutcomes[MCPEventPath(server)] = mcpAdmissionOutcome{hash: hash, withoutScan: true}
		f.w.mcpAdmissionMu.Unlock()
	}
	listed := f.extra
	f.status()
	f.extra = nil
	f.status()
	query := func(connector, home string) MCPAdmissionStatus {
		return f.w.MCPAdmissionStatus(MCPAdmissionQuery{Connector: connector, Server: "never-seen", Home: home})
	}
	if status := query(f.server.Connector, "/home/other"); status.Failed || status.Pending {
		t.Fatalf("another account after the overflow: %+v, want no admission state", status)
	}
	if status := query("claudecode", f.server.Home); status.Failed || status.Pending {
		t.Fatalf("another connector after the overflow: %+v, want no admission state", status)
	}
	if status := query(f.server.Connector, f.server.Home); !status.Failed {
		t.Fatalf("the account the overflow came from: %+v, want the failed admission", status)
	}
	f.extra = listed
	f.status()
	if status := query(f.server.Connector, f.server.Home); status.Failed || status.Pending {
		t.Fatalf("after the lost definitions listed again: %+v, want no admission state", status)
	}
	f.w.mcpAdmissionMu.RLock()
	scopes, keys := len(f.w.mcpAdmissionLost), f.w.mcpAdmissionLostKeys
	f.w.mcpAdmissionMu.RUnlock()
	if scopes != 0 || keys != 0 {
		t.Fatalf("%d lost scopes and %d lost definitions after they listed again, want none", scopes, keys)
	}
}
