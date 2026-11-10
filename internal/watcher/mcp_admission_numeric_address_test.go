// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

var numericLoopbackSpellings = []struct{ host, canonical string }{
	{"127.0.0.1", "127.0.0.1"}, {"127.1", "127.0.0.1"}, {"0", "0.0.0.0"}, {"2130706433", "127.0.0.1"},
	{"0x7f000001", "127.0.0.1"}, {"0177.0.0.1", "127.0.0.1"},
}

// A loopback address written as a shorthand is the address the scanner refuses
// from its text, so install admission fails it without a scan like the plain
// spelling, and an exact allow of the endpoint, written either way, admits it
// without one (GAP-1019).
func TestNumericLoopbackAddressInstallAdmission(t *testing.T) {
	for _, tc := range numericLoopbackSpellings {
		t.Run(tc.host, func(t *testing.T) {
			t.Run("canonical allow admits the alias", func(t *testing.T) {
				f := newAllowRemovalFixture(t)
				f.server.URL = "http://" + tc.host + ":28772/mcp"
				f.cfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: f.server.Name, URL: "http://" + tc.canonical + ":28772/mcp", Reason: "same local target"}}
				f.w.AdmitAddedMCPServers([]string{f.server.Name})
				f.admitQueued()
				if got := f.status(); got.Failed || got.Pending || f.blocked() || f.scans.calls != 0 {
					t.Fatalf("allow of the canonical address did not admit the alias: status=%+v blocked=%v scans=%d", got, f.blocked(), f.scans.calls)
				}
			})
			t.Run("alias allow admits the canonical address", func(t *testing.T) {
				f := newAllowRemovalFixture(t)
				f.server.URL = "http://" + tc.canonical + ":28772/mcp"
				f.cfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: f.server.Name, URL: "http://" + tc.host + ":28772/mcp", Reason: "same local target"}}
				f.w.AdmitAddedMCPServers([]string{f.server.Name})
				f.admitQueued()
				if got := f.status(); got.Failed || got.Pending || f.blocked() || f.scans.calls != 0 {
					t.Fatalf("allow of the alias did not admit the canonical address: status=%+v blocked=%v scans=%d", got, f.blocked(), f.scans.calls)
				}
			})
			t.Run("allow after a failed admission releases it", func(t *testing.T) {
				f := newAllowRemovalFixture(t)
				f.server.URL = "http://" + tc.host + ":28772/mcp"
				f.w.AdmitAddedMCPServers([]string{f.server.Name})
				f.admitQueued()
				if got := f.status(); !got.Failed || got.ScanIssue != MCPScanIssueAddress || !f.blocked() {
					t.Fatalf("no allow: status=%+v blocked=%v, want a failed admission for the address", got, f.blocked())
				}
				f.cfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: f.server.Name, URL: "http://" + tc.canonical + ":28772/mcp", Reason: "reviewed"}}
				f.status()
				f.admitQueued()
				if got := f.status(); got.Failed || got.Pending || f.blocked() {
					t.Fatalf("allow of the endpoint did not release the failed admission: status=%+v blocked=%v", got, f.blocked())
				}
			})
			t.Run("allow of another endpoint does not admit it", func(t *testing.T) {
				f := newAllowRemovalFixture(t)
				f.server.URL = "http://" + tc.host + ":28772/mcp"
				f.cfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: f.server.Name, URL: "http://127.0.0.1:28773/mcp", Reason: "another endpoint"}}
				f.w.AdmitAddedMCPServers([]string{f.server.Name})
				f.admitQueued()
				if got := f.status(); !got.Failed || !f.blocked() {
					t.Fatalf("allow of another port admitted the endpoint: status=%+v blocked=%v", got, f.blocked())
				}
			})
		})
	}
}

// A shorthand for an address the scanner refuses is refused whichever address it
// names; a name or number that is not an address is not.
func TestMCPScanRefusedReadsNumericAddressSpellings(t *testing.T) {
	for url, want := range map[string]bool{
		"http://127.1:1/mcp": true, "http://0/mcp": true, "http://2130706433/mcp": true, "http://0x7f000001/mcp": true,
		"http://0177.0.0.1/mcp": true, "http://10.1/mcp": true, "http://127.0.0.1/mcp": true,
		"https://mcp.example.test/mcp": false, "https://256.1.1.1/mcp": false, "https://93.184.216.34/mcp": false,
	} {
		if got := MCPScanRefused(config.MCPServerEntry{Name: "n", URL: url}); got != want {
			t.Errorf("MCPScanRefused(%q) = %v, want %v", url, got, want)
		}
		if got := mcpScanIssue(config.MCPServerEntry{Name: "n", URL: url}) == MCPScanIssueAddress; got != want {
			t.Errorf("mcpScanIssue(%q) names the address = %v, want %v", url, got, want)
		}
	}
}
