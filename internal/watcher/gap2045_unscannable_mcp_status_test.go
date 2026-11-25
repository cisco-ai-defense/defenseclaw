// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-2045 (GitHub #1452, GAS GAP-0091): an MCP server whose URL the scanner
// refuses from its text (a loopback or private address) can never be scanned,
// yet its first call was told "still scanning, retry in about a minute" and
// only the second call named the cause. The status of such a server is the
// failed one with its cause from the first call. A URL the scanner dials, and
// a refused URL that admission decides before any scan (scan_on_install
// false), keep the pending path.
func TestGAP2045UnscannableMCPURLIsFailedOnItsFirstCall(t *testing.T) {
	off := false
	for _, tc := range []struct {
		name, url string
		noScan    bool
		failed    bool
	}{
		{name: "loopback address", url: "http://127.0.0.1:18795/mcp", failed: true},
		{name: "private address", url: "http://10.1.2.3/mcp", failed: true},
		{name: "loopback alias", url: "http://localhost:8080/mcp", failed: true},
		{name: "public host", url: "https://mcp.example.test/mcp"},
		{name: "loopback, scan_on_install false", url: "http://127.0.0.1:18795/mcp", noScan: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, store, logger, _ := setupTestEnv(t)
			cfg.Gateway.Watcher.MCP.TakeAction = true
			if tc.noScan {
				cfg.Admission.MCP.ScanOnInstall = &off
			}
			server := config.MCPServerEntry{Name: "loopsrv", URL: tc.url, Connector: "claudecode", Home: "/home/eng1"}
			w := New(cfg, nil, nil, store, logger, nil, nil)
			w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return []config.MCPServerEntry{server}, nil })
			w.firstCycleDone.Store(true)
			status := w.MCPAdmissionStatus(MCPAdmissionQuery{Connector: "claudecode", Server: "loopsrv", Home: "/home/eng1"})
			if tc.failed {
				if !status.Failed || status.Pending || status.Name != "loopsrv" || status.ScanIssue != MCPScanIssueAddress {
					t.Fatalf("first call status %+v, want failed with the address cause, not still scanning", status)
				}
				return
			}
			if status.Failed {
				t.Fatalf("first call status %+v, want not failed", status)
			}
		})
	}
}
