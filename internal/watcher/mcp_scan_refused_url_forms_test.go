// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// MCPScanRefused follows the scanner for every URL it refuses from the text
// of the definition, the loopback aliases, the metadata host and inline
// credentials included, so a managed gateway holds them like a loopback
// address (GAP-0925).
func TestMCPScanRefusedCoversEveryURLTheScannerRefusesFromItsText(t *testing.T) {
	for _, tc := range []struct {
		url     string
		refused bool
		issue   string
	}{
		{"http://127.0.0.1:18795/mcp", true, MCPScanIssueAddress},
		{"http://10.1.2.3/mcp", true, MCPScanIssueAddress},
		{"http://localhost/mcp", true, MCPScanIssueAddress},
		{"http://ip6-localhost:18795/mcp", true, MCPScanIssueAddress},
		{"http://ip6-loopback:18795/mcp", true, MCPScanIssueAddress},
		{"http://metadata.google.internal/mcp", true, MCPScanIssueAddress},
		{"https://user:pass@mcp.example.test/mcp", true, ""},
		{"https://mcp.example.test/mcp", false, ""},
		{"https://93.184.216.34/mcp", false, ""},
		{"", false, ""},
	} {
		entry := config.MCPServerEntry{Name: "vgr", URL: tc.url}
		if got := MCPScanRefused(entry); got != tc.refused {
			t.Errorf("MCPScanRefused(%q) = %v, want %v", tc.url, got, tc.refused)
		}
		if got := mcpScanIssue(entry); got != tc.issue {
			t.Errorf("mcpScanIssue(%q) = %q, want %q", tc.url, got, tc.issue)
		}
	}
}
