// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"errors"
	"net"
	"testing"
)

// MCPScanTargetRefusal is the one place that says which MCP URLs the scanner
// refuses from their text, and validateMCPScanTargetURL applies the same
// function, so the managed gateway holds exactly the refused definitions.
func TestMCPScanTargetRefusalIsWhatTheScanGuardRefusesFromText(t *testing.T) {
	t.Setenv("DEFENSECLAW_ALLOW_LOCAL_MCP_TARGETS", "")
	prior := mcpScanLookupIP
	t.Cleanup(func() { mcpScanLookupIP = prior })
	mcpScanLookupIP = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("93.184.216.34")}, nil }

	for _, tc := range []struct {
		target string
		want   MCPTargetRefusal
	}{
		{"http://127.0.0.1:18795/mcp", MCPTargetRefusalAddress},
		{"http://[::1]:18795/mcp", MCPTargetRefusalAddress},
		{"http://10.1.2.3/mcp", MCPTargetRefusalAddress},
		{"http://169.254.169.254/mcp", MCPTargetRefusalAddress},
		{"http://localhost/mcp", MCPTargetRefusalAddress},
		{"http://LocalHost:80/mcp", MCPTargetRefusalAddress},
		{"http://ip6-localhost:18795/mcp", MCPTargetRefusalAddress},
		{"http://ip6-loopback:18795/mcp", MCPTargetRefusalAddress},
		{"http://tools.localhost/mcp", MCPTargetRefusalAddress},
		{"http://metadata.google.internal/mcp", MCPTargetRefusalAddress},
		{"https://user:pass@mcp.example.test/mcp", MCPTargetRefusalCredentials},
		{"https://user@mcp.example.test/mcp", MCPTargetRefusalCredentials},
		{"https:///mcp", MCPTargetRefusalMalformed},
		{"http://bad host/mcp", MCPTargetRefusalMalformed},
		// Not refused from the text: a public literal, a name left to the
		// resolver, and a target that is not a URL.
		{"https://93.184.216.34/mcp", MCPTargetRefusalNone},
		{"https://mcp.example.test/mcp", MCPTargetRefusalNone},
		{"notes", MCPTargetRefusalNone},
		{"", MCPTargetRefusalNone},
	} {
		t.Run(tc.target, func(t *testing.T) {
			if got := MCPScanTargetRefusal(tc.target); got != tc.want {
				t.Fatalf("MCPScanTargetRefusal(%q) = %q, want %q", tc.target, got, tc.want)
			}
			if !mcpScanTargetLooksLikeURL(tc.target) {
				return
			}
			err := validateMCPScanTargetURL(tc.target)
			if refused := tc.want != MCPTargetRefusalNone; refused != (err != nil) {
				t.Fatalf("validateMCPScanTargetURL(%q) = %v, want an error: %v", tc.target, err, refused)
			}
			if errors.Is(err, errMCPScanTargetUnresolved) {
				t.Fatalf("%q is refused from its text, not left to the resolver: %v", tc.target, err)
			}
		})
	}
}

// A name that only the resolver can place is not refused from its text: the
// scan decides it.
func TestMCPScanTargetRefusalLeavesResolvedNamesToTheScan(t *testing.T) {
	t.Setenv("DEFENSECLAW_ALLOW_LOCAL_MCP_TARGETS", "")
	prior := mcpScanLookupIP
	t.Cleanup(func() { mcpScanLookupIP = prior })
	mcpScanLookupIP = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("10.0.0.7")}, nil }
	const target = "https://internal-mcp.example.test/mcp"
	if got := MCPScanTargetRefusal(target); got != MCPTargetRefusalNone {
		t.Fatalf("MCPScanTargetRefusal(%q) = %q, want none", target, got)
	}
	if err := validateMCPScanTargetURL(target); err == nil {
		t.Fatalf("validateMCPScanTargetURL(%q) accepted a name that resolves to a private address", target)
	}
}
