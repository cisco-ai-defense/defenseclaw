// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1277: an MCP URL whose host had no DNS answer was scanned as a refusal
// of the server's definition, so the gateway watcher blocked a server that mcp
// set had just added with a warning. No address means nothing was dialed: the
// scan did not finish. A host that resolves to a private address is still
// refused.
func TestMCPScanUnresolvedHostIsAScanThatDidNotFinish(t *testing.T) {
	t.Setenv("DEFENSECLAW_ALLOW_LOCAL_MCP_TARGETS", "")
	prior := mcpScanLookupIP
	t.Cleanup(func() { mcpScanLookupIP = prior })
	ms := NewMCPScannerFromLLM(config.MCPScannerConfig{Binary: "mcp-scanner"}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})

	mcpScanLookupIP = func(string) ([]net.IP, error) {
		return nil, &net.DNSError{Err: "no such host", Name: "t11-dns.invalid", IsNotFound: true}
	}
	_, err := ms.Scan(context.Background(), "https://t11-dns.invalid/mcp")
	if err == nil || MCPScanRefused(err) || errors.Is(err, ErrMCPScanRefused) {
		t.Fatalf("unresolved host: %v, want a scan that did not finish, not a refusal", err)
	}
	mcpScanLookupIP = func(string) ([]net.IP, error) {
		return nil, &net.DNSError{Err: "server misbehaving", Name: "mcp.example.test", IsTemporary: true}
	}
	if _, err := ms.Scan(context.Background(), "https://mcp.example.test/mcp"); err == nil || MCPScanRefused(err) {
		t.Fatalf("temporary DNS failure: %v, want a scan that did not finish", err)
	}

	mcpScanLookupIP = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("10.0.0.5")}, nil }
	if _, err := ms.Scan(context.Background(), "https://mcp.example.test/mcp"); !errors.Is(err, ErrMCPScanRefused) {
		t.Fatalf("private address: %v, want a refusal", err)
	}
}
