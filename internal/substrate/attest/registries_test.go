// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import "testing"

func TestNormalizeHost(t *testing.T) {
	ok := map[string]string{"Example.COM.": "example.com", "*.skills.example.org": "*.skills.example.org", "203.0.113.9": "203.0.113.9"}
	for in, want := range ok {
		if got, err := NormalizeHost(in); err != nil || got != want {
			t.Errorf("%q → %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "*", "a.*.com", "https://x.com", "x.com:443", "x.com/path", "user@x.com", "10.0.0.1", "127.0.0.1", "169.254.169.254", "::1", "bad_host.com", "nodots", "-x.com"} {
		if got, err := NormalizeHost(bad); err == nil {
			t.Errorf("%q accepted as %q", bad, got)
		}
	}
}

func TestAllowRules(t *testing.T) {
	r, err := AllowRules{MCPHosts: []string{"mcp.example.com", "MCP.example.com", "*.tools.example.com"},
		SkillRegistries: []string{"skills.example.com"}, PluginMarketplaces: []string{"skills.example.com", "plugins.example.com"}}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if len(r.MCPHosts) != 2 || len(r.RegistryHosts()) != 2 {
		t.Fatalf("rules: %+v %v", r, r.RegistryHosts())
	}
	if !r.AllowsMCPHost("mcp.example.com") || !r.AllowsMCPHost("a.tools.example.com") || r.AllowsMCPHost("evil.example.com") || r.AllowsMCPHost("tools.example.com.evil.net") {
		t.Fatal("host matching")
	}
	bad, err := AllowRules{MCPHosts: []string{"ok.example.com", "http://nope.example.com"}}.Normalize()
	if err == nil || len(bad.MCPHosts) != 1 {
		t.Fatalf("bad entry must be an error and left out: %+v %v", bad, err)
	}
}
