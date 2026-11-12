// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func TestLegacyIPv4HostReadsTheShorthandsResolversRead(t *testing.T) {
	for host, want := range map[string]string{
		"127.1": "127.0.0.1", "0": "0.0.0.0", "2130706433": "127.0.0.1", "0x7f000001": "127.0.0.1",
		"0X7F000001": "127.0.0.1", "0177.0.0.1": "127.0.0.1", "127.0.1": "127.0.0.1", "10.1": "10.0.0.1",
		"0xa9.0xfe.0xa9.0xfe": "169.254.169.254", "127.0.0.1": "127.0.0.1",
	} {
		got, ok := LegacyIPv4Host(host)
		if !ok || got.String() != want {
			t.Errorf("LegacyIPv4Host(%q) = %v, %v, want %s", host, got, ok, want)
		}
	}
	for _, host := range []string{"", "localhost", "example.test", "256.1.1.1", "1.2.3.4.5", "0x", "08", "1e100", "-1", "+1", "1..2", "4294967296", "1.16777216", "0x1_0"} {
		if got, ok := LegacyIPv4Host(host); ok {
			t.Errorf("LegacyIPv4Host(%q) = %v, want not an address", host, got)
		}
	}
}

func TestCanonicalMCPURLNamesTheAddressNotItsSpelling(t *testing.T) {
	const canonical = "http://127.0.0.1:18795/mcp?x=1"
	for _, raw := range []string{
		canonical, " " + canonical + " ", "HTTP://127.1:18795/mcp?x=1", "http://0x7f000001:18795/mcp?x=1",
		"http://2130706433:18795/mcp?x=1", "http://0177.0.0.1:18795/mcp?x=1", "http://[::ffff:127.0.0.1]:18795/mcp?x=1",
	} {
		if got := CanonicalMCPURL(raw); got != canonical {
			t.Errorf("CanonicalMCPURL(%q) = %q, want %q", raw, got, canonical)
		}
	}
	if got, want := CanonicalMCPURL("http://[0:0:0:0:0:0:0:1]:80/a"), "http://[::1]:80/a"; got != want {
		t.Errorf("IPv6 spelling = %q, want %q", got, want)
	}
	if got, want := CanonicalMCPURL("https://MCP.Example.test/Path"), "https://mcp.example.test/Path"; got != want {
		t.Errorf("name spelling = %q, want %q", got, want)
	}
	// Other endpoints, and anything that cannot be read as a URL, stay as written.
	for _, raw := range []string{"http://127.0.0.1:18796/mcp?x=1", "http://user:pw@127.1/mcp", "not a url", "%zz", "stdio:server", ""} {
		if got := CanonicalMCPURL(raw); got == canonical {
			t.Errorf("CanonicalMCPURL(%q) = %q, want a different endpoint", raw, got)
		}
	}
	if got, want := CanonicalMCPURL("http://user:pw@127.1/mcp"), "http://user:pw@127.1/mcp"; got != want {
		t.Errorf("URL with credentials = %q, want it as written", got)
	}
}

// An exact allow of an address admits the same endpoint written with a
// shorthand, in either direction, and never another endpoint. Secure Client keeps
// the exact text.
func TestMCPURLRuleMatchesTheEndpointInAnySpelling(t *testing.T) {
	cfg := func(secureClient bool, ruleURL string) *Config {
		c := &Config{AssetPolicy: DefaultAssetPolicy()}
		if secureClient {
			c.DeploymentMode = "managed_enterprise"
			c.Enterprise = EnterpriseConfig{Profile: "secure_client"}
		}
		c.AssetPolicy.MCP.Allowed = []AssetPolicyRule{{Name: "vgr", URL: ruleURL}}
		return c
	}
	decide := func(c *Config, url string) string {
		verdict, _ := c.AssetListDecision(AssetPolicyInput{TargetType: "mcp", Name: "vgr", URL: url})
		return verdict
	}
	for _, tc := range []struct {
		rule, server string
		want         string
	}{
		{"http://127.0.0.1:28772/mcp", "http://127.0.0.1:28772/mcp", AssetListAllow},
		{"http://127.0.0.1:28772/mcp", "http://127.1:28772/mcp", AssetListAllow},
		{"http://127.0.0.1:28772/mcp", "http://2130706433:28772/mcp", AssetListAllow},
		{"http://127.0.0.1:28772/mcp", "http://0x7f000001:28772/mcp", AssetListAllow},
		{"http://127.0.0.1:28772/mcp", "http://0177.0.0.1:28772/mcp", AssetListAllow},
		{"http://0.0.0.0:28772/mcp", "http://0:28772/mcp", AssetListAllow},
		{"http://0177.0.0.1:28772/mcp", "http://127.0.0.1:28772/mcp", AssetListAllow},
		{"http://127.1:28772/mcp", "http://127.1:28772/mcp", AssetListAllow},
		{"http://127.0.0.1:28773/mcp", "http://127.1:28772/mcp", ""},
		{"http://127.0.0.1:28772/other", "http://127.1:28772/mcp", ""},
		{"https://127.0.0.1:28772/mcp", "http://127.1:28772/mcp", ""},
		{"http://127.0.0.2:28772/mcp", "http://127.1:28772/mcp", ""},
	} {
		if got := decide(cfg(false, tc.rule), tc.server); got != tc.want {
			t.Errorf("rule %q, server %q: %q, want %q", tc.rule, tc.server, got, tc.want)
		}
	}
	if got := decide(cfg(true, "http://127.0.0.1:28772/mcp"), "http://127.1:28772/mcp"); got != "" {
		t.Errorf("Secure Client matched a shorthand: %q, want the exact text only", got)
	}
	if got := decide(cfg(true, "http://127.1:28772/mcp"), "http://127.1:28772/mcp"); got != AssetListAllow {
		t.Errorf("Secure Client lost its exact match: %q", got)
	}
}
