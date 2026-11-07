// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A project server that does not fit the hook fact is checked against the pins
// of its endpoint. A deny that differs at any argument position, however deep,
// does not refuse an ordinary server (asset policy off or observe); the same
// deny with the server own argument there refuses it; and a rule that needs a
// source path, which the input of an MCP call never carries, does not refuse
// it either.
func TestProjectMCPDenyIsRuledOutAtAnyArgumentAndBySourcePath(t *testing.T) {
	args := make([]string, 40)
	for i := range args {
		args[i] = fmt.Sprintf("--arg-%d", i)
	}
	command := config.MCPServerEntry{Name: "notes", Command: "/opt/tools/node", Args: args}
	longURL := "https://ordinary.example.invalid/mcp?key=" + strings.Repeat("a", 1100)
	byURL := config.MCPServerEntry{Name: "notes", URL: longURL}
	withPrefix := func(at int, value string) []string {
		prefix := append([]string(nil), args[:at+1]...)
		prefix[at] = value
		return prefix
	}
	for _, tc := range []struct {
		name  string
		entry config.MCPServerEntry
		rule  config.AssetPolicyRule
		block bool
	}{
		{"another 33rd argument", command, config.AssetPolicyRule{Name: "notes", Command: "node", ArgsPrefix: withPrefix(32, "--other")}, false},
		{"the same 33rd argument", command, config.AssetPolicyRule{Name: "notes", Command: "node", ArgsPrefix: withPrefix(32, args[32])}, true},
		{"another last argument", command, config.AssetPolicyRule{Name: "notes", Command: "node", ArgsPrefix: withPrefix(39, "--other")}, false},
		{"the same last argument", command, config.AssetPolicyRule{Name: "notes", Command: "node", ArgsPrefix: withPrefix(39, args[39])}, true},
		{"unrelated source path", byURL, config.AssetPolicyRule{Name: "notes", URL: longURL, SourcePathContains: []string{"another-source"}}, false},
		{"the same URL", byURL, config.AssetPolicyRule{Name: "notes", URL: longURL}, true},
	} {
		for _, mode := range []string{"policy off", "observe"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
				if mode == "observe" {
					cfg.AssetPolicy.Enabled = true
					cfg.AssetPolicy.Mode = config.AssetPolicyModeObserve
				}
				cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{tc.rule}
				api := &APIServer{scannerCfg: cfg}
				gap0686Publish(api, cfg)
				decision, matched := gap0686Hook(t, api, t.TempDir(), "PreToolUse", gap0686Claim(tc.entry, false))
				if blocked := matched && decision.Action == "block"; blocked != tc.block {
					t.Fatalf("rule %+v: blocked=%v (matched=%v decision=%+v), want blocked=%v", tc.rule, blocked, matched, decision, tc.block)
				}
			})
		}
	}
}

// A deny prefix longer than the arguments a claim holds digests of cannot be
// ruled out, so it refuses; one that asks for more arguments than the server
// has does not.
func TestDeniedPrefixPastTheHeldDigestsMayMatch(t *testing.T) {
	args := make([]string, 2100)
	for i := range args {
		args[i] = fmt.Sprintf("--arg-%d", i)
	}
	facts, ok := assetfacts.Decode(assetfacts.Encode(assetfacts.Facts{MCP: &assetfacts.MCPServer{
		Name: "notes", Command: "node", Args: args, ProjectScope: true, Digest: strings.Repeat("ab", 32)}}))
	if !ok || facts.MCP == nil || facts.MCP.Pins == nil {
		t.Fatalf("no pins: %+v", facts.MCP)
	}
	may := func(prefix []string) bool {
		return deniedRulesMayPinClaim([]config.AssetPolicyRule{{Name: "notes", Command: "node", ArgsPrefix: prefix}}, "codex", "notes", facts.MCP.Pins)
	}
	if !may(args[:2050]) {
		t.Error("a prefix past the held digests was ruled out")
	}
	if may(append(append([]string(nil), args[:2]...), "--other")) {
		t.Error("a prefix that differs within the held digests was not ruled out")
	}
	if may(append(append([]string(nil), args...), "--more")) {
		t.Error("a prefix longer than the arguments the server has was not ruled out")
	}
}
