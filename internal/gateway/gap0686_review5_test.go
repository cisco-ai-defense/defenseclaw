// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0686 review 5: a project definition that does not fit the hook fact
// reaches the gateway as a name, a digest and the pins of its endpoint. A deny
// pinned to where the server points is checked against the pins: one that may
// match refuses the call (every mode), one pinned to another endpoint, command,
// arguments or transport does not, and a claim from a hook that took no pins
// cannot rule a rule out.
func TestGAP0686EndpointDenyIsCheckedAgainstTheClaimPins(t *testing.T) {
	longURL := "https://ordinary.example.invalid/mcp?key=" + strings.Repeat("a", 1100)
	args := make([]string, 40)
	for i := range args {
		args[i] = fmt.Sprintf("--flag%d", i)
	}
	byURL := config.MCPServerEntry{Name: "notes", URL: longURL}
	byCommand := config.MCPServerEntry{Name: "notes", Command: "/opt/tools/node", Args: args}
	for _, tc := range []struct {
		name  string
		entry config.MCPServerEntry
		rule  config.AssetPolicyRule
		block bool
		strip bool
	}{
		{"deny of another URL", byURL, config.AssetPolicyRule{Name: "notes", URL: "https://denied.example.invalid/mcp"}, false, false},
		{"deny of the same URL", byURL, config.AssetPolicyRule{Name: "notes", URL: longURL}, true, false},
		{"deny of the same URL, spelled with spaces", byURL, config.AssetPolicyRule{Name: "notes", URL: " " + longURL + " "}, true, false},
		{"deny of the same URL, no name", byURL, config.AssetPolicyRule{URL: longURL}, true, false},
		{"deny of another URL, any name", byURL, config.AssetPolicyRule{URL: "https://denied.example.invalid/mcp"}, false, false},
		{"deny of a command on a URL server", byURL, config.AssetPolicyRule{Name: "notes", Command: "node"}, false, false},
		{"deny of the http transport", byURL, config.AssetPolicyRule{Name: "notes", Transport: "streamable-http"}, true, false},
		{"deny of the stdio transport on a URL server", byURL, config.AssetPolicyRule{Name: "notes", Transport: "stdio"}, false, false},
		{"deny of the command", byCommand, config.AssetPolicyRule{Name: "notes", Command: "node"}, true, false},
		{"deny of another command", byCommand, config.AssetPolicyRule{Name: "notes", Command: "python"}, false, false},
		{"deny of the command and its first arguments", byCommand, config.AssetPolicyRule{Name: "notes", Command: "node", ArgsPrefix: args[:3]}, true, false},
		{"deny of the command and other arguments", byCommand, config.AssetPolicyRule{Name: "notes", Command: "node", ArgsPrefix: []string{"--other"}}, false, false},
		{"deny of the command and more arguments than it has", byCommand, config.AssetPolicyRule{Name: "notes", Command: "node", ArgsPrefix: make([]string, 41)}, false, false},
		{"deny of a URL on a command server", byCommand, config.AssetPolicyRule{Name: "notes", URL: longURL}, false, false},
		{"deny of another URL, claim without pins", byURL, config.AssetPolicyRule{Name: "notes", URL: "https://denied.example.invalid/mcp"}, true, true},
	} {
		for _, mode := range []string{"policy off", "observe"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				home := t.TempDir()
				cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
				if mode == "observe" {
					cfg.AssetPolicy.Enabled = true
					cfg.AssetPolicy.Mode = config.AssetPolicyModeObserve
				}
				cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{tc.rule}
				api := &APIServer{scannerCfg: cfg}
				gap0686Publish(api, cfg)
				claim := gap0686Claim(tc.entry, false)
				if tc.strip {
					// A hook from before the pins: the claim as the earlier codec left it.
					claim.URL, claim.Command, claim.Args = "", "", nil
				}
				decision, matched := gap0686Hook(t, api, home, "PreToolUse", claim)
				if blocked := matched && decision.Action == "block"; blocked != tc.block {
					t.Fatalf("rule %+v: blocked=%v (matched=%v decision=%+v), want blocked=%v", tc.rule, blocked, matched, decision, tc.block)
				}
			})
		}
	}
}
