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

// A deny that differs only past the full digests a claim carries is still ruled
// out by the tail digest, and the same-argument twin still blocks. The
// differing argument is one whose first digest byte equals the protected
// argument first byte: a narrower digest would keep it as a possible match
// and block the ordinary server.
func TestProjectMCPDenyDifferingPastTheFullDigestsIsRuledOut(t *testing.T) {
	args := make([]string, 2050)
	for i := range args {
		args[i] = fmt.Sprintf("--arg-%d", i)
	}
	entry := config.MCPServerEntry{Name: "notes", Command: "/opt/tools/node", Args: args}
	for _, mode := range []string{"off", "observe"} {
		t.Run(mode, func(t *testing.T) {
			cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
			if mode == "observe" {
				cfg.AssetPolicy.Enabled = true
				cfg.AssetPolicy.Mode = config.AssetPolicyModeObserve
			}
			prefix := append([]string(nil), args[:2049]...)
			prefix[2048] = gap0686SameFirstByte(args[2048])
			cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{Name: "notes", Command: "node", ArgsPrefix: prefix}}
			api := &APIServer{scannerCfg: cfg}
			gap0686Publish(api, cfg)
			decision, matched := gap0686Hook(t, api, t.TempDir(), "PreToolUse", gap0686Claim(entry, false))
			if matched && decision.Action == "block" {
				t.Errorf("ordinary server blocked past pin bound: %+v", decision)
			}
			cfg.AssetPolicy.MCP.Denied[0].ArgsPrefix[2048] = args[2048]
			decision, matched = gap0686Hook(t, api, t.TempDir(), "PreToolUse", gap0686Claim(entry, false))
			if !matched || decision.Action != "block" {
				t.Errorf("protected twin allowed: matched=%v decision=%+v", matched, decision)
			}
		})
	}
}

// gap0686SameFirstByte is an argument other than value whose tail digest
// begins with the same byte as the tail digest of value.
func gap0686SameFirstByte(value string) string {
	want := assetfacts.PinTailDigest(value)[0]
	for i := 0; ; i++ {
		if other := fmt.Sprintf("--other-%d", i); other != value && assetfacts.PinTailDigest(other)[0] == want {
			return other
		}
	}
}

// An exact deny of an argument list longer than the pinned positions blocks: the
// count a claim states is not clamped below it.
func TestProjectMCPExactDenyOfAVeryLongArgumentListBlocks(t *testing.T) {
	args := make([]string, 1<<16+1)
	for i := range args {
		args[i] = "--same"
	}
	entry := config.MCPServerEntry{Name: "notes", Command: "/opt/tools/node", Args: args}
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{Name: "notes", Command: "node", ArgsPrefix: args}}
	api := &APIServer{scannerCfg: cfg}
	gap0686Publish(api, cfg)
	decision, matched := gap0686Hook(t, api, t.TempDir(), "PreToolUse", gap0686Claim(entry, false))
	if !matched || decision.Action != "block" {
		t.Errorf("exact denied prefix past ArgCount clamp allowed: matched=%v decision=%+v", matched, decision)
	}
}

// A deny that differs from an ordinary server only at one argument deep in a
// long list is ruled out, wherever that argument is, up to the last position
// the claim holds a digest for, and the exact deny of the same list still
// blocks. The list lengths are the ones past the full digests and the largest
// one with a digest for every position.
func TestProjectMCPDenyDifferingDeepInALongArgumentListIsRuledOut(t *testing.T) {
	for _, total := range []int{10242, 20000, 2048 + 1<<16} {
		t.Run(fmt.Sprint(total), func(t *testing.T) {
			args := make([]string, total)
			for i := range args {
				args[i] = fmt.Sprintf("--arg-%d", i)
			}
			entry := config.MCPServerEntry{Name: "notes", Command: "/opt/tools/node", Args: args}
			cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
			cfg.Guardrail.Mode = "balanced"
			deep := total - 1
			if total == 10242 {
				deep = 10240
			}
			prefix := append([]string(nil), args[:deep+1]...)
			prefix[deep] = "--different"
			cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{Name: "notes", Command: "node", ArgsPrefix: prefix}}
			api := &APIServer{scannerCfg: cfg}
			gap0686Publish(api, cfg)
			decision, matched := gap0686Hook(t, api, t.TempDir(), "PreToolUse", gap0686Claim(entry, false))
			if matched && decision.Action == "block" {
				t.Errorf("ordinary server blocked for an argument at %d: %+v", deep, decision)
			}
			cfg.AssetPolicy.MCP.Denied[0].ArgsPrefix[deep] = args[deep]
			decision, matched = gap0686Hook(t, api, t.TempDir(), "PreToolUse", gap0686Claim(entry, false))
			if !matched || decision.Action != "block" {
				t.Errorf("exact denied twin allowed: matched=%v decision=%+v", matched, decision)
			}
		})
	}
}

// The tail of the claim is decoded once for a request, not once per rule or
// per argument of a prefix, and comparing a prefix allocates nothing per
// argument: an ordinary 10,242-argument server against a deny that differs in
// its last argument is ruled out with a handful of allocations in all.
func TestProjectMCPDeepArgumentDenyDecodesTheTailOnce(t *testing.T) {
	args := make([]string, 10242)
	for i := range args {
		args[i] = fmt.Sprintf("--arg-%d", i)
	}
	facts, ok := assetfacts.Decode(assetfacts.Encode(assetfacts.Facts{MCP: &assetfacts.MCPServer{
		Name: "notes", Command: "/opt/tools/node", Args: args, ProjectScope: true, Digest: strings.Repeat("ab", 32)}}))
	if !ok || facts.MCP == nil || facts.MCP.Pins == nil {
		t.Fatalf("no pins: %+v", facts.MCP)
	}
	prefix := append([]string(nil), args...)
	prefix[len(prefix)-1] = "--different"
	rules := []config.AssetPolicyRule{{Name: "notes", Command: "node", ArgsPrefix: prefix}}
	var may bool
	allocs := testing.AllocsPerRun(5, func() {
		may = deniedRulesMayPinClaim(rules, "codex", "notes", facts.MCP.Pins)
	})
	if may {
		t.Error("a deny that differs in the last argument may match")
	}
	// The decode of the tail and the config name comparisons are a few
	// allocations; one per argument would be over eight thousand.
	if allocs > 16 {
		t.Errorf("rule comparison made %v allocations, want a constant few", allocs)
	}
	// Many rules share one decode.
	shared := &claimTail{}
	first := shared.of(facts.MCP.Pins)
	held := facts.MCP.Pins.Tail
	facts.MCP.Pins.Tail = ""
	if again := shared.of(facts.MCP.Pins); len(first) == 0 || len(again) != len(first) {
		t.Errorf("tail decoded again for a second rule: %d then %d bytes", len(first), len(again))
	}
	facts.MCP.Pins.Tail = held
	rules[0].ArgsPrefix[len(prefix)-1] = args[len(prefix)-1]
	if !deniedRulesMayPinClaim(rules, "codex", "notes", facts.MCP.Pins) {
		t.Error("the exact deny may not match")
	}
}
