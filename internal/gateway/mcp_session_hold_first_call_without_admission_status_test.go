// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// The watcher answers nothing for a server it has not listed yet (its first
// cycle), while the definition is already in the agent config. A first call that
// policy lets run in that window opens the connection, so the session holds the
// definition on that call, as it does when the answer is pending: once the allow
// is withdrawn and only a replacement is allowed, every hook of the session keeps
// the earlier connection refused. A call policy did not let run, and a server
// with a clean scan, hold nothing and the replacement is judged alone.
func TestPerUserFirstCallBeforeAnyAdmissionStatusIsHeldForTheSession(t *testing.T) {
	const urlA, urlB = "http://127.0.0.1:18795/mcp", "http://127.0.0.1:18796/mcp"
	stdio := func(arg string) string {
		return `{"type":"stdio","command":"python3","args":["/fx/server.py","` + arg + `"]}`
	}
	stdioRule := func(arg string) config.AssetPolicyRule {
		return config.AssetPolicyRule{Name: "vgr", Command: "python3", ArgsPrefix: []string{"/fx/server.py", arg}}
	}
	for _, tc := range []struct {
		name           string
		entryA, entryB string
		ruleA, ruleB   *config.AssetPolicyRule
		scanOff        bool
		// held says the first call ran on the policy, so its connection is held.
		held bool
	}{
		{name: "stdio/exact-allow", entryA: stdio("--a"), entryB: stdio("--b"), ruleA: ptrRule(stdioRule("--a")), ruleB: ptrRule(stdioRule("--b")), held: true},
		{name: "url/exact-allow", entryA: `{"type":"http","url":"` + urlA + `"}`, entryB: `{"type":"http","url":"` + urlB + `"}`,
			ruleA: &config.AssetPolicyRule{Name: "vgr", URL: urlA}, ruleB: &config.AssetPolicyRule{Name: "vgr", URL: urlB}, held: true},
		{name: "stdio/scan-disabled", entryA: stdio("--a"), entryB: stdio("--b"), ruleB: ptrRule(stdioRule("--b")), scanOff: true, held: true},
		{name: "stdio/no-allow", entryA: stdio("--a"), entryB: stdio("--b"), ruleB: ptrRule(stdioRule("--b"))},
		{name: "stdio/allow-of-another-definition", entryA: stdio("--a"), entryB: stdio("--b"), ruleA: ptrRule(stdioRule("--other")), ruleB: ptrRule(stdioRule("--b"))},
		{name: "url/no-allow", entryA: `{"type":"http","url":"` + urlA + `"}`, entryB: `{"type":"http","url":"` + urlB + `"}`,
			ruleB: &config.AssetPolicyRule{Name: "vgr", URL: urlB}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, project, sibling := t.TempDir(), t.TempDir(), t.TempDir()
			api := mcpTierCases[2].api()
			api.hookMCP = &hookReportedMCPServers{}
			if tc.scanOff {
				off := false
				api.scannerCfg.Admission.MCP.ScanOnInstall = &off
			}
			ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
			aListed := true
			// The watcher: it has no answer for A yet; B (admitted by its exact
			// allow) is an admitted definition.
			api.SetMCPAdmissionStatus(func(_, server, _, cwd string) watcher.MCPAdmissionStatus {
				if cwd != project || aListed {
					return watcher.MCPAdmissionStatus{}
				}
				entry, ok := config.LookupMCPServerUnderHome("claudecode", home, project, "vgr")
				if !ok {
					t.Fatal("the local-scope entry is not listed for its project")
				}
				return watcher.MCPAdmissionStatus{Name: server, Admitted: &entry}
			})
			set := func(entry string) { writeClaudeServers(t, home, project, `{"vgr":`+entry+`}`) }
			call := func(cwd string) (config.AssetPolicyDecision, bool) {
				return claudeMCPCall(api, ctx, cwd, "s1", "mcp__vgr__ping")
			}
			if tc.ruleA != nil {
				api.scannerCfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{*tc.ruleA}
			}
			set(tc.entryA)
			if decision, matched := call(project); matched && decision.Action == "block" {
				t.Fatalf("first call with no admission status: %+v, want the ordinary call", decision)
			}
			aListed = false
			api.scannerCfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{*tc.ruleB}
			if tc.scanOff {
				on := true
				api.scannerCfg.Admission.MCP.ScanOnInstall = &on
			}
			set(tc.entryB)
			for _, cwd := range []string{project, sibling, "/", ""} {
				decision, matched := call(cwd)
				if tc.held && (!matched || decision.Action != "block" || decision.Source != "mcp-admission-failed") {
					t.Fatalf("allow B, the live connection of A, hook directory %q: %+v matched=%v, want the failed-admission block", cwd, decision, matched)
				}
				if !tc.held && matched && decision.Action == "block" {
					t.Fatalf("allow B, no connection to A ran on an admission, hook directory %q: %+v, want the allow", cwd, decision)
				}
			}
		})
	}
}

func ptrRule(rule config.AssetPolicyRule) *config.AssetPolicyRule { return &rule }
