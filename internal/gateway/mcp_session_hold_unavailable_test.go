// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// The balanced tier warns and runs the first call of a server while its
// admission cannot be read, with an exact allow, with no rule at all or with a
// rule written for something else, and the connection of the agent to that
// definition opens. The session holds it on that call, so once the tier is
// strict, the entry is replaced and only the replacement is allowed, every
// hook of the session keeps the earlier connection refused (GAP-1018). Another
// session is judged on the replacement alone.
func TestPerUserFirstCallWhileAdmissionIsUnavailableIsHeldForTheSession(t *testing.T) {
	const urlA, urlB = "http://127.0.0.1:18795/mcp", "http://127.0.0.1:18796/mcp"
	for _, tc := range []struct {
		name           string
		entryA, entryB string
		ruleA, ruleB   config.AssetPolicyRule
	}{
		{"stdio", `{"type":"stdio","command":"python3","args":["/fx/server.py","--a"]}`, `{"type":"stdio","command":"python3","args":["/fx/server.py","--b"]}`,
			config.AssetPolicyRule{Name: "vgr", Command: "python3", ArgsPrefix: []string{"/fx/server.py", "--a"}},
			config.AssetPolicyRule{Name: "vgr", Command: "python3", ArgsPrefix: []string{"/fx/server.py", "--b"}}},
		{"url", `{"type":"http","url":"` + urlA + `"}`, `{"type":"http","url":"` + urlB + `"}`,
			config.AssetPolicyRule{Name: "vgr", URL: urlA}, config.AssetPolicyRule{Name: "vgr", URL: urlB}},
	} {
		for _, rule := range []string{"allowed", "no-allow", "wrong-rule"} {
			for _, kind := range []string{"unavailable", "pending"} {
				t.Run(tc.name+"/"+rule+"/"+kind, func(t *testing.T) {
					home, project, sibling := t.TempDir(), t.TempDir(), t.TempDir()
					api := mcpTierCases[0].api()
					api.hookMCP = &hookReportedMCPServers{}
					ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
					aListed := true
					api.SetMCPAdmissionStatus(func(_, server, _, cwd string) watcher.MCPAdmissionStatus {
						if cwd != project {
							return watcher.MCPAdmissionStatus{}
						}
						if aListed {
							return watcher.MCPAdmissionStatus{Name: server, Unavailable: kind == "unavailable", Pending: kind == "pending", RetryAfter: time.Second}
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
					switch rule {
					case "allowed":
						api.scannerCfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{tc.ruleA}
					case "wrong-rule":
						api.scannerCfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: "other", URL: "http://127.0.0.1:18797/mcp"}}
					}
					set(tc.entryA)
					if api.scannerCfg.MCPAdmissionFailsClosed("claudecode") {
						t.Fatal("the first tier must warn and allow")
					}
					decision, matched := call(project)
					if rule == "allowed" && kind == "pending" {
						// The exact allow answers a scan that has not finished: no wait.
						if matched && decision.Action == "block" {
							t.Fatalf("allowed first call while admission is pending: %+v, want the allow", decision)
						}
					} else if !matched || decision.Action != "allow" || decision.Source != "mcp-admission-"+kind {
						t.Fatalf("first call while admission is %s: %+v matched=%v, want the visible warning allow", kind, decision, matched)
					}
					aListed = false
					api.scannerCfg.Guardrail.RulePack = "strict"
					api.scannerCfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{tc.ruleB}
					set(tc.entryB)
					for _, cwd := range []string{project, sibling, "/", ""} {
						decision, matched := call(cwd)
						if !matched || decision.Action != "block" || decision.Source != "mcp-admission-failed" {
							t.Fatalf("allow B, the live connection of A, hook directory %q: %+v matched=%v, want the failed-admission block", cwd, decision, matched)
						}
					}
					if decision, matched := claudeMCPCall(api, ctx, project, "s2", "mcp__vgr__ping"); matched && decision.Action == "block" {
						t.Fatalf("allow B, a session that never ran A: %+v, want the allow", decision)
					}
				})
			}
		}
	}
}

// A strict first call is blocked while admission cannot be read: nothing ran,
// so nothing is held, and once the entry is replaced and the replacement is
// allowed the session runs it.
func TestStrictBlockedFirstCallWhileAdmissionIsUnavailableHoldsNothing(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	api := mcpTierCases[0].api()
	api.hookMCP = &hookReportedMCPServers{}
	api.scannerCfg.Guardrail.RulePack = "strict"
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
	aListed := true
	api.SetMCPAdmissionStatus(func(_, server, _, cwd string) watcher.MCPAdmissionStatus {
		if cwd != project {
			return watcher.MCPAdmissionStatus{}
		}
		if aListed {
			return watcher.MCPAdmissionStatus{Name: server, Unavailable: true, RetryAfter: time.Second}
		}
		entry, ok := config.LookupMCPServerUnderHome("claudecode", home, project, "vgr")
		if !ok {
			t.Fatal("the local-scope entry is not listed for its project")
		}
		return watcher.MCPAdmissionStatus{Name: server, Admitted: &entry}
	})
	writeClaudeServers(t, home, project, `{"vgr":{"type":"stdio","command":"python3","args":["/fx/server.py","--a"]}}`)
	if decision, matched := claudeMCPCall(api, ctx, project, "s1", "mcp__vgr__ping"); !matched || decision.Action != "block" {
		t.Fatalf("strict first call while admission is unavailable: %+v matched=%v, want the block", decision, matched)
	}
	aListed = false
	api.scannerCfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: "vgr", Command: "python3", ArgsPrefix: []string{"/fx/server.py", "--b"}}}
	writeClaudeServers(t, home, project, `{"vgr":{"type":"stdio","command":"python3","args":["/fx/server.py","--b"]}}`)
	if decision, matched := claudeMCPCall(api, ctx, project, "s1", "mcp__vgr__ping"); matched && decision.Action == "block" {
		t.Fatalf("allow B, A was blocked and never ran: %+v, want the allow", decision)
	}
}
