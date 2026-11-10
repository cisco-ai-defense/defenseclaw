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

// An exact allow lets the first call of a server run while its admission
// cannot be read: the balanced tier warns and runs the call, and the
// connection of the agent to that definition opens. The session holds it on
// that call, so once the tier is strict, the entry is replaced and only the
// replacement is allowed, every hook of the session keeps the earlier
// connection refused (GAP-1018). Without the allow, nothing was admitted by
// the administrator and the replacement is judged alone.
func TestPerUserAllowedFirstCallWhileAdmissionIsUnavailableIsHeldForTheSession(t *testing.T) {
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
		for _, withAllow := range []bool{true, false} {
			name := tc.name + "/allowed"
			if !withAllow {
				name = tc.name + "/no-allow"
			}
			t.Run(name, func(t *testing.T) {
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
						return watcher.MCPAdmissionStatus{Name: server, Unavailable: true, RetryAfter: time.Second}
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
				if withAllow {
					api.scannerCfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{tc.ruleA}
				}
				set(tc.entryA)
				if api.scannerCfg.MCPAdmissionFailsClosed("claudecode") {
					t.Fatal("the first tier must warn and allow")
				}
				decision, matched := call(project)
				if !matched || decision.Action != "allow" || decision.Source != "mcp-admission-unavailable" {
					t.Fatalf("first call while admission is unavailable: %+v matched=%v, want the visible warning allow", decision, matched)
				}
				aListed = false
				api.scannerCfg.Guardrail.RulePack = "strict"
				api.scannerCfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{tc.ruleB}
				set(tc.entryB)
				for _, cwd := range []string{project, sibling, "/", ""} {
					decision, matched := call(cwd)
					if withAllow && (!matched || decision.Action != "block" || decision.Source != "mcp-admission-failed") {
						t.Fatalf("allow B, the live connection of A, hook directory %q: %+v matched=%v, want the failed-admission block", cwd, decision, matched)
					}
					if !withAllow && matched && decision.Action == "block" {
						t.Fatalf("allow B, A was never allowed to run, hook directory %q: %+v, want the allow", cwd, decision)
					}
				}
			})
		}
	}
}
