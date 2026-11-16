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

// A call that the complete decision refuses opens no connection: the session
// holds a definition only for a call that runs. Definition C is denied, A
// replaces it while its admission is pending or cannot be read, and the call
// is still refused because the session met C. Once the deny is removed and
// the replacement B is allowed exactly under the strict profile, nothing ran
// for A, so B is an ordinary allow. The twin has no deny: A's first call runs
// with a warning, so the live connection of A stays refused after B is
// allowed.
func TestHoldIsKeptOnlyForACallTheCompleteDecisionLetsRun(t *testing.T) {
	for _, deniedFirst := range []bool{true, false} {
		for _, allowA := range []bool{false, true} {
			for _, kind := range []string{"pending", "unavailable"} {
				for _, shape := range []string{"stdio", "url"} {
					name := shape + "/" + kind + "/twin-no-deny"
					if deniedFirst {
						name = shape + "/" + kind + "/denied-first"
					}
					if allowA {
						name += "/A-allowed"
					}
					t.Run(name, func(t *testing.T) {
						home, project := t.TempDir(), t.TempDir()
						api := mcpTierCases[0].api()
						api.hookMCP = &hookReportedMCPServers{}
						ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
						define := func(suffix string) (string, config.AssetPolicyRule) {
							if shape == "url" {
								url := "http://127.0.0.1:1879" + suffix + "/mcp"
								return `{"type":"http","url":"` + url + `"}`, config.AssetPolicyRule{Name: "vgr", URL: url}
							}
							arg := "--" + suffix
							return `{"type":"stdio","command":"python3","args":["/fx/server.py","` + arg + `"]}`,
								config.AssetPolicyRule{Name: "vgr", Command: "python3", ArgsPrefix: []string{"/fx/server.py", arg}}
						}
						c, denyC := define("1")
						a, allowRuleA := define("2")
						b, allowB := define("3")
						stage := "C"
						api.SetMCPAdmissionStatus(func(_, server, _, _ string) watcher.MCPAdmissionStatus {
							switch stage {
							case "A":
								return watcher.MCPAdmissionStatus{Name: server, Pending: kind == "pending", Unavailable: kind == "unavailable", RetryAfter: time.Second}
							case "B":
								entry, ok := config.LookupMCPServerUnderHome("claudecode", home, project, "vgr")
								if !ok {
									t.Fatal("B is not listed")
								}
								return watcher.MCPAdmissionStatus{Name: server, Admitted: &entry}
							}
							return watcher.MCPAdmissionStatus{}
						})
						put := func(entry string) { writeClaudeServers(t, home, project, `{"vgr":`+entry+`}`) }
						call := func() (config.AssetPolicyDecision, bool) {
							return claudeMCPCall(api, ctx, project, "s1", "mcp__vgr__ping")
						}
						first := a
						if allowA {
							api.scannerCfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{allowRuleA}
						}
						if deniedFirst {
							api.scannerCfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{denyC}
							put(c)
							if d, matched := call(); !matched || d.Action != "block" || d.Source != "admin-deny" {
								t.Fatalf("C explicitly denied: %+v matched=%v", d, matched)
							}
						}
						stage = "A"
						put(first)
						d, matched := call()
						if deniedFirst && (!matched || d.Action != "block" || d.Source != "admin-deny") {
							t.Fatalf("A's call refused because the session met denied C: %+v matched=%v", d, matched)
						}
						if !deniedFirst && matched && d.Action == "block" {
							t.Fatalf("A's first call while admission is %s, balanced tier: %+v, want the warning and the run", kind, d)
						}
						stage = "B"
						api.scannerCfg.Guardrail.RulePack = "strict"
						api.scannerCfg.AssetPolicy.MCP.Denied = nil
						api.scannerCfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{allowB}
						put(b)
						d, matched = call()
						if deniedFirst && matched && d.Action == "block" {
							t.Fatalf("B blocked by a hold of A, whose call was refused and never ran: %+v", d)
						}
						if !deniedFirst && (!matched || d.Action != "block" || d.Source != "mcp-admission-failed") {
							t.Fatalf("B after A ran: %+v matched=%v, want the live connection of A refused", d, matched)
						}
					})
				}
			}
		}
	}
}
