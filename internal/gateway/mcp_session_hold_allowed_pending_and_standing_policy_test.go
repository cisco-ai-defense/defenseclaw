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

// An exact allow lets the first call of a server run while the watcher has not
// decided its admission. That call opens the connection, so the session holds
// the definition on it: once the allow is withdrawn, the entry is replaced and
// only the replacement is allowed, every hook of the session keeps the earlier
// connection refused (GAP-0998, GAP-1018). Without the allow the first call
// was not allowed to run, so nothing is held and the replacement is judged
// alone.
func TestPerUserAllowedFirstCallWhileAdmissionPendingIsHeldForTheSession(t *testing.T) {
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
				api := mcpTierCases[2].api()
				api.hookMCP = &hookReportedMCPServers{}
				ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
				aListed := true
				// The watcher: A is still pending its admission; B (admitted by its
				// exact allow) is answered as an admitted definition.
				api.SetMCPAdmissionStatus(func(_, server, _, cwd string) watcher.MCPAdmissionStatus {
					if cwd != project {
						return watcher.MCPAdmissionStatus{}
					}
					entry, ok := config.LookupMCPServerUnderHome("claudecode", home, project, "vgr")
					if !ok {
						t.Fatal("the local-scope entry is not listed for its project")
					}
					if aListed {
						return watcher.MCPAdmissionStatus{Name: server, Pending: true, RetryAfter: 300 * time.Second}
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
				decision, matched := call(project)
				if withAllow && matched && decision.Action == "block" {
					t.Fatalf("allowed first call while admission is pending: %+v, want the allow", decision)
				}
				if !withAllow && (!matched || decision.Action != "block") {
					t.Fatalf("first call with no allow while admission is pending: %+v matched=%v, want the wait", decision, matched)
				}
				aListed = false
				api.scannerCfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{tc.ruleB}
				set(tc.entryB)
				for _, cwd := range []string{project, sibling, "/", ""} {
					decision, matched := call(cwd)
					if withAllow && (!matched || decision.Action != "block" || decision.Source != "mcp-admission-failed") {
						t.Fatalf("allow B, the live connection of A, hook directory %q: %+v matched=%v, want the failed-admission block", cwd, decision, matched)
					}
					if !withAllow && matched && decision.Action == "block" {
						t.Fatalf("allow B, no connection to A ever ran, hook directory %q: %+v, want the allow", cwd, decision)
					}
				}
			})
		}
	}
}

// With admission.mcp.scan_on_install off, every definition of the server is
// admitted without a scan, the earlier one and its replacement alike: an
// ordinary edit is not a revoked admission while that setting stands, and the
// earlier connection is refused only once the setting is turned back on.
func TestPerUserStandingScanDisabledPolicyKeepsEarlierUnscannedAdmissionValid(t *testing.T) {
	home, project, sibling := t.TempDir(), t.TempDir(), t.TempDir()
	api := mcpTierCases[2].api()
	api.hookMCP = &hookReportedMCPServers{}
	off, on := false, true
	api.scannerCfg.Admission.MCP.ScanOnInstall = &off
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
	entry := func(arg string) config.MCPServerEntry {
		return config.MCPServerEntry{Name: "vgr", Connector: "claudecode", Home: home, Project: project,
			Command: "python3", Args: []string{"/fx/server.py", arg}, Transport: "stdio"}
	}
	probe := func(cwd string) mcpRuntimeProbe {
		return mcpRuntimeProbe{ServerName: "vgr", SessionID: "s1", WorkspaceDir: cwd, Surface: "hook", Matched: true}
	}
	set := func(arg string) {
		writeClaudeServers(t, home, project, `{"vgr":{"type":"stdio","command":"python3","args":["/fx/server.py","`+arg+`"]}}`)
	}
	admitted := func(e config.MCPServerEntry) watcher.MCPAdmissionStatus {
		return watcher.MCPAdmissionStatus{Name: "vgr", Admitted: &e}
	}
	// The calls run: the hold the policy asks for is kept, as the hook does
	// once the complete decision lets the call run.
	answered := func(p mcpRuntimeProbe, status watcher.MCPAdmissionStatus) watcher.MCPAdmissionStatus {
		got, opened := api.failedMCPSessionHold(ctx, api.scannerCfg, "claudecode", p, status)
		if opened != nil {
			api.holdFailedMCP("claudecode", home, p, *opened, time.Now())
		}
		return got
	}
	a, b := entry("--a"), entry("--b")
	set("--a")
	if got := answered(probe(project), admitted(a)); got.Failed {
		t.Fatalf("call of A while scan_on_install is off: %+v, want the admission", got)
	}
	set("--b")
	for _, cwd := range []string{project, sibling} {
		if got := answered(probe(cwd), admitted(b)); got.Failed {
			t.Fatalf("call of B, hook directory %q, scan_on_install still off: %+v, want the admission", cwd, got)
		}
	}
	// The setting that admitted A is gone: its live connection is a failed admission.
	api.scannerCfg.Admission.MCP.ScanOnInstall = &on
	if got := answered(probe(sibling), watcher.MCPAdmissionStatus{Name: "vgr"}); !got.Failed {
		t.Fatalf("call after scan_on_install is back on: %+v, want the earlier unscanned connection refused", got)
	}
}
