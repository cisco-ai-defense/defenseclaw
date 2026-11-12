// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// A local-scope entry is listed only for the project folder it belongs to, so
// the watcher answers a hook that reports another folder with nothing. The
// session still holds the connection it opened: once the allow of the first
// definition is withdrawn, the entry is replaced and the replacement is
// allowed, every hook of that session keeps the revoked connection refused
// whatever folder it reports (GAP-1018). Another session is not held.
func TestPerUserLocalScopeRevokedConnectionStaysRefusedWhateverDirectoryTheHookReports(t *testing.T) {
	const urlA, urlB = "http://127.0.0.1:18795/mcp", "http://127.0.0.1:18796/mcp"
	for _, tc := range []struct {
		name         string
		entryA       string
		entryB       string
		ruleA, ruleB config.AssetPolicyRule
	}{
		{"stdio", `{"type":"stdio","command":"python3","args":["/fx/server.py","--a"]}`, `{"type":"stdio","command":"python3","args":["/fx/server.py","--b"]}`,
			config.AssetPolicyRule{Name: "vgr", Command: "python3", ArgsPrefix: []string{"/fx/server.py", "--a"}},
			config.AssetPolicyRule{Name: "vgr", Command: "python3", ArgsPrefix: []string{"/fx/server.py", "--b"}}},
		{"url", `{"type":"http","url":"` + urlA + `"}`, `{"type":"http","url":"` + urlB + `"}`,
			config.AssetPolicyRule{Name: "vgr", URL: urlA}, config.AssetPolicyRule{Name: "vgr", URL: urlB}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, project, sibling := t.TempDir(), t.TempDir(), t.TempDir()
			sub := filepath.Join(project, "sub")
			api := mcpTierCases[2].api()
			api.hookMCP = &hookReportedMCPServers{}
			ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
			within := func(cwd string) bool {
				return cwd != "" && (cwd == project || strings.HasPrefix(cwd, project+string(filepath.Separator)))
			}
			listed := func() config.MCPServerEntry {
				entry, ok := config.LookupMCPServerUnderHome("claudecode", home, project, "vgr")
				if !ok {
					t.Fatal("the local-scope entry is not listed for its project")
				}
				return entry
			}
			var departed *config.MCPServerEntry
			allows := func(entry config.MCPServerEntry) bool {
				probe := mcpProbeWithEntry(mcpRuntimeProbe{ServerName: "vgr", Surface: "hook", Matched: true}, entry, true)
				verdict := mcpProbeDecision(context.Background(), api.scannerCfg, "claudecode", probe)
				return verdict.Enabled && verdict.Source == "admin-allow"
			}
			// The watcher: a local-scope entry serves only its project folder; the
			// listed definition is admitted without a scan while an allow covers it,
			// else its admission fails; a departed one whose allow is gone is a
			// revoked failure until the replacement is admitted.
			api.SetMCPAdmissionStatus(func(_, server, _, cwd string) watcher.MCPAdmissionStatus {
				if !within(cwd) {
					return watcher.MCPAdmissionStatus{}
				}
				entry := listed()
				if departed != nil && !allows(*departed) && !allows(entry) {
					status := watcher.FailedMCPStatus(*departed)
					status.Revoked = true
					return status
				}
				if allows(entry) {
					return watcher.MCPAdmissionStatus{Name: server, Admitted: &entry}
				}
				return watcher.FailedMCPStatus(entry)
			})
			call := func(session, cwd string) (config.AssetPolicyDecision, bool) {
				return claudeMCPCall(api, ctx, cwd, session, "mcp__vgr__ping")
			}
			setServers := func(entry string) { writeClaudeServers(t, home, project, `{"vgr":`+entry+`}`) }

			api.scannerCfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{tc.ruleA}
			setServers(tc.entryA)
			if decision, matched := call("s1", project); matched && decision.Action == "block" {
				t.Fatalf("allow A, the call of A: %+v, want the allow", decision)
			}
			a := listed()
			departed = &a
			api.scannerCfg.AssetPolicy.MCP.Allowed = nil
			setServers(tc.entryB)
			if decision, matched := call("s1", project); !matched || decision.Action != "block" {
				t.Fatalf("entry replaced, allow of A withdrawn: %+v matched=%v, want the block", decision, matched)
			}
			api.scannerCfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{tc.ruleB}
			for _, cwd := range []string{project, sub, sibling, "/", home, ""} {
				if decision, matched := call("s1", cwd); !matched || decision.Action != "block" || decision.Source != "mcp-admission-failed" {
					t.Fatalf("allow B, the live connection of A, hook directory %q: %+v matched=%v, want the failed-admission block", cwd, decision, matched)
				}
			}
			// Benign twin: a session that never ran A is not held, in any directory.
			for _, cwd := range []string{project, sibling} {
				if decision, matched := call("s2", cwd); matched && decision.Action == "block" {
					t.Fatalf("allow B, another session, hook directory %q: %+v, want the allow", cwd, decision)
				}
			}
		})
	}
}

// Benign twin: an allowed definition that stays listed and allowed is never
// refused by the hold, in the project or elsewhere, in the same session.
func TestPerUserAllowedLocalScopeServerIsNeverHeldWhileItsAllowStands(t *testing.T) {
	home, project, sibling := t.TempDir(), t.TempDir(), t.TempDir()
	api := mcpTierCases[2].api(config.AssetPolicyRule{Name: "vgr", Command: "python3", ArgsPrefix: []string{"/fx/server.py", "--a"}})
	api.hookMCP = &hookReportedMCPServers{}
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
	writeClaudeServers(t, home, project, `{"vgr":{"type":"stdio","command":"python3","args":["/fx/server.py","--a"]}}`)
	entry, ok := config.LookupMCPServerUnderHome("claudecode", home, project, "vgr")
	if !ok {
		t.Fatal("entry not listed")
	}
	api.SetMCPAdmissionStatus(func(_, server, _, cwd string) watcher.MCPAdmissionStatus {
		if cwd != project {
			return watcher.MCPAdmissionStatus{}
		}
		return watcher.MCPAdmissionStatus{Name: server, Admitted: &entry}
	})
	for _, cwd := range []string{project, sibling, project, "/", ""} {
		if decision, matched := claudeMCPCall(api, ctx, cwd, "s1", "mcp__vgr__ping"); matched && decision.Action == "block" {
			t.Fatalf("allowed server, hook directory %q: %+v, want the allow", cwd, decision)
		}
	}
}
