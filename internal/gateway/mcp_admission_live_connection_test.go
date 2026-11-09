// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// watcherLikeStatus makes the stand-in watcher of the harness answer as the
// real one does for a server an administrator rule allows: the allow admits
// the listed definition without a scan, so its status is clean, not failed.
// A listed definition the scanner refuses and no rule allows is a failed
// admission, and any other listed server waits for its scan.
func (h *reportedMCPHarness) watcherLikeStatus() {
	h.api.SetMCPAdmissionStatus(func(connector, server, home, _ string) watcher.MCPAdmissionStatus {
		servers, _ := h.reported.list()
		for _, entry := range servers {
			if entry.Connector != connector || entry.Name != server || entry.Home != home {
				continue
			}
			probe := mcpProbeWithEntry(mcpRuntimeProbe{ServerName: server, Surface: "hook", Matched: true}, entry, true)
			if verdict := mcpProbeDecision(context.Background(), h.api.scannerCfg, connector, probe); verdict.Enabled && verdict.Source == "admin-allow" {
				return watcher.MCPAdmissionStatus{Name: server}
			}
			if watcher.MCPScanRefused(entry) {
				return watcher.FailedMCPStatus(entry)
			}
			return watcher.MCPAdmissionStatus{Name: server, Pending: true, RetryAfter: 30 * time.Second}
		}
		return watcher.MCPAdmissionStatus{}
	})
}

func (h *reportedMCPHarness) allowOnly(servers ...assetfacts.MCPServer) {
	rules := make([]config.AssetPolicyRule, 0, len(servers))
	for _, server := range servers {
		rules = append(rules, config.AssetPolicyRule{Name: server.Name, URL: server.URL, Command: server.Command, ArgsPrefix: server.Args})
	}
	h.api.scannerCfg.AssetPolicy.MCP.Allowed = rules
}

func wantMCPBlock(t *testing.T, what string, resp claudeCodeHookResponse) {
	t.Helper()
	if resp.Action != "block" || !strings.Contains(resp.SourceReason, "reason_code=mcp-admission-failed") {
		t.Fatalf("%s: action=%q reason=%q, want a block with the failed admission", what, resp.Action, resp.SourceReason)
	}
}

func wantMCPAllow(t *testing.T, what string, resp claudeCodeHookResponse) {
	t.Helper()
	if resp.Action != "allow" || strings.Contains(resp.SourceReason, "mcp-admission") {
		t.Fatalf("%s: action=%q reason=%q, want an ordinary allow", what, resp.Action, resp.SourceReason)
	}
}

// The agent keeps the connection it opened to a definition for as long as it
// lives, and the hook names the server, not the connection. On a managed
// Linux or macOS gateway: allow A, the call runs, the entry is replaced by B
// under the same name, the allow of A is removed (the call is refused), then
// B is allowed. The live connection is still the revoked A, so the allow of B
// does not admit it: the calls stay refused until the agent starts again and
// connects to B (GAP-0925, FL27-01).
func TestManagedUnixHookReportedMCPAllowOfTheReplacementDoesNotAdmitTheLiveConnectionOfARevokedDefinition(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed Windows reads the enumerator records instead")
	}
	cases := []struct {
		name string
		a, b assetfacts.MCPServer
	}{
		{"local python server",
			assetfacts.MCPServer{Name: "vgr", Command: "python3", Args: []string{"/opt/ping.py"}},
			assetfacts.MCPServer{Name: "vgr", Command: "python3", Args: []string{"/opt/ping.py", "--v2"}}},
		{"loopback url server",
			assetfacts.MCPServer{Name: "vgr", URL: "http://127.0.0.1:18795/mcp"},
			assetfacts.MCPServer{Name: "vgr", URL: "http://127.0.0.1:18796/mcp"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newReportedMCPHarness()
			h.watcherLikeStatus()
			other := assetfacts.MCPServer{Name: "other", Command: "python3", Args: []string{"/opt/other.py"}}

			h.allowOnly(tc.a, other)
			wantMCPAllow(t, "allow A, the call of A", h.callInSession(t, "s1", tc.a))
			wantMCPAllow(t, "allow A, a call of another allowed server", h.callInSession(t, "s1", other))

			h.allowOnly(other)
			wantMCPBlock(t, "entry replaced by B, the allow of A removed", h.callInSession(t, "s1", tc.b))

			h.allowOnly(tc.b, other)
			wantMCPBlock(t, "allow B, the live connection is the revoked A", h.callInSession(t, "s1", tc.b))
			wantMCPBlock(t, "allow B, a later call", h.callInSession(t, "s1", tc.b))
			wantMCPBlock(t, "allow B, the entry listed back as A without its allow", h.callInSession(t, "s1", tc.a))

			// Benign twins: another session never held A, and another server of
			// the held session is its own.
			wantMCPAllow(t, "allow B, another session", h.callInSession(t, "s2", tc.b))
			wantMCPAllow(t, "allow B, another server of the held session", h.callInSession(t, "s1", other))

			// The administrator allows every definition the session met.
			h.allowOnly(tc.a, tc.b, other)
			wantMCPAllow(t, "allow A and B", h.callInSession(t, "s1", tc.b))

			// Only the replacement stays allowed: the agent starting again
			// connects to B, which the config lists.
			h.allowOnly(tc.b, other)
			wantMCPBlock(t, "allow B only, the same session", h.callInSession(t, "s1", tc.b))
			h.startSession(t, "s1")
			wantMCPAllow(t, "allow B only, after the agent started again", h.callInSession(t, "s1", tc.b))
		})
	}
}

// Benign twin of the above: an administrator who allowed every definition the
// session met keeps its calls, whichever of them the config lists, and the
// clean admission the watcher gives each allowed definition is not a failure.
func TestManagedUnixHookReportedMCPEveryAllowedDefinitionOfASessionStaysAllowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed Windows reads the enumerator records instead")
	}
	h := newReportedMCPHarness()
	h.watcherLikeStatus()
	a := assetfacts.MCPServer{Name: "vgr", Command: "python3", Args: []string{"/opt/ping.py"}}
	b := assetfacts.MCPServer{Name: "vgr", Command: "python3", Args: []string{"/opt/ping.py", "--v2"}}
	h.allowOnly(a, b)
	for _, server := range []assetfacts.MCPServer{a, b, a, b} {
		wantMCPAllow(t, "an allowed definition of the session", h.callInSession(t, "s1", server))
	}
}

// The same timeline on a per-user gateway, whose watcher keeps the failed
// scan of a loopback server visible whatever the administrator allowed: the
// strict tier refuses the live connection of the revoked definition after
// the allow of its replacement, and the ordinary calls around it are allowed.
func TestPerUserAllowOfTheReplacementDoesNotAdmitTheLiveConnectionOfARevokedDefinition(t *testing.T) {
	const urlA, urlB = "http://127.0.0.1:18795/mcp", "http://127.0.0.1:18796/mcp"
	strict := mcpTierCases[2]
	api := strict.api(config.AssetPolicyRule{Name: "vgr", URL: urlA})
	api.hookMCP = &hookReportedMCPServers{}
	api.SetMCPAdmissionStatus(func(_, server, _, _ string) watcher.MCPAdmissionStatus {
		return watcher.MCPAdmissionStatus{Name: server, Failed: true, ScanIssue: watcher.MCPScanIssueAddress}
	})
	home, project := t.TempDir(), t.TempDir()
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
	call := func(session string) (config.AssetPolicyDecision, bool) {
		return claudeMCPCall(api, ctx, project, session, "mcp__vgr__ping")
	}
	wantBlock := func(what string) {
		t.Helper()
		if decision, matched := call("s1"); !matched || decision.Action != "block" || decision.Source != "mcp-admission-failed" {
			t.Fatalf("%s: matched=%v decision=%+v, want the failed-admission block", what, matched, decision)
		}
	}
	listed := func(url string) { writeClaudeServers(t, home, project, `{"vgr":{"type":"http","url":"`+url+`"}}`) }

	listed(urlA)
	if decision, matched := call("s1"); matched {
		t.Fatalf("allow A, the call of A: decision %+v, want the allow", decision)
	}
	listed(urlB)
	api.scannerCfg.AssetPolicy.MCP.Allowed = nil
	wantBlock("entry replaced by B, the allow of A removed")
	api.scannerCfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: "vgr", URL: urlB}}
	wantBlock("allow B, the live connection is the revoked A")
	// Benign twin: another session never held A.
	if decision, matched := call("s2"); matched {
		t.Fatalf("allow B, another session: decision %+v, want the allow", decision)
	}
}
