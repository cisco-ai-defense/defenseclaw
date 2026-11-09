// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

const sessionHoldURL = "http://127.0.0.1:27103/mcp"

// sessionHoldFixture is a per-user gateway whose watcher answers a failed
// admission for the loopback server while it is listed and failed is set, as
// a scan that could not run does, and nothing for any other server.
type sessionHoldFixture struct {
	t       *testing.T
	api     *APIServer
	home    string
	project string
	failed  bool
	listed  bool
}

func newSessionHoldFixture(t *testing.T, pack string) *sessionHoldFixture {
	t.Helper()
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.RulePack = pack
	f := &sessionHoldFixture{t: t, home: t.TempDir(), project: t.TempDir(), failed: true}
	f.api = &APIServer{scannerCfg: cfg, hookMCP: &hookReportedMCPServers{}}
	f.api.SetMCPAdmissionStatus(func(_, server, _, _ string) watcher.MCPAdmissionStatus {
		if f.failed && f.listed && server == "wiki-ok" {
			return watcher.MCPAdmissionStatus{Name: server, Failed: true, ScanIssue: watcher.MCPScanIssueAddress}
		}
		return watcher.MCPAdmissionStatus{}
	})
	return f
}

func (f *sessionHoldFixture) list(servers string) {
	f.t.Helper()
	f.listed = strings.Contains(servers, sessionHoldURL)
	writeClaudeServers(f.t, f.home, f.project, servers)
}

func (f *sessionHoldFixture) call(session, server string) claudeCodeHookResponse {
	f.t.Helper()
	return f.callAs(f.home, session, server)
}

func (f *sessionHoldFixture) callAs(home, session, server string) claudeCodeHookResponse {
	f.t.Helper()
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
	return f.api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
		SessionID: session, HookEventName: "PreToolUse", ToolName: "mcp__" + server + "__count_words",
		ToolInput: map[string]interface{}{}, CWD: f.project,
	})
}

func (f *sessionHoldFixture) wantFailed(what, action string, resp claudeCodeHookResponse) {
	f.t.Helper()
	if resp.Action != action || !strings.Contains(resp.SourceReason, "reason_code=mcp-admission-failed") {
		f.t.Fatalf("%s: action=%q reason=%q, want %s with the failed admission", what, resp.Action, resp.SourceReason, action)
	}
}

func (f *sessionHoldFixture) wantOrdinary(what string, resp claudeCodeHookResponse) {
	f.t.Helper()
	if resp.Action != "allow" || strings.Contains(resp.SourceReason, "mcp-admission") {
		f.t.Fatalf("%s: action=%q reason=%q, want an ordinary allow", what, resp.Action, resp.SourceReason)
	}
}

const sessionHoldListed = `{"wiki-ok":{"type":"http","url":"` + sessionHoldURL + `"},"wiki-fine":{"type":"http","url":"https://mcp.example.invalid/fine"}}`
const sessionHoldRemoved = `{"wiki-fine":{"type":"http","url":"https://mcp.example.invalid/fine"}}`

// A server whose admission failed stays failed for the agent session that met
// it after its entry is removed from the agent config: the agent keeps the
// connection, so the strict tier keeps blocking it and the default tier keeps
// allowing it with the warning, whichever tier decided the earlier call
// (GAP-0984). The tier is applied to the held failure at each call.
func TestFailedMCPAdmissionStaysHeldForTheSessionAfterTheEntryIsRemoved(t *testing.T) {
	for _, tc := range []struct{ pack, action string }{{"strict", "block"}, {"default", "allow"}} {
		t.Run(tc.pack, func(t *testing.T) {
			f := newSessionHoldFixture(t, tc.pack)
			f.list(sessionHoldListed)
			f.wantFailed("listed", tc.action, f.call("s1", "wiki-ok"))
			f.list(sessionHoldRemoved)
			f.wantFailed("removed", tc.action, f.call("s1", "wiki-ok"))
			f.wantFailed("removed, a later call", tc.action, f.call("s1", "wiki-ok"))

			// Benign twins: no other session, server or account is held.
			f.wantOrdinary("another session", f.callAs(f.home, "s2", "wiki-ok"))
			f.wantOrdinary("another server of the session", f.call("s1", "wiki-fine"))
			f.wantOrdinary("another account", f.callAs(t.TempDir(), "s1", "wiki-ok"))

			// The agent starting again connects to what the config lists now.
			f.api.mcpSessionStarted(withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: f.home}),
				"claudecode", "s1", "SessionStart", "startup")
			f.wantOrdinary("after the session started again", f.call("s1", "wiki-ok"))
		})
	}
}

// The repro of GAP-0984: the default tier allowed the failed server with a
// warning, the profile moved to strict, and the entry was removed in the same
// session. The earlier warned allow does not carry into strict.
func TestWarnedFailedMCPAdmissionDoesNotCarryIntoStrictAfterRemoval(t *testing.T) {
	f := newSessionHoldFixture(t, "default")
	f.list(sessionHoldListed)
	f.wantFailed("default, listed", "allow", f.call("s1", "wiki-ok"))
	f.api.scannerCfg.Guardrail.RulePack = "strict"
	f.wantFailed("strict, listed", "block", f.call("s1", "wiki-ok"))
	f.list(sessionHoldRemoved)
	f.wantFailed("strict, removed", "block", f.call("s1", "wiki-ok"))
	f.api.scannerCfg.Guardrail.RulePack = "default"
	f.wantFailed("default again, removed", "allow", f.call("s1", "wiki-ok"))
}

// A definition edited to another, ordinary one keeps the failed one held for
// the session that met it, and a definition whose admission stops failing
// (an allow, a clean scan) is released.
func TestFailedMCPAdmissionHeldAfterAnEditAndReleasedWhenItNoLongerFails(t *testing.T) {
	f := newSessionHoldFixture(t, "strict")
	f.list(sessionHoldListed)
	f.wantFailed("listed", "block", f.call("s1", "wiki-ok"))
	f.list(`{"wiki-ok":{"type":"http","url":"https://mcp.example.invalid/ok"}}`)
	f.failed = false
	f.wantFailed("edited to an ordinary URL", "block", f.call("s1", "wiki-ok"))
	f.wantOrdinary("edited, another session", f.callAs(f.home, "s2", "wiki-ok"))

	// The failed definition is listed again and its admission no longer
	// fails: it is released, and removing it later holds nothing.
	f.list(sessionHoldListed)
	f.wantOrdinary("listed again, admitted", f.call("s1", "wiki-ok"))
	f.list(sessionHoldRemoved)
	f.wantOrdinary("removed after it was admitted", f.call("s1", "wiki-ok"))
}
