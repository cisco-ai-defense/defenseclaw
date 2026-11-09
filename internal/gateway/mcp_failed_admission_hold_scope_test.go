// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// scopeHoldFixture is a per-user gateway for a user-scope server in
// ~/.claude.json whose admission status the test sets by definition.
type scopeHoldFixture struct {
	t      *testing.T
	api    *APIServer
	home   string
	cwd    string
	status func(server string) watcher.MCPAdmissionStatus
}

func newScopeHoldFixture(t *testing.T, pack string) *scopeHoldFixture {
	t.Helper()
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.RulePack = pack
	f := &scopeHoldFixture{t: t, home: t.TempDir(), cwd: t.TempDir()}
	f.api = &APIServer{scannerCfg: cfg, hookMCP: &hookReportedMCPServers{}}
	f.api.SetMCPAdmissionStatus(func(_, server, _, _ string) watcher.MCPAdmissionStatus {
		if f.status == nil {
			return watcher.MCPAdmissionStatus{}
		}
		return f.status(server)
	})
	return f
}

// listUser writes servers as the user-scope mcpServers of ~/.claude.json.
func (f *scopeHoldFixture) listUser(servers string) {
	f.t.Helper()
	data := `{"mcpServers":` + servers + `}`
	if err := os.WriteFile(filepath.Join(f.home, ".claude.json"), []byte(data), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *scopeHoldFixture) call(cwd, session, server string) claudeCodeHookResponse {
	f.t.Helper()
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: f.home})
	return f.api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
		SessionID: session, HookEventName: "PreToolUse", ToolName: "mcp__" + server + "__count_words",
		ToolInput: map[string]interface{}{}, CWD: cwd,
	})
}

func wantHeldFailed(t *testing.T, what, action string, resp claudeCodeHookResponse) {
	t.Helper()
	if resp.Action != action || !strings.Contains(resp.SourceReason, "reason_code=mcp-admission-failed") {
		t.Fatalf("%s: action=%q reason=%q, want %s with the failed admission", what, resp.Action, resp.SourceReason, action)
	}
}

func wantHeldOrdinary(t *testing.T, what string, resp claudeCodeHookResponse) {
	t.Helper()
	if resp.Action != "allow" || strings.Contains(resp.SourceReason, "mcp-admission") {
		t.Fatalf("%s: action=%q reason=%q, want an ordinary allow", what, resp.Action, resp.SourceReason)
	}
}

const (
	scopeHoldFailedURL = "http://127.0.0.1:27103/mcp"
	scopeHoldCleanURL  = "https://mcp.example.invalid/ok"
)

func scopeHoldServer(url, header string) string {
	headers := ""
	if header != "" {
		headers = `,"headers":{"Authorization":"` + header + `"}`
	}
	return `{"wiki-ok":{"type":"http","url":"` + url + `"` + headers + `}}`
}

// A user-scope server is one connection whatever directory the agent works in:
// the hold of its failed admission follows the config scope, not the working
// directory of the call that met it. A call from a subfolder, or a folder
// elsewhere, of the same session still meets it; another session does not.
func TestFailedMCPAdmissionHoldFollowsTheConfigScopeNotTheWorkingDirectory(t *testing.T) {
	for _, tc := range []struct{ pack, action string }{{"strict", "block"}, {"default", "allow"}} {
		t.Run(tc.pack, func(t *testing.T) {
			f := newScopeHoldFixture(t, tc.pack)
			sub := filepath.Join(f.cwd, "sub")
			elsewhere := t.TempDir()
			if err := os.Mkdir(sub, 0o700); err != nil {
				t.Fatal(err)
			}
			listed := true
			f.status = func(server string) watcher.MCPAdmissionStatus {
				if listed && server == "wiki-ok" {
					return watcher.MCPAdmissionStatus{Name: server, Failed: true, ScanIssue: watcher.MCPScanIssueAddress}
				}
				return watcher.MCPAdmissionStatus{}
			}
			f.listUser(scopeHoldServer(scopeHoldFailedURL, ""))
			wantHeldFailed(t, "listed", tc.action, f.call(f.cwd, "s1", "wiki-ok"))
			listed = false
			f.listUser(`{}`)
			wantHeldFailed(t, "removed, same folder", tc.action, f.call(f.cwd, "s1", "wiki-ok"))
			wantHeldFailed(t, "removed, subfolder", tc.action, f.call(sub, "s1", "wiki-ok"))
			wantHeldFailed(t, "removed, another folder", tc.action, f.call(elsewhere, "s1", "wiki-ok"))

			// Benign twins: another session, and a server nothing held.
			wantHeldOrdinary(t, "another session, subfolder", f.call(sub, "s2", "wiki-ok"))
			wantHeldOrdinary(t, "another server, subfolder", f.call(sub, "s1", "wiki-fine"))
		})
	}
}

// A hold under a project scope is the connection of that folder: a call from a
// folder below it meets it, and the same name in another session does not.
func TestFailedMCPAdmissionHoldOfAProjectScopeFollowsTheFolderBelowIt(t *testing.T) {
	f := newSessionHoldFixture(t, "strict")
	sub := filepath.Join(f.project, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	f.list(sessionHoldListed)
	f.wantFailed("listed", "block", f.call("s1", "wiki-ok"))
	f.list(sessionHoldRemoved)
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: f.home})
	resp := f.api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
		SessionID: "s1", HookEventName: "PreToolUse", ToolName: "mcp__wiki-ok__count_words",
		ToolInput: map[string]interface{}{}, CWD: sub,
	})
	f.wantFailed("removed, subfolder", "block", resp)
}

// A failed definition listed again while its new admission is still pending,
// or whose admission cannot be read, has not been admitted: the old failure is
// not released, and removing the entry before the scan completes leaves the
// session held. A completed clean admission releases it.
func TestFailedMCPAdmissionIsNotReleasedByAPendingReadmission(t *testing.T) {
	for _, state := range []string{"pending", "unavailable"} {
		t.Run(state, func(t *testing.T) {
			f := newScopeHoldFixture(t, "strict")
			current := "failed"
			f.status = func(server string) watcher.MCPAdmissionStatus {
				if server != "wiki-ok" {
					return watcher.MCPAdmissionStatus{}
				}
				switch current {
				case "failed":
					return watcher.MCPAdmissionStatus{Name: server, Failed: true, ScanIssue: watcher.MCPScanIssueAddress}
				case "pending":
					return watcher.MCPAdmissionStatus{Name: server, Pending: true}
				case "unavailable":
					return watcher.MCPAdmissionStatus{Name: server, Unavailable: true}
				}
				return watcher.MCPAdmissionStatus{}
			}
			f.listUser(scopeHoldServer(scopeHoldFailedURL, ""))
			wantHeldFailed(t, "failed, listed", "block", f.call(f.cwd, "s1", "wiki-ok"))
			current = "none"
			f.listUser(`{}`)
			wantHeldFailed(t, "removed", "block", f.call(f.cwd, "s1", "wiki-ok"))
			f.listUser(scopeHoldServer(scopeHoldCleanURL, ""))
			wantHeldFailed(t, "edited to a clean definition", "block", f.call(f.cwd, "s1", "wiki-ok"))

			current = state
			f.listUser(scopeHoldServer(scopeHoldFailedURL, ""))
			if got := f.call(f.cwd, "s1", "wiki-ok"); got.Action != "block" || !strings.Contains(got.SourceReason, "mcp-admission-"+state) {
				t.Fatalf("same definition %s: action=%q reason=%q, want the %s block", state, got.Action, got.SourceReason, state)
			}
			current = "none"
			f.listUser(`{}`)
			wantHeldFailed(t, "removed before the new admission completed", "block", f.call(f.cwd, "s1", "wiki-ok"))

			// A completed clean admission of the same definition releases it.
			f.listUser(scopeHoldServer(scopeHoldFailedURL, ""))
			wantHeldOrdinary(t, "listed again, admitted", f.call(f.cwd, "s1", "wiki-ok"))
			f.listUser(`{}`)
			wantHeldOrdinary(t, "removed after it was admitted", f.call(f.cwd, "s1", "wiki-ok"))
		})
	}
}

// A header-only edit is a different definition for admission: the clean
// admission of the edited definition does not release the failed one the
// running agent still connects to, and the hold keeps no header value.
func TestFailedMCPAdmissionHoldKeepsTheFullDefinitionIdentity(t *testing.T) {
	f := newScopeHoldFixture(t, "strict")
	failed := true
	f.status = func(server string) watcher.MCPAdmissionStatus {
		if failed && server == "wiki-ok" {
			return watcher.MCPAdmissionStatus{Name: server, Failed: true}
		}
		return watcher.MCPAdmissionStatus{}
	}
	f.listUser(scopeHoldServer(scopeHoldCleanURL, "old-secret-value"))
	wantHeldFailed(t, "failed first definition", "block", f.call(f.cwd, "s1", "wiki-ok"))
	f.listUser(scopeHoldServer(scopeHoldCleanURL, "new-secret-value"))
	failed = false
	wantHeldFailed(t, "header-only edit admitted clean", "block", f.call(f.cwd, "s1", "wiki-ok"))
	wantHeldOrdinary(t, "header-only edit, another session", f.call(f.cwd, "s2", "wiki-ok"))

	f.api.hookMCP.mu.Lock()
	for _, set := range f.api.hookMCP.refused {
		for _, def := range set.defs {
			if len(def.Headers) != 0 || len(def.Env) != 0 || def.Fingerprint == "" || strings.Contains(def.Fingerprint, "secret") {
				t.Errorf("hold kept a header, an environment value or no digest: %+v", def)
			}
		}
	}
	f.api.hookMCP.mu.Unlock()

	// The failed definition itself listed again and admitted is released.
	f.listUser(scopeHoldServer(scopeHoldCleanURL, "old-secret-value"))
	wantHeldOrdinary(t, "failed definition listed again, admitted", f.call(f.cwd, "s1", "wiki-ok"))
}
