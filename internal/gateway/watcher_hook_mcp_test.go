// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// GAP-2591: on managed Linux and macOS the gateway service may not read the
// home folders, so the install watcher had no MCP source at all: a server an
// enrolled user added with claude mcp add was never scanned and its tool
// calls were allowed in action mode. The URL server the hook reports with
// the call (read as the user) is now listed for the watcher, so the pending
// check refuses the call and admission scans it; a local server, another
// account and a per-user gateway are left as before.
func TestManagedUnixHookReportedMCPServerIsAdmittedBeforeItsCalls(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed Windows reads the enumerator records instead")
	}
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy(), DeploymentMode: "managed_enterprise",
		Enterprise: config.EnterpriseConfig{Profile: "standalone"}}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Gateway.Watcher.Enabled = true
	if !watcherUsesHookReportedMCP(cfg) || !WatcherWatchesDirs(cfg) {
		t.Fatal("a standalone managed Unix gateway does not run the watcher for hook-reported MCP servers")
	}
	reported := &hookReportedMCPServers{}
	api := &APIServer{scannerCfg: cfg, hookMCP: reported}
	// Stands in for the watcher: a listed server without a baseline is pending.
	admitted := map[string]bool{}
	api.SetMCPAdmissionPending(func(connector, server, home, _ string) (string, bool) {
		servers, _ := reported.list()
		for _, entry := range servers {
			if entry.Connector == connector && entry.Name == server && entry.Home == home && !admitted[home+"|"+server] {
				return server, true
			}
		}
		return "", false
	})
	call := func(uid int, home string, facts assetfacts.Facts, event string) string {
		ctx := context.WithValue(withManagedHookPeer(context.Background(), managedHookPeer{UID: uid, Home: home}),
			claimedAssetFactsContextKey{}, facts)
		resp := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{HookEventName: event,
			ToolName: "mcp__fcctx7__resolve-library-id", ToolInput: map[string]interface{}{}, CWD: home + "/proj"})
		return resp.Action
	}
	url := assetfacts.Facts{MCP: &assetfacts.MCPServer{Name: "fcctx7", URL: "https://mcp.example.com/mcp", Transport: "http"}}
	if got := call(1001, "/home/eng1", url, "PreToolUse"); got != "block" {
		t.Fatalf("first call of a reported URL server: action=%q, want block until admitted", got)
	}
	servers, _ := reported.list()
	if len(servers) != 1 || servers[0].URL != "https://mcp.example.com/mcp" || servers[0].Home != "/home/eng1" ||
		servers[0].Connector != "claudecode" || servers[0].Command != "" || servers[0].RunAsSID != "" {
		t.Fatalf("watched servers %+v, want the URL server of /home/eng1", servers)
	}
	admitted["/home/eng1|fcctx7"] = true
	if got := call(1001, "/home/eng1", url, "PreToolUse"); got == "block" {
		t.Fatalf("admitted server: action=%q, want its verdict to decide", got)
	}
	// Another account with the same name is its own server.
	if got := call(1002, "/home/eng2", url, "PreToolUse"); got != "block" {
		t.Fatalf("other account: action=%q, want its own admission first", got)
	}
	// A changed definition replaces the listed one (the watcher re-admits it).
	if !reported.note(config.MCPServerEntry{Name: "fcctx7", URL: "https://other.example.com/mcp", Connector: "claudecode", Home: "/home/eng1"}) {
		t.Fatal("a changed URL was not recorded")
	}
	// A local server would start as the gateway service account: not listed.
	local := assetfacts.Facts{MCP: &assetfacts.MCPServer{Name: "fcctx7", Command: "npx", Args: []string{"-y", "pkg"}}}
	call(1003, "/home/eng3", local, "PreToolUse")
	// A tool result never lists a server.
	call(1004, "/home/eng4", url, "PostToolUse")
	servers, _ = reported.list()
	for _, entry := range servers {
		if entry.Home == "/home/eng3" || entry.Home == "/home/eng4" {
			t.Fatalf("listed %+v, want no local server and nothing from a tool result", entry)
		}
	}

	// A per-user gateway reads its own files; Secure Client keeps main.
	for _, other := range []*config.Config{
		{AssetPolicy: config.DefaultAssetPolicy()},
		{AssetPolicy: config.DefaultAssetPolicy(), DeploymentMode: "managed_enterprise"},
	} {
		if watcherUsesHookReportedMCP(other) {
			t.Fatalf("config %q/%q lists hook-reported MCP servers", other.DeploymentMode, other.Enterprise.Profile)
		}
	}
}

// One account reporting many servers (its hook facts are its own claim)
// must not use up the list for the other accounts, whose new servers would
// then be left unscanned (GAP-2591 review).
func TestHookReportedMCPServersCapIsPerAccount(t *testing.T) {
	reported := &hookReportedMCPServers{}
	for i := 0; i < hookReportedMCPLimit; i++ {
		reported.note(config.MCPServerEntry{Name: fmt.Sprintf("forged%d", i), URL: "https://mcp.example.com/mcp",
			Connector: "claudecode", Home: "/home/eng1"})
	}
	if servers, _ := reported.list(); len(servers) >= hookReportedMCPLimit {
		t.Fatalf("one account filled the list of every account (%d servers)", len(servers))
	}
	if !reported.note(config.MCPServerEntry{Name: "fcctx7", URL: "https://mcp.example.com/mcp", Connector: "claudecode", Home: "/home/eng2"}) {
		t.Fatal("a new server of another account was not listed after one account reported many")
	}
	// A changed definition of a listed server is still recorded at the cap.
	if !reported.note(config.MCPServerEntry{Name: "forged0", URL: "https://other.example.com/mcp", Connector: "claudecode", Home: "/home/eng1"}) {
		t.Fatal("a changed URL of a listed server was not recorded at the per-account cap")
	}
}

// GAP-0925: a local (stdio) server added with claude mcp add whose launcher
// the scanner refuses (python3, node, a command path) was never listed, so
// it had no admission record and its calls were allowed on a managed device,
// where a URL server is admitted or blocked. It is listed like a URL server,
// the first call waits for the admission, and the recorded refusal blocks
// with the cause and the administrator step. A launcher a scan would start
// (npx, uvx) stays unlisted: nothing here starts it as its user.
func TestManagedUnixHookReportedRefusedLauncherServerIsAdmittedAndBlocked(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed Windows reads the enumerator records instead")
	}
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy(), DeploymentMode: "managed_enterprise",
		Enterprise: config.EnterpriseConfig{Profile: "standalone"}}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Gateway.Watcher.Enabled = true
	reported := &hookReportedMCPServers{}
	api := &APIServer{scannerCfg: cfg, hookMCP: reported}
	// Stands in for the watcher: a listed server is pending until its scan
	// is done, and a refused definition is a failed admission.
	scanned := false
	api.SetMCPAdmissionStatus(func(connector, server, home, _ string) watcher.MCPAdmissionStatus {
		servers, _ := reported.list()
		for _, entry := range servers {
			if entry.Connector == connector && entry.Name == server && entry.Home == home {
				if !scanned {
					return watcher.MCPAdmissionStatus{Name: server, Pending: true, RetryAfter: 30 * time.Second}
				}
				return watcher.MCPAdmissionStatus{Name: server, Failed: true, ScanIssue: watcher.MCPScanIssueLauncher}
			}
		}
		return watcher.MCPAdmissionStatus{}
	})
	call := func(home string, server *assetfacts.MCPServer) claudeCodeHookResponse {
		ctx := context.WithValue(withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home}),
			claimedAssetFactsContextKey{}, assetfacts.Facts{MCP: server})
		return api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{HookEventName: "PreToolUse",
			ToolName: "mcp__" + server.Name + "__ping", ToolInput: map[string]interface{}{}, CWD: home + "/proj"})
	}
	python := &assetfacts.MCPServer{Name: "localpy", Command: "python3", Args: []string{"/home/eng1/server.py"}}
	if got := call("/home/eng1", python); got.Action != "block" {
		t.Fatalf("first call of a reported python3 server: action=%q, want block until admitted", got.Action)
	}
	servers, _ := reported.list()
	if len(servers) != 1 || servers[0].Command != "python3" || len(servers[0].Args) != 1 || servers[0].URL != "" ||
		servers[0].Home != "/home/eng1" || servers[0].Connector != "claudecode" || servers[0].RunAsSID != "" {
		t.Fatalf("watched servers %+v, want the python3 server of /home/eng1", servers)
	}
	scanned = true
	later := call("/home/eng1", python)
	if later.Action != "block" || !strings.Contains(later.Reason, "asset_policy.mcp.allowed") ||
		!strings.Contains(later.Reason, "launcher") {
		t.Fatalf("later call: action=%q reason=%q, want a block naming the launcher and asset_policy.mcp.allowed", later.Action, later.Reason)
	}
	// A changed definition is recorded again (the watcher re-admits it).
	if !reported.note(config.MCPServerEntry{Name: "localpy", Command: "python3", Args: []string{"/home/eng1/other.py"},
		Connector: "claudecode", Home: "/home/eng1"}) {
		t.Fatal("a changed argument list was not recorded")
	}
	// Benign twins: a launcher a scan would start, and an account that has no
	// server of that name, stay as before.
	for _, server := range []*assetfacts.MCPServer{
		{Name: "localnpx", Command: "npx", Args: []string{"-y", "pkg"}},
		{Name: "localuvx", Command: "uvx", Args: []string{"mcp-server-time"}},
	} {
		if got := call("/home/eng2", server); got.Action == "block" {
			t.Fatalf("%s server: action=%q reason=%q, want it left to the asset_policy lists", server.Command, got.Action, got.Reason)
		}
	}
	servers, _ = reported.list()
	for _, entry := range servers {
		if entry.Home == "/home/eng2" {
			t.Fatalf("listed %+v, want no server whose launcher a scan starts", entry)
		}
	}
}
