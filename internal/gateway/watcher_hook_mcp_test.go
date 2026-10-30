// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
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
