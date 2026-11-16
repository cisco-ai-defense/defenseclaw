// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const (
	gap0686DeniedURL = "http://127.0.0.1:28561/mcp"
	gap0686OtherURL  = "http://127.0.0.1:28562/mcp"
)

// gap0686Facts is the header a standalone hook sends for a Codex tool call:
// the definition of the server it read in the config file the agent runs.
// It is built as JSON so the test also runs on a tree that has not got the
// field yet.
func gap0686Facts(ctx context.Context, t *testing.T, url string, relocated bool) context.Context {
	t.Helper()
	server := map[string]any{"name": "notes", "url": url}
	if relocated {
		server["relocated"] = true
	}
	raw, err := json.Marshal(map[string]any{"mcp": server})
	if err != nil {
		t.Fatal(err)
	}
	header := http.Header{}
	header.Set("X-DefenseClaw-Asset-Facts", base64.RawURLEncoding.EncodeToString(raw))
	return withClaimedAssetFacts(ctx, header)
}

func gap0686CodexHome(t *testing.T, defaultURL string) string {
	t.Helper()
	home := t.TempDir()
	path := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("[mcp_servers.notes]\nurl = \""+defaultURL+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

// GAP-0686: Codex reads the config.toml under its CODEX_HOME instead of
// ~/.codex/config.toml. A gateway that read the default file first decided
// a same-named server on the old definition: an explicit deny of the
// endpoint that runs became an allow, and a deny of the unused default
// blocked an ordinary call. The hook names the definition it read in the
// file the agent runs, and the gateway judges that one.
func TestGAP0686CodexDenyFollowsTheConfigTheAgentReads(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{URL: gap0686DeniedURL}}
	api := &APIServer{scannerCfg: cfg}
	call := func(home string, facts func(context.Context) context.Context) bool {
		t.Helper()
		ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
		if facts != nil {
			ctx = facts(ctx)
		}
		decision, matched := api.codexMCPAssetDecision(ctx, codexHookRequest{
			HookEventName: "PreToolUse", ToolName: "mcp__notes__count_words", ToolInput: map[string]interface{}{}, CWD: home,
		})
		return matched && decision.Action == "block"
	}
	relocated := func(url string) func(context.Context) context.Context {
		return func(ctx context.Context) context.Context { return gap0686Facts(ctx, t, url, true) }
	}
	// The protected definition runs from CODEX_HOME; the default file holds an
	// old benign one under the same name.
	if !call(gap0686CodexHome(t, gap0686OtherURL), relocated(gap0686DeniedURL)) {
		t.Fatal("a denied endpoint in the CODEX_HOME config was allowed on the verdict of the default file")
	}
	// Benign twin: the benign definition runs from CODEX_HOME while the unused
	// default file holds the denied one.
	if call(gap0686CodexHome(t, gap0686DeniedURL), relocated(gap0686OtherURL)) {
		t.Fatal("an ordinary CODEX_HOME server was refused for a definition Codex does not read")
	}
	// Without a relocated source the default file decides, as before: the
	// denied default is refused and an ordinary one is allowed.
	if !call(gap0686CodexHome(t, gap0686DeniedURL), nil) {
		t.Fatal("a denied endpoint in the default config was allowed")
	}
	if call(gap0686CodexHome(t, gap0686OtherURL), nil) {
		t.Fatal("an ordinary default server was refused")
	}
	plain := func(url string) func(context.Context) context.Context {
		return func(ctx context.Context) context.Context { return gap0686Facts(ctx, t, url, false) }
	}
	if !call(gap0686CodexHome(t, gap0686DeniedURL), plain(gap0686OtherURL)) {
		t.Fatal("a hook claim without a relocated source displaced the gateway reading of the default file")
	}
}
