// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const (
	removedDeniedURL = "http://127.0.0.1:28771/mcp"
	removedOtherURL  = "http://127.0.0.1:28772/mcp"
)

func writeClaudeServers(t *testing.T, home, project, servers string) {
	t.Helper()
	state := `{"projects":{"` + filepath.ToSlash(project) + `":{"mcpServers":` + servers + `}}}`
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
}

func claudeMCPCall(api *APIServer, ctx context.Context, project, tool string) (config.AssetPolicyDecision, bool) {
	return api.claudeCodeMCPAssetDecision(ctx, claudeCodeHookRequest{
		HookEventName: "PreToolUse", ToolName: tool, CWD: project,
	})
}

// A server on asset_policy.mcp.denied by URL stays denied for the running
// agent after its entry leaves the agent config: the agent keeps the
// connection, so the call is judged on the definition last resolved, in
// every asset_policy mode.
func TestDeniedMCPServerStaysDeniedAfterItsEntryIsRemoved(t *testing.T) {
	for _, mode := range []string{"policy off", "observe", "action"} {
		t.Run(mode, func(t *testing.T) {
			cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
			switch mode {
			case "observe":
				cfg.AssetPolicy.Enabled = true
				cfg.AssetPolicy.Mode = config.AssetPolicyModeObserve
			case "action":
				cfg.AssetPolicy.Enabled = true
				cfg.AssetPolicy.Mode = config.AssetPolicyModeAction
			}
			cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{URL: removedDeniedURL}}
			api := &APIServer{scannerCfg: cfg}
			home, project := t.TempDir(), t.TempDir()
			ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})

			writeClaudeServers(t, home, project, `{"wiki-rogue":{"type":"http","url":"`+removedDeniedURL+`"}}`)
			decision, matched := claudeMCPCall(api, ctx, project, "mcp__wiki-rogue__count_words")
			if !matched || decision.Action != "block" || decision.Source != "admin-deny" {
				t.Fatalf("configured: matched=%v decision=%+v, want an admin-deny block", matched, decision)
			}

			writeClaudeServers(t, home, project, `{}`)
			decision, matched = claudeMCPCall(api, ctx, project, "mcp__wiki-rogue__count_words")
			if !matched || decision.Action != "block" || decision.Source != "admin-deny" {
				t.Fatalf("removed: matched=%v decision=%+v, want the admin-deny block to hold", matched, decision)
			}

			// Another account, or another server of the same session, is
			// not judged on it.
			otherCtx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1002, Home: t.TempDir()})
			if decision, matched := claudeMCPCall(api, otherCtx, project, "mcp__wiki-rogue__count_words"); matched && decision.Action == "block" {
				t.Fatalf("another account blocked: %+v", decision)
			}
			if decision, matched := claudeMCPCall(api, ctx, project, "mcp__never-seen__count_words"); matched && decision.Action == "block" {
				t.Fatalf("a server never resolved blocked: %+v", decision)
			}

			// The same name defined again elsewhere is judged on the new
			// definition, not on the remembered one.
			writeClaudeServers(t, home, project, `{"wiki-rogue":{"type":"http","url":"`+removedOtherURL+`"}}`)
			if decision, matched := claudeMCPCall(api, ctx, project, "mcp__wiki-rogue__count_words"); matched && decision.Action == "block" {
				t.Fatalf("redefined to a benign URL blocked: %+v", decision)
			}
		})
	}
}

// Benign twins: with no list that pins a URL, or with a server that was never
// denied, removing the entry changes nothing and nothing is blocked.
func TestRemovedMCPServerIsAllowedWithoutADenyForIt(t *testing.T) {
	for name, denied := range map[string][]config.AssetPolicyRule{
		"no lists":            nil,
		"deny of another url": {{URL: removedDeniedURL}},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
			cfg.AssetPolicy.MCP.Denied = denied
			api := &APIServer{scannerCfg: cfg}
			home, project := t.TempDir(), t.TempDir()
			ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
			writeClaudeServers(t, home, project, `{"notes":{"type":"http","url":"`+removedOtherURL+`"}}`)
			for _, servers := range []string{`{"notes":{"type":"http","url":"` + removedOtherURL + `"}}`, `{}`} {
				writeClaudeServers(t, home, project, servers)
				if decision, matched := claudeMCPCall(api, ctx, project, "mcp__notes__count_words"); matched && decision.Action == "block" {
					t.Fatalf("servers %s: blocked: %+v", servers, decision)
				}
			}
		})
	}
}

// The memory is bounded per account and in all, and a definition expires when
// it has not been used for the TTL.
func TestResolvedMCPDefinitionMemoryExpiresAndIsBounded(t *testing.T) {
	var memory mcpResolvedDefinitions
	now := time.Now()
	entry := config.MCPServerEntry{Name: "notes", URL: removedDeniedURL}
	memory.remember("claudecode", "/home/a", "/work", "notes", entry, now)
	if got, ok := memory.recall("claudecode", "/home/a", "/work", "notes", now.Add(mcpResolvedTTL-time.Minute)); !ok || got.URL != removedDeniedURL {
		t.Fatalf("recall within the TTL = %+v, %v", got, ok)
	}
	if _, ok := memory.recall("claudecode", "/home/a", "/work", "notes", now.Add(2*mcpResolvedTTL)); ok {
		t.Fatal("a definition unused for longer than the TTL was recalled")
	}
	if _, ok := memory.recall("codex", "/home/a", "/work", "notes", now); ok {
		t.Fatal("a definition was recalled for another connector")
	}
	for i := 0; i < mcpResolvedPerHome+10; i++ {
		memory.remember("claudecode", "/home/flood", "/work", fmt.Sprintf("made-up-%d", i), entry, now)
	}
	memory.remember("claudecode", "/home/b", "/work", "notes", entry, now)
	if _, ok := memory.recall("claudecode", "/home/b", "/work", "notes", now); !ok {
		t.Fatal("one account filling its share pushed out another account")
	}
	if len(memory.entries) > mcpResolvedPerHome+1 {
		t.Fatalf("%d entries kept, want the share of one account bounded", len(memory.entries))
	}
}
