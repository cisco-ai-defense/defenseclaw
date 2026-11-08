// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
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

func claudeMCPCall(api *APIServer, ctx context.Context, project, session, tool string) (config.AssetPolicyDecision, bool) {
	return api.claudeCodeMCPAssetDecision(ctx, claudeCodeHookRequest{
		HookEventName: "PreToolUse", SessionID: session, ToolName: tool, CWD: project,
	})
}

func deniedURLConfig() *config.Config {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{URL: removedDeniedURL}}
	return cfg
}

func managedURLDenyConfig() *config.Config {
	cfg := deniedURLConfig()
	cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
	cfg.Enterprise.Profile = "standalone"
	return cfg
}

func wantDenyBlock(t *testing.T, what string, decision config.AssetPolicyDecision, matched bool) {
	t.Helper()
	if !matched || decision.Action != "block" || decision.Source != "admin-deny" {
		t.Fatalf("%s: matched=%v decision=%+v, want an admin-deny block", what, matched, decision)
	}
}

func wantNotBlocked(t *testing.T, what string, decision config.AssetPolicyDecision, matched bool) {
	t.Helper()
	if matched && decision.Action == "block" {
		t.Fatalf("%s: blocked: %+v", what, decision)
	}
}

// wantUnknownWarning is the verdict on a server found nowhere under a deny
// that pins an endpoint: allowed with a warning in the default tier.
func wantUnknownWarning(t *testing.T, what string, decision config.AssetPolicyDecision, matched bool) {
	t.Helper()
	if !matched || decision.Action != "allow" || decision.RawAction != "block" || decision.Source != "mcp-definition-unproven" {
		t.Fatalf("%s: matched=%v decision=%+v, want an allow with the unproven-definition warning", what, matched, decision)
	}
}

// A server on asset_policy.mcp.denied by URL stays denied for the running
// agent after its entry leaves the agent config or is edited: the agent keeps
// the connection, so the call is judged on the definition its session
// resolved, in every asset_policy mode.
func TestDeniedMCPServerStaysDeniedAfterItsEntryIsRemoved(t *testing.T) {
	for _, mode := range []string{"policy off", "observe", "action"} {
		t.Run(mode, func(t *testing.T) {
			cfg := deniedURLConfig()
			switch mode {
			case "observe":
				cfg.AssetPolicy.Enabled = true
				cfg.AssetPolicy.Mode = config.AssetPolicyModeObserve
			case "action":
				cfg.AssetPolicy.Enabled = true
				cfg.AssetPolicy.Mode = config.AssetPolicyModeAction
			}
			api := &APIServer{scannerCfg: cfg}
			home, project := t.TempDir(), t.TempDir()
			ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
			const tool = "mcp__wiki-rogue__count_words"

			writeClaudeServers(t, home, project, `{"wiki-rogue":{"type":"http","url":"`+removedDeniedURL+`"}}`)
			decision, matched := claudeMCPCall(api, ctx, project, "s1", tool)
			wantDenyBlock(t, "configured", decision, matched)

			writeClaudeServers(t, home, project, `{}`)
			decision, matched = claudeMCPCall(api, ctx, project, "s1", tool)
			wantDenyBlock(t, "removed", decision, matched)

			// The edit of the config does not change the live connection.
			writeClaudeServers(t, home, project, `{"wiki-rogue":{"type":"http","url":"`+removedOtherURL+`"}}`)
			decision, matched = claudeMCPCall(api, ctx, project, "s1", tool)
			wantDenyBlock(t, "redefined to another URL in the same session", decision, matched)

			// Another account is not judged on it.
			otherCtx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1002, Home: t.TempDir()})
			decision, matched = claudeMCPCall(api, otherCtx, project, "s1", tool)
			wantNotBlocked(t, "another account", decision, matched)

			// The agent starting again connects to what the config lists.
			api.mcpSessionStarted(ctx, "claudecode", "s1", "SessionStart", "resume")
			decision, matched = claudeMCPCall(api, ctx, project, "s1", tool)
			wantNotBlocked(t, "redefined to another URL after the session started again", decision, matched)
		})
	}
}

// A new session does not inherit what an earlier one resolved: an ordinary
// server of the same name that its config no longer lists is unknown, and the
// default tier allows it with a warning.
func TestRememberedMCPServerBelongsToItsSession(t *testing.T) {
	api := &APIServer{scannerCfg: deniedURLConfig()}
	home, project := t.TempDir(), t.TempDir()
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
	const tool = "mcp__wiki__count_words"

	writeClaudeServers(t, home, project, `{"wiki":{"type":"http","url":"`+removedDeniedURL+`"}}`)
	decision, matched := claudeMCPCall(api, ctx, project, "old", tool)
	wantDenyBlock(t, "old session", decision, matched)
	writeClaudeServers(t, home, project, `{}`)
	decision, matched = claudeMCPCall(api, ctx, project, "old", tool)
	wantDenyBlock(t, "old session after removal", decision, matched)
	decision, matched = claudeMCPCall(api, ctx, project, "new", tool)
	wantUnknownWarning(t, "new session", decision, matched)

	// A clear or a compaction keeps the connections of the session.
	api.mcpSessionStarted(ctx, "claudecode", "old", "SessionStart", "compact")
	api.mcpSessionStarted(ctx, "claudecode", "old", "SessionStart", "clear")
	api.mcpSessionStarted(ctx, "claudecode", "old", "SessionStart", "")
	decision, matched = claudeMCPCall(api, ctx, project, "old", tool)
	wantDenyBlock(t, "old session after a clear", decision, matched)
	api.mcpSessionStarted(ctx, "claudecode", "old", "SessionStart", "startup")
	decision, matched = claudeMCPCall(api, ctx, project, "old", tool)
	wantUnknownWarning(t, "old session started again", decision, matched)
}

// A server found nowhere cannot be checked against a deny that pins where a
// server points: the default tier allows it with a warning, a managed
// deployment refuses it, also after a gateway restart lost what the session
// had resolved. With no such deny nothing changes.
func TestUnknownMCPServerUnderAnEndpointDeny(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
	writeClaudeServers(t, home, project, `{}`)

	decision, matched := claudeMCPCall(&APIServer{scannerCfg: deniedURLConfig()}, ctx, project, "s1", "mcp__never-seen__count_words")
	wantUnknownWarning(t, "default tier", decision, matched)

	decision, matched = claudeMCPCall(&APIServer{scannerCfg: managedURLDenyConfig()}, ctx, project, "s1", "mcp__never-seen__count_words")
	if !matched || decision.Action != "block" || decision.Source != "mcp-definition-unproven" {
		t.Fatalf("managed: matched=%v decision=%+v, want a block", matched, decision)
	}

	// Gateway restart after the denied connection was removed.
	writeClaudeServers(t, home, project, `{"wiki":{"type":"http","url":"`+removedDeniedURL+`"}}`)
	first := &APIServer{scannerCfg: managedURLDenyConfig()}
	decision, matched = claudeMCPCall(first, ctx, project, "s1", "mcp__wiki__count_words")
	wantDenyBlock(t, "before the restart", decision, matched)
	writeClaudeServers(t, home, project, `{}`)
	restarted := &APIServer{scannerCfg: managedURLDenyConfig()}
	decision, matched = claudeMCPCall(restarted, ctx, project, "s1", "mcp__wiki__count_words")
	if !matched || decision.Action != "block" {
		t.Fatalf("managed after a restart: matched=%v decision=%+v, want a block", matched, decision)
	}
	decision, matched = claudeMCPCall(&APIServer{scannerCfg: deniedURLConfig()}, ctx, project, "s1", "mcp__wiki__count_words")
	wantUnknownWarning(t, "default tier after a restart", decision, matched)

	// Benign twins: no list that pins an endpoint, or only a name rule.
	for name, denied := range map[string][]config.AssetPolicyRule{
		"no lists":           nil,
		"a deny by name":     {{Name: "another-server"}},
		"a deny of its name": {{Name: "other-server", URL: removedDeniedURL}},
	} {
		cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
		cfg.AssetPolicy.MCP.Denied = denied
		cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
		cfg.Enterprise.Profile = "standalone"
		decision, matched := claudeMCPCall(&APIServer{scannerCfg: cfg}, ctx, project, "s1", "mcp__never-seen__count_words")
		if matched {
			t.Fatalf("%s: matched=%v decision=%+v, want no verdict on an ordinary server", name, matched, decision)
		}
	}
}

// Benign twins: a server that was never denied is allowed after its entry
// goes, and a benign redefinition in the same session is allowed.
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
			for _, servers := range []string{
				`{"notes":{"type":"http","url":"` + removedOtherURL + `"}}`,
				`{"notes":{"type":"http","url":"http://127.0.0.1:28773/mcp"}}`,
				`{}`,
			} {
				writeClaudeServers(t, home, project, servers)
				decision, matched := claudeMCPCall(api, ctx, project, "s1", "mcp__notes__count_words")
				wantNotBlocked(t, "servers "+servers, decision, matched)
			}
		})
	}
}

// The remembered definition stays with the server name the tool call carries:
// names that differ in case stay apart, and a Codex tool name that lost the
// punctuation of the configured name finds it.
func TestRememberedMCPServerKeepsTheNameOfTheCall(t *testing.T) {
	t.Run("case distinct names", func(t *testing.T) {
		api := &APIServer{scannerCfg: deniedURLConfig()}
		home, project := t.TempDir(), t.TempDir()
		ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
		write := func(withDenied bool) {
			servers := `{"wiki":{"type":"http","url":"` + removedOtherURL + `"}`
			if withDenied {
				servers += `,"Wiki":{"type":"http","url":"` + removedDeniedURL + `"}`
			}
			writeClaudeServers(t, home, project, servers+`}`)
		}
		write(true)
		decision, matched := claudeMCPCall(api, ctx, project, "s1", "mcp__Wiki__count_words")
		wantDenyBlock(t, "denied name", decision, matched)
		decision, matched = claudeMCPCall(api, ctx, project, "s1", "mcp__wiki__count_words")
		wantNotBlocked(t, "ordinary name", decision, matched)
		write(false)
		decision, matched = claudeMCPCall(api, ctx, project, "s1", "mcp__Wiki__count_words")
		wantDenyBlock(t, "denied name after removal", decision, matched)
		decision, matched = claudeMCPCall(api, ctx, project, "s1", "mcp__wiki__count_words")
		wantNotBlocked(t, "ordinary name after removal", decision, matched)
	})
	t.Run("codex normalized name", func(t *testing.T) {
		api := &APIServer{scannerCfg: deniedURLConfig()}
		home, project := t.TempDir(), t.TempDir()
		ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
		path := filepath.Join(home, ".codex", "config.toml")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		call := func() (config.AssetPolicyDecision, bool) {
			return api.codexMCPAssetDecision(ctx, codexHookRequest{
				HookEventName: "PreToolUse", SessionID: "s1", ToolName: "mcp__acme_notes__count_words", CWD: project,
			})
		}
		if err := os.WriteFile(path, []byte("[mcp_servers.\"acme-notes\"]\nurl = \""+removedDeniedURL+"\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		decision, matched := call()
		wantDenyBlock(t, "configured", decision, matched)
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		decision, matched = call()
		wantDenyBlock(t, "removed", decision, matched)
	})
}

// A denied definition is kept when the memory of ordinary ones is full.
func TestResolvedMCPMemoryKeepsADeniedDefinitionWhenFull(t *testing.T) {
	api := &APIServer{scannerCfg: deniedURLConfig()}
	home, project := t.TempDir(), t.TempDir()
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
	servers := map[string]any{}
	for i := 0; i < mcpResolvedPerHome; i++ {
		servers[fmt.Sprintf("ordinary%d", i)] = map[string]any{"type": "http", "url": removedOtherURL}
	}
	servers["wiki"] = map[string]any{"type": "http", "url": removedDeniedURL}
	write := func() {
		t.Helper()
		data, err := json.Marshal(map[string]any{"projects": map[string]any{filepath.ToSlash(project): map[string]any{"mcpServers": servers}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, ".claude.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	for i := 0; i < mcpResolvedPerHome; i++ {
		decision, matched := claudeMCPCall(api, ctx, project, "s1", fmt.Sprintf("mcp__ordinary%d__count_words", i))
		wantNotBlocked(t, fmt.Sprintf("ordinary call %d", i), decision, matched)
	}
	decision, matched := claudeMCPCall(api, ctx, project, "s1", "mcp__wiki__count_words")
	wantDenyBlock(t, "configured denied server", decision, matched)
	delete(servers, "wiki")
	write()
	decision, matched = claudeMCPCall(api, ctx, project, "s1", "mcp__wiki__count_words")
	wantDenyBlock(t, "denied server after the memory was full", decision, matched)
}

// The memory is bounded per account and in all, a definition expires when it
// has not been used for the TTL, and a session is forgotten as a whole.
func TestResolvedMCPDefinitionMemoryExpiresAndIsBounded(t *testing.T) {
	var memory mcpResolvedDefinitions
	now := time.Now()
	entry := config.MCPServerEntry{Name: "notes", URL: removedDeniedURL}
	memory.remember("claudecode", "/home/a", "s1", "/work", "notes", entry, false, now)
	if got, ok := memory.recall("claudecode", "/home/a", "s1", "/work", "notes", now.Add(mcpResolvedTTL-time.Minute)); !ok || got.URL != removedDeniedURL {
		t.Fatalf("recall within the TTL = %+v, %v", got, ok)
	}
	if _, ok := memory.recall("claudecode", "/home/a", "s1", "/work", "notes", now.Add(2*mcpResolvedTTL)); ok {
		t.Fatal("a definition unused for longer than the TTL was recalled")
	}
	if _, ok := memory.recall("codex", "/home/a", "s1", "/work", "notes", now); ok {
		t.Fatal("a definition was recalled for another connector")
	}
	memory.remember("claudecode", "/home/a", "s1", "/work", "notes", entry, false, now)
	if _, ok := memory.recall("claudecode", "/home/a", "s2", "/work", "notes", now); ok {
		t.Fatal("a definition was recalled for another session")
	}
	for i := 0; i < mcpResolvedPerHome+10; i++ {
		memory.remember("claudecode", "/home/flood", "s1", "/work", fmt.Sprintf("made-up-%d", i), entry, false, now)
	}
	memory.remember("claudecode", "/home/b", "s1", "/work", "notes", entry, false, now)
	if _, ok := memory.recall("claudecode", "/home/b", "s1", "/work", "notes", now); !ok {
		t.Fatal("one account filling its share pushed out another account")
	}
	if len(memory.entries) > mcpResolvedPerHome+2 {
		t.Fatalf("%d entries kept, want the share of one account bounded", len(memory.entries))
	}
	// A denied definition has room of its own, and a later benign one does
	// not replace it.
	if !memory.remember("claudecode", "/home/flood", "s1", "/work", "wiki", entry, true, now) {
		t.Fatal("a denied definition was refused room because ordinary ones filled the memory")
	}
	memory.remember("claudecode", "/home/flood", "s1", "/work", "wiki", config.MCPServerEntry{Name: "wiki", URL: removedOtherURL}, false, now)
	if got, ok := memory.recall("claudecode", "/home/flood", "s1", "/work", "wiki", now); !ok || got.URL != removedDeniedURL {
		t.Fatalf("a benign definition replaced the denied one: %+v, %v", got, ok)
	}
	memory.forgetSession("claudecode", "/home/flood", "s1")
	if _, ok := memory.recall("claudecode", "/home/flood", "s1", "/work", "wiki", now); ok {
		t.Fatal("a forgotten session was recalled")
	}
	if _, ok := memory.recall("claudecode", "/home/b", "s1", "/work", "notes", now); !ok {
		t.Fatal("forgetting one account session dropped another account")
	}
}
