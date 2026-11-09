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
	memory.remember("claudecode", "/home/a", "s1", "/work", "notes", entry, false, mcpOneDefinition, now)
	if got, ok := memory.recall("claudecode", "/home/a", "s1", "/work", "notes", now.Add(mcpResolvedTTL-time.Minute)); !ok || got.URL != removedDeniedURL {
		t.Fatalf("recall within the TTL = %+v, %v", got, ok)
	}
	if _, ok := memory.recall("claudecode", "/home/a", "s1", "/work", "notes", now.Add(2*mcpResolvedTTL)); ok {
		t.Fatal("a definition unused for longer than the TTL was recalled")
	}
	if _, ok := memory.recall("codex", "/home/a", "s1", "/work", "notes", now); ok {
		t.Fatal("a definition was recalled for another connector")
	}
	memory.remember("claudecode", "/home/a", "s1", "/work", "notes", entry, false, mcpOneDefinition, now)
	if _, ok := memory.recall("claudecode", "/home/a", "s2", "/work", "notes", now); ok {
		t.Fatal("a definition was recalled for another session")
	}
	for i := 0; i < mcpResolvedPerHome+10; i++ {
		memory.remember("claudecode", "/home/flood", "s1", "/work", fmt.Sprintf("made-up-%d", i), entry, false, mcpOneDefinition, now)
	}
	memory.remember("claudecode", "/home/b", "s1", "/work", "notes", entry, false, mcpOneDefinition, now)
	if _, ok := memory.recall("claudecode", "/home/b", "s1", "/work", "notes", now); !ok {
		t.Fatal("one account filling its share pushed out another account")
	}
	if len(memory.entries) > mcpResolvedPerHome+2 {
		t.Fatalf("%d entries kept, want the share of one account bounded", len(memory.entries))
	}
	// A denied definition has room of its own, and a later benign one does
	// not replace it.
	if !memory.remember("claudecode", "/home/flood", "s1", "/work", "wiki", entry, true, mcpOneDefinition, now) {
		t.Fatal("a denied definition was refused room because ordinary ones filled the memory")
	}
	memory.remember("claudecode", "/home/flood", "s1", "/work", "wiki", config.MCPServerEntry{Name: "wiki", URL: removedOtherURL}, false, mcpOneDefinition, now)
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

func allowedURLConfig(managedMode bool, mode string) *config.Config {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = mode
	cfg.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{URL: removedDeniedURL}}
	if managedMode {
		cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
		cfg.Enterprise.Profile = "standalone"
	}
	return cfg
}

// A server found nowhere cannot be checked against an allowed list that pins
// an endpoint either: with asset_policy enabled the call gets the same
// verdict as under an endpoint deny (a warning in the default tier, a block
// in a managed one, the asset_policy mode for the allowed list), and nothing
// changes while the policy is off or the rule does not pin an endpoint.
func TestUnknownMCPServerUnderAnEndpointAllowedList(t *testing.T) {
	home, project := t.TempDir(), t.TempDir()
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
	writeClaudeServers(t, home, project, `{}`)
	call := func(cfg *config.Config) (config.AssetPolicyDecision, bool) {
		return claudeMCPCall(&APIServer{scannerCfg: cfg}, ctx, project, "s1", "mcp__never-seen__count_words")
	}

	decision, matched := call(allowedURLConfig(false, config.AssetPolicyModeAction))
	wantUnknownWarning(t, "default tier", decision, matched)
	decision, matched = call(allowedURLConfig(true, config.AssetPolicyModeAction))
	if !matched || decision.Action != "block" || decision.Source != "mcp-definition-unproven" {
		t.Fatalf("managed: matched=%v decision=%+v, want a block", matched, decision)
	}
	decision, matched = call(allowedURLConfig(true, config.AssetPolicyModeObserve))
	if !matched || decision.Action != "allow" || decision.Source != "mcp-definition-unproven" || !decision.WouldBlock {
		t.Fatalf("managed with asset_policy in observe mode: matched=%v decision=%+v, want an allow with the warning", matched, decision)
	}
	strict := allowedURLConfig(false, config.AssetPolicyModeAction)
	strict.Guardrail.RulePack = "strict"
	decision, matched = call(strict)
	if !matched || decision.Action != "block" || decision.Source != "mcp-definition-unproven" {
		t.Fatalf("strict: matched=%v decision=%+v, want a block", matched, decision)
	}

	// Benign twins.
	off := allowedURLConfig(true, config.AssetPolicyModeAction)
	off.AssetPolicy.Enabled = false
	if decision, matched = call(off); matched {
		t.Fatalf("policy off: matched=%v decision=%+v, want no verdict", matched, decision)
	}
	noDetection := allowedURLConfig(true, config.AssetPolicyModeAction)
	noDetection.AssetPolicy.MCP.RuntimeDetection.Enabled = false
	if decision, matched = call(noDetection); matched {
		t.Fatalf("runtime detection off: matched=%v decision=%+v, want no verdict", matched, decision)
	}
	nameOnly := allowedURLConfig(true, config.AssetPolicyModeAction)
	nameOnly.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: "never-seen"}}
	if decision, matched = call(nameOnly); matched {
		t.Fatalf("name-only allowed rule: matched=%v decision=%+v, want no verdict", matched, decision)
	}
	other := allowedURLConfig(true, config.AssetPolicyModeAction)
	other.AssetPolicy.MCP.Allowed = []config.AssetPolicyRule{{Name: "another-server", URL: removedDeniedURL}}
	if decision, matched = call(other); matched {
		t.Fatalf("allowed rule of another server: matched=%v decision=%+v, want no verdict", matched, decision)
	}
}

// More denied definitions than the memory holds for one account do not let
// the last one run once its entry is gone, in any tier: the definition is held
// apart and judged on the policy in force. Another session keeps the ordinary
// verdicts.
func TestDeniedMCPServerPastTheMemoryLimitStaysDenied(t *testing.T) {
	servers := map[string]any{}
	for i := 0; i < mcpResolvedDeniedPerHome; i++ {
		servers[fmt.Sprintf("denied%d", i)] = map[string]any{"type": "http", "url": removedDeniedURL}
	}
	servers["wiki"] = map[string]any{"type": "http", "url": removedDeniedURL}
	for name, cfg := range map[string]*config.Config{"default tier": deniedURLConfig(), "managed": managedURLDenyConfig()} {
		t.Run(name, func(t *testing.T) {
			api := &APIServer{scannerCfg: cfg}
			home, project := t.TempDir(), t.TempDir()
			ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
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
			for i := 0; i < mcpResolvedDeniedPerHome; i++ {
				decision, matched := claudeMCPCall(api, ctx, project, "s1", fmt.Sprintf("mcp__denied%d__count_words", i))
				wantDenyBlock(t, fmt.Sprintf("denied call %d", i), decision, matched)
			}
			decision, matched := claudeMCPCall(api, ctx, project, "s1", "mcp__wiki__count_words")
			wantDenyBlock(t, "configured denied server past the limit", decision, matched)
			delete(servers, "wiki")
			defer func() { servers["wiki"] = map[string]any{"type": "http", "url": removedDeniedURL} }()
			write()
			decision, matched = claudeMCPCall(api, ctx, project, "s1", "mcp__wiki__count_words")
			wantDenyBlock(t, "removed denied server past the limit", decision, matched)
			if name == "default tier" {
				decision, matched = claudeMCPCall(api, ctx, project, "other-session", "mcp__wiki__count_words")
				wantUnknownWarning(t, "another session of the same account", decision, matched)
			}
		})
	}
}

// A denied definition that did not fit is held whole for its name, belongs to
// its session, expires with the TTL and is dropped when the session starts
// again.
func TestResolvedMCPMemoryHoldsLostDeniedDefinitionsPerSession(t *testing.T) {
	var memory mcpResolvedDefinitions
	now := time.Now()
	entry := config.MCPServerEntry{Name: "notes", URL: removedDeniedURL}
	lost := func(connector, home, session, cwd, name string, at time.Time) bool {
		_, held, _ := memory.lostDenied(connector, home, session, cwd, name, at)
		return held
	}
	for i := 0; i < mcpResolvedDeniedPerHome; i++ {
		if !memory.remember("claudecode", "/home/a", "s1", "/work", fmt.Sprintf("denied%d", i), entry, true, mcpOneDefinition, now) {
			t.Fatalf("denied definition %d refused below the limit", i)
		}
	}
	if lost("claudecode", "/home/a", "s1", "/work", "one-too-many", now) {
		t.Fatal("a session within the limit holds a lost definition")
	}
	if memory.remember("claudecode", "/home/a", "s1", "/work", "one-too-many", entry, true, mcpOneDefinition, now) {
		t.Fatal("a denied definition past the limit was kept")
	}
	got, held, _ := memory.lostDenied("claudecode", "/home/a", "s1", "/work", "one-too-many", now)
	if !held || !sameMCPDefinition(got, entry) {
		t.Fatalf("lost denied definition not held whole: held=%v entry=%+v", held, got)
	}
	// The first one held for a name stays.
	memory.remember("claudecode", "/home/a", "s1", "/work", "one-too-many", config.MCPServerEntry{Name: "notes", URL: removedOtherURL}, true, mcpOneDefinition, now)
	if got, _, _ := memory.lostDenied("claudecode", "/home/a", "s1", "/work", "one-too-many", now); got.URL != removedDeniedURL {
		t.Fatalf("a later definition replaced the lost one: %+v", got)
	}
	if lost("claudecode", "/home/a", "s1", "/work", "never-lost", now) {
		t.Fatal("a name that was not lost was reported")
	}
	if lost("claudecode", "/home/a", "s2", "/work", "one-too-many", now) ||
		lost("codex", "/home/a", "s1", "/work", "one-too-many", now) ||
		lost("claudecode", "/home/b", "s1", "/work", "one-too-many", now) ||
		lost("claudecode", "/home/a", "s1", "/other", "one-too-many", now) {
		t.Fatal("the definition leaked to another session, connector, account or directory")
	}
	if lost("claudecode", "/home/a", "s1", "/work", "one-too-many", now.Add(2*mcpResolvedTTL)) {
		t.Fatal("the definition outlived the TTL")
	}
	memory.remember("claudecode", "/home/a", "s1", "/work", "one-too-many", entry, true, mcpOneDefinition, now)
	memory.forgetSession("claudecode", "/home/a", "s1")
	if lost("claudecode", "/home/a", "s1", "/work", "one-too-many", now) {
		t.Fatal("a session that started again kept its lost definition")
	}
}

// The lost definitions are exact: no number of names makes an unrecorded one
// answer yes, and every session keeps its own, however many sessions there
// are, so a session that starts again drops its own whatever the others hold.
func TestResolvedMCPMemoryLostDefinitionsAreExactPerSession(t *testing.T) {
	var memory mcpResolvedDefinitions
	now := time.Now()
	entry := config.MCPServerEntry{Name: "wiki", URL: removedDeniedURL}
	sessions := mcpResolvedDeniedPerHome + 100
	memory.mu.Lock()
	for i := 0; i < sessions; i++ {
		session := fmt.Sprintf("flood%d", i)
		memory.markLostLocked("claudecode", "/home/a", session, mcpResolvedKey("claudecode", "/home/a", session, "/work", "wiki"), entry, mcpOneDefinition, now)
	}
	for i := 0; i < 20000; i++ {
		memory.markLostLocked("claudecode", "/home/a", "big", mcpResolvedKey("claudecode", "/home/a", "big", "/work", fmt.Sprintf("lost%d", i)), entry, mcpOneDefinition, now)
	}
	memory.mu.Unlock()
	for i := 0; i < sessions; i++ {
		if _, held, over := memory.lostDenied("claudecode", "/home/a", fmt.Sprintf("flood%d", i), "/work", "wiki", now); !held || over {
			t.Fatalf("session %d: held=%v overflow=%v, want its definition", i, held, over)
		}
	}
	for i := 0; i < 20000; i++ {
		if _, held, _ := memory.lostDenied("claudecode", "/home/a", "big", "/work", fmt.Sprintf("lost%d", i), now); !held {
			t.Fatalf("lost%d was held and not found", i)
		}
		if _, held, over := memory.lostDenied("claudecode", "/home/a", "big", "/work", fmt.Sprintf("ordinary%d", i), now); held || over {
			t.Fatalf("ordinary%d: held=%v overflow=%v, want neither", i, held, over)
		}
	}
	memory.forgetSession("claudecode", "/home/a", "flood0")
	if _, held, over := memory.lostDenied("claudecode", "/home/a", "flood0", "/work", "wiki", now); held || over {
		t.Fatal("a session that started again kept its definition")
	}
	if _, held, _ := memory.lostDenied("claudecode", "/home/a", "flood1", "/work", "wiki", now); !held {
		t.Fatal("restarting one session dropped the definition of another")
	}
}

// A session that cannot hold one more lost denied definition (they are full)
// is marked: a name a denied rule covers is refused there, and the mark is
// dropped with the session.
func TestResolvedMCPMemoryMarksASessionThatCannotHoldMore(t *testing.T) {
	var memory mcpResolvedDefinitions
	now := time.Now()
	entry := config.MCPServerEntry{Name: "wiki", URL: removedDeniedURL}
	memory.mu.Lock()
	for i := 0; i < mcpResolvedLostLimit; i++ {
		memory.markLostLocked("claudecode", "/home/a", "full", mcpResolvedKey("claudecode", "/home/a", "full", "/work", fmt.Sprintf("lost%d", i)), entry, mcpOneDefinition, now)
	}
	if memory.lostCountLocked() != mcpResolvedLostLimit {
		t.Fatalf("%d definitions held, want %d", memory.lostCountLocked(), mcpResolvedLostLimit)
	}
	memory.markLostLocked("claudecode", "/home/a", "late", mcpResolvedKey("claudecode", "/home/a", "late", "/work", "wiki"), entry, mcpOneDefinition, now)
	memory.mu.Unlock()
	if _, held, over := memory.lostDenied("claudecode", "/home/a", "late", "/work", "wiki", now); held || !over {
		t.Fatalf("late: held=%v overflow=%v, want a session mark", held, over)
	}
	if _, held, over := memory.lostDenied("claudecode", "/home/a", "full", "/work", "ordinary", now); held || over {
		t.Fatal("a session that filled the records was marked without losing one")
	}
	if _, _, over := memory.lostDenied("claudecode", "/home/a", "late", "/work", "wiki", now.Add(2*mcpResolvedTTL)); over {
		t.Fatal("the mark outlived the TTL")
	}
	memory.forgetSession("claudecode", "/home/a", "late")
	if _, _, over := memory.lostDenied("claudecode", "/home/a", "late", "/work", "wiki", now); over {
		t.Fatal("a session that started again kept its mark")
	}
}

// A denied server past the memory limit is still denied once its config entry
// is edited to an ordinary endpoint in the same session, in every profile.
// Another server of the session, another session and a server that was never
// denied keep the ordinary verdicts.
func TestDeniedMCPServerPastTheMemoryLimitStaysDeniedAfterAnEdit(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *config.Config
		pack string
	}{
		{"default", deniedURLConfig(), ""},
		{"permissive", deniedURLConfig(), "permissive"},
		{"strict", deniedURLConfig(), "strict"},
		{"managed", managedURLDenyConfig(), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.pack != "" {
				tc.cfg.Guardrail.RulePack = tc.pack
			}
			api := &APIServer{scannerCfg: tc.cfg}
			home, project := t.TempDir(), t.TempDir()
			ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
			servers := map[string]any{}
			write := func() { writeClaudeServerMap(t, home, project, servers) }
			fillDeniedMCPPartition(t, api, ctx, project, servers, write)
			servers["calendar"] = map[string]any{"type": "http", "url": removedOtherURL}
			write()
			servers["wiki"] = map[string]any{"type": "http", "url": removedOtherURL}
			write()
			decision, matched := claudeMCPCall(api, ctx, project, "s1", "mcp__wiki__count_words")
			wantDenyBlock(t, "edited denied server past the limit", decision, matched)
			// Benign twins.
			decision, matched = claudeMCPCall(api, ctx, project, "s1", "mcp__calendar__count_words")
			wantNotBlocked(t, "ordinary server of the same session", decision, matched)
			decision, matched = claudeMCPCall(api, ctx, project, "other-session", "mcp__wiki__count_words")
			wantNotBlocked(t, "another session", decision, matched)
		})
	}
}

// A Codex server denied by its configured name, whose denied definition did
// not fit in the memory (the partition was filled by Claude calls of the same
// account), is still denied after its entry is removed from the Codex config.
func TestCodexNameDenyPastTheMemoryLimitSurvivesRemoval(t *testing.T) {
	for name, managedMode := range map[string]bool{"default tier": false, "managed": true} {
		t.Run(name, func(t *testing.T) {
			cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
			cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{Connector: "claudecode", URL: removedDeniedURL}, {Connector: "codex", Name: "acme-notes"}}
			if managedMode {
				cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
				cfg.Enterprise.Profile = "standalone"
			}
			api := &APIServer{scannerCfg: cfg}
			home, project := t.TempDir(), t.TempDir()
			ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
			servers := map[string]any{}
			fillDeniedMCPPartition(t, api, ctx, project, servers, func() { writeClaudeServerMap(t, home, project, servers) })
			path := filepath.Join(home, ".codex", "config.toml")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			write := func(content string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			call := func(tool string) (config.AssetPolicyDecision, bool) {
				return api.codexMCPAssetDecision(ctx, codexHookRequest{
					HookEventName: "PreToolUse", SessionID: "s1", ToolName: tool, CWD: project,
				})
			}
			write("[mcp_servers.\"acme-notes\"]\nurl = \"" + removedOtherURL + "\"\n[mcp_servers.calendar]\nurl = \"" + removedOtherURL + "\"\n")
			decision, matched := call("mcp__acme_notes__count_words")
			wantDenyBlock(t, "configured Codex name deny", decision, matched)
			write("[mcp_servers.calendar]\nurl = \"" + removedOtherURL + "\"\n")
			decision, matched = call("mcp__acme_notes__count_words")
			wantDenyBlock(t, "removed Codex name-denied server past the limit", decision, matched)
			// Benign twin: a server no rule denies.
			decision, matched = call("mcp__calendar__count_words")
			wantNotBlocked(t, "ordinary Codex server", decision, matched)
		})
	}
}

// A config edit that only renames the entry (a Codex tool name folds both
// spellings into one) does not make the live connection benign when a rule
// denies the old name.
func TestRenamedCodexServerKeepsTheDenyOfItsOldName(t *testing.T) {
	for name, cfg := range map[string]*config.Config{"default tier": deniedURLConfig(), "managed": managedURLDenyConfig()} {
		t.Run(name, func(t *testing.T) {
			cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{Name: "acme-notes"}}
			api := &APIServer{scannerCfg: cfg}
			home, project := t.TempDir(), t.TempDir()
			ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
			path := filepath.Join(home, ".codex", "config.toml")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			write := func(server string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("[mcp_servers.\""+server+"\"]\nurl = \""+removedOtherURL+"\"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			call := func(session string) (config.AssetPolicyDecision, bool) {
				return api.codexMCPAssetDecision(ctx, codexHookRequest{
					HookEventName: "PreToolUse", SessionID: session, ToolName: "mcp__acme_notes__count_words", CWD: project,
				})
			}
			write("acme-notes")
			decision, matched := call("s1")
			wantDenyBlock(t, "configured name", decision, matched)
			write("acme.notes")
			decision, matched = call("s1")
			wantDenyBlock(t, "after a rename with the same endpoint", decision, matched)
			// Benign twin: a session that began after the edit connects to
			// the renamed server, which no rule denies.
			decision, matched = call("s2")
			wantNotBlocked(t, "new session after the rename", decision, matched)
		})
	}
}

// fillDeniedMCPPartition makes a session resolve and be denied on as many
// servers as one account keeps, so the next denied definition does not fit.
// The first filler is resolved by a real call of the hook path; the others
// enter the memory through its own remember, the function that call ends in,
// because a real call reads and parses the whole agent config, and 1,024
// calls on a config of 1,025 servers took minutes on a CI runner without
// exercising anything the first call did not. The last server then does not
// fit and must be held whole in the lost set of its session.
func fillDeniedMCPPartition(t *testing.T, api *APIServer, ctx context.Context, project string, servers map[string]any, write func()) {
	t.Helper()
	peer, ok := managedHookPeerFromContext(ctx)
	if !ok {
		t.Fatal("the context carries no hook peer")
	}
	servers["filler0"] = map[string]any{"type": "http", "url": removedDeniedURL}
	servers["wiki"] = map[string]any{"type": "http", "url": removedDeniedURL}
	write()
	decision, matched := claudeMCPCall(api, ctx, project, "s1", "mcp__filler0__count_words")
	wantDenyBlock(t, "filler 0", decision, matched)
	for i := 1; i < mcpResolvedDeniedPerHome; i++ {
		name := fmt.Sprintf("filler%d", i)
		entry := config.MCPServerEntry{Name: name, URL: removedDeniedURL, Transport: "http"}
		if !api.mcpResolved.remember("claudecode", peer.Home, "s1", project, name, entry, true, mcpOneDefinition, time.Now()) {
			t.Fatalf("denied definition %d does not fit below the limit", i)
		}
	}
	decision, matched = claudeMCPCall(api, ctx, project, "s1", "mcp__wiki__count_words")
	wantDenyBlock(t, "denied server that does not fit", decision, matched)
	if _, held, _ := api.mcpResolved.lostDenied("claudecode", peer.Home, "s1", project, "wiki", time.Now()); !held {
		t.Fatal("the denied definition that does not fit is not held in the lost set of its session")
	}
}

// A denied definition the memory could not keep is judged on the policy in
// force now: while the rule that matched it is in the denied list (reworded,
// or beside others) the live connection stays denied, and once the rule is
// replaced by one for another endpoint the server is ordinary, in every
// profile.
func TestLostDeniedMCPDefinitionFollowsTheDeniedListInForce(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  func() *config.Config
	}{
		{"default", deniedURLConfig},
		{"managed", managedURLDenyConfig},
		{"strict", func() *config.Config {
			cfg := deniedURLConfig()
			cfg.Guardrail.RulePack = "strict"
			return cfg
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg()
			api := &APIServer{scannerCfg: cfg}
			home, project := t.TempDir(), t.TempDir()
			ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
			servers := map[string]any{}
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
			fillDeniedMCPPartition(t, api, ctx, project, servers, write)
			// The entry leaves the config. The rule is reworded and joined by
			// another: the connection is still the denied one.
			delete(servers, "wiki")
			write()
			cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{URL: "http://127.0.0.1:28773/mcp"}, {URL: removedDeniedURL, Reason: "reworded"}}
			decision, matched := claudeMCPCall(api, ctx, project, "s1", "mcp__wiki__count_words")
			wantDenyBlock(t, "rule reworded", decision, matched)
			// The rule is replaced by one for another endpoint and the server
			// is configured on an ordinary endpoint: nothing denies it now.
			cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{URL: "http://127.0.0.1:28773/mcp"}}
			servers["wiki"] = map[string]any{"type": "http", "url": removedOtherURL}
			write()
			decision, matched = claudeMCPCall(api, ctx, project, "s1", "mcp__wiki__count_words")
			wantNotBlocked(t, "ordinary server after the rule was replaced", decision, matched)
		})
	}
}

// A session that starts again drops the record of a denied definition that
// did not fit, however many other sessions hold one, so a fresh connection to
// an ordinary server of the same name is allowed.
func TestRestartedSessionDropsItsLostDeniedRecordAmongManySessions(t *testing.T) {
	api := &APIServer{scannerCfg: deniedURLConfig()}
	home, project := t.TempDir(), t.TempDir()
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
	entry := config.MCPServerEntry{Name: "wiki", URL: removedDeniedURL, Transport: "http"}
	api.mcpResolved.mu.Lock()
	for i := 0; i < 2*mcpResolvedDeniedPerHome; i++ {
		session := fmt.Sprintf("flood%d", i)
		api.mcpResolved.markLostLocked("claudecode", home, session, mcpResolvedKey("claudecode", home, session, project, "lost"), entry, mcpOneDefinition, time.Now())
	}
	api.mcpResolved.markLostLocked("claudecode", home, "s1", mcpResolvedKey("claudecode", home, "s1", project, "wiki"), entry, mcpOneDefinition, time.Now())
	api.mcpResolved.mu.Unlock()
	writeClaudeServers(t, home, project, `{"wiki":{"type":"http","url":"`+removedOtherURL+`"}}`)
	decision, matched := claudeMCPCall(api, ctx, project, "s1", "mcp__wiki__count_words")
	wantDenyBlock(t, "before the restart", decision, matched)
	api.mcpSessionStarted(ctx, "claudecode", "s1", "SessionStart", "resume")
	decision, matched = claudeMCPCall(api, ctx, project, "s1", "mcp__wiki__count_words")
	wantNotBlocked(t, "ordinary server after the session restarted", decision, matched)
}

// A denied definition the memory could not keep is judged on the policy in
// force now, as every remembered one is, not on the rule that matched it
// then: another rule that denies the same endpoint, an equivalent spelling of
// the connector, a second matching rule that stays, all keep the live
// connection denied; a connector-scoped allow for the endpoint releases it,
// and so does a policy that no longer denies it.
func TestLostDeniedMCPDefinitionIsJudgedOnThePolicyInForce(t *testing.T) {
	for _, tc := range []struct {
		name    string
		before  []config.AssetPolicyRule
		after   []config.AssetPolicyRule
		allowed []config.AssetPolicyRule
		denied  bool
	}{
		{"replacement rule denies the same endpoint", nil, []config.AssetPolicyRule{{Transport: "http"}}, nil, true},
		{"equivalent connector spelling", []config.AssetPolicyRule{{Connector: "claudecode", URL: removedDeniedURL}},
			[]config.AssetPolicyRule{{Connector: "claude-code", URL: removedDeniedURL}}, nil, true},
		{"a second matching rule remains", []config.AssetPolicyRule{{URL: removedDeniedURL}, {Transport: "http"}},
			[]config.AssetPolicyRule{{Transport: "http"}}, nil, true},
		{"rule reworded", nil, []config.AssetPolicyRule{{URL: removedDeniedURL, Reason: "reworded"}}, nil, true},
		{"scoped allow supersedes the old deny", nil, nil,
			[]config.AssetPolicyRule{{Connector: "claudecode", URL: removedDeniedURL}}, false},
		{"policy no longer denies the endpoint", nil, []config.AssetPolicyRule{{URL: "http://127.0.0.1:28773/mcp"}}, nil, false},
	} {
		for _, profile := range []string{"default", "managed"} {
			t.Run(tc.name+"/"+profile, func(t *testing.T) {
				cfg := deniedURLConfig()
				if profile == "managed" {
					cfg = managedURLDenyConfig()
				}
				if tc.before != nil {
					cfg.AssetPolicy.MCP.Denied = tc.before
				}
				api := &APIServer{scannerCfg: cfg}
				home, project := t.TempDir(), t.TempDir()
				ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
				servers := map[string]any{}
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
				fillDeniedMCPPartition(t, api, ctx, project, servers, write)
				delete(servers, "wiki")
				write()
				if tc.after != nil {
					cfg.AssetPolicy.MCP.Denied = tc.after
				}
				if tc.allowed != nil {
					cfg.AssetPolicy.MCP.Allowed = tc.allowed
				}
				decision, matched := claudeMCPCall(api, ctx, project, "s1", "mcp__wiki__count_words")
				if tc.denied {
					if !matched || decision.Action != "block" {
						t.Fatalf("matched=%v decision=%+v, want a block of the live connection", matched, decision)
					}
					return
				}
				wantNotBlocked(t, "live connection the policy in force no longer denies", decision, matched)
			})
		}
	}
}
