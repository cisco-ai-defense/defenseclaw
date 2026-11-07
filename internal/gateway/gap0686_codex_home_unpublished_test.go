// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// gap0686Hook sends one Codex tool call of server "notes" to the gateway the
// way a standalone hook does: the claim goes through the real header codec,
// so the bounds the hook fact has apply.
func gap0686Hook(t *testing.T, api *APIServer, home, event string, claim *assetfacts.MCPServer) (config.AssetPolicyDecision, bool) {
	t.Helper()
	header := http.Header{}
	header.Set(assetfacts.Header, assetfacts.Encode(assetfacts.Facts{MCP: claim}))
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
	ctx = withClaimedAssetFacts(ctx, header)
	return api.codexMCPAssetDecision(ctx, codexHookRequest{
		HookEventName: event, ToolName: "mcp__notes__count_words", ToolInput: map[string]interface{}{}, CWD: home,
	})
}

// gap0686Enforcing is a gateway with asset policy enabled in action mode.
func gap0686Enforcing(deniedURLs ...string) (*APIServer, *config.Config) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = config.AssetPolicyModeAction
	for _, url := range deniedURLs {
		cfg.AssetPolicy.MCP.Denied = append(cfg.AssetPolicy.MCP.Denied, config.AssetPolicyRule{URL: url})
	}
	return &APIServer{scannerCfg: cfg}, cfg
}

// gap0686Publish wires the gateway to a real watcher whose admitted servers
// are servers.
func gap0686Publish(api *APIServer, cfg *config.Config, servers ...config.MCPServerEntry) {
	w := watcher.New(cfg, nil, nil, nil, nil, nil, nil)
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) { return servers, nil })
	api.SetMCPPublished(func(connector, server, home, cwd, digest string) watcher.MCPPublication {
		return w.MCPPublished(watcher.MCPAdmissionQuery{Connector: connector, Server: server, Home: home, CWD: cwd}, digest)
	})
}

// claim is the hook fact for a definition read from a source the enumerator
// does not publish.
func gap0686Claim(entry config.MCPServerEntry, relocated bool) *assetfacts.MCPServer {
	if entry.SourceScope == "project" && entry.TrustRequired {
		// The hook sends no claim for a project file Codex does not trust: the
		// definition in effect is the one the gateway already knows.
		return nil
	}
	return &assetfacts.MCPServer{
		Name: entry.Name, URL: entry.URL, Command: entry.Command, Args: entry.Args, Transport: entry.Transport,
		Relocated: relocated, ProjectScope: !relocated, Digest: config.MCPLaunchDigest(entry),
	}
}

// GAP-0686: a CODEX_HOME set only for the session is not in the account
// environment the hook enumerator reads, so the server it defines has no
// install admission and no scan verdict. A managed Windows gateway refuses
// the call until the published record holds the same definition; the default
// file, a persistent CODEX_HOME (both published) and a tool result are not
// refused.
func TestGAP0686SessionOnlyCodexHomeIsRefusedUntilPublished(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	api := &APIServer{scannerCfg: cfg}
	published, asked := false, 0
	entry := config.MCPServerEntry{Name: "notes", URL: gap0686OtherURL}
	api.SetMCPPublished(func(connector, server, home, _, digest string) watcher.MCPPublication {
		asked++
		if connector != "codex" || server != "notes" || home == "" || digest != config.MCPLaunchDigest(entry) {
			t.Errorf("asked about %q %q %q digest %q", connector, server, home, digest)
		}
		return watcher.MCPPublication{Entry: entry, Matched: published, Named: true}
	})
	home := t.TempDir()
	decision, refused := gap0686Hook(t, api, home, "PreToolUse", gap0686Claim(entry, true))
	if !refused || decision.Action != "block" || decision.Source != "mcp-source-unpublished" {
		t.Fatalf("unpublished session-only server: refused=%v decision=%+v, want a block", refused, decision)
	}
	published = true
	if decision, _ := gap0686Hook(t, api, home, "PreToolUse", gap0686Claim(entry, true)); decision.Source == "mcp-source-unpublished" || decision.Action == "block" {
		t.Fatalf("published definition: %+v, want it allowed", decision)
	}
	published = false
	asked = 0
	plain := gap0686Claim(entry, false)
	plain.ProjectScope, plain.Digest = false, ""
	if decision, _ := gap0686Hook(t, api, home, "PreToolUse", plain); decision.Source == "mcp-source-unpublished" || decision.Action == "block" || asked != 0 {
		t.Fatalf("ordinary server from the default config: %+v after %d questions, want it allowed unasked", decision, asked)
	}
	if decision, _ := gap0686Hook(t, api, home, "PostToolUse", gap0686Claim(entry, true)); decision.Source == "mcp-source-unpublished" || asked != 0 {
		t.Fatalf("tool result: %+v after %d questions, want it left alone", decision, asked)
	}
}

// GAP-0686 (review 3): a hook fact is bounded (1,024 bytes a field, 32
// arguments, no environment), and a definition it cannot carry must neither
// vanish, so the default file decides, nor be mistaken for the scanned one.
func TestGAP0686BoundedHookFactStaysBoundToTheCompleteDefinition(t *testing.T) {
	home := t.TempDir()
	longURL := "https://example.invalid/mcp?value=" + strings.Repeat("a", 1100)
	args := make([]string, 33)
	for i := range args {
		args[i] = fmt.Sprintf("arg%d", i)
	}

	t.Run("a long denied URL from a session-only CODEX_HOME is refused", func(t *testing.T) {
		api, cfg := gap0686Enforcing(longURL)
		gap0686Publish(api, cfg) // nothing published
		decision, matched := gap0686Hook(t, api, home, "PreToolUse", gap0686Claim(config.MCPServerEntry{Name: "notes", URL: longURL}, true))
		if !matched || decision.Action != "block" {
			t.Fatalf("a protected long URL was allowed: matched=%v decision=%+v", matched, decision)
		}
	})
	t.Run("a published long denied URL is refused by the rule", func(t *testing.T) {
		api, cfg := gap0686Enforcing(longURL)
		entry := config.MCPServerEntry{Name: "notes", URL: longURL}
		gap0686Publish(api, cfg, config.MCPServerEntry{Name: "notes", URL: longURL, Connector: "codex", Home: home})
		decision, matched := gap0686Hook(t, api, home, "PreToolUse", gap0686Claim(entry, true))
		if !matched || decision.Action != "block" || decision.Source == "mcp-source-unpublished" {
			t.Fatalf("a published denied long URL: matched=%v decision=%+v, want the denied rule to block", matched, decision)
		}
	})
	t.Run("a published ordinary 33-argument server stays allowed", func(t *testing.T) {
		api, cfg := gap0686Enforcing()
		entry := config.MCPServerEntry{Name: "notes", Command: "node", Args: args}
		gap0686Publish(api, cfg, config.MCPServerEntry{Name: "notes", Command: "node", Args: args, Connector: "codex", Home: home})
		if decision, matched := gap0686Hook(t, api, home, "PreToolUse", gap0686Claim(entry, true)); matched && decision.Action == "block" {
			t.Fatalf("a published ordinary server was blocked in balanced: %+v", decision)
		}
	})
	t.Run("a 33-argument server that is not published is refused", func(t *testing.T) {
		api, cfg := gap0686Enforcing()
		other := append(append([]string(nil), args[:32]...), "different")
		gap0686Publish(api, cfg, config.MCPServerEntry{Name: "notes", Command: "node", Args: other, Connector: "codex", Home: home})
		decision, _ := gap0686Hook(t, api, home, "PreToolUse", gap0686Claim(config.MCPServerEntry{Name: "notes", Command: "node", Args: args}, true))
		if decision.Source != "mcp-source-unpublished" {
			t.Fatalf("a definition that differs after the 32nd argument was taken for the published one: %+v", decision)
		}
	})
	t.Run("a changed environment is not the published definition", func(t *testing.T) {
		api, cfg := gap0686Enforcing()
		gap0686Publish(api, cfg, config.MCPServerEntry{
			Name: "notes", Command: "node", Args: []string{"server.js"}, Env: map[string]string{"TARGET": "ordinary"},
			Connector: "codex", Home: home,
		})
		changed := config.MCPServerEntry{Name: "notes", Command: "node", Args: []string{"server.js"}, Env: map[string]string{"TARGET": "protected"}}
		if decision, _ := gap0686Hook(t, api, home, "PreToolUse", gap0686Claim(changed, true)); decision.Source != "mcp-source-unpublished" {
			t.Fatalf("a changed environment was taken for the published definition: %+v", decision)
		}
		same := config.MCPServerEntry{Name: "notes", Command: "node", Args: []string{"server.js"}, Env: map[string]string{"TARGET": "ordinary"}}
		if decision, _ := gap0686Hook(t, api, home, "PreToolUse", gap0686Claim(same, true)); decision.Source == "mcp-source-unpublished" || decision.Action == "block" {
			t.Fatalf("the published definition was refused: %+v", decision)
		}
	})
}

// GAP-0686 (review 3): Codex project config takes precedence over the user
// config, and the enumerator publishes only the user config. A project server
// no published server matches is refused when it would override a published
// server of that name or when asset policy enforces runtime detection in
// action mode; an ordinary one stays usable in balanced.
func TestGAP0686UnpublishedProjectServerIsRefused(t *testing.T) {
	home := t.TempDir()
	project := config.MCPServerEntry{Name: "notes", URL: gap0686OtherURL}
	published := config.MCPServerEntry{Name: "notes", URL: gap0686DeniedURL, Connector: "codex", Home: home}

	api, cfg := gap0686Enforcing()
	gap0686Publish(api, cfg, published)
	if decision, _ := gap0686Hook(t, api, home, "PreToolUse", gap0686Claim(project, false)); decision.Source != "mcp-source-unpublished" || decision.Action != "block" {
		t.Fatalf("a project server overriding a published one: %+v, want a refusal", decision)
	}
	// Enforcing asset policy: a project-only server is unscanned too.
	api, cfg = gap0686Enforcing()
	gap0686Publish(api, cfg)
	if decision, _ := gap0686Hook(t, api, home, "PreToolUse", gap0686Claim(project, false)); decision.Source != "mcp-source-unpublished" || decision.Action != "block" {
		t.Fatalf("an unscanned project server under action-mode asset policy: %+v, want a refusal", decision)
	}
	// Twins that stay allowed: the project definition is the published one,
	// and balanced defaults (asset policy off) with a project-only server.
	api, cfg = gap0686Enforcing()
	gap0686Publish(api, cfg, config.MCPServerEntry{Name: "notes", URL: gap0686OtherURL, Connector: "codex", Home: home})
	if decision, _ := gap0686Hook(t, api, home, "PreToolUse", gap0686Claim(project, false)); decision.Source == "mcp-source-unpublished" || decision.Action == "block" {
		t.Fatalf("a project definition identical to the published one: %+v, want it allowed", decision)
	}
	balanced := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	api = &APIServer{scannerCfg: balanced}
	gap0686Publish(api, balanced)
	if decision, _ := gap0686Hook(t, api, home, "PreToolUse", gap0686Claim(project, false)); decision.Source == "mcp-source-unpublished" || decision.Action == "block" {
		t.Fatalf("a project-only server under balanced defaults: %+v, want it allowed", decision)
	}
}
