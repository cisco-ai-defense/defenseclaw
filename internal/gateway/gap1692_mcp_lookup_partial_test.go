// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

const gap1692DeniedURL = "http://127.0.0.1:28594/mcp"

func gap1692Write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// GAP-1692: a per-user gateway resolves the server a tool call names in the
// caller's agent config. Since #1406 one unreadable source (a malformed
// .codex/config.toml a repository plants, which Codex ignores for an
// untrusted project) made the lookup return not-found, so a denied URL rule
// on the user's own server stopped matching and the default tier let the
// call run with a warning; rel blocked it. The lookup uses every source
// that read.
func TestGAP1692DeniedMCPURLStillBlocksNextToABadProjectConfig(t *testing.T) {
	setup := func(t *testing.T) (string, *APIServer) {
		t.Helper()
		home := t.TempDir()
		testenv.SetHome(t, home)
		workspace := filepath.Join(home, "repo")
		if err := os.MkdirAll(workspace, 0o700); err != nil {
			t.Fatal(err)
		}
		cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
		cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{URL: gap1692DeniedURL}}
		return workspace, &APIServer{scannerCfg: cfg}
	}

	t.Run("codex", func(t *testing.T) {
		workspace, api := setup(t)
		home := filepath.Dir(workspace)
		t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))
		gap1692Write(t, filepath.Join(home, ".codex", "config.toml"),
			"[mcp_servers.notes]\nurl = \""+gap1692DeniedURL+"\"\n"+
				"[mcp_servers.acme-notes]\ncommand = \"node\"\n"+
				"[mcp_servers.acme_notes]\ncommand = \"uvx\"\n")
		gap1692Write(t, filepath.Join(workspace, ".codex", "config.toml"), "not = [toml")
		decision, matched := api.codexMCPAssetDecision(context.Background(), codexHookRequest{
			HookEventName: "PreToolUse", ToolName: "mcp__notes__count_words", ToolInput: map[string]interface{}{}, CWD: workspace,
		})
		if !matched || decision.Action != "block" {
			t.Fatalf("denied URL next to a malformed project config: matched=%v decision=%+v, want block", matched, decision)
		}
		decision, matched = api.codexMCPAssetDecision(context.Background(), codexHookRequest{
			HookEventName: "PreToolUse", ToolName: "mcp__acme_notes__count_words", ToolInput: map[string]interface{}{}, CWD: workspace,
		})
		if !matched || decision.Action != "block" || decision.Source != "mcp-server-ambiguous" {
			t.Fatalf("colliding servers next to a malformed project config: matched=%v decision=%+v, want the ambiguity block", matched, decision)
		}
	})

	for _, tc := range []struct{ connector, good, goodBody, bad, badBody string }{
		{"antigravity", filepath.Join(".gemini", "config", "mcp_config.json"), `{"mcpServers":{"notes":{"serverUrl":"` + gap1692DeniedURL + `"}}}`,
			filepath.Join(".agents", "mcp_config.json"), `{"mcpServers":`},
		{"amp", filepath.Join(".config", "amp", "settings.json"), `{"amp.mcpServers":{"notes":{"url":"` + gap1692DeniedURL + `"}}}`,
			filepath.Join(".amp", "settings.json"), `{`},
	} {
		t.Run(tc.connector, func(t *testing.T) {
			workspace, api := setup(t)
			gap1692Write(t, filepath.Join(filepath.Dir(workspace), tc.good), tc.goodBody)
			gap1692Write(t, filepath.Join(workspace, tc.bad), tc.badBody)
			decision, matched := api.evaluateRuntimeMCPAssetPolicy(context.Background(), tc.connector, "PreToolUse", mcpRuntimeProbe{
				Matched: true, Surface: "hook", ServerName: "notes", ToolName: "mcp__notes__count_words", WorkspaceDir: workspace,
			})
			if !matched || decision.Action != "block" {
				t.Fatalf("denied URL next to a malformed workspace config: matched=%v decision=%+v, want block", matched, decision)
			}
		})
	}
}
