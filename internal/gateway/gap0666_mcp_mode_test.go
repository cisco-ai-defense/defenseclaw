// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// An explicit MCP deny is an admission decision. Its final connector response
// must stay a veto while guardrail findings are only observed.
func TestGAP0666ExplicitMCPDenyAcrossHookModes(t *testing.T) {
	const deniedURL = "http://127.0.0.1:28561/mcp"
	const ordinaryURL = "http://127.0.0.1:28562/mcp"
	for _, mode := range []string{"observe", "action"} {
		for _, enabled := range []bool{false, true} {
			for _, source := range []string{"claude local", "codex url", "claude command line"} {
				for _, endpoint := range []string{deniedURL, ordinaryURL} {
					name := mode + "/" + source + "/" + endpoint
					if enabled {
						name += "/asset policy enabled"
					}
					t.Run(name, func(t *testing.T) {
						connectorName := "claudecode"
						if source == "codex url" {
							connectorName = "codex"
						}
						cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
						cfg.Guardrail.Mode = mode
						cfg.Guardrail.Connector = connectorName
						cfg.AssetPolicy.Enabled = enabled
						cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{URL: deniedURL}}
						api := &APIServer{scannerCfg: cfg}
						home := t.TempDir()
						ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
						switch source {
						case "claude local":
							state := `{"mcpServers":{"notes":{"type":"http","url":"` + endpoint + `"}}}`
							if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(state), 0o600); err != nil {
								t.Fatal(err)
							}
						case "codex url":
							if err := os.Mkdir(filepath.Join(home, ".codex"), 0o700); err != nil {
								t.Fatal(err)
							}
							state := "[mcp_servers.notes]\nurl = \"" + endpoint + "\"\n"
							if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte(state), 0o600); err != nil {
								t.Fatal(err)
							}
						case "claude command line":
							ctx = context.WithValue(ctx, claimedAssetFactsContextKey{}, assetfacts.Facts{MCP: &assetfacts.MCPServer{
								Name: "notes", URL: endpoint, Source: assetfacts.SourceCommandLine,
							}})
						}
						var action, rawAction, reason string
						var nativeOutput map[string]interface{}
						if connectorName == "codex" {
							resp := api.evaluateCodexHook(ctx, codexHookRequest{
								HookEventName: "PreToolUse", ToolName: "mcp__notes__count_words", CWD: home,
							})
							action, rawAction, reason = resp.Action, resp.RawAction, resp.Reason
							nativeOutput = resp.CodexOutput
						} else {
							resp := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
								HookEventName: "PreToolUse", ToolName: "mcp__notes__count_words", CWD: home,
							})
							action, rawAction, reason = resp.Action, resp.RawAction, resp.Reason
							nativeOutput = resp.ClaudeCodeOutput
						}
						if endpoint == deniedURL {
							if action != "block" || rawAction != "block" || !strings.Contains(reason, "denied by asset policy") {
								t.Fatalf("explicit deny: action=%q raw=%q reason=%q", action, rawAction, reason)
							}
							hookOutput, ok := nativeOutput["hookSpecificOutput"].(map[string]interface{})
							if !ok || hookOutput["permissionDecision"] != "deny" {
								t.Fatalf("explicit deny native output=%v, want permissionDecision=deny", nativeOutput)
							}
						} else if action != "allow" || rawAction != "allow" {
							t.Fatalf("ordinary server: action=%q raw=%q reason=%q", action, rawAction, reason)
						}
					})
				}
			}
		}
	}
}

func TestGAP0666MCPConnectorModeParity(t *testing.T) {
	const deniedURL = "http://127.0.0.1:28561/mcp"
	const ordinaryURL = "http://127.0.0.1:28562/mcp"
	for _, tc := range []struct {
		connector string
		event     string
	}{
		{"cursor", "beforeMCPExecution"},
		{"hermes", "pre_tool_call"},
		{"devin", "PreToolUse"},
		{"copilot", "preToolUse"},
		{"antigravity", "PreToolUse"},
		{"opencode", "tool.execute.before"},
		{"amp", "tool.call"},
		{"kiro", "PreToolUse"},
	} {
		for _, mode := range []string{"observe", "action"} {
			for _, endpoint := range []string{deniedURL, ordinaryURL} {
				t.Run(tc.connector+"/"+mode+"/"+endpoint, func(t *testing.T) {
					cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
					cfg.Guardrail.Mode = mode
					cfg.Guardrail.Connector = tc.connector
					cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{Name: "notes"}}
					server := "notes"
					if endpoint == ordinaryURL {
						server = "ordinary"
					}
					payload := map[string]interface{}{"mcp_server_name": server}
					toolName := "mcp__" + server + "__count_words"
					if tc.connector == "cursor" {
						cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{URL: deniedURL}}
						payload = map[string]interface{}{"url": endpoint}
					}
					api := &APIServer{scannerCfg: cfg}
					resp := api.evaluateAgentHook(context.Background(), agentHookRequest{
						ConnectorName: tc.connector,
						HookEventName: tc.event,
						HookSurface:   "v3",
						ToolName:      toolName,
						Payload:       payload,
					})
					if endpoint == deniedURL {
						if resp.Action != "block" || resp.RawAction != "block" || !strings.Contains(resp.Reason, "denied by asset policy") {
							t.Fatalf("explicit deny: action=%q raw=%q reason=%q", resp.Action, resp.RawAction, resp.Reason)
						}
					} else if resp.Action != "allow" || resp.RawAction != "allow" {
						t.Fatalf("ordinary server: action=%q raw=%q reason=%q", resp.Action, resp.RawAction, resp.Reason)
					}
				})
			}
		}
	}
}
