// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

func TestGAP0034ProtectedEndpointOutageAndOrdinaryTwin(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{URL: "https://mcp.example.invalid/protected"}}
	api := &APIServer{scannerCfg: cfg}
	api.SetMCPRefreshBeforeCall(func(context.Context, string) error { return errors.New("refresh unavailable") })
	call := claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "mcp__notes__lookup", ToolInput: map[string]interface{}{}}
	for _, tc := range []struct{ name, endpoint, action string }{
		{"protected", "https://mcp.example.invalid/protected", "block"},
		{"ordinary", "https://mcp.example.invalid/ordinary", "allow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.WithValue(withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001}),
				claimedAssetFactsContextKey{}, assetfacts.Facts{MCP: &assetfacts.MCPServer{Name: "notes", URL: tc.endpoint}})
			resp := api.evaluateClaudeCodeHook(ctx, call)
			if resp.Action != tc.action {
				t.Fatalf("endpoint %q: action=%q, want %q", tc.endpoint, resp.Action, tc.action)
			}
		})
	}
}

func TestGAP0034UnresolvedProtectedPluginBlocksOnRefreshOutage(t *testing.T) {
	home := t.TempDir()
	pluginDir := filepath.Join(home, ".claude", "plugins")
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatal(err)
	}
	registry := `{"plugins":{},"padding":"` + strings.Repeat("x", 4<<20) + `"}`
	if err := os.WriteFile(filepath.Join(pluginDir, "installed_plugins.json"), []byte(registry), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{Command: "protected-command"}}
	api := &APIServer{scannerCfg: cfg}
	api.SetMCPRefreshBeforeCall(func(context.Context, string) error { return errors.New("refresh unavailable") })
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
	decision, matched := api.claudeCodeMCPAssetDecision(ctx, claudeCodeHookRequest{
		HookEventName: "PreToolUse", ToolName: "mcp__plugin_alpha_clock__now", CWD: home,
	})
	if !matched || decision.Action != "block" || decision.Source != "mcp-definition-unproven" {
		t.Fatalf("protected plugin during outage: matched=%v decision=%+v", matched, decision)
	}
}

// A completed scan failure survives a refresh outage with the tier's own
// decision: blocked in the strict tier, allowed with a warning in the default
// tier (the cell that moved with the GAP-0775 ruling).
func TestGAP0034CompletedFailureFollowsTierOnRefreshOutage(t *testing.T) {
	for _, tc := range []struct{ pack, action string }{{"strict", "block"}, {"default", "allow"}} {
		t.Run(tc.pack, func(t *testing.T) {
			cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "claudecode"
			cfg.Guardrail.RulePack = tc.pack
			api := &APIServer{scannerCfg: cfg}
			api.SetMCPRefreshBeforeCall(func(context.Context, string) error { return errors.New("refresh unavailable") })
			api.SetMCPAdmissionStatus(func(_, server, _, _ string) watcher.MCPAdmissionStatus {
				return watcher.MCPAdmissionStatus{Name: server, Failed: true}
			})
			resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
				HookEventName: "PreToolUse", ToolName: "mcp__notes__lookup", ToolInput: map[string]interface{}{},
			})
			if resp.Action != tc.action || resp.RawAction != "block" ||
				!strings.Contains(resp.SourceReason, "reason_code=mcp-admission-failed") {
				t.Fatalf("completed failure during outage: %+v", resp)
			}
		})
	}
}
