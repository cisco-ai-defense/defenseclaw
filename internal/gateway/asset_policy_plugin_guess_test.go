// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1198: when the plugin registry cannot be read, a plugin MCP server
// whose name has several underscore boundaries still answers to an explicit
// deny of any plugin its name may belong to, reported with its owner
// unknown (rel-1-0-6:GAP-0293).
func TestUnreadablePluginRegistryKeepsTheDenyOfAnAmbiguousPluginServer(t *testing.T) {
	home := t.TempDir()
	pluginDir := filepath.Join(home, ".claude", "plugins")
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatal(err)
	}
	registry := `{"plugins":{},"padding":"` + strings.Repeat("x", 4<<20) + `"}`
	if err := os.WriteFile(filepath.Join(pluginDir, "installed_plugins.json"), []byte(registry), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
	req := claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "mcp__plugin_alpha_beta_clock__now", CWD: home}

	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.Plugin.Denied = []config.AssetPolicyRule{{Name: "alpha_beta"}}
	api := &APIServer{scannerCfg: cfg}
	// The owner is unknown, not the denied plugin (rel-1-0-6:GAP-0293).
	if decision, blocked := api.claudeCodePluginAssetDecision(ctx, req); !blocked ||
		decision.Source != "plugin-owner-unknown" || decision.TargetName != "unknown" {
		t.Fatalf("denied plugin admitted through an unreadable registry: blocked=%v decision=%+v", blocked, decision)
	}

	other := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	other.AssetPolicy.Plugin.Denied = []config.AssetPolicyRule{{Name: "gamma"}}
	if decision, blocked := (&APIServer{scannerCfg: other}).claudeCodePluginAssetDecision(ctx, req); blocked {
		t.Fatalf("a deny of another plugin refused the call: %+v", decision)
	}
}

// unreadablePluginRegistryHome is a home whose Claude Code plugin registry is
// over the size the gateway reads, so no plugin MCP owner can be proven.
func unreadablePluginRegistryHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	pluginDir := filepath.Join(home, ".claude", "plugins")
	if err := os.MkdirAll(pluginDir, 0o700); err != nil {
		t.Fatal(err)
	}
	registry := `{"plugins":{},"padding":"` + strings.Repeat("x", 4<<20) + `"}`
	if err := os.WriteFile(filepath.Join(pluginDir, "installed_plugins.json"), []byte(registry), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

// rel-1-0-6:GAP-0293: when the hook cannot prove which plugin owns an MCP
// server, the owner is reported as unknown. A quarantined (or install
// blocked) plugin whose name is a prefix of the server name was reported as
// the owner, and its refusal was shown for the tool of another plugin. The
// refusal itself stays, because it cannot be ruled out without the owner;
// a quarantine of a plugin the name cannot belong to refuses nothing, and
// the default profile lets an unknown owner run.
func TestClaudePluginMCPUnprovenOwnerIsReportedUnknown(t *testing.T) {
	home := unreadablePluginRegistryHome(t)
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
	req := claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "mcp__plugin_alpha_beta_clock__now", CWD: home}
	for _, action := range []struct{ field, value string }{{"file", "quarantine"}, {"install", "block"}} {
		t.Run(action.field+"="+action.value, func(t *testing.T) {
			store, err := audit.NewStore(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })
			if err := store.Init(); err != nil {
				t.Fatal(err)
			}
			if err := store.SetActionFieldForConnector("plugin", "alpha", "claudecode", action.field, action.value, "test"); err != nil {
				t.Fatal(err)
			}
			api := &APIServer{scannerCfg: &config.Config{AssetPolicy: config.DefaultAssetPolicy()}, store: store}
			decision, blocked := api.claudeCodePluginAssetDecision(ctx, req)
			if !blocked || decision.Source != "plugin-owner-unknown" || decision.TargetName != "unknown" ||
				decision.RegistryStatus != "unknown" || strings.Contains(decision.Reason, `"alpha"`) {
				t.Fatalf("unproven owner: blocked=%v decision=%+v, want refused with the owner unknown", blocked, decision)
			}
			subject := agentAssetPolicySubject(assetPolicyResponseReason(decision))
			if !strings.Contains(subject, "is unknown") || strings.Contains(subject, "alpha") {
				t.Fatalf("agent sentence %q, want the owner unknown and no plugin named", subject)
			}
			// A quarantined plugin the server name cannot belong to refuses
			// nothing.
			other := claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "mcp__plugin_gamma_beta_clock__now", CWD: home}
			if decision, blocked := api.claudeCodePluginAssetDecision(ctx, other); blocked {
				t.Fatalf("unrelated server refused: %+v", decision)
			}
		})
	}
}

// rel-1-0-6:GAP-0293: an unknown owner gets what asset_policy.plugin gives an
// unknown plugin: nothing in the default profile, a refusal when
// registry_required is on and runtime detection evaluates plugins.
func TestClaudePluginMCPUnprovenOwnerFollowsTheUnknownPluginPolicy(t *testing.T) {
	home := unreadablePluginRegistryHome(t)
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
	req := claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "mcp__plugin_alpha_beta_clock__now", CWD: home}
	if decision, blocked := (&APIServer{scannerCfg: &config.Config{AssetPolicy: config.DefaultAssetPolicy()}}).
		claudeCodePluginAssetDecision(ctx, req); blocked {
		t.Fatalf("default profile refused an unknown owner: %+v", decision)
	}
	strict := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	strict.AssetPolicy.Enabled = true
	strict.AssetPolicy.Mode = config.AssetPolicyModeAction
	strict.AssetPolicy.Plugin.RegistryRequired = true
	strict.AssetPolicy.Plugin.Registry = []config.AssetPolicyRule{{Name: "alpha_beta"}}
	strict.AssetPolicy.Plugin.RuntimeDetection.Enabled = true
	decision, blocked := (&APIServer{scannerCfg: strict}).claudeCodePluginAssetDecision(ctx, req)
	if !blocked || decision.TargetName != "unknown" || decision.Action != "block" {
		t.Fatalf("registry_required admitted an unknown owner: blocked=%v decision=%+v", blocked, decision)
	}
}
