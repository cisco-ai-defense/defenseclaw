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

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1198: when the plugin registry cannot be read, a plugin MCP server
// whose name has several underscore boundaries still answers to an explicit
// deny of any plugin its name may belong to; registry_required does not
// block on such a guess.
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
	if decision, blocked := api.claudeCodePluginAssetDecision(ctx, req); !blocked || decision.Source != "admin-deny" {
		t.Fatalf("denied plugin admitted through an unreadable registry: blocked=%v decision=%+v", blocked, decision)
	}

	other := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	other.AssetPolicy.Plugin.Denied = []config.AssetPolicyRule{{Name: "gamma"}}
	if decision, blocked := (&APIServer{scannerCfg: other}).claudeCodePluginAssetDecision(ctx, req); blocked {
		t.Fatalf("a deny of another plugin refused the call: %+v", decision)
	}
}
