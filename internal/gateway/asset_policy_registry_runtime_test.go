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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-2488: a registry-promoted MCP rule is pinned to name, URL and
// transport. A Claude Code tool call carries only the server name, so the
// gateway must resolve the configured server before matching; otherwise an
// approved server is blocked as "not in the approved registry".
func TestClaudeCodeMCPRegistryRequiredAdmitsConfiguredApprovedServer(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	approvedDir := filepath.Join(home, "approved")
	otherDir := filepath.Join(home, "other")
	const url = "https://mcp.example.test/mcp"
	state := map[string]any{"projects": map[string]any{
		approvedDir: map[string]any{"mcpServers": map[string]any{
			"t2r1-deepwiki": map[string]any{"type": "http", "url": url},
			"t2r1-off":      map[string]any{"type": "http", "url": url},
		}},
		// Same name as the approved entry, different endpoint.
		otherDir: map[string]any{"mcpServers": map[string]any{
			"t2r1-deepwiki": map[string]any{"type": "http", "url": "https://elsewhere.example.test/mcp"},
		}},
	}}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "action"
	cfg.AssetPolicy.MCP.RegistryRequired = true
	cfg.AssetPolicy.MCP.Registry = []config.AssetPolicyRule{{
		Name:      "t2r1-deepwiki",
		URL:       url,
		Transport: "streamable-http",
		Reason:    "registry:t2r1-local",
	}}
	api := &APIServer{scannerCfg: cfg}
	call := func(server, cwd string) (config.AssetPolicyDecision, bool) {
		return api.claudeCodeMCPAssetDecision(context.Background(), claudeCodeHookRequest{
			HookEventName: "PreToolUse",
			ToolName:      "mcp__" + server + "__read_wiki_structure",
			CWD:           cwd,
		})
	}

	if decision, blocked := call("t2r1-deepwiki", approvedDir); blocked {
		t.Fatalf("approved registry server blocked: %+v", decision)
	}
	if decision, blocked := call("t2r1-off", approvedDir); !blocked || decision.Source != "registry-required" {
		t.Fatalf("off-registry server not blocked: blocked=%v decision=%+v", blocked, decision)
	}
	if decision, blocked := call("t2r1-deepwiki", otherDir); !blocked {
		t.Fatalf("same name with a different URL was admitted: %+v", decision)
	}
	if decision, blocked := call("t2r1-deepwiki", filepath.Join(home, "unknown")); !blocked {
		t.Fatalf("unconfigured server name was admitted: %+v", decision)
	}
}
