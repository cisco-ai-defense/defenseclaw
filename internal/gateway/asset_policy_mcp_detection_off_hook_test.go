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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// With asset_policy.mcp.runtime_detection.enabled false the agent hook
// enforces only the denied list for MCP servers: registry_required does not
// refuse an unregistered server there, and a denied one is still refused
// (docs: policies/admission, "enabled and mode").
func TestMCPRuntimeDetectionOffEnforcesOnlyTheDeniedListAtTheHook(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = config.AssetPolicyModeAction
	cfg.AssetPolicy.MCP.RegistryRequired = true
	cfg.AssetPolicy.MCP.Registry = []config.AssetPolicyRule{{Name: "acme-notes", URL: "http://127.0.0.1:28581/mcp"}}
	cfg.AssetPolicy.MCP.RuntimeDetection.Enabled = false
	cfg.AssetPolicy.MCP.RuntimeDetection.TerminalCommands = false
	cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{Name: "denied-rogue"}}
	api := &APIServer{scannerCfg: cfg}
	eval := func(server string) (config.AssetPolicyDecision, bool) {
		return api.evaluateRuntimeMCPAssetPolicy(context.Background(), "claudecode", "PreToolUse", mcpRuntimeProbe{
			Matched: true, Surface: "hook", ServerName: server, ToolName: "mcp__" + server + "__count_words",
		})
	}
	if decision, matched := eval("wiki-rogue"); matched {
		t.Fatalf("unregistered server with runtime detection off: decision=%+v, want it to run", decision)
	}
	if decision, matched := eval("denied-rogue"); !matched || decision.Action != "block" || decision.Source != "admin-deny" {
		t.Fatalf("denied server: matched=%v decision=%+v, want an admin-deny block", matched, decision)
	}
	cfg.AssetPolicy.MCP.RuntimeDetection.Enabled = true
	cfg.AssetPolicy.MCP.RuntimeDetection.TerminalCommands = true
	if decision, matched := eval("wiki-rogue"); !matched || decision.Action != "block" {
		t.Fatalf("runtime detection on: matched=%v decision=%+v, want registry_required to refuse the unregistered server", matched, decision)
	}
}
