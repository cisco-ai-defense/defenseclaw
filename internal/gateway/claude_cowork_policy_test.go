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
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func coworkWorkspaceCall(api *APIServer, tool string, input map[string]interface{}) claudeCodeHookResponse {
	return api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
		HookEventName: "PreToolUse", ToolName: tool, ToolInput: input,
		Payload: map[string]interface{}{"mcp_server": map[string]interface{}{"name": "workspace", "source": "sdk"}},
	})
}

// An administrator's deny written for the native Cowork names still wins when
// the call is judged as Bash or WebFetch: a static block of
// mcp__workspace__bash or mcp__workspace__web_fetch, and a block of the MCP
// server "workspace". The allow list applies to the Bash name, and an allow
// of the native name never skips the inspection.
func TestCoworkNativeNameDeniesStillBlock(t *testing.T) {
	newAPI := func(change func(*config.Config)) *APIServer {
		cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.Connector = "claudecode"
		change(cfg)
		return &APIServer{scannerCfg: cfg}
	}
	shell := map[string]interface{}{"command": "ls -la"}
	fetch := map[string]interface{}{"url": "https://example.com"}
	for _, tc := range []struct {
		name    string
		change  func(*config.Config)
		tool    string
		input   map[string]interface{}
		finding string
	}{
		{"static deny of the native shell name", func(cfg *config.Config) {
			cfg.AssetPolicy.Tool.Denied = []config.AssetPolicyToolRule{{Name: "mcp__workspace__bash", Connector: "claudecode"}}
		}, "mcp__workspace__bash", shell, "STATIC-BLOCK"},
		{"static deny of the native fetch name", func(cfg *config.Config) {
			cfg.AssetPolicy.Tool.Denied = []config.AssetPolicyToolRule{{Name: "mcp__workspace__web_fetch"}}
		}, "mcp__workspace__web_fetch", fetch, "STATIC-BLOCK"},
		{"block of the workspace MCP server", func(cfg *config.Config) {
			cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{Name: "workspace"}}
		}, "mcp__workspace__bash", shell, "MCP-BLOCK"},
		{"static deny of Bash", func(cfg *config.Config) {
			cfg.AssetPolicy.Tool.Denied = []config.AssetPolicyToolRule{{Name: "Bash", Connector: "claudecode"}}
		}, "mcp__workspace__bash", shell, "STATIC-BLOCK"},
	} {
		resp := coworkWorkspaceCall(newAPI(tc.change), tc.tool, tc.input)
		if resp.Action != "block" || !slices.Contains(resp.Findings, tc.finding) {
			t.Errorf("%s: action=%q findings=%v reason=%q, want a block with %s", tc.name, resp.Action, resp.Findings, resp.Reason, tc.finding)
		}
	}
	// A deny of another tool leaves the call alone.
	resp := coworkWorkspaceCall(newAPI(func(cfg *config.Config) {
		cfg.AssetPolicy.Tool.Denied = []config.AssetPolicyToolRule{{Name: "mcp__other__bash"}}
	}), "mcp__workspace__bash", shell)
	if resp.Action != "allow" {
		t.Errorf("unrelated deny: action=%q findings=%v", resp.Action, resp.Findings)
	}
	// An allow of the native name does not skip the inspection.
	resp = coworkWorkspaceCall(newAPI(func(cfg *config.Config) {
		cfg.AssetPolicy.Tool.Allowed = []config.AssetPolicyToolRule{{Name: "mcp__workspace__bash"}}
	}), "mcp__workspace__bash", map[string]interface{}{"command": "rm -rf /"})
	if resp.Action != "block" {
		t.Errorf("native-name allow skipped the inspection: action=%q findings=%v", resp.Action, resp.Findings)
	}
}

// Secure Client keeps the decisions of main: no Cowork tool mapping, no
// MCP bypass, no page-content check and no save_skill probe. Each Cowork
// call is decided exactly like an MCP tool outside the Cowork vocabulary.
func TestSecureClientKeepsCoworkToolsOnTheMCPPath(t *testing.T) {
	cfg := &config.Config{DeploymentMode: "managed_enterprise", AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Enterprise.Profile = "secure_client"
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{Name: "cowork-marker-skill"}}
	if !cfg.SecureClientIntegration() || coworkInspected(cfg) {
		t.Fatal("fixture is not a Secure Client config")
	}
	api := &APIServer{scannerCfg: cfg}
	const token = "ghp_A7b9C2d4E6f8G1h3J5k7L9m2N4p6Q8r1S3t5"
	for _, tc := range []struct {
		tool, twin string
		input      map[string]interface{}
	}{
		{"mcp__workspace__bash", "mcp__workspacx__bash", map[string]interface{}{"command": "rm -rf /"}},
		{"mcp__Claude_Browser__form_input", "mcp__Claude_Browsex__form_input", map[string]interface{}{"ref": "r", "value": token}},
		{"mcp__cowork__save_skill", "mcp__coworx__save_skill", map[string]interface{}{"name": "cowork-marker-skill"}},
	} {
		got := coworkWorkspaceCall(api, tc.tool, tc.input)
		want := coworkWorkspaceCall(api, tc.twin, tc.input)
		if got.Action != want.Action || got.RawAction != want.RawAction || got.Severity != want.Severity || !slices.Equal(got.Findings, want.Findings) {
			t.Errorf("%s under Secure Client: %s/%s/%s %v, an unmapped MCP tool gets %s/%s/%s %v", tc.tool,
				got.Action, got.RawAction, got.Severity, got.Findings, want.Action, want.RawAction, want.Severity, want.Findings)
		}
	}
	if probe := claudeCodeCoworkSkillProbe(claudeCodeHookRequest{ToolName: coworkSaveSkillTool, ToolInput: map[string]interface{}{"name": "x"}}); probe.Matched {
		// The probe itself is pure; the gate is at its call site.
		if decision, matched := api.claudeCodeSkillAssetDecision(context.Background(), claudeCodeHookRequest{
			HookEventName: "PreToolUse", ToolName: coworkSaveSkillTool, ToolInput: map[string]interface{}{"name": "cowork-marker-skill"},
		}); matched && decision.RawAction == "block" {
			t.Errorf("Secure Client applied the save_skill probe: %+v", decision)
		}
	}
	// The gates themselves: no remap, no MCP bypass, no Cowork context, so
	// the inspect request keeps the native MCP name and server.
	sdk := map[string]interface{}{"mcp_server": map[string]interface{}{"name": "workspace", "source": "sdk"}}
	args := []byte(`{"command":"ls"}`)
	if got, ok := claudeCodeCoworkInspectionUnder(cfg, "mcp__workspace__bash", args, sdk); ok {
		t.Errorf("Secure Client remapped mcp__workspace__bash to %+v", got)
	}
	if got, ok := claudeCodeCoworkInspectionUnder(&config.Config{}, "mcp__workspace__bash", args, sdk); !ok || got.requestTool != "Bash" {
		t.Errorf("outside Secure Client the remap is %+v, %v; want the Bash request tool", got, ok)
	}
	if !claudeCodeCoworkNativeTool(claudeCodeHookRequest{ToolName: "mcp__workspace__bash", Payload: sdk}) || coworkInspected(cfg) {
		t.Error("the MCP bypass gate does not depend on the profile")
	}
	if api.inspectClaudeCodeCoworkPageContent(context.Background(), claudeCodeHookRequest{
		ToolName: "mcp__Claude_Browser__form_input", ToolInput: map[string]interface{}{"value": token},
	}) != nil {
		t.Error("Secure Client ran the page-content check")
	}
}
