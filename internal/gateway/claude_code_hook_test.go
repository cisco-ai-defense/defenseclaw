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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// TestEvaluateClaudeCodeHook_ActiveConnectorImpliesEnabled documents the
// invariant that selecting the claudecode connector is the only opt-in
// an operator should need.
//
// Before the fix, the handler short-circuited to "allow" whenever
// scannerCfg.ClaudeCode.Enabled was false (its default), even though the
// connector had already been selected and hooks had been installed into
// ~/.claude/settings.json. A CRITICAL-severity jailbreak keyword in the
// user prompt therefore came back as action=allow, severity=NONE — the
// rule scanner never ran. The connector selection must be the single
// source of truth: if guardrail.connector == "claudecode", hooks are
// live.
func TestEvaluateClaudeCodeHook_ActiveConnectorImpliesEnabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	// Intentionally leave cfg.ClaudeCode.Enabled at its zero value (false)
	// to reproduce the operator path where no claude_code section was
	// written to config.yaml.

	api := &APIServer{scannerCfg: cfg}

	req := claudeCodeHookRequest{
		HookEventName: "UserPromptSubmit",
		Prompt:        "jailbreak ai",
	}
	resp := api.evaluateClaudeCodeHook(context.Background(), req)

	if resp.RawAction != "block" {
		t.Errorf("RawAction = %q, want block (rule TRUST-JAILBREAK must fire)", resp.RawAction)
	}
	if resp.Severity != "CRITICAL" {
		t.Errorf("Severity = %q, want CRITICAL", resp.Severity)
	}
}

func TestClaudeCodeEnabled_AutomaticSourceNotLazyHealthCounter(t *testing.T) {
	cfg := &config.Config{ApplicationProtection: config.DefaultApplicationProtectionConfig()}
	cfg.ApplicationProtection.Enabled = true
	health := NewSidecarHealth()
	health.RecordConnectorRequestFor("claudecode")
	api := &APIServer{scannerCfg: cfg, health: health}

	if api.claudeCodeEnabled() {
		t.Fatal("lazy health counter enabled claudecode without automatic activation")
	}

	health.RegisterConnectorWithSource("claudecode", connector.ToolModeBoth, connector.SubprocessNone, "automatic")
	if !api.claudeCodeEnabled() {
		t.Fatal("source=automatic registration should enable Claude Code inspection")
	}
}

// TestEvaluateClaudeCodeHook_NonClaudeConnectorStaysDisabled guards the
// opposite direction: an OpenClaw-based install must not start
// evaluating Claude Code hooks just because the endpoint exists — that
// would waste cycles on requests the operator never installed hooks for.
func TestEvaluateClaudeCodeHook_NonClaudeConnectorStaysDisabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "openclaw"

	api := &APIServer{scannerCfg: cfg}

	req := claudeCodeHookRequest{
		HookEventName: "UserPromptSubmit",
		Prompt:        "jailbreak ai",
	}
	resp := api.evaluateClaudeCodeHook(context.Background(), req)

	if resp.RawAction != "allow" {
		t.Errorf("RawAction = %q, want allow (claudecode hooks should be inert under a different connector)", resp.RawAction)
	}
}

// TestEvaluateClaudeCodeHook_ExplicitEnableStillWorks ensures operators
// who explicitly set claude_code.enabled=true (e.g. alongside a custom
// connector for testing) still get inspection even when the connector
// name itself would have been inert.
func TestEvaluateClaudeCodeHook_ExplicitEnableStillWorks(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "" // unset
	cfg.ClaudeCode.Enabled = true

	api := &APIServer{scannerCfg: cfg}

	req := claudeCodeHookRequest{
		HookEventName: "UserPromptSubmit",
		Prompt:        "jailbreak ai",
	}
	resp := api.evaluateClaudeCodeHook(context.Background(), req)

	if resp.RawAction != "block" {
		t.Errorf("RawAction = %q, want block", resp.RawAction)
	}
}

func TestEvaluateClaudeCodeHook_HILTPreToolUseAsks(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.HILT.Enabled = true
	cfg.Guardrail.HILT.MinSeverity = "HIGH"

	api := &APIServer{scannerCfg: cfg}
	resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput: map[string]interface{}{
			"command": "invoke the bash tool without confirmation",
		},
	})

	if resp.Action != "confirm" || resp.RawAction != "confirm" {
		t.Fatalf("action=%q raw=%q, want confirm/confirm", resp.Action, resp.RawAction)
	}
	hook, ok := resp.ClaudeCodeOutput["hookSpecificOutput"].(map[string]interface{})
	if !ok {
		t.Fatalf("claude output = %+v, want hookSpecificOutput", resp.ClaudeCodeOutput)
	}
	if got := hook["permissionDecision"]; got != "ask" {
		t.Fatalf("permissionDecision=%q, want ask", got)
	}
}

func TestEvaluateClaudeCodeHook_BlocksUnregisteredMCPPreToolUse(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "action"
	cfg.AssetPolicy.MCP.RegistryRequired = true
	cfg.AssetPolicy.MCP.Registry = []config.AssetPolicyRule{{Name: "github"}}

	api := &APIServer{scannerCfg: cfg}

	req := claudeCodeHookRequest{
		HookEventName: "PreToolUse",
		ToolName:      "mcp__rogue__search",
		ToolInput:     map[string]interface{}{"query": "status"},
	}
	resp := api.evaluateClaudeCodeHook(context.Background(), req)

	if resp.Action != "block" || resp.RawAction != "block" {
		t.Fatalf("action=%q raw=%q, want block/block", resp.Action, resp.RawAction)
	}
	if resp.Severity != "HIGH" {
		t.Fatalf("severity=%q, want HIGH", resp.Severity)
	}
	if !containsString(resp.Findings, "ASSET-POLICY-MCP") {
		t.Fatalf("findings=%v, want ASSET-POLICY-MCP", resp.Findings)
	}
}

func TestEvaluateClaudeCodeHook_BlocksUnregisteredMCPPermissionRequest(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "action"
	cfg.AssetPolicy.MCP.RegistryRequired = true
	cfg.AssetPolicy.MCP.Registry = []config.AssetPolicyRule{{Name: "github"}}

	api := &APIServer{scannerCfg: cfg}

	req := claudeCodeHookRequest{
		HookEventName: "PermissionRequest",
		ToolName:      "mcp__rogue__search",
		ToolInput:     map[string]interface{}{"query": "status"},
	}
	resp := api.evaluateClaudeCodeHook(context.Background(), req)

	if resp.Action != "block" || resp.RawAction != "block" {
		t.Fatalf("action=%q raw=%q, want block/block", resp.Action, resp.RawAction)
	}
	if !containsString(resp.Findings, "ASSET-POLICY-MCP") {
		t.Fatalf("findings=%v, want ASSET-POLICY-MCP", resp.Findings)
	}
	hook, ok := resp.ClaudeCodeOutput["hookSpecificOutput"].(map[string]interface{})
	if !ok {
		t.Fatalf("claude output = %+v, want hookSpecificOutput", resp.ClaudeCodeOutput)
	}
	decision, ok := hook["decision"].(map[string]interface{})
	if !ok || decision["behavior"] != "deny" {
		t.Fatalf("permission decision = %+v, want behavior=deny", hook["decision"])
	}
	for _, want := range []string{"reason_code=not-in-approved-registry", "asset_type=mcp", "asset_name=rogue", "connector=claudecode", "source=registry-required", "registry_status=not-registered", "registry_configured=true"} {
		if !strings.Contains(resp.Reason, want) {
			t.Fatalf("reason %q missing %q", resp.Reason, want)
		}
	}
}

func TestEvaluateClaudeCodeHook_BlocksUnregisteredSkillPreToolUse(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "action"
	cfg.AssetPolicy.Skill.RegistryRequired = true
	cfg.AssetPolicy.Skill.Registry = []config.AssetPolicyRule{{Name: "trusted-skill"}}
	enableSkillRuntimeDetection(cfg)

	api := &APIServer{scannerCfg: cfg}

	req := claudeCodeHookRequest{
		HookEventName: "PreToolUse",
		ToolName:      "Skill",
		ToolInput:     map[string]interface{}{"skill_name": "rogue-skill"},
	}
	resp := api.evaluateClaudeCodeHook(context.Background(), req)

	if resp.Action != "block" || resp.RawAction != "block" {
		t.Fatalf("action=%q raw=%q, want block/block", resp.Action, resp.RawAction)
	}
	if resp.Severity != "HIGH" {
		t.Fatalf("severity=%q, want HIGH", resp.Severity)
	}
	if !containsString(resp.Findings, "ASSET-POLICY-SKILL") {
		t.Fatalf("findings=%v, want ASSET-POLICY-SKILL", resp.Findings)
	}
	for _, want := range []string{"reason_code=not-in-approved-registry", "asset_type=skill", "asset_name=rogue-skill", "connector=claudecode", "source=registry-required", "registry_status=not-registered", "registry_configured=true"} {
		if !strings.Contains(resp.Reason, want) {
			t.Fatalf("reason %q missing %q", resp.Reason, want)
		}
	}
}

func TestEvaluateClaudeCodeHook_BlocksUnregisteredSkillUserPromptExpansion(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "action"
	cfg.AssetPolicy.Skill.RegistryRequired = true
	cfg.AssetPolicy.Skill.Registry = []config.AssetPolicyRule{{Name: "trusted-skill"}}
	enableSkillRuntimeDetection(cfg)

	api := &APIServer{scannerCfg: cfg}

	req := claudeCodeHookRequest{
		HookEventName: "UserPromptExpansion",
		ExpansionType: "slash_command",
		CommandName:   "rogue-skill",
		CommandSource: "skill",
		Prompt:        "/rogue-skill check",
	}
	resp := api.evaluateClaudeCodeHook(context.Background(), req)

	if resp.Action != "block" || resp.RawAction != "block" {
		t.Fatalf("action=%q raw=%q, want block/block", resp.Action, resp.RawAction)
	}
	if !containsString(resp.Findings, "ASSET-POLICY-SKILL") {
		t.Fatalf("findings=%v, want ASSET-POLICY-SKILL", resp.Findings)
	}
	if resp.ClaudeCodeOutput["decision"] != "block" {
		t.Fatalf("claude output = %+v, want decision=block", resp.ClaudeCodeOutput)
	}
	for _, want := range []string{"reason_code=not-in-approved-registry", "asset_type=skill", "asset_name=rogue-skill", "connector=claudecode", "source=registry-required", "registry_status=not-registered", "registry_configured=true", "surface=prompt_expansion"} {
		if !strings.Contains(resp.Reason, want) {
			t.Fatalf("reason %q missing %q", resp.Reason, want)
		}
	}
}

func TestEvaluateClaudeCodeHook_NamespacedPluginUserPromptExpansionPolicy(t *testing.T) {
	tests := []struct {
		name        string
		commandName string
		configure   func(*config.Config)
		wantAction  string
		wantSource  string
		wantTarget  string
	}{
		{
			name:        "admin allow uses bare plugin id",
			commandName: "release-tools:deploy",
			configure: func(cfg *config.Config) {
				cfg.AssetPolicy.Plugin.Default = "deny"
				cfg.AssetPolicy.Plugin.Allowed = []config.AssetPolicyRule{{Name: "release-tools"}}
			},
			wantAction: "allow",
		},
		{
			name:        "admin deny uses bare plugin id",
			commandName: "release-tools:deploy",
			configure: func(cfg *config.Config) {
				cfg.AssetPolicy.Plugin.Denied = []config.AssetPolicyRule{{Name: "release-tools"}}
			},
			wantAction: "block",
			wantSource: "admin-deny",
			wantTarget: "release-tools",
		},
		{
			name:        "registered bare plugin id is allowed",
			commandName: "release-tools:deploy",
			configure: func(cfg *config.Config) {
				cfg.AssetPolicy.Plugin.RegistryRequired = true
				cfg.AssetPolicy.Plugin.Registry = []config.AssetPolicyRule{{Name: "release-tools", Reason: "registry:internal"}}
			},
			wantAction: "allow",
		},
		{
			name:        "unregistered bare plugin id is blocked",
			commandName: "rogue-tools:deploy",
			configure: func(cfg *config.Config) {
				cfg.AssetPolicy.Plugin.RegistryRequired = true
				cfg.AssetPolicy.Plugin.Registry = []config.AssetPolicyRule{{Name: "release-tools", Reason: "registry:internal"}}
			},
			wantAction: "block",
			wantSource: "registry-required",
			wantTarget: "rogue-tools",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "claudecode"
			cfg.AssetPolicy.Enabled = true
			cfg.AssetPolicy.Mode = "action"
			enablePluginRuntimeDetection(cfg)
			tc.configure(cfg)
			store, logger := newNativeSkillRuntimeTestStore(t)
			api := &APIServer{scannerCfg: cfg, store: store, logger: logger}

			resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
				HookEventName: "UserPromptExpansion",
				ExpansionType: "slash_command",
				CommandName:   tc.commandName,
				CommandArgs:   "staging",
				CommandSource: "plugin",
				Prompt:        "/" + tc.commandName + " staging",
			})

			if resp.Action != tc.wantAction || resp.RawAction != tc.wantAction {
				t.Fatalf("action=%q raw=%q, want %s/%s", resp.Action, resp.RawAction, tc.wantAction, tc.wantAction)
			}
			if tc.wantAction == "allow" {
				if containsString(resp.Findings, "ASSET-POLICY-PLUGIN") {
					t.Fatalf("findings=%v, did not expect plugin policy block", resp.Findings)
				}
				return
			}
			if !containsString(resp.Findings, "ASSET-POLICY-PLUGIN") {
				t.Fatalf("findings=%v, want ASSET-POLICY-PLUGIN", resp.Findings)
			}
			if resp.ClaudeCodeOutput["decision"] != "block" {
				t.Fatalf("claude output=%+v, want decision=block", resp.ClaudeCodeOutput)
			}
			for _, want := range []string{
				"asset_type=plugin",
				"asset_name=" + tc.wantTarget,
				"source=" + tc.wantSource,
				"surface=prompt_expansion",
			} {
				if !strings.Contains(resp.Reason, want) {
					t.Fatalf("reason %q missing %q", resp.Reason, want)
				}
			}
		})
	}
}

func TestEvaluateClaudeCodeHook_BlocksUnregisteredMCPPromptExpansion(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "action"
	cfg.AssetPolicy.MCP.RegistryRequired = true
	cfg.AssetPolicy.MCP.Registry = []config.AssetPolicyRule{{Name: "github"}}

	api := &APIServer{scannerCfg: cfg}

	req := claudeCodeHookRequest{
		HookEventName: "UserPromptExpansion",
		ExpansionType: "mcp_prompt",
		CommandName:   "search",
		CommandSource: "rogue",
		Prompt:        "/mcp/rogue/search status",
	}
	resp := api.evaluateClaudeCodeHook(context.Background(), req)

	if resp.Action != "block" || resp.RawAction != "block" {
		t.Fatalf("action=%q raw=%q, want block/block", resp.Action, resp.RawAction)
	}
	if !containsString(resp.Findings, "ASSET-POLICY-MCP") {
		t.Fatalf("findings=%v, want ASSET-POLICY-MCP", resp.Findings)
	}
	if resp.ClaudeCodeOutput["decision"] != "block" {
		t.Fatalf("claude output = %+v, want decision=block", resp.ClaudeCodeOutput)
	}
	for _, want := range []string{"reason_code=not-in-approved-registry", "asset_type=mcp", "asset_name=rogue", "connector=claudecode", "source=registry-required", "registry_status=not-registered", "registry_configured=true", "surface=prompt_expansion"} {
		if !strings.Contains(resp.Reason, want) {
			t.Fatalf("reason %q missing %q", resp.Reason, want)
		}
	}
}

// TestEvaluateClaudeCodeHook_RegistryRequiredEmptyDeniesByDefault pins
// the new fail-closed default at the hook layer: registry_required=true
// with an empty registry now blocks unregistered MCPs even when the
// type policy's Default is "allow". This is the safer default for a
// security-critical knob — operators who haven't populated the
// registry should not silently get fall-through-to-allow behavior.
func TestEvaluateClaudeCodeHook_RegistryRequiredEmptyDeniesByDefault(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "action"
	cfg.AssetPolicy.MCP.RegistryRequired = true
	// Default "allow" is intentionally left in place so the test
	// proves the empty-registry guard kicks in BEFORE Default is
	// consulted.

	api := &APIServer{scannerCfg: cfg}

	req := claudeCodeHookRequest{
		HookEventName: "PermissionRequest",
		ToolName:      "mcp__rogue__search",
		ToolInput:     map[string]interface{}{"query": "status"},
	}
	resp := api.evaluateClaudeCodeHook(context.Background(), req)

	if resp.Action != "block" || resp.RawAction != "block" {
		t.Fatalf("action=%q raw=%q, want block/block", resp.Action, resp.RawAction)
	}
	if !containsString(resp.Findings, "ASSET-POLICY-MCP") {
		t.Fatalf("findings=%v, want ASSET-POLICY-MCP", resp.Findings)
	}
	if !strings.Contains(resp.Reason, "reason_code=registry-required-but-empty") {
		t.Fatalf("reason %q missing registry-required-but-empty reason_code", resp.Reason)
	}
}

// TestEvaluateClaudeCodeHook_RegistryRequiredEmptyAllowOptInPermits pins
// the explicit opt-in path: setting registry_empty_action="allow" gets
// the previous (looser) behavior of falling through to Default. This
// test asserts the knob actually works end-to-end through the hook
// layer, not just at the config-evaluation layer.
func TestEvaluateClaudeCodeHook_RegistryRequiredEmptyAllowOptInPermits(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "action"
	cfg.AssetPolicy.MCP.RegistryRequired = true
	cfg.AssetPolicy.MCP.RegistryEmptyAction = "allow"

	api := &APIServer{scannerCfg: cfg}

	req := claudeCodeHookRequest{
		HookEventName: "PermissionRequest",
		ToolName:      "mcp__rogue__search",
		ToolInput:     map[string]interface{}{"query": "status"},
	}
	resp := api.evaluateClaudeCodeHook(context.Background(), req)

	if resp.Action != "allow" || resp.RawAction != "allow" {
		t.Fatalf("action=%q raw=%q, want allow/allow", resp.Action, resp.RawAction)
	}
	if containsString(resp.Findings, "ASSET-POLICY-MCP") {
		t.Fatalf("findings=%v, did not expect ASSET-POLICY-MCP", resp.Findings)
	}
}

func TestEvaluateClaudeCodeHook_UserPromptExpansionRegistryRequiredEmptyDeniesByDefault(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "action"
	cfg.AssetPolicy.Skill.RegistryRequired = true
	enableSkillRuntimeDetection(cfg)

	api := &APIServer{scannerCfg: cfg}

	req := claudeCodeHookRequest{
		HookEventName: "UserPromptExpansion",
		ExpansionType: "slash_command",
		CommandName:   "rogue-skill",
		CommandSource: "skill",
		Prompt:        "/rogue-skill check",
	}
	resp := api.evaluateClaudeCodeHook(context.Background(), req)

	if resp.Action != "block" || resp.RawAction != "block" {
		t.Fatalf("action=%q raw=%q, want block/block", resp.Action, resp.RawAction)
	}
	if !containsString(resp.Findings, "ASSET-POLICY-SKILL") {
		t.Fatalf("findings=%v, want ASSET-POLICY-SKILL", resp.Findings)
	}
	if !strings.Contains(resp.Reason, "reason_code=registry-required-but-empty") {
		t.Fatalf("reason %q missing registry-required-but-empty reason_code", resp.Reason)
	}
}

func TestEvaluateClaudeCodeHook_UserPromptExpansionRegistryRequiredEmptyAllowOptInPermits(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "action"
	cfg.AssetPolicy.Skill.RegistryRequired = true
	cfg.AssetPolicy.Skill.RegistryEmptyAction = "allow"
	enableSkillRuntimeDetection(cfg)

	api := &APIServer{scannerCfg: cfg}

	req := claudeCodeHookRequest{
		HookEventName: "UserPromptExpansion",
		ExpansionType: "slash_command",
		CommandName:   "rogue-skill",
		CommandSource: "skill",
		Prompt:        "/rogue-skill check",
	}
	resp := api.evaluateClaudeCodeHook(context.Background(), req)

	if resp.Action != "allow" || resp.RawAction != "allow" {
		t.Fatalf("action=%q raw=%q, want allow/allow", resp.Action, resp.RawAction)
	}
	if containsString(resp.Findings, "ASSET-POLICY-SKILL") {
		t.Fatalf("findings=%v, did not expect ASSET-POLICY-SKILL", resp.Findings)
	}
}

// TestEvaluateClaudeCodeHook_SkillCraftedPathStillBlocksWhenUnregistered
// is a security regression test for the skill-name normalization
// behavior: an agent passing a path-shaped value can match an approved
// name only via filepath.Base, but a path that doesn't end at an
// approved basename must still be blocked. This covers the "raw
// input != normalized" code path that audit telemetry relies on.
func TestEvaluateClaudeCodeHook_SkillCraftedPathStillBlocksWhenUnregistered(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "action"
	cfg.AssetPolicy.Skill.RegistryRequired = true
	cfg.AssetPolicy.Skill.Registry = []config.AssetPolicyRule{{Name: "trusted-skill"}}
	enableSkillRuntimeDetection(cfg)

	api := &APIServer{scannerCfg: cfg}

	req := claudeCodeHookRequest{
		HookEventName: "PermissionRequest",
		ToolName:      "Skill",
		ToolInput: map[string]interface{}{
			// basename collapses to "evil-skill", which is NOT in the registry.
			"skill_name": "/tmp/attacker/evil-skill/SKILL.md",
		},
	}
	resp := api.evaluateClaudeCodeHook(context.Background(), req)

	if resp.Action != "block" || resp.RawAction != "block" {
		t.Fatalf("action=%q raw=%q, want block/block", resp.Action, resp.RawAction)
	}
	if !containsString(resp.Findings, "ASSET-POLICY-SKILL") {
		t.Fatalf("findings=%v, want ASSET-POLICY-SKILL", resp.Findings)
	}
	if !strings.Contains(resp.Reason, "asset_name=evil-skill") {
		t.Fatalf("reason %q must surface the normalized basename so audit can see what was matched", resp.Reason)
	}
}

// TestEvaluateClaudeCodeHook_SkillCraftedPathMatchesApprovedBasename
// pins the fix: when the agent supplies a path-shaped
// skill_name like "/tmp/attacker/trusted-skill/SKILL.md", the
// connector MUST treat the request as unregistered regardless of
// whether the basename matches a registry entry. The legacy
// behavior was allow/allow because the registry matched by name
// only; that allowed any agent to bypass runtime skill admission
// by crafting a path whose basename shadowed an approved skill.
func TestEvaluateClaudeCodeHook_SkillCraftedPathMatchesApprovedBasename(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "action"
	cfg.AssetPolicy.Skill.RegistryRequired = true
	cfg.AssetPolicy.Skill.Registry = []config.AssetPolicyRule{{Name: "trusted-skill"}}
	enableSkillRuntimeDetection(cfg)

	api := &APIServer{scannerCfg: cfg}

	req := claudeCodeHookRequest{
		HookEventName: "PermissionRequest",
		ToolName:      "Skill",
		ToolInput: map[string]interface{}{
			"skill_name": "/tmp/attacker/trusted-skill/SKILL.md",
		},
	}
	resp := api.evaluateClaudeCodeHook(context.Background(), req)

	if resp.Action != "block" || resp.RawAction != "block" {
		t.Fatalf("action=%q raw=%q, want block/block — path-shaped skill_name must force unregistered match", resp.Action, resp.RawAction)
	}
}

func TestEvaluateClaudeCodeHook_SkillDefaultDenyBlocksWithoutRegistry(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "action"
	cfg.AssetPolicy.Skill.Default = "deny"
	enableSkillRuntimeDetection(cfg)

	api := &APIServer{scannerCfg: cfg}

	req := claudeCodeHookRequest{
		HookEventName: "PermissionRequest",
		ToolName:      "Skill",
		ToolInput:     map[string]interface{}{"skill_name": "rogue-skill"},
	}
	resp := api.evaluateClaudeCodeHook(context.Background(), req)

	if resp.Action != "block" || resp.RawAction != "block" {
		t.Fatalf("action=%q raw=%q, want block/block", resp.Action, resp.RawAction)
	}
	if !containsString(resp.Findings, "ASSET-POLICY-SKILL") {
		t.Fatalf("findings=%v, want ASSET-POLICY-SKILL", resp.Findings)
	}
	for _, want := range []string{"reason_code=default-deny", "source=default-deny", "asset_type=skill", "asset_name=rogue-skill", "connector=claudecode", "registry_status=unknown", "registry_configured=false"} {
		if !strings.Contains(resp.Reason, want) {
			t.Fatalf("reason %q missing %q", resp.Reason, want)
		}
	}
}

func TestEvaluateClaudeCodeHook_AssetPolicyPostToolUseWouldBlock(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "action"
	cfg.AssetPolicy.MCP.Default = "deny"

	api := &APIServer{scannerCfg: cfg}

	req := claudeCodeHookRequest{
		HookEventName: "PostToolUse",
		ToolName:      "mcp__rogue__search",
		ToolResponse:  map[string]interface{}{"ok": true},
	}
	resp := api.evaluateClaudeCodeHook(context.Background(), req)

	if resp.Action != "allow" || resp.RawAction != "block" {
		t.Fatalf("action=%q raw=%q, want allow/block", resp.Action, resp.RawAction)
	}
	if !resp.WouldBlock {
		t.Fatal("PostToolUse asset policy match should be reported as would_block")
	}
}

func TestEvaluateClaudeCodeHook_PostToolUseRuleFindingIsNotReportedAsEnforced(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"

	api := &APIServer{scannerCfg: cfg}
	resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
		HookEventName: "PostToolUse",
		ToolResponse:  map[string]interface{}{"stdout": "jailbreak ai"},
	})

	if resp.Action != "allow" || resp.RawAction != "block" || !resp.WouldBlock {
		t.Fatalf("action=%q raw=%q would_block=%v, want allow/block/true", resp.Action, resp.RawAction, resp.WouldBlock)
	}
	if decision, ok := resp.ClaudeCodeOutput["decision"]; ok && decision == "block" {
		t.Fatalf("claude output = %+v, PostToolUse cannot undo an already-executed tool", resp.ClaudeCodeOutput)
	}
}

func TestEvaluateClaudeCodeHook_PostToolBatchFindingStopsNextModelCall(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"

	api := &APIServer{scannerCfg: cfg}
	resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
		HookEventName: "PostToolBatch",
		ToolCalls:     "jailbreak ai",
	})

	if resp.Action != "block" || resp.RawAction != "block" || resp.WouldBlock {
		t.Fatalf("action=%q raw=%q would_block=%v, want block/block/false", resp.Action, resp.RawAction, resp.WouldBlock)
	}
	if decision, ok := resp.ClaudeCodeOutput["decision"]; !ok || decision != "block" {
		t.Fatalf("claude output = %+v, PostToolBatch must stop before the next model call", resp.ClaudeCodeOutput)
	}
}

func TestEvaluateClaudeCodeHook_ConfigChangeEnforcementDependsOnSource(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := &APIServer{scannerCfg: cfg}

	tests := []struct {
		name           string
		source         string
		wantAction     string
		wantWouldBlock bool
	}{
		{name: "policy settings cannot be blocked", source: "policy_settings", wantAction: "allow", wantWouldBlock: true},
		{name: "user settings remain blockable", source: "user_settings", wantAction: "block", wantWouldBlock: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
				HookEventName: "ConfigChange",
				Source:        tc.source,
				Message:       "jailbreak ai",
			})
			if resp.Action != tc.wantAction || resp.RawAction != "block" || resp.WouldBlock != tc.wantWouldBlock {
				t.Fatalf("action=%q raw=%q would_block=%v, want %s/block/%v", resp.Action, resp.RawAction, resp.WouldBlock, tc.wantAction, tc.wantWouldBlock)
			}
		})
	}
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
