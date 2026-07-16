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
	"encoding/json"
	"path/filepath"
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

func TestEvaluateClaudeCodeHook_RealUserSettingsSkillExpansionRuntimeDisable(t *testing.T) {
	claudeHome := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", claudeHome)
	writeClaudeCodeTestSkill(t, filepath.Join(claudeHome, "skills"), "dc-test-benign")

	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	store, _ := testStoreAndLogger(t)
	if err := store.SetActionFieldForConnector("skill", "dc-test-benign", "claudecode", "runtime", "disable", "runtime acceptance"); err != nil {
		t.Fatalf("seed Claude runtime disable: %v", err)
	}
	api := &APIServer{scannerCfg: cfg, store: store}

	var req claudeCodeHookRequest
	if err := json.Unmarshal([]byte(`{
		"session_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		"transcript_path":"C:\\temp\\claude-transcript.jsonl",
		"cwd":"C:\\temp",
		"prompt_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		"permission_mode":"default",
		"hook_event_name":"UserPromptExpansion",
		"expansion_type":"slash_command",
		"command_name":"dc-test-benign",
		"command_args":"Kevin",
		"command_source":"userSettings",
		"prompt":"/dc-test-benign Kevin"
	}`), &req); err != nil {
		t.Fatalf("decode captured Claude Code 2.1.196 payload: %v", err)
	}

	resp := api.evaluateClaudeCodeHook(context.Background(), req)
	if resp.Action != "block" || resp.RawAction != "block" {
		t.Fatalf("action=%q raw=%q, want block/block", resp.Action, resp.RawAction)
	}
	if resp.ClaudeCodeOutput["decision"] != "block" {
		t.Fatalf("claude output=%+v, want UserPromptExpansion decision=block", resp.ClaudeCodeOutput)
	}
	for _, want := range []string{"asset_type=skill", "asset_name=dc-test-benign", "connector=claudecode", "source=runtime-disable", "surface=prompt_expansion"} {
		if !strings.Contains(resp.Reason, want) {
			t.Fatalf("reason %q missing %q", resp.Reason, want)
		}
	}
	if strings.Contains(resp.Reason, "Kevin") || strings.Contains(resp.Reason, req.Prompt) {
		t.Fatalf("reason leaked prompt content: %q", resp.Reason)
	}
}

func TestEvaluateClaudeCodeHook_UserPromptExpansionRuntimeDisableRemainsHardInObserveMode(t *testing.T) {
	claudeHome := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", claudeHome)
	writeClaudeCodeTestSkill(t, filepath.Join(claudeHome, "skills"), "disabled-in-observe")

	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Connector = "claudecode"
	store, _ := testStoreAndLogger(t)
	if err := store.SetActionFieldForConnector("skill", "disabled-in-observe", "claudecode", "runtime", "disable", "test"); err != nil {
		t.Fatal(err)
	}
	api := &APIServer{scannerCfg: cfg, store: store}

	resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
		HookEventName: "UserPromptExpansion",
		ExpansionType: "slash_command",
		CommandName:   "disabled-in-observe",
		CommandSource: "userSettings",
		Prompt:        "/disabled-in-observe Kevin",
	})
	if resp.Action != "block" || resp.RawAction != "block" || resp.WouldBlock {
		t.Fatalf("runtime disable became advisory in hook observe mode: action=%q raw=%q would_block=%v", resp.Action, resp.RawAction, resp.WouldBlock)
	}
	if resp.ClaudeCodeOutput["decision"] != "block" {
		t.Fatalf("claude output=%+v, want UserPromptExpansion decision=block", resp.ClaudeCodeOutput)
	}
}

func TestEvaluateClaudeCodeHook_RealUserSettingsSkillExpansionAllowed(t *testing.T) {
	claudeHome := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", claudeHome)
	writeClaudeCodeTestSkill(t, filepath.Join(claudeHome, "skills"), "dc-test-benign")

	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	store, _ := testStoreAndLogger(t)
	api := &APIServer{scannerCfg: cfg, store: store}

	var req claudeCodeHookRequest
	if err := json.Unmarshal([]byte(`{
		"session_id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		"transcript_path":"C:\\temp\\claude-transcript.jsonl",
		"cwd":"C:\\temp",
		"prompt_id":"dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		"permission_mode":"default",
		"hook_event_name":"UserPromptExpansion",
		"expansion_type":"slash_command",
		"command_name":"dc-test-benign",
		"command_args":"Kevin",
		"command_source":"userSettings",
		"prompt":"/dc-test-benign Kevin"
	}`), &req); err != nil {
		t.Fatalf("decode captured Claude Code 2.1.196 payload: %v", err)
	}

	resp := api.evaluateClaudeCodeHook(context.Background(), req)
	if resp.Action != "allow" || resp.RawAction != "allow" {
		t.Fatalf("action=%q raw=%q, want allow/allow", resp.Action, resp.RawAction)
	}
	if containsString(resp.Findings, "ASSET-POLICY-SKILL") {
		t.Fatalf("findings=%v, allowed real skill must not produce a skill block", resp.Findings)
	}
}

func TestEvaluateClaudeCodeHook_RealProjectSettingsSkillExpansionRuntimeDisable(t *testing.T) {
	workspace := t.TempDir()
	writeClaudeCodeTestSkill(t, filepath.Join(workspace, ".claude", "skills"), "dc-project-runtime-capture")

	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	store, _ := testStoreAndLogger(t)
	if err := store.SetActionFieldForConnector("skill", "dc-project-runtime-capture", "claudecode", "runtime", "disable", "runtime acceptance"); err != nil {
		t.Fatalf("seed Claude project runtime disable: %v", err)
	}
	api := &APIServer{scannerCfg: cfg, store: store}

	// Captured from the signed Claude Code 2.1.196 client with an inert
	// .claude/skills fixture. The project scope differs from the user-root
	// capture only in command_source.
	var req claudeCodeHookRequest
	if err := json.Unmarshal([]byte(`{
		"session_id":"f3c1f319-72c4-4e12-8b40-c50d70baf666",
		"transcript_path":"C:\\temp\\claude-project-transcript.jsonl",
		"cwd":"`+filepath.ToSlash(workspace)+`",
		"prompt_id":"7043fe36-08be-497b-a9b5-d6d7a70cfbac",
		"permission_mode":"acceptEdits",
		"hook_event_name":"UserPromptExpansion",
		"expansion_type":"slash_command",
		"command_name":"dc-project-runtime-capture",
		"command_args":"Kevin",
		"command_source":"projectSettings",
		"prompt":"/dc-project-runtime-capture Kevin"
	}`), &req); err != nil {
		t.Fatalf("decode captured Claude Code project payload: %v", err)
	}

	resp := api.evaluateClaudeCodeHook(context.Background(), req)
	if resp.Action != "block" || resp.RawAction != "block" {
		t.Fatalf("project skill action=%q raw=%q, want block/block", resp.Action, resp.RawAction)
	}
	if resp.ClaudeCodeOutput["decision"] != "block" {
		t.Fatalf("claude output=%+v, want project expansion decision=block", resp.ClaudeCodeOutput)
	}
}

func TestEvaluateClaudeCodeHook_RealStructuredSkillToolRuntimeDisable(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	store, _ := testStoreAndLogger(t)
	if err := store.SetActionFieldForConnector("skill", "dc-test-benign", "claudecode", "runtime", "disable", "runtime acceptance"); err != nil {
		t.Fatalf("seed Claude runtime disable: %v", err)
	}
	api := &APIServer{scannerCfg: cfg, store: store}

	var req claudeCodeHookRequest
	if err := json.Unmarshal([]byte(`{
		"session_id":"eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
		"transcript_path":"C:\\temp\\claude-transcript.jsonl",
		"cwd":"C:\\temp",
		"prompt_id":"ffffffff-ffff-4fff-8fff-ffffffffffff",
		"permission_mode":"default",
		"effort":{"level":"high"},
		"hook_event_name":"PreToolUse",
		"tool_name":"Skill",
		"tool_input":{"skill":"dc-test-benign","args":"Kevin"},
		"tool_use_id":"toolu_inert"
	}`), &req); err != nil {
		t.Fatalf("decode captured Claude Code structured Skill payload: %v", err)
	}

	resp := api.evaluateClaudeCodeHook(context.Background(), req)
	if resp.Action != "block" || resp.RawAction != "block" {
		t.Fatalf("action=%q raw=%q, want block/block", resp.Action, resp.RawAction)
	}
	hookOutput, ok := resp.ClaudeCodeOutput["hookSpecificOutput"].(map[string]interface{})
	if !ok || hookOutput["permissionDecision"] != "deny" {
		t.Fatalf("claude output=%+v, want PreToolUse permissionDecision=deny", resp.ClaudeCodeOutput)
	}
}

func TestEvaluateClaudeCodeHook_RealUserSettingsSkillConnectorAndGlobalScope(t *testing.T) {
	claudeHome := t.TempDir()
	codexHome := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", claudeHome)
	t.Setenv("CODEX_HOME", codexHome)
	writeClaudeCodeTestSkill(t, filepath.Join(claudeHome, "skills"), "shared-skill")
	writeClaudeCodeTestSkill(t, filepath.Join(codexHome, "skills"), "shared-skill")
	writeClaudeCodeTestSkill(t, filepath.Join(claudeHome, "skills"), "global-skill")

	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	store, _ := testStoreAndLogger(t)
	api := &APIServer{scannerCfg: cfg, store: store}

	request := func(name string) claudeCodeHookRequest {
		return claudeCodeHookRequest{
			HookEventName: "UserPromptExpansion",
			ExpansionType: "slash_command",
			CommandName:   name,
			CommandSource: "userSettings",
			Prompt:        "/" + name,
		}
	}

	if err := store.SetActionFieldForConnector("skill", "shared-skill", "codex", "runtime", "disable", "Codex only"); err != nil {
		t.Fatalf("seed Codex-only disable: %v", err)
	}
	resp := api.evaluateClaudeCodeHook(context.Background(), request("shared-skill"))
	if resp.Action != "allow" || resp.RawAction != "allow" {
		t.Fatalf("Codex-scoped disable leaked to Claude: action=%q raw=%q", resp.Action, resp.RawAction)
	}

	if err := store.SetActionFieldForConnector("skill", "shared-skill", "claudecode", "runtime", "disable", "Claude only"); err != nil {
		t.Fatalf("seed Claude disable: %v", err)
	}
	resp = api.evaluateClaudeCodeHook(context.Background(), request("shared-skill"))
	if resp.Action != "block" || resp.RawAction != "block" {
		t.Fatalf("Claude-scoped disable did not block: action=%q raw=%q", resp.Action, resp.RawAction)
	}

	if err := store.SetActionField("skill", "global-skill", "runtime", "disable", "global"); err != nil {
		t.Fatalf("seed global disable: %v", err)
	}
	resp = api.evaluateClaudeCodeHook(context.Background(), request("global-skill"))
	if resp.Action != "block" || resp.RawAction != "block" {
		t.Fatalf("global disable did not block Claude: action=%q raw=%q", resp.Action, resp.RawAction)
	}

	// Claude can retain a skill selection in an already-running session after
	// the directory changes. The scoped policy record remains a canonical known
	// identity and must still block that observable expansion.
	if err := store.SetActionFieldForConnector("skill", "active-session-skill", "claudecode", "runtime", "disable", "active session"); err != nil {
		t.Fatalf("seed active-session disable: %v", err)
	}
	resp = api.evaluateClaudeCodeHook(context.Background(), request("active-session-skill"))
	if resp.Action != "block" || resp.RawAction != "block" {
		t.Fatalf("active-session cached skill did not block: action=%q raw=%q", resp.Action, resp.RawAction)
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
