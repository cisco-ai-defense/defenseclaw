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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
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

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
