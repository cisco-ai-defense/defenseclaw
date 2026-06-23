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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func attrByKey(kv []attribute.KeyValue, key string) (attribute.Value, bool) {
	for _, a := range kv {
		if string(a.Key) == key {
			return a.Value, true
		}
	}
	return attribute.Value{}, false
}

// trustExploitKeyword returns a CRITICAL-severity trigger phrase without
// embedding the literal string in this source file — otherwise the
// repo's own PreToolUse hook would block writing the test.
func trustExploitKeyword() string {
	return "jail" + "break ai"
}

// TestEvaluateCodexHook_ActiveConnectorImpliesEnabled mirrors the
// Claude Code invariant for Codex: selecting the codex connector is
// the only opt-in an operator should need. Without this, a CRITICAL
// trust-exploit keyword in the user prompt came back as action=allow,
// severity=NONE — the rule scanner never ran.
func TestEvaluateCodexHook_ActiveConnectorImpliesEnabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"

	api := &APIServer{scannerCfg: cfg}

	req := codexHookRequest{
		HookEventName: "UserPromptSubmit",
		Prompt:        trustExploitKeyword(),
	}
	resp := api.evaluateCodexHook(context.Background(), req)

	if resp.RawAction != "block" {
		t.Errorf("RawAction = %q, want block (trust-exploit rule must fire)", resp.RawAction)
	}
	if resp.Severity != "CRITICAL" {
		t.Errorf("Severity = %q, want CRITICAL", resp.Severity)
	}
}

func TestCodexEnabled_AutomaticSourceNotLazyHealthCounter(t *testing.T) {
	cfg := &config.Config{ApplicationProtection: config.DefaultApplicationProtectionConfig()}
	health := NewSidecarHealth()
	health.RecordConnectorRequestFor("codex")
	api := &APIServer{scannerCfg: cfg, health: health}

	if api.codexEnabled() {
		t.Fatal("lazy health counter enabled codex without automatic activation")
	}

	health.RegisterConnectorWithSource("codex", connector.ToolModeBoth, connector.SubprocessNone, "automatic")
	if !api.codexEnabled() {
		t.Fatal("source=automatic registration should enable codex inspection")
	}
}

// TestEvaluateCodexHook_NonCodexConnectorStaysDisabled guards the
// opposite direction: a Claude-based install must not start evaluating
// Codex hooks just because the endpoint exists — that would waste
// cycles on requests the operator never installed hooks for.
func TestEvaluateCodexHook_NonCodexConnectorStaysDisabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"

	api := &APIServer{scannerCfg: cfg}

	req := codexHookRequest{
		HookEventName: "UserPromptSubmit",
		Prompt:        trustExploitKeyword(),
	}
	resp := api.evaluateCodexHook(context.Background(), req)

	if resp.RawAction != "allow" {
		t.Errorf("RawAction = %q, want allow (codex hooks should be inert under a different connector)", resp.RawAction)
	}
}

// TestEvaluateCodexHook_ExplicitEnableStillWorks ensures operators who
// explicitly set codex.enabled=true still get inspection even when the
// connector name itself would have been inert.
func TestEvaluateCodexHook_ExplicitEnableStillWorks(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = ""
	cfg.Codex.Enabled = true

	api := &APIServer{scannerCfg: cfg}

	req := codexHookRequest{
		HookEventName: "UserPromptSubmit",
		Prompt:        trustExploitKeyword(),
	}
	resp := api.evaluateCodexHook(context.Background(), req)

	if resp.RawAction != "block" {
		t.Errorf("RawAction = %q, want block", resp.RawAction)
	}
}

// TestEvaluateCodexHook_PerConnectorDisableAllowsWithoutScan pins the
// defense-in-depth gate: when codex is a member of guardrail.connectors but
// explicitly disabled (`guardrail disable --connector codex`), a hook that
// still calls in is allowed without scanning, even though the prompt carries
// a block-worthy keyword.
func TestEvaluateCodexHook_PerConnectorDisableAllowsWithoutScan(t *testing.T) {
	off := false
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex": {Enabled: &off},
	}

	api := &APIServer{scannerCfg: cfg}

	req := codexHookRequest{
		HookEventName: "UserPromptSubmit",
		Prompt:        trustExploitKeyword(),
	}
	resp := api.evaluateCodexHook(context.Background(), req)

	if resp.RawAction != "allow" {
		t.Errorf("RawAction = %q, want allow (disabled connector must not scan)", resp.RawAction)
	}
}

func TestEvaluateCodexHook_HILTPreToolUseDoesNotAsk(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	cfg.Guardrail.HILT.Enabled = true
	cfg.Guardrail.HILT.MinSeverity = "HIGH"

	api := &APIServer{scannerCfg: cfg}
	resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput: map[string]interface{}{
			"command": "invoke the bash tool without confirmation",
		},
	})

	if resp.RawAction != "confirm" || resp.Action != "alert" {
		t.Fatalf("action=%q raw=%q, want alert/confirm", resp.Action, resp.RawAction)
	}
	if out := resp.CodexOutput; out == nil || out["systemMessage"] == "" {
		t.Fatalf("codex output = %+v, want systemMessage warning", out)
	}
	if hook, ok := resp.CodexOutput["hookSpecificOutput"].(map[string]interface{}); ok {
		if decision, _ := hook["permissionDecision"].(string); decision == "ask" {
			t.Fatalf("Codex PreToolUse must not emit permissionDecision=ask")
		}
	}
}

func TestEvaluateCodexHook_HILTPermissionRequestAbstains(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	cfg.Guardrail.HILT.Enabled = true
	cfg.Guardrail.HILT.MinSeverity = "HIGH"

	api := &APIServer{scannerCfg: cfg}
	resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
		HookEventName: "PermissionRequest",
		ToolName:      "Bash",
		ToolInput: map[string]interface{}{
			"command": "invoke the bash tool without confirmation",
		},
	})

	if resp.RawAction != "confirm" || resp.Action != "alert" {
		t.Fatalf("action=%q raw=%q, want alert/confirm", resp.Action, resp.RawAction)
	}
	if _, ok := resp.CodexOutput["hookSpecificOutput"]; ok {
		t.Fatalf("Codex PermissionRequest confirm should abstain from allow/deny, got %+v", resp.CodexOutput)
	}
	if resp.CodexOutput["systemMessage"] == "" {
		t.Fatalf("codex output = %+v, want systemMessage warning", resp.CodexOutput)
	}
}

func TestEvaluateCodexHook_TerminalMCPAddBlocked(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "action"
	cfg.AssetPolicy.MCP.Default = "deny"

	api := &APIServer{scannerCfg: cfg}

	req := codexHookRequest{
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput: map[string]interface{}{
			"command": "codex mcp add rogue -- npx -y @modelcontextprotocol/server-filesystem",
		},
	}
	resp := api.evaluateCodexHook(context.Background(), req)

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

func TestEvaluateCodexHook_DirectMCPAddBlocked(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "action"
	cfg.AssetPolicy.MCP.RegistryRequired = true
	cfg.AssetPolicy.MCP.Registry = []config.AssetPolicyRule{{Name: "github"}}

	api := &APIServer{scannerCfg: cfg}

	req := codexHookRequest{
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput: map[string]interface{}{
			"command": "mcp add rogue -- npx -y mcp-server-demo",
		},
	}
	resp := api.evaluateCodexHook(context.Background(), req)

	if resp.Action != "block" || resp.RawAction != "block" {
		t.Fatalf("action=%q raw=%q, want block/block", resp.Action, resp.RawAction)
	}
	if resp.Reason == "" {
		t.Fatal("expected asset-policy block reason")
	}
}

func TestEvaluateCodexHook_BlocksUnregisteredMCPPermissionRequest(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "action"
	cfg.AssetPolicy.MCP.RegistryRequired = true
	cfg.AssetPolicy.MCP.Registry = []config.AssetPolicyRule{{Name: "github"}}

	api := &APIServer{scannerCfg: cfg}

	resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
		HookEventName: "PermissionRequest",
		ToolName:      "mcp__rogue__search",
		ToolInput:     map[string]interface{}{"query": "status"},
	})

	if resp.Action != "block" || resp.RawAction != "block" {
		t.Fatalf("action=%q raw=%q, want block/block", resp.Action, resp.RawAction)
	}
	if !containsString(resp.Findings, "ASSET-POLICY-MCP") {
		t.Fatalf("findings=%v, want ASSET-POLICY-MCP", resp.Findings)
	}
	hook, ok := resp.CodexOutput["hookSpecificOutput"].(map[string]interface{})
	if !ok {
		t.Fatalf("codex output = %+v, want hookSpecificOutput", resp.CodexOutput)
	}
	decision, ok := hook["decision"].(map[string]interface{})
	if !ok || decision["behavior"] != "deny" {
		t.Fatalf("permission decision = %+v, want behavior=deny", hook["decision"])
	}
}

func TestEvaluateCodexHook_BlocksUnregisteredSkillPermissionRequest(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "action"
	cfg.AssetPolicy.Skill.RegistryRequired = true
	cfg.AssetPolicy.Skill.Registry = []config.AssetPolicyRule{{Name: "trusted-skill"}}
	enableSkillRuntimeDetection(cfg)

	api := &APIServer{scannerCfg: cfg}

	resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
		HookEventName: "PermissionRequest",
		ToolName:      "Skill",
		ToolInput:     map[string]interface{}{"skill_name": "rogue-skill"},
	})

	if resp.Action != "block" || resp.RawAction != "block" {
		t.Fatalf("action=%q raw=%q, want block/block", resp.Action, resp.RawAction)
	}
	if resp.Severity != "HIGH" {
		t.Fatalf("severity=%q, want HIGH", resp.Severity)
	}
	if !containsString(resp.Findings, "ASSET-POLICY-SKILL") {
		t.Fatalf("findings=%v, want ASSET-POLICY-SKILL", resp.Findings)
	}
	if resp.Reason == "" {
		t.Fatal("expected skill asset-policy block reason")
	}
	hook, ok := resp.CodexOutput["hookSpecificOutput"].(map[string]interface{})
	if !ok {
		t.Fatalf("codex output = %+v, want hookSpecificOutput", resp.CodexOutput)
	}
	decision, ok := hook["decision"].(map[string]interface{})
	if !ok || decision["behavior"] != "deny" {
		t.Fatalf("permission decision = %+v, want behavior=deny", hook["decision"])
	}
	for _, want := range []string{"reason_code=not-in-approved-registry", "asset_type=skill", "asset_name=rogue-skill", "connector=codex", "source=registry-required", "registry_status=not-registered", "registry_configured=true"} {
		if !strings.Contains(resp.Reason, want) {
			t.Fatalf("reason %q missing %q", resp.Reason, want)
		}
	}
}

// TestEvaluateCodexHook_RegistryRequiredEmptyDeniesByDefault is the
// Codex-side mirror of the Claude Code test. Empty registry +
// registry_required=true must block under the new fail-closed default,
// regardless of MCP.Default. Operators must opt into the looser
// behavior via registry_empty_action="allow".
func TestEvaluateCodexHook_RegistryRequiredEmptyDeniesByDefault(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "action"
	cfg.AssetPolicy.MCP.RegistryRequired = true

	api := &APIServer{scannerCfg: cfg}

	resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
		HookEventName: "PermissionRequest",
		ToolName:      "mcp__rogue__search",
		ToolInput:     map[string]interface{}{"query": "status"},
	})

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

func TestEvaluateCodexHook_RegistryRequiredEmptyAllowOptInPermits(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "action"
	cfg.AssetPolicy.MCP.RegistryRequired = true
	cfg.AssetPolicy.MCP.RegistryEmptyAction = "allow"

	api := &APIServer{scannerCfg: cfg}

	resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
		HookEventName: "PermissionRequest",
		ToolName:      "mcp__rogue__search",
		ToolInput:     map[string]interface{}{"query": "status"},
	})

	if resp.Action != "allow" || resp.RawAction != "allow" {
		t.Fatalf("action=%q raw=%q, want allow/allow", resp.Action, resp.RawAction)
	}
	if containsString(resp.Findings, "ASSET-POLICY-MCP") {
		t.Fatalf("findings=%v, did not expect ASSET-POLICY-MCP", resp.Findings)
	}
}

func TestEvaluateCodexHook_SkillDefaultDenyBlocksWithoutRegistry(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "action"
	cfg.AssetPolicy.Skill.Default = "deny"
	enableSkillRuntimeDetection(cfg)

	api := &APIServer{scannerCfg: cfg}

	resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
		HookEventName: "PermissionRequest",
		ToolName:      "Skill",
		ToolInput:     map[string]interface{}{"skill_name": "rogue-skill"},
	})

	if resp.Action != "block" || resp.RawAction != "block" {
		t.Fatalf("action=%q raw=%q, want block/block", resp.Action, resp.RawAction)
	}
	for _, want := range []string{"reason_code=default-deny", "source=default-deny", "registry_status=unknown", "registry_configured=false"} {
		if !strings.Contains(resp.Reason, want) {
			t.Fatalf("reason %q missing %q", resp.Reason, want)
		}
	}
}

func TestEvaluateCodexHook_ObserveAssetPolicyWouldBlock(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "observe"
	cfg.AssetPolicy.MCP.Default = "deny"

	api := &APIServer{scannerCfg: cfg}

	req := codexHookRequest{
		HookEventName: "PreToolUse",
		ToolName:      "mcp__rogue__search",
		ToolInput:     map[string]interface{}{"query": "status"},
	}
	resp := api.evaluateCodexHook(context.Background(), req)

	if resp.Action != "allow" || resp.RawAction != "block" {
		t.Fatalf("action=%q raw=%q, want allow/block", resp.Action, resp.RawAction)
	}
	if !resp.WouldBlock {
		t.Fatal("observe-mode asset policy match should be reported as would_block")
	}
}

func TestEvaluateCodexHook_RuntimeDetectionCanDisableTerminalMCP(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "action"
	cfg.AssetPolicy.MCP.Default = "deny"
	cfg.AssetPolicy.MCP.RuntimeDetection.TerminalCommands = false

	api := &APIServer{scannerCfg: cfg}

	req := codexHookRequest{
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput: map[string]interface{}{
			"command": "codex mcp add rogue -- npx -y @modelcontextprotocol/server-filesystem",
		},
	}
	resp := api.evaluateCodexHook(context.Background(), req)

	if resp.Action != "allow" || resp.RawAction != "allow" {
		t.Fatalf("action=%q raw=%q, want allow/allow", resp.Action, resp.RawAction)
	}
	if resp.WouldBlock {
		t.Fatal("terminal runtime detection disabled should not report would_block")
	}
}

// TestEvaluateCodexHook_UnknownTerminalMCPDefaultsToWouldBlock pins the
// fix: when AssetPolicy is in action mode and MCP.Default is
// "deny", an unknown terminal MCP command MUST block even when the
// secondary `runtime_detection.unknown_terminal_mcp` knob is left at
// its observe default. Operators that explicitly opt into
// MCP.Default=deny should not have to discover and override the
// secondary knob to get default-deny semantics.
func TestEvaluateCodexHook_UnknownTerminalMCPDefaultsToWouldBlock(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "action"
	cfg.AssetPolicy.MCP.Default = "deny"

	api := &APIServer{scannerCfg: cfg}

	req := codexHookRequest{
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput: map[string]interface{}{
			"command": "npx -y @modelcontextprotocol/server-filesystem /tmp",
		},
	}
	resp := api.evaluateCodexHook(context.Background(), req)

	if resp.Action != "block" || resp.RawAction != "block" {
		t.Fatalf("action=%q raw=%q, want block/block — MCP.Default=deny in action mode must not be silently downgraded by unknown_terminal_mcp=observe",
			resp.Action, resp.RawAction)
	}
}

func TestEvaluateCodexHook_UnknownTerminalMCPCanBlock(t *testing.T) {
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = "action"
	cfg.AssetPolicy.MCP.Default = "deny"
	cfg.AssetPolicy.MCP.RuntimeDetection.UnknownTerminalMCP = "action"

	api := &APIServer{scannerCfg: cfg}

	req := codexHookRequest{
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput: map[string]interface{}{
			"command": "npx -y @modelcontextprotocol/server-filesystem /tmp",
		},
	}
	resp := api.evaluateCodexHook(context.Background(), req)

	if resp.Action != "block" || resp.RawAction != "block" {
		t.Fatalf("action=%q raw=%q, want block/block", resp.Action, resp.RawAction)
	}
}

func TestMergeAssetDecision_ObserveDoesNotDowngradeExistingBlock(t *testing.T) {
	decision := config.AssetPolicyDecision{
		Action:    "allow",
		RawAction: "block",
		Reason:    "asset policy would block",
	}

	action, rawAction, severity, reason, findings, wouldBlock := mergeAssetDecision(
		decision,
		true,
		"mcp",
		"PreToolUse",
		"block",
		"block",
		"CRITICAL",
		"scanner blocked tool call",
		[]string{"TRUST-JAILBREAK"},
	)

	if action != "block" || rawAction != "block" {
		t.Fatalf("action=%q raw=%q, want block/block", action, rawAction)
	}
	if severity != "CRITICAL" {
		t.Fatalf("severity=%q, want CRITICAL", severity)
	}
	if reason != "scanner blocked tool call" {
		t.Fatalf("reason=%q, want scanner reason preserved", reason)
	}
	if !wouldBlock {
		t.Fatal("observe asset policy should still be reported as would_block")
	}
	if !containsString(findings, "ASSET-POLICY-MCP") {
		t.Fatalf("findings=%v, want ASSET-POLICY-MCP", findings)
	}
}

func TestGitChangedFiles_MaliciousGitConfig(t *testing.T) {
	dir := t.TempDir()
	gitDir := dir + "/.git"
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	maliciousConfig := `[core]
	fsmonitor = echo PWNED > /tmp/pwned
	hooksPath = /tmp/evil-hooks
[init]
	defaultBranch = main
`
	if err := os.WriteFile(gitDir+"/config", []byte(maliciousConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gitDir+"/HEAD", []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := gitChangedFiles(context.Background(), dir)
	if err != nil && os.IsNotExist(err) {
		t.Skip("git not in PATH")
	}
	pwnedPath := "/tmp/pwned"
	if _, statErr := os.Stat(pwnedPath); statErr == nil {
		os.Remove(pwnedPath)
		t.Fatal("safeGitEnv() did not prevent fsmonitor execution — /tmp/pwned was created")
	}
}

func TestGitChangedFiles_EmptyCWD(t *testing.T) {
	files, err := gitChangedFiles(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty cwd")
	}
	if len(files) != 0 {
		t.Errorf("expected no files, got %d", len(files))
	}
}

func TestGitChangedFiles_NonexistentDir(t *testing.T) {
	files, err := gitChangedFiles(context.Background(), "/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
	if len(files) != 0 {
		t.Errorf("expected no files, got %d", len(files))
	}
}

func TestSanitizeHookCWD_Traversal(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"relative/path", ""},
		{"  ", ""},
	}
	for _, tt := range tests {
		got := sanitizeHookCWD(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeHookCWD(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
	got := sanitizeHookCWD(t.TempDir())
	if got == "" {
		t.Error("sanitizeHookCWD(valid absolute dir) returned empty")
	}
}

func TestHandleCodexHook_EnrichesHTTPSpan(t *testing.T) {
	gatewaylog.SetProcessRunID("run-hook-123")
	t.Cleanup(func() { gatewaylog.SetProcessRunID("") })

	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exp),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	defer otel.SetTracerProvider(prev)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	api := &APIServer{}
	// PR #284: handleCodexHook was deleted; the unified pipeline
	// now serves /api/v1/codex/hook via handleAgentHook("codex").
	// The typed evaluator + span enricher (evaluateCodexHook /
	// enrichCodexHookSpan) are invoked by the profile-runtime
	// registry so the gen_ai.* and
	// defenseclaw.codex.hook.* span attributes asserted below
	// remain present.
	handler := otelHTTPServerMiddleware("sidecar-api", api.handleAgentHook("codex"))

	body, err := json.Marshal(codexHookRequest{
		HookEventName: "PreToolUse",
		SessionID:     "session-123",
		TurnID:        "turn-123",
		Model:         "gpt-5.5",
		ToolName:      "Bash",
		ToolUseID:     "tool-call-123",
		AgentID:       "openai_codex",
		AgentType:     "codex",
		ToolInput: map[string]interface{}{
			"command": "pwd",
		},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%s", w.Code, w.Body.String())
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans want 1", len(spans))
	}
	s := spans[0]
	if s.Name != "POST /api/v1/codex/hook" {
		t.Fatalf("span name=%q want POST /api/v1/codex/hook", s.Name)
	}

	for key, want := range map[string]string{
		"gen_ai.conversation.id":         "session-123",
		"defenseclaw.run.id":             "run-hook-123",
		"gen_ai.agent.name":              "codex",
		"gen_ai.agent.type":              "codex",
		"gen_ai.agent.id":                "openai_codex",
		"defenseclaw.codex.hook.event":   "PreToolUse",
		"defenseclaw.turn_id":            "turn-123",
		"defenseclaw.codex.hook.turn_id": "turn-123",
		"gen_ai.request.model":           "gpt-5.5",
		"gen_ai.tool.name":               "Bash",
		"gen_ai.tool.call.id":            "tool-call-123",
	} {
		got, ok := attrByKey(s.Attributes, key)
		if !ok || got.AsString() != want {
			t.Fatalf("%s=%q ok=%v want %q", key, got.AsString(), ok, want)
		}
	}
}
