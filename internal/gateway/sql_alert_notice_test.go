// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const sqlAlertOnlyNoticeText = "Rule impact.sql_destructive_mutation is alert-only; block_at does not turn it into a block."

const sqlAlertNoticeCommand = "psql -h 127.0.0.1 -d scratchdb -c \"DELETE FROM scratch_table\""

// GAP-0914: the in-chat text for the alert-only SQL rule says that block_at
// does not turn it into a block on Claude Code too, as it does on Codex. The
// decision stays alert and the call runs.
func TestGAP0914ClaudeCodeSQLAlertOnlyNotice(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.BlockAt = "HIGH"
	cfg.Guardrail.Connector = "claudecode"
	api := &APIServer{scannerCfg: cfg}
	response := api.evaluateClaudeCodeHook(authenticatedClaudeCodeTestContext(), claudeCodeHookRequest{
		HookEventName: "PreToolUse", SessionID: "gap0914", CWD: t.TempDir(), ToolName: "Bash",
		ToolInput: map[string]interface{}{"command": sqlAlertNoticeCommand},
	})
	if response.Action != guardrailActionAlert || response.RawAction != guardrailActionAlert ||
		response.WouldBlock || !findingStringHasRuleID(response.Findings, sqlDestructiveMutationRuleID) {
		t.Fatalf("decision changed: %+v", response)
	}
	if !strings.Contains(response.AdditionalContext, "DefenseClaw observed") ||
		!strings.Contains(response.AdditionalContext, sqlAlertOnlyNoticeText) {
		t.Fatalf("additional context=%q", response.AdditionalContext)
	}
	shown, _ := response.ClaudeCodeOutput["systemMessage"].(string)
	if !strings.Contains(shown, sqlAlertOnlyNoticeText) {
		t.Fatalf("claude output=%v", response.ClaudeCodeOutput)
	}
}

// A call without the SQL rule keeps the plain finding line.
func TestGAP0914ClaudeCodeOtherCallHasNoSQLNotice(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.BlockAt = "HIGH"
	cfg.Guardrail.Connector = "claudecode"
	api := &APIServer{scannerCfg: cfg}
	response := api.evaluateClaudeCodeHook(authenticatedClaudeCodeTestContext(), claudeCodeHookRequest{
		HookEventName: "PreToolUse", SessionID: "gap0914b", CWD: t.TempDir(), ToolName: "Bash",
		ToolInput: map[string]interface{}{"command": "ls -la"},
	})
	if strings.Contains(response.AdditionalContext, "alert-only") {
		t.Fatalf("unrelated call got the notice: %+v", response)
	}
}

// GAP-0914 class check: every other connector hook response for the same call
// carries the notice in the additional context, and a native output that
// renders the finding line renders the notice with it.
func TestGAP0914EveryConnectorSQLAlertOnlyNotice(t *testing.T) {
	cases := []struct {
		name string
		tool string
		args map[string]interface{}
	}{
		{"copilot", "bash", map[string]interface{}{"command": sqlAlertNoticeCommand}},
		{"opencode", "bash", map[string]interface{}{"command": sqlAlertNoticeCommand}},
		{"amp", "Bash", map[string]interface{}{"cmd": sqlAlertNoticeCommand}},
		{"cursor", "Shell", map[string]interface{}{"command": sqlAlertNoticeCommand}},
		{"devin", "exec", map[string]interface{}{"command": sqlAlertNoticeCommand}},
		{"antigravity", "run_command", map[string]interface{}{"CommandLine": sqlAlertNoticeCommand}},
		{"hermes", "terminal", map[string]interface{}{"command": sqlAlertNoticeCommand}},
		{"kiro", "execute_bash", map[string]interface{}{"command": sqlAlertNoticeCommand}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.BlockAt = "HIGH"
			cfg.Guardrail.Connector = tc.name
			api := &APIServer{scannerCfg: cfg}
			profile := api.hookProfileForConnector(tc.name)
			event := panicTestEvent(profile, true)
			if tc.name == "kiro" && event == "" {
				// Host Kiro installs two surfaces without a versioned contract.
				event = "preToolUse"
			}
			if event == "" {
				t.Fatalf("no pre-tool event for %s", tc.name)
			}
			args, err := json.Marshal(tc.args)
			if err != nil {
				t.Fatal(err)
			}
			resp := api.evaluateAgentHook(t.Context(), agentHookRequest{
				ConnectorName: tc.name, HookEventName: event, SessionID: "gap0914-" + tc.name,
				CWD: t.TempDir(), ToolName: tc.tool, ToolArgs: args,
			})
			if resp.Action != guardrailActionAlert || resp.WouldBlock ||
				!findingStringHasRuleID(resp.Findings, sqlDestructiveMutationRuleID) {
				t.Fatalf("decision: action=%q raw=%q findings=%v reason=%q", resp.Action, resp.RawAction, resp.Findings, resp.Reason)
			}
			if !strings.Contains(resp.AdditionalContext, sqlAlertOnlyNoticeText) {
				t.Fatalf("additional context=%q", resp.AdditionalContext)
			}
			wire := renderAgentHookResponseForProfile(profile, resp)
			if text, _ := wire["additional_context"].(string); !strings.Contains(text, sqlAlertOnlyNoticeText) {
				t.Fatalf("wire additional_context=%q", text)
			}
			out, _ := json.Marshal(resp.HookOutput)
			if strings.Contains(string(out), "DefenseClaw observed") && !strings.Contains(string(out), "alert-only") {
				t.Fatalf("native output drops the notice: %s", out)
			}
		})
	}
}
