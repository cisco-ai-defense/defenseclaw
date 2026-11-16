// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// kiroV3PwshArgs is the execute_pwsh call kiro-cli 2.35.1 --v3 sent on
// per-user Windows (rel-1-0-6:GAP-0589 evidence, run1 08-audit-raw.jsonl),
// with the user and project directory redacted.
func kiroV3PwshArgs(command string) json.RawMessage {
	return json.RawMessage(`{"command":` + string(mustJSONMarshal(command)) +
		`,"cwd":"c:\\Users\\alice\\proj","description":null,"run_in_background":false,"timeout":null}`)
}

// rel-1-0-6:GAP-0589: on Windows the kiro-cli --v3 engine names its shell
// tool execute_pwsh. The call had no command facts, so a command-fact rule
// only matched its pattern ("detection-only: tool-call patterns alone cannot
// block") and the command ran. It now blocks like the V2 shell and the V3
// execute_bash call; a benign command is still allowed, and an execute_pwsh
// call with no readable command is judged as unverified, as every shell tool.
func TestKiroV3ExecutePwshCommandFactRuleBlocks(t *testing.T) {
	resetConnectorRuleCategories(t)
	const ruleID = "V108V-MARKER-BLOCK"
	if err := ApplyRulePackOverrides(&guardrail.RulePack{RuleFiles: []*guardrail.RulesFileYAML{{
		Version: 1, Category: "v108v-marker", Rules: []guardrail.RuleDefYAML{{
			ID: ruleID, ToolCallOnly: true,
			Pattern:    "v108v-block-marker-",
			Expression: `f.commands.exists(c, c.argv_complete && c.argv.exists(a, a.startsWith("v108v-block-marker-")))`,
			Title:      "v108v marker block", Severity: "CRITICAL", Confidence: 0.99,
		}},
	}}}); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "kiro"
	api := &APIServer{scannerCfg: cfg}
	const marker = "echo v108v-block-marker-act1"
	for _, tc := range []struct {
		name, surface, event, tool string
		args                       json.RawMessage
		want, rule                 string
	}{
		{"v3 pwsh marker", connector.KiroHookSurfaceV3, "PreToolUse", "execute_pwsh", kiroV3PwshArgs(marker), "block", ruleID},
		{"v3 pwsh marker unset cwd", connector.KiroHookSurfaceV3, "PreToolUse", "execute_pwsh",
			json.RawMessage(`{"command":"` + marker + `","cwd":null,"description":null,"run_in_background":false,"timeout":null}`), "block", ruleID},
		{"v3 pwsh benign", connector.KiroHookSurfaceV3, "PreToolUse", "execute_pwsh", kiroV3PwshArgs("echo hello"), "allow", ""},
		{"v3 pwsh no command", connector.KiroHookSurfaceV3, "PreToolUse", "execute_pwsh",
			json.RawMessage(`{"cwd":null,"description":null,"run_in_background":false,"timeout":null}`), "block", unverifiedShellCommandRuleID},
		// Unchanged: the V3 execute_bash call and the CLI 2.x shell call.
		{"v3 bash marker", connector.KiroHookSurfaceV3, "PreToolUse", "execute_bash",
			json.RawMessage(`{"command":"` + marker + `","cwd":null,"description":null,"run_in_background":false,"timeout":null}`), "block", ruleID},
		{"v2 shell marker", connector.KiroHookSurfaceV2, "preToolUse", "shell",
			json.RawMessage(`{"command":"` + marker + `","__tool_use_purpose":"run it"}`), "block", ruleID},
		{"v2 execute_bash marker", connector.KiroHookSurfaceV2, "preToolUse", "execute_bash",
			json.RawMessage(`{"command":"` + marker + `","working_dir":"/w"}`), "block", ruleID},
		{"v2 shell benign", connector.KiroHookSurfaceV2, "preToolUse", "shell",
			json.RawMessage(`{"command":"echo hello","__tool_use_purpose":"run it"}`), "allow", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := api.evaluateAgentHook(t.Context(), agentHookRequest{
				ConnectorName: "kiro", HookEventName: tc.event, HookSurface: tc.surface,
				SessionID: "gap0589", CWD: t.TempDir(), ToolName: tc.tool, ToolArgs: tc.args,
			})
			if resp.Action != tc.want || resp.RawAction != tc.want {
				t.Fatalf("action=%q raw=%q rules=%v reason=%q, want %q", resp.Action, resp.RawAction, resp.RuleIDs, resp.Reason, tc.want)
			}
			if tc.rule != "" && !strings.Contains(resp.Reason, tc.rule) && !containsString(resp.RuleIDs, tc.rule) {
				t.Fatalf("rules=%v reason=%q, want %s", resp.RuleIDs, resp.Reason, tc.rule)
			}
			if tc.want == "block" && strings.Contains(resp.Reason, "detection-only") {
				t.Fatalf("block reason is detection-only: %q", resp.Reason)
			}
			if tc.want == "allow" && containsString(resp.RuleIDs, ruleID) {
				t.Fatalf("benign command matched %s: %v", ruleID, resp.RuleIDs)
			}
		})
	}
}
