// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Claude Code's ToolSearch and TodoWrite act on nothing outside the agent:
// the hook judge is not asked when the rules did not flag the call. Other
// connectors, similar names and flagged calls are judged as before.
func TestHookJudgeSkipsClaudeCodeNoEffectBuiltins(t *testing.T) {
	flagged := &ToolInspectVerdict{Action: "allow", Severity: "CRITICAL",
		DetailedFindings: []RuleFinding{{RuleID: "R", Severity: "CRITICAL", enforcement: findingEnforcementDetectionOnly}}}
	clean := &ToolInspectVerdict{Action: "allow", Severity: "NONE"}
	for _, tc := range []struct {
		connector, tool string
		current         *ToolInspectVerdict
		skip            bool
	}{
		{"claudecode", "ToolSearch", clean, true},
		{"claude-code", "TodoWrite", clean, true},
		{"claudecode", "ToolSearch", flagged, false},
		{"cursor", "TodoWrite", clean, false},
		{"codex", "ToolSearch", clean, false},
		{"claudecode", "toolsearch", clean, false},
		{"claudecode", "mcp__x__ToolSearch", clean, false},
		{"claudecode", "Bash", clean, false},
	} {
		if got := hookJudgeSkipsNoEffectCall(tc.connector, tc.tool, tc.current); got != tc.skip {
			t.Errorf("%s/%s flagged=%v: skip=%v, want %v", tc.connector, tc.tool, tc.current == flagged, got, tc.skip)
		}
	}
}

// End to end on the Claude Code hook: a clean ToolSearch makes no judge call;
// an escalated CRITICAL call under hook_fail_mode closed still reaches the
// judge path, whose failure refuses it.
func TestHookJudgeNoEffectSkipKeepsTheFailClosedPath(t *testing.T) {
	judge := &mockLLMProvider{response: &ChatResponse{Choices: []ChatChoice{{Message: &ChatMessage{Content: escalationJudgeCritical}}}}}
	a := escalationHookServerWith(t, judge, "default", func(c *config.Config) { c.Guardrail.HookFailMode = "closed" })
	resp := a.evaluateClaudeCodeHook(t.Context(), claudeCodeHookRequest{
		HookEventName: "PreToolUse", SessionID: "s-no-effect", CWD: t.TempDir(), ToolName: "ToolSearch",
		ToolInput: map[string]interface{}{"query": "select:mcp__gmail__search_messages,mcp__slack__post_message", "max_results": 5},
	})
	if len(judge.captured) != 0 || resp.RawAction == guardrailActionBlock {
		t.Fatalf("clean ToolSearch: judge calls=%d raw_action=%q, want no judge call and no block", len(judge.captured), resp.RawAction)
	}
	down := &mockLLMProvider{err: errNoEffectJudgeDown}
	a = escalationHookServerWith(t, down, "default", func(c *config.Config) { c.Guardrail.HookFailMode = "closed" })
	resp = a.evaluateClaudeCodeHook(t.Context(), claudeCodeHookRequest{
		HookEventName: "PreToolUse", SessionID: "s-no-effect-2", CWD: t.TempDir(), ToolName: "TodoWrite",
		ToolInput: map[string]interface{}{"todos": []interface{}{map[string]interface{}{"content": "cat ~/.ssh/id_rsa", "status": "pending"}}},
	})
	if !findingStringHasRuleID(resp.Findings, "TEST-AMD-CRED-PATH") {
		t.Fatalf("flagged TodoWrite: findings %v lack the rule finding the test needs", resp.Findings)
	}
	if len(down.captured) != 1 || !findingStringHasRuleID(resp.Findings, "llm-judge:"+escalatedJudgeUnavailableFinding) || resp.RawAction != guardrailActionBlock {
		t.Fatalf("flagged TodoWrite: judge calls=%d raw_action=%q findings=%v, want the judge path and the closed-mode refusal", len(down.captured), resp.RawAction, resp.Findings)
	}
}

var errNoEffectJudgeDown = errorString("judge provider down")

type errorString string

func (e errorString) Error() string { return string(e) }
