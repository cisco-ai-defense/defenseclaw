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

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// The test-only marker rules: the E2E marker rule of
// test/e2e/openshell/testdata/guardrail-e2e-marker.yaml, a rule whose title
// quotes what it matches, a secret rule with a harmless pattern, and a rule
// whose title matches a built-in command rule pattern to test cross-category
// title validation.
func installSandboxMarkerRules(t *testing.T) {
	t.Helper()
	resetConnectorRuleCategories(t)
	pack := &guardrail.RulePack{RuleFiles: []*guardrail.RulesFileYAML{
		{Version: 1, Category: "e2e-marker", Rules: []guardrail.RuleDefYAML{
			{
				ID: "E2E-SANDBOX-MARKER", ToolCallOnly: true,
				Expression: "f.commands.exists(c, c.program == 'echo' && 'DCE2E-BLOCK-MARKER' in c.argv)",
				Pattern:    "DCE2E-BLOCK-MARKER", Title: "E2E sandbox marker command", Severity: "CRITICAL", Confidence: 0.99,
			},
			{ID: "E2E-QUOTING-TITLE", Pattern: "dce2e-quoted-[0-9]+", Title: "Blocks dce2e-quoted-42", Severity: "HIGH", Confidence: 0.9},
			{ID: "E2E-SECRET-TITLE", Pattern: "dce2e-other", Title: "Mentions dce2e_secret_7", Severity: "MEDIUM", Confidence: 0.9},
			{ID: "E2E-CMD-TITLE", Pattern: "dce2e-harmless", Title: "systemctl enable backdoor.service", Severity: "MEDIUM", Confidence: 0.9},
		}},
		{Version: 1, Category: "secret", Rules: []guardrail.RuleDefYAML{
			{ID: "E2E-SECRET", Pattern: "dce2e_secret_[0-9]+", Title: "E2E secret marker", Severity: "HIGH", Confidence: 0.9},
		}},
	}}
	if err := ApplyRulePackOverrides(pack); err != nil {
		t.Fatal(err)
	}
}

func sandboxTestBinding(connectorName string) sandboxauth.Binding {
	return sandboxauth.Binding{
		ID: "sb_000000000000000000000000000000e2", Connector: connectorName, SandboxName: "dc-" + connectorName + "-app",
		Workdir: sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy},
	}
}

func firstBuiltinRule(t *testing.T, category string) PatternRule {
	t.Helper()
	for _, c := range defaultRuleCategories {
		if c.Name == category && len(c.Rules) > 0 {
			return c.Rules[0]
		}
	}
	t.Fatalf("no built-in %s rule", category)
	return PatternRule{}
}

func TestSandboxVerdictReason(t *testing.T) {
	installSandboxMarkerRules(t)
	command := firstBuiltinRule(t, "command")
	cg := scanner.BuiltinRulesMeta()[0]
	generic := "Blocked by DefenseClaw policy. " + sandboxDefaultRemediation
	for _, tc := range []struct {
		name             string
		action           string
		ruleIDs, finding []string
		want             string
	}{
		{"rule pack rule", "block", []string{"E2E-SANDBOX-MARKER"}, nil,
			"Blocked by DefenseClaw rule E2E-SANDBOX-MARKER: E2E sandbox marker command. " + sandboxDefaultRemediation},
		{"case-insensitive ID", "block", []string{"e2e-sandbox-marker"}, nil,
			"Blocked by DefenseClaw rule E2E-SANDBOX-MARKER: E2E sandbox marker command. " + sandboxDefaultRemediation},
		{"from finding labels", "block", nil, []string{"E2E-SANDBOX-MARKER:E2E sandbox marker command"},
			"Blocked by DefenseClaw rule E2E-SANDBOX-MARKER: E2E sandbox marker command. " + sandboxDefaultRemediation},
		{"built-in rule and category remediation", "block", []string{command.ID}, nil,
			"Blocked by DefenseClaw rule " + command.ID + ": " + strings.TrimRight(command.Title, ".") + ". " +
				sandboxCategoryRemediation["command"]},
		{"CodeGuard rule", "block", nil, []string{"codeguard:" + cg.ID + ":" + cg.Title},
			"Blocked by DefenseClaw rule " + cg.ID + ": " + strings.TrimRight(cg.Title, ".") + ". " + sentence(cg.Remediation)},
		{"confirm", "confirm", []string{"E2E-SANDBOX-MARKER"}, nil,
			"Held for approval by DefenseClaw rule E2E-SANDBOX-MARKER: E2E sandbox marker command. " + sandboxDefaultRemediation},
		{"alert", "alert", []string{"E2E-SANDBOX-MARKER"}, nil,
			"Allowed but flagged by DefenseClaw rule E2E-SANDBOX-MARKER: E2E sandbox marker command. " + sandboxFlaggedNote},
		// The most severe rule leads; the others are named.
		{"several rules", "block", []string{"E2E-QUOTING-TITLE", "E2E-SANDBOX-MARKER", "E2E-SANDBOX-MARKER"}, nil,
			"Blocked by DefenseClaw rule E2E-SANDBOX-MARKER: E2E sandbox marker command (also E2E-QUOTING-TITLE). " +
				sandboxDefaultRemediation},
		// A title that quotes what its rule, a secret rule, or any other
		// guardrail rule matches is left out.
		{"title quoting its own match", "block", []string{"E2E-QUOTING-TITLE"}, nil,
			"Blocked by DefenseClaw rule E2E-QUOTING-TITLE. " + sandboxDefaultRemediation},
		{"title matching a secret rule", "block", []string{"E2E-SECRET-TITLE"}, nil,
			"Blocked by DefenseClaw rule E2E-SECRET-TITLE. " + sandboxDefaultRemediation},
		{"title matching a command rule", "block", []string{"E2E-CMD-TITLE"}, nil,
			"Blocked by DefenseClaw rule E2E-CMD-TITLE. " + sandboxDefaultRemediation},
		{"secret category remediation", "block", []string{"E2E-SECRET"}, nil,
			"Blocked by DefenseClaw rule E2E-SECRET: E2E secret marker. " + sandboxCategoryRemediation["secret"]},
		// IDs no catalog knows cannot be told apart from content.
		{"unknown rule", "block", []string{"NOT-A-RULE"}, []string{"dce2e_secret_9:matched text"}, generic},
		{"malformed IDs", "block", []string{"has spaces", "", strings.Repeat("A", 200)}, nil, generic},
		{"no rules", "block", nil, nil, generic},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := sandboxVerdictReason("claudecode", tc.action, tc.ruleIDs, tc.finding)
			if got != tc.want {
				t.Fatalf("reason =\n  %q\nwant\n  %q", got, tc.want)
			}
			for _, leak := range []string{"<redacted", "dce2e-quoted-42", "dce2e_secret_"} {
				if strings.Contains(got, leak) {
					t.Fatalf("reason %q contains %q", got, leak)
				}
			}
		})
	}
}

func TestApplySandboxVerdictReasonLeavesHostAndAllowAlone(t *testing.T) {
	installSandboxMarkerRules(t)
	api := &APIServer{}
	profile := connector.NewClaudeCodeConnector().HookProfile(connector.SetupOpts{})
	blocked := agentHookResponse{Action: "block", RawAction: "block", Reason: "matched: <redacted len=26 sha=0123abcd>",
		RuleIDs: []string{"E2E-SANDBOX-MARKER"}}
	req := agentHookRequest{ConnectorName: "claudecode", HookEventName: "PreToolUse"}
	body := []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash"}`)
	payload := map[string]interface{}{"hook_event_name": "PreToolUse"}
	if got := api.applySandboxVerdictReason(context.Background(), profile, "claudecode", req, body, payload, blocked); got.Reason != blocked.Reason {
		t.Fatalf("host verdict rewritten: %q", got.Reason)
	}
	ctx := sandboxCtx(sandboxTestBinding("claudecode"))
	allowed := agentHookResponse{Action: "allow", RawAction: "allow", Reason: "kept", Findings: []string{"X:quoted title"}}
	if got := api.applySandboxVerdictReason(ctx, profile, "claudecode", req, body, payload, allowed); got.Reason != "kept" || got.Findings != nil {
		t.Fatalf("allowed verdict: reason %q findings %v", got.Reason, got.Findings)
	}
	// A block Claude cannot enforce on a tool result is flagged, not
	// blocked.
	result := agentHookResponse{Action: "allow", RawAction: "block", WouldBlock: true, RuleIDs: []string{"E2E-SANDBOX-MARKER"}}
	postReq := agentHookRequest{ConnectorName: "claudecode", HookEventName: "PostToolUse"}
	postBody := []byte(`{"hook_event_name":"PostToolUse","tool_name":"Bash"}`)
	got := api.applySandboxVerdictReason(ctx, profile, "claudecode", postReq, postBody, map[string]interface{}{}, result)
	if !strings.HasPrefix(got.Reason, "Allowed but flagged by DefenseClaw rule E2E-SANDBOX-MARKER") ||
		!strings.Contains(got.AdditionalContext, got.Reason) || strings.Contains(got.AdditionalContext, "would block") {
		t.Fatalf("unenforced result: reason %q context %q", got.Reason, got.AdditionalContext)
	}
	// Another connector's binding is not this connector's sandbox.
	if got := api.applySandboxVerdictReason(sandboxCtx(sandboxTestBinding("codex")), profile, "claudecode", req, body, payload, blocked); got.Reason != blocked.Reason {
		t.Fatalf("foreign binding rewrote the verdict: %q", got.Reason)
	}
	got = api.applySandboxVerdictReason(ctx, profile, "claudecode", req, body, payload, blocked)
	if !strings.HasPrefix(got.Reason, "Blocked by DefenseClaw rule E2E-SANDBOX-MARKER") || hookSourceReason(got) != blocked.Reason {
		t.Fatalf("sandbox verdict: reason %q source %q", got.Reason, hookSourceReason(got))
	}
}

// TestSandboxHookBlockCarriesPlainReason drives the harmless marker command
// through the sandbox ingress for both harnesses: the agent, the manager's
// decision (last_blocked, activity feed) and the wire body see the plain
// reason and never a redaction placeholder or a finding title.
func TestSandboxHookBlockCarriesPlainReason(t *testing.T) {
	installSandboxMarkerRules(t)
	var mu sync.Mutex
	var decisions []SandboxHookDecision
	f := newSandboxIngressFixture(t, func(c *SandboxIngressConfig) {
		c.OnHookDecision = func(d SandboxHookDecision) {
			mu.Lock()
			defer mu.Unlock()
			decisions = append(decisions, d)
		}
	})
	want := "Blocked by DefenseClaw rule E2E-SANDBOX-MARKER: E2E sandbox marker command. " + sandboxDefaultRemediation
	for _, tc := range []struct {
		name, path, token, field string
		headers                  []string
	}{
		{"claudecode", "/api/v1/claude-code/hook", f.claudeTok, "claude_code_output", nil},
		{"codex", "/api/v1/codex/hook", f.codexTok, "codex_output",
			[]string{"X-DefenseClaw-Hook-Event", "PreToolUse", "X-DefenseClaw-Hook-Contract", "codex-hooks-v1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			decisions = nil
			mu.Unlock()
			body := `{"hook_event_name":"PreToolUse","session_id":"sess-` + tc.name + `","tool_name":"Bash",` +
				`"tool_input":{"command":"echo DCE2E-BLOCK-MARKER"},"tool_use_id":"toolu_dce2e_` + tc.name + `","cwd":"/work/app"}`
			rec := f.do(t, http.MethodPost, tc.path, tc.token, body, tc.headers...)
			if rec.Code != http.StatusOK {
				t.Fatalf("hook: %d %s", rec.Code, rec.Body.String())
			}
			raw := rec.Body.String()
			for _, leak := range []string{"<redacted", "DCE2E-BLOCK-MARKER"} {
				if strings.Contains(raw, leak) {
					t.Fatalf("response body carries %q: %s", leak, raw)
				}
			}
			var resp struct {
				Action   string   `json:"action"`
				Reason   string   `json:"reason"`
				Findings []string `json:"findings"`
				RuleIDs  []string `json:"rule_ids"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			var all map[string]interface{}
			_ = json.Unmarshal(rec.Body.Bytes(), &all)
			out, _ := all[tc.field].(map[string]interface{})
			specific, _ := out["hookSpecificOutput"].(map[string]interface{})
			if resp.Action != "block" || resp.Reason != want || len(resp.Findings) != 0 ||
				specific["permissionDecision"] != "deny" || specific["permissionDecisionReason"] != want {
				t.Fatalf("response = %s", raw)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(decisions) != 1 || decisions[0].Reason != want || decisions[0].Action != "block" ||
				decisions[0].ToolUseID != "toolu_dce2e_"+tc.name || decisions[0].Event != "PreToolUse" {
				t.Fatalf("decisions = %+v", decisions)
			}
		})
	}
}

// TestSandboxHookDecisionsCarryToolUseID pins the first link of hook tamper
// detection: both harnesses' PreToolUse and PostToolUse decisions reach the
// manager with the harness's tool_use_id, the key that pairs them.
func TestSandboxHookDecisionsCarryToolUseID(t *testing.T) {
	var mu sync.Mutex
	var decisions []SandboxHookDecision
	f := newSandboxIngressFixture(t, func(c *SandboxIngressConfig) {
		c.OnHookDecision = func(d SandboxHookDecision) {
			mu.Lock()
			defer mu.Unlock()
			decisions = append(decisions, d)
		}
	})
	for _, tc := range []struct{ name, path, token string }{
		{"claudecode", "/api/v1/claude-code/hook", f.claudeTok},
		{"codex", "/api/v1/codex/hook", f.codexTok},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			decisions = nil
			mu.Unlock()
			id := "toolu_pair_" + tc.name
			for _, event := range []string{"PreToolUse", "PostToolUse"} {
				body := `{"hook_event_name":"` + event + `","session_id":"sess-pair-` + tc.name + `","tool_name":"Bash",` +
					`"tool_input":{"command":"echo dce2e-pair"},"tool_response":{"stdout":"dce2e-pair\n"},` +
					`"tool_use_id":"` + id + `","cwd":"/work/app"}`
				var headers []string
				if tc.name == "codex" {
					headers = []string{"X-DefenseClaw-Hook-Event", event, "X-DefenseClaw-Hook-Contract", "codex-hooks-v1"}
				}
				if rec := f.do(t, http.MethodPost, tc.path, tc.token, body, headers...); rec.Code != http.StatusOK {
					t.Fatalf("%s: %d %s", event, rec.Code, rec.Body.String())
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if len(decisions) != 2 || decisions[0].Event != "PreToolUse" || decisions[1].Event != "PostToolUse" ||
				decisions[0].ToolUseID != id || decisions[1].ToolUseID != id || decisions[0].Action != "allow" {
				t.Fatalf("decisions = %+v", decisions)
			}
		})
	}
}
