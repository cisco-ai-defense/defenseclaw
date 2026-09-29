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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
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

// sandboxMarkerBlockReason is the plain reason of a marker rule block.
const sandboxMarkerBlockReason = "Blocked by DefenseClaw rule E2E-SANDBOX-MARKER: E2E sandbox marker command. " + sandboxDefaultRemediation

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
	apply := func(ctx context.Context, resp agentHookResponse) agentHookResponse {
		return api.applySandboxVerdictReason(ctx, profile, "claudecode", req, body, payload, resp)
	}
	if got := apply(context.Background(), blocked); got.Reason != blocked.Reason {
		t.Fatalf("host verdict rewritten: %q", got.Reason)
	}
	ctx := sandboxCtx(sandboxTestBinding("claudecode"))
	allowed := agentHookResponse{Action: "allow", RawAction: "allow", Reason: "kept", Findings: []string{"X:quoted title"}}
	if got := apply(ctx, allowed); got.Reason != "kept" || got.Findings != nil {
		t.Fatalf("allowed verdict: reason %q findings %v", got.Reason, got.Findings)
	}
	// A plain allow of a HIGH finding (a profile can answer a HIGH rule so)
	// is flagged instead of carrying the redacted verdict text, while the
	// harness output stays that of an allow. Without a finding it is kept.
	flagged := agentHookResponse{Action: "allow", RawAction: "allow", Severity: "HIGH", Reason: blocked.Reason,
		RuleIDs: []string{"E2E-SANDBOX-MARKER"}, HookOutput: map[string]interface{}{"continue": true}}
	got := apply(ctx, flagged)
	if !strings.HasPrefix(got.Reason, "Allowed but flagged by DefenseClaw rule E2E-SANDBOX-MARKER") ||
		!strings.HasSuffix(got.Reason, sandboxFlaggedNote) || hookSourceReason(got) != flagged.Reason ||
		got.AdditionalContext != "" || got.HookOutput["continue"] != true {
		t.Fatalf("allow with a finding: reason %q source %q context %q output %v",
			got.Reason, hookSourceReason(got), got.AdditionalContext, got.HookOutput)
	}
	flagged.Severity, flagged.Reason = "NONE", "kept"
	if got := apply(ctx, flagged); got.Reason != "kept" {
		t.Fatalf("plain allow reason = %q", got.Reason)
	}
	// A block Claude cannot enforce on a tool result is flagged, not
	// blocked.
	result := agentHookResponse{Action: "allow", RawAction: "block", WouldBlock: true, RuleIDs: []string{"E2E-SANDBOX-MARKER"}}
	postReq := agentHookRequest{ConnectorName: "claudecode", HookEventName: "PostToolUse"}
	postBody := []byte(`{"hook_event_name":"PostToolUse","tool_name":"Bash"}`)
	got = api.applySandboxVerdictReason(ctx, profile, "claudecode", postReq, postBody, map[string]interface{}{}, result)
	if !strings.HasPrefix(got.Reason, "Allowed but flagged by DefenseClaw rule E2E-SANDBOX-MARKER") ||
		!strings.Contains(got.AdditionalContext, got.Reason) || strings.Contains(got.AdditionalContext, "would block") {
		t.Fatalf("unenforced result: reason %q context %q", got.Reason, got.AdditionalContext)
	}
	// Another connector's binding is not this connector's sandbox.
	if got := apply(sandboxCtx(sandboxTestBinding("codex")), blocked); got.Reason != blocked.Reason {
		t.Fatalf("foreign binding rewrote the verdict: %q", got.Reason)
	}
	got = apply(ctx, blocked)
	if !strings.HasPrefix(got.Reason, "Blocked by DefenseClaw rule E2E-SANDBOX-MARKER") || hookSourceReason(got) != blocked.Reason {
		t.Fatalf("sandbox verdict: reason %q source %q", got.Reason, hookSourceReason(got))
	}
}

// TestSandboxHookBlockCarriesPlainReason drives the harmless marker command
// through the sandbox ingress for both harnesses: the agent, the manager's
// decision (last_blocked, activity feed) and the wire body see the plain
// reason and never a redaction placeholder or a finding title. The call's
// PreToolUse and PostToolUse decisions reach the manager with the harness's
// tool_use_id, the key hook tamper detection pairs them by.
func TestSandboxHookBlockCarriesPlainReason(t *testing.T) {
	installSandboxMarkerRules(t)
	var obs sandboxObserver
	f := newSandboxIngressFixture(t, obs.observe)
	for _, tc := range []struct{ name, path, token, field string }{
		{"claudecode", "/api/v1/claude-code/hook", f.claudeTok, "claude_code_output"},
		{"codex", "/api/v1/codex/hook", f.codexTok, "codex_output"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obs.take()
			id := "toolu_dce2e_" + tc.name
			post := func(event, command, extra string) *httptest.ResponseRecorder {
				var headers []string
				if tc.name == "codex" {
					headers = []string{"X-DefenseClaw-Hook-Event", event, "X-DefenseClaw-Hook-Contract", "codex-hooks-v1"}
				}
				rec := f.do(t, http.MethodPost, tc.path, tc.token, `{"hook_event_name":"`+event+`","session_id":"sess-`+tc.name+`","tool_name":"Bash",`+
					`"tool_input":{"command":"`+command+`"},`+extra+`"tool_use_id":"`+id+`","cwd":"/work/app"}`, headers...)
				if rec.Code != http.StatusOK {
					t.Fatalf("%s: %d %s", event, rec.Code, rec.Body.String())
				}
				return rec
			}
			rec := post("PreToolUse", "echo DCE2E-BLOCK-MARKER", "")
			for _, leak := range []string{"<redacted", "DCE2E-BLOCK-MARKER"} {
				if strings.Contains(rec.Body.String(), leak) {
					t.Fatalf("response body carries %q: %s", leak, rec.Body.String())
				}
			}
			var resp map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			out, _ := resp[tc.field].(map[string]interface{})
			specific, _ := out["hookSpecificOutput"].(map[string]interface{})
			findings, _ := resp["findings"].([]interface{})
			if resp["action"] != "block" || resp["reason"] != sandboxMarkerBlockReason || len(findings) != 0 ||
				specific["permissionDecision"] != "deny" || specific["permissionDecisionReason"] != sandboxMarkerBlockReason {
				t.Fatalf("response = %v", resp)
			}
			post("PostToolUse", "echo dce2e-pair", `"tool_response":{"stdout":"dce2e-pair\n"},`)
			decisions, _ := obs.take()
			if len(decisions) != 2 || decisions[0].Reason != sandboxMarkerBlockReason || decisions[0].Action != "block" ||
				decisions[0].Event != "PreToolUse" || decisions[1].Event != "PostToolUse" ||
				decisions[0].ToolUseID != id || decisions[1].ToolUseID != id {
				t.Fatalf("decisions = %+v", decisions)
			}
		})
	}
}

// TestSandboxEvaluatorFailureIsNotAPolicyBlock pins that a sandbox hook
// DefenseClaw failed evaluating (a recovered panic) is blocked with a
// reason that says so, in the harness's own block shape, and is reported to
// the manager as a hook failure. It was a 200 block that read "Blocked by
// DefenseClaw policy. Try another approach", which sent the agent looking
// for a workaround and the user for a rule that does not exist, and nothing
// counted it as a failed hook. An ordinary policy block is not a failure.
func TestSandboxEvaluatorFailureIsNotAPolicyBlock(t *testing.T) {
	installSandboxMarkerRules(t)
	var obs sandboxObserver
	f := newSandboxIngressFixture(t, obs.observe)
	binding, token := f.mint(t, "dc-hermes-crash", "hermes", "0.19.0", "hermes-hooks-v1", "")
	post := func(command string) map[string]interface{} {
		t.Helper()
		return f.hook(t, "/api/v1/hermes/hook", token, `{"hook_event_name":"pre_tool_call","tool_name":"terminal",`+
			`"tool_input":{"command":"`+command+`"},"session_id":"20260927_1","cwd":"/work/app","extra":{"tool_call_id":"call_1","task_id":"t1"}}`)
	}

	prev := hookEvaluatorPanicHook
	hookEvaluatorPanicHook = func() { panic("synthetic evaluator panic for sandbox test") }
	resp := post("ls")
	hookEvaluatorPanicHook = prev
	out, _ := resp["hook_output"].(map[string]interface{})
	if resp["action"] != "block" || resp["reason"] != sandboxInternalErrorReason ||
		out["decision"] != "block" || out["reason"] != sandboxInternalErrorReason {
		t.Fatalf("crashed evaluation = %v", resp)
	}
	gotDecisions, gotFailures := obs.take()
	want := SandboxHookFailure{BindingID: binding.ID, SandboxName: "dc-hermes-crash", Connector: "hermes",
		Route: sandboxauth.RouteHook, Status: http.StatusInternalServerError}
	if len(gotFailures) != 1 || gotFailures[0] != want {
		t.Fatalf("failures = %+v, want %+v", gotFailures, want)
	}
	if len(gotDecisions) != 1 || gotDecisions[0].Action != "block" || gotDecisions[0].Reason != sandboxInternalErrorReason {
		t.Fatalf("decisions = %+v", gotDecisions)
	}

	// A policy block keeps its rule reason and is no failure.
	resp = post("echo DCE2E-BLOCK-MARKER > /tmp/dce2e-blocked.txt")
	if resp["action"] != "block" || !strings.HasPrefix(resp["reason"].(string), "Blocked by DefenseClaw rule E2E-SANDBOX-MARKER") {
		t.Fatalf("policy block = %v", resp)
	}
	if _, gotFailures := obs.take(); len(gotFailures) != 0 {
		t.Fatalf("a policy block was reported as a failure: %+v", gotFailures)
	}
}

// TestSandboxHookDecisionsNameEachHarnessCall pins the gateway half of hook
// tamper detection for the hook-only harnesses: each one's pre-tool and
// post-tool events reach the manager under the harness's own event names,
// with what names the call. Cursor, OpenCode and Amp send a per-call ID;
// Kiro CLI and Copilot CLI send none (measured on 2.24.1 and 1.0.88), so the
// call's session and tool input must reach the manager byte for byte the
// same from both events.
func TestSandboxHookDecisionsNameEachHarnessCall(t *testing.T) {
	var obs sandboxObserver
	f := newSandboxIngressFixture(t, obs.observe)
	for _, tc := range []struct {
		spec      *harness.Spec
		path      string
		pre, post string
		// preBody and postBody are the harness's payloads (the plugins'
		// for OpenCode and Amp).
		preBody, postBody string
		// preHeaders and postHeaders carry the event of a harness whose
		// payload names none (Copilot: the hook command's --event).
		preHeaders, postHeaders []string
		id, session             string
		status                  string
		// inputKeys is the number of keys in the call's tool input (1 when
		// unset).
		inputKeys int
	}{
		{
			spec: harness.Kiro, path: "/api/v1/kiro/hook", pre: "preToolUse", post: "postToolUse",
			// Kiro CLI 2.24.1's own payloads.
			preBody: `{"hook_event_name":"preToolUse","cwd":"/work/app","session_id":"c2197843-ce66-4011-a627-052241fa9da8",` +
				`"tool_name":"shell","tool_input":{"command":"echo dce2e-pair"}}`,
			postBody: `{"hook_event_name":"postToolUse","cwd":"/work/app","session_id":"c2197843-ce66-4011-a627-052241fa9da8",` +
				`"tool_name":"shell","tool_input":{"command":"echo dce2e-pair"},"tool_response":{"items":[{"Text":"dce2e-pair\n"}]}}`,
			session: "c2197843-ce66-4011-a627-052241fa9da8",
		},
		{
			spec: harness.Cursor, path: "/api/v1/cursor/hook", pre: "preToolUse", post: "postToolUse",
			preBody: `{"hook_event_name":"preToolUse","conversation_id":"conv-pair","generation_id":"gen-pair",` +
				`"tool_name":"Shell","tool_input":{"command":"echo dce2e-pair"},"tool_use_id":"tool_cursor_pair","cwd":"/work/app"}`,
			postBody: `{"hook_event_name":"postToolUse","conversation_id":"conv-pair","generation_id":"gen-pair",` +
				`"tool_name":"Shell","tool_input":{"command":"echo dce2e-pair"},"tool_output":"dce2e-pair\n","tool_use_id":"tool_cursor_pair","cwd":"/work/app"}`,
			id: "tool_cursor_pair",
		},
		{
			spec: harness.OpenCode, path: "/api/v1/opencode/hook", pre: "tool.execute.before", post: "tool.execute.after",
			preBody: `{"hook_event_name":"tool.execute.before","tool_name":"bash","tool_input":{"command":"echo dce2e-pair"},` +
				`"session_id":"ses_pair","turn_id":"msg_pair","tool_call_id":"call_opencode_pair","cwd":"/work/app",` +
				`"load_heartbeat":true,"arguments_authoritative":true,"mcp_identity_status":"not_mcp"}`,
			postBody: `{"hook_event_name":"tool.execute.after","tool_name":"bash","tool_input":{"command":"echo dce2e-pair"},` +
				`"session_id":"ses_pair","turn_id":"msg_pair","tool_call_id":"call_opencode_pair","cwd":"/work/app",` +
				`"load_heartbeat":true,"arguments_authoritative":true,"mcp_identity_status":"not_mcp",` +
				`"tool_response":{"title":"echo","output":"dce2e-pair\n","metadata":{"exit":0}}}`,
			id: "call_opencode_pair",
		},
		{
			spec: harness.Copilot, path: "/api/v1/copilot/hook", pre: "preToolUse", post: "postToolUse",
			// Copilot CLI 1.0.88's own payloads; the event arrives out of band.
			preHeaders:  []string{"X-DefenseClaw-Copilot-Event", "preToolUse"},
			postHeaders: []string{"X-DefenseClaw-Copilot-Event", "postToolUse"},
			preBody: `{"sessionId":"506e99d3-3a4f-4a7c-9d0e-0f2c6d1e8b11","timestamp":1790483549431,"cwd":"/work/app",` +
				`"toolName":"bash","toolArgs":{"command":"echo dce2e-pair","description":"write the pair marker"}}`,
			postBody: `{"sessionId":"506e99d3-3a4f-4a7c-9d0e-0f2c6d1e8b11","timestamp":1790483551012,"cwd":"/work/app",` +
				`"toolName":"bash","toolArgs":{"command":"echo dce2e-pair","description":"write the pair marker"},` +
				`"toolResult":{"resultType":"success","textResultForLlm":"dce2e-pair\n"}}`,
			session: "506e99d3-3a4f-4a7c-9d0e-0f2c6d1e8b11", inputKeys: 2,
		},
		{
			spec: harness.Amp, path: "/api/v1/amp/hook", pre: "tool.call", post: "tool.result",
			preBody: `{"hook_event_name":"tool.call","thread_id":"T-pair","session_id":"T-pair","tool_call_id":"toolu_amp_pair",` +
				`"tool_name":"Bash","tool_input":{"cmd":"echo dce2e-pair"},"cwd":"/work/app"}`,
			postBody: `{"hook_event_name":"tool.result","thread_id":"T-pair","session_id":"T-pair","tool_call_id":"toolu_amp_pair",` +
				`"tool_name":"Bash","tool_input":{"cmd":"echo dce2e-pair"},"tool_response":{"output":"dce2e-pair\n"},` +
				`"status":"done","error":"","cwd":"/work/app"}`,
			id: "toolu_amp_pair", status: "done",
		},
	} {
		t.Run(tc.spec.Name, func(t *testing.T) {
			version := tc.spec.DefaultVersion
			contract := connector.ResolveSandboxHookContract(tc.spec.Name, version)
			if contract.Status != connector.HookCompatibilityKnown {
				t.Fatalf("%s %s: no sandbox hook contract: %s", tc.spec.Name, version, contract.Reason)
			}
			_, token := f.mint(t, "dc-pair-"+tc.spec.Name, tc.spec.Name, version, contract.Contract.ContractID, "")
			obs.take()
			f.hook(t, tc.path, token, tc.preBody, tc.preHeaders...)
			f.hook(t, tc.path, token, tc.postBody, tc.postHeaders...)
			decisions, _ := obs.take()
			if len(decisions) != 2 {
				t.Fatalf("decisions = %+v", decisions)
			}
			pre, post := decisions[0], decisions[1]
			if pre.Connector != tc.spec.Name || pre.Event != tc.pre || post.Event != tc.post || pre.Action != "allow" {
				t.Fatalf("events: pre %+v post %+v", pre, post)
			}
			if pre.ToolUseID != tc.id || post.ToolUseID != tc.id {
				t.Fatalf("tool-use IDs %q and %q, want %q", pre.ToolUseID, post.ToolUseID, tc.id)
			}
			if pre.ResultStatus != "" || post.ResultStatus != tc.status {
				t.Fatalf("result status: pre %q post %q, want %q", pre.ResultStatus, post.ResultStatus, tc.status)
			}
			if tc.session != "" && (pre.SessionID != tc.session || post.SessionID != tc.session) {
				t.Fatalf("sessions %q and %q, want %q", pre.SessionID, post.SessionID, tc.session)
			}
			if len(pre.ToolInput) == 0 || !bytes.Equal(pre.ToolInput, post.ToolInput) || pre.Tool == "" || pre.Tool != post.Tool {
				t.Fatalf("the call's tool and input differ: pre %q %s, post %q %s", pre.Tool, pre.ToolInput, post.Tool, post.ToolInput)
			}
			var input map[string]interface{}
			if err := json.Unmarshal(pre.ToolInput, &input); err != nil || len(input) != max(tc.inputKeys, 1) {
				t.Fatalf("tool input %s is not the call's input: %v", pre.ToolInput, err)
			}
		})
	}
}

// A hook event without a tool input names no call by content: ToolArgs
// falls back to the whole payload there, which a call's pre-tool and
// post-tool events do not share.
func TestSandboxDecisionToolInput(t *testing.T) {
	withInput := agentHookRequest{
		Payload:  map[string]interface{}{"tool_input": map[string]interface{}{"command": "ls"}},
		ToolArgs: json.RawMessage(`{"command":"ls"}`),
	}
	if got := sandboxDecisionToolInput(withInput); string(got) != `{"command":"ls"}` {
		t.Fatalf("tool input = %s", got)
	}
	without := agentHookRequest{
		Payload:  map[string]interface{}{"hook_event_name": "stop", "assistant_response": "done"},
		ToolArgs: json.RawMessage(`{"assistant_response":"done","hook_event_name":"stop"}`),
	}
	if got := sandboxDecisionToolInput(without); got != nil {
		t.Fatalf("an event without a tool input named %s", got)
	}
}
