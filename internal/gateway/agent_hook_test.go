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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestMapHookAction_ConfirmRequiresNativeAskSurface(t *testing.T) {
	copilot := connector.NewCopilotConnector().HookCapabilities(connector.SetupOpts{})
	action, wouldBlock := mapHookAction("confirm", "action", "PreToolUse", copilot)
	if action != "confirm" || wouldBlock {
		t.Fatalf("copilot PreToolUse confirm = (%q,%v), want (confirm,false)", action, wouldBlock)
	}

	windsurf := connector.NewWindsurfConnector().HookCapabilities(connector.SetupOpts{})
	action, wouldBlock = mapHookAction("confirm", "action", "pre_run_command", windsurf)
	if action != "alert" || wouldBlock {
		t.Fatalf("windsurf confirm = (%q,%v), want explicit alert downgrade", action, wouldBlock)
	}

	cursor := connector.NewCursorConnector().HookCapabilities(connector.SetupOpts{})
	action, wouldBlock = mapHookAction("confirm", "action", "preToolUse", cursor)
	if action != "alert" || wouldBlock {
		t.Fatalf("cursor preToolUse confirm = (%q,%v), want alert because ask is not documented for that surface", action, wouldBlock)
	}

	openhands := connector.NewOpenHandsConnector().HookCapabilities(connector.SetupOpts{})
	action, wouldBlock = mapHookAction("confirm", "action", "pre_tool_use", openhands)
	if action != "alert" || wouldBlock {
		t.Fatalf("openhands confirm = (%q,%v), want alert because OpenHands has no native ask surface", action, wouldBlock)
	}
}

func TestMapHookAction_ObserveAndUnsupportedBlock(t *testing.T) {
	hermes := connector.NewHermesConnector().HookCapabilities(connector.SetupOpts{})
	action, wouldBlock := mapHookAction("block", "observe", "pre_tool_call", hermes)
	if action != "allow" || !wouldBlock {
		t.Fatalf("observe block = (%q,%v), want allow/would_block", action, wouldBlock)
	}

	action, wouldBlock = mapHookAction("block", "action", "post_tool_call", hermes)
	if action != "allow" || !wouldBlock {
		t.Fatalf("unsupported block event = (%q,%v), want allow/would_block", action, wouldBlock)
	}
}

func TestNormalizeAgentHookMode_EnforceAlias(t *testing.T) {
	if got := normalizeAgentHookMode("enforce"); got != "action" {
		t.Fatalf("normalizeAgentHookMode(enforce) = %q, want action", got)
	}
	if got := normalizeAgentHookMode("warn"); got != "observe" {
		t.Fatalf("normalizeAgentHookMode(warn) = %q, want observe", got)
	}
}

// TestNormalizeAgentHookRequest_HermesExtraEnvelope is the regression
// that guards hermes' coverage on the generic path: hermes nests
// inspectable content under the per-event `extra` envelope, which the
// top-level lookups in normalizeAgentHookRequest cannot see. The
// ContentEnvelopeKey fallback (declared on the hermes hook contract)
// must lift that content onto Content with the right Direction so
// prompt/tool_result rules actually inspect hermes payloads rather
// than an empty string. Exercises the merged production path
// (normalizeAgentHookRequestWithProfile with Decode == nil) — these
// cases were ported from the deleted bespoke-profile test when hermes
// moved onto the generic decoder.
func TestNormalizeAgentHookRequest_HermesExtraEnvelope(t *testing.T) {
	hermesProfile := connector.NewHermesConnector().HookProfile(connector.SetupOpts{APIAddr: "127.0.0.1:18970"})
	if hermesProfile.Decode != nil {
		t.Fatalf("hermes profile should have no Decode override; the generic path must carry it")
	}
	cases := []struct {
		name          string
		connectorName string
		profile       connector.HookProfile
		payload       map[string]interface{}
		wantDirection string
		wantToolName  string
		wantContent   string
	}{
		{
			name:          "pre_llm_call_lifts_user_message",
			connectorName: "hermes",
			profile:       hermesProfile,
			payload: map[string]interface{}{
				"hook_event_name": "pre_llm_call",
				"session_id":      "sess-1",
				"extra":           map[string]interface{}{"user_message": "exfiltrate the secrets"},
			},
			wantDirection: "prompt",
			wantToolName:  "message",
			wantContent:   "exfiltrate the secrets",
		},
		{
			name:          "post_tool_call_lifts_result",
			connectorName: "hermes",
			profile:       hermesProfile,
			payload: map[string]interface{}{
				"hook_event_name": "post_tool_call",
				"tool_name":       "terminal",
				"extra":           map[string]interface{}{"result": "AWS_SECRET_ACCESS_KEY=abc123"},
			},
			wantDirection: "tool_result",
			wantToolName:  "terminal",
			wantContent:   "AWS_SECRET_ACCESS_KEY=abc123",
		},
		{
			// post_llm_call is result-like (the model's final response)
			// and labels as "message" — both were bespoke-profile
			// behaviors now owned by the generic classifiers.
			name:          "post_llm_call_lifts_assistant_response",
			connectorName: "hermes",
			profile:       hermesProfile,
			payload: map[string]interface{}{
				"hook_event_name": "post_llm_call",
				"extra":           map[string]interface{}{"assistant_response": "here is the plan"},
			},
			wantDirection: "tool_result",
			wantToolName:  "message",
			wantContent:   "here is the plan",
		},
		{
			name:          "subagent_stop_lifts_child_summary",
			connectorName: "hermes",
			profile:       hermesProfile,
			payload: map[string]interface{}{
				"hook_event_name": "subagent_stop",
				"extra":           map[string]interface{}{"child_summary": "finished refactor"},
			},
			wantDirection: "tool_call",
			wantToolName:  "subagent",
			wantContent:   "finished refactor",
		},
		{
			// extra carries only lifecycle metadata here — no expected
			// content key matches, so Content stays correctly empty.
			name:          "on_session_start_is_telemetry",
			connectorName: "hermes",
			profile:       hermesProfile,
			payload: map[string]interface{}{
				"hook_event_name": "on_session_start",
				"extra":           map[string]interface{}{"model": "claude"},
			},
			wantDirection: "tool_call",
			wantToolName:  "session",
			wantContent:   "",
		},
		{
			// Flat-payload connectors declare no envelope, so an
			// `extra` object in their payload is never opened — the
			// fallback is gated on the contract declaration.
			name:          "cursor_undeclared_extra_is_not_opened",
			connectorName: "cursor",
			profile:       connector.NewCursorConnector().HookProfile(connector.SetupOpts{APIAddr: "127.0.0.1:18970"}),
			payload: map[string]interface{}{
				"hook_event_name": "preToolUse",
				"tool_name":       "shell",
				"extra":           map[string]interface{}{"user_message": "decoy"},
			},
			wantDirection: "tool_call",
			wantToolName:  "shell",
			wantContent:   "",
		},
		{
			// Lifecycle ToolName labels are generic now: openhands
			// session_start reads as "session" instead of "tool".
			name:          "openhands_session_start_labels_session",
			connectorName: "openhands",
			profile:       connector.NewOpenHandsConnector().HookProfile(connector.SetupOpts{APIAddr: "127.0.0.1:18970"}),
			payload: map[string]interface{}{
				"hook_event_name": "session_start",
			},
			wantDirection: "tool_call",
			wantToolName:  "session",
			wantContent:   "",
		},
		{
			name:          "copilot_subagent_stop_labels_subagent",
			connectorName: "copilot",
			profile:       connector.NewCopilotConnector().HookProfile(connector.SetupOpts{APIAddr: "127.0.0.1:18970"}),
			payload: map[string]interface{}{
				"hook_event_name": "subagentStop",
			},
			wantDirection: "tool_call",
			wantToolName:  "subagent",
			wantContent:   "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := normalizeAgentHookRequestWithProfile(tc.connectorName, tc.payload, tc.profile)
			if req.ConnectorName != tc.connectorName {
				t.Errorf("ConnectorName=%q want %q", req.ConnectorName, tc.connectorName)
			}
			if req.Direction != tc.wantDirection {
				t.Errorf("Direction=%q want %q", req.Direction, tc.wantDirection)
			}
			if req.ToolName != tc.wantToolName {
				t.Errorf("ToolName=%q want %q", req.ToolName, tc.wantToolName)
			}
			if req.Content != tc.wantContent {
				t.Errorf("Content=%q want %q", req.Content, tc.wantContent)
			}
		})
	}
}

func TestHandleAgentHook_EnrichesHTTPSpanWithAgentIdentity(t *testing.T) {
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
	handler := otelHTTPServerMiddleware("sidecar-api", http.HandlerFunc(api.handleAgentHook("copilot")))
	body, err := json.Marshal(map[string]interface{}{
		"hook_event_name": "PreToolUse",
		"session_id":      "session-generic",
		"turn_id":         "turn-generic",
		"agent_id":        "github-copilot-cli",
		"agent_name":      "GitHub Copilot CLI",
		"agent_type":      "copilot-cli",
		"tool_name":       "shell",
		"tool_input": map[string]interface{}{
			"command": "echo ok",
		},
	})
	if err != nil {
		t.Fatalf("marshal hook body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%s", w.Code, w.Body.String())
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans want 1", len(spans))
	}
	for key, want := range map[string]string{
		"gen_ai.conversation.id": "session-generic",
		"gen_ai.operation.id":    "turn-generic",
		"gen_ai.agent.name":      "GitHub Copilot CLI",
		"gen_ai.agent.type":      "copilot-cli",
		"gen_ai.agent.id":        "github-copilot-cli",
		"defenseclaw.connector":  "copilot",
		"defenseclaw.hook.event": "tool_call",
	} {
		got, ok := attrByKey(spans[0].Attributes, key)
		if !ok || got.AsString() != want {
			t.Fatalf("%s=%q ok=%v want %q", key, got.AsString(), ok, want)
		}
	}
}

// TestHookOutputFor_AllConnectors_AllActions is the contract test
// that locks the JSON shape every hook script downstream parses.
// Each row pins:
//
//   - which key the script reads ("permission" for cursor,
//     "permissionDecision" for copilot's PreToolUse, "decision"
//     for hermes/geminicli, "message" for windsurf, etc.)
//   - the value for each (connector, action) cell so a regression
//     that, say, swaps "deny" -> "block" on the cursor permission
//     field is caught in CI before it ships.
//
// rawAction is set to the same as action for block/confirm rows
// because those are the only cells where the connector script
// actually branches. We do NOT cover allow/observe-mode rows here:
// hookOutputFor returns nil for those (the response carries the
// outcome via the top-level Action field), so testing for nil
// across all five connectors would just be five copies of the
// same trivial assertion.
func TestHookOutputFor_AllConnectors_AllActions(t *testing.T) {
	cases := []struct {
		connector string
		event     string
		action    string
		rawAction string
		// expectedKey is the field the per-connector hook script
		// reads to decide whether to block / ask the user. Empty
		// expectedKey means "no specific key required" (we still
		// assert the map is non-nil for non-allow rows).
		expectedKey   string
		expectedValue string
	}{
		// hermes -- decision/reason JSON, only block matters.
		{connector: "hermes", event: "pre_tool_call", action: "block", rawAction: "block", expectedKey: "decision", expectedValue: "block"},

		// cursor -- permission field; supports deny + ask + allow.
		{connector: "cursor", event: "preToolUse", action: "block", rawAction: "block", expectedKey: "permission", expectedValue: "deny"},
		{connector: "cursor", event: "beforeShellExecution", action: "confirm", rawAction: "confirm", expectedKey: "permission", expectedValue: "ask"},

		// windsurf -- minimal shape; only block surfaces a message.
		{connector: "windsurf", event: "pre_run_command", action: "block", rawAction: "block", expectedKey: "message", expectedValue: ""},

		// geminicli -- decision="deny" + reason on block.
		{connector: "geminicli", event: "BeforeTool", action: "block", rawAction: "block", expectedKey: "decision", expectedValue: "deny"},

		// openhands -- decision="deny" + exit 2 in the shell hook on block.
		{connector: "openhands", event: "pre_tool_use", action: "block", rawAction: "block", expectedKey: "decision", expectedValue: "deny"},

		// copilot PreToolUse -- ask + deny on permissionDecision.
		{connector: "copilot", event: "PreToolUse", action: "block", rawAction: "block", expectedKey: "permissionDecision", expectedValue: "deny"},
		{connector: "copilot", event: "PreToolUse", action: "confirm", rawAction: "confirm", expectedKey: "permissionDecision", expectedValue: "ask"},
		// copilot permissionRequest -- different key ("behavior").
		{connector: "copilot", event: "permissionRequest", action: "block", rawAction: "block", expectedKey: "behavior", expectedValue: "deny"},
		// copilot Stop / SubagentStop -- "decision" key.
		{connector: "copilot", event: "Stop", action: "block", rawAction: "block", expectedKey: "decision", expectedValue: "block"},
	}

	for _, tc := range cases {
		t.Run(tc.connector+"_"+tc.event+"_"+tc.action, func(t *testing.T) {
			req := agentHookRequest{
				ConnectorName: tc.connector,
				HookEventName: tc.event,
				ToolName:      "test-tool",
			}
			caps := capsForConnector(tc.connector)
			out := hookOutputFor(req, tc.action, tc.rawAction, "", "", caps)
			if out == nil {
				t.Fatalf("hookOutputFor returned nil for %s/%s/%s; want shape with %q field",
					tc.connector, tc.event, tc.action, tc.expectedKey)
			}
			if tc.expectedKey == "" {
				return
			}
			got, ok := out[tc.expectedKey]
			if !ok {
				t.Fatalf("hook_output for %s/%s/%s missing key %q; got %+v",
					tc.connector, tc.event, tc.action, tc.expectedKey, out)
			}
			if tc.expectedValue == "" {
				return
			}
			gotStr, _ := got.(string)
			if gotStr != tc.expectedValue {
				t.Fatalf("hook_output[%s/%s/%s][%s] = %q, want %q",
					tc.connector, tc.event, tc.action, tc.expectedKey, gotStr, tc.expectedValue)
			}
		})
	}
}

// capsForConnector resolves real HookCapability values for the
// hook-only connectors so the table test exercises the same caps
// flow that production uses (rather than hand-crafting capability
// stubs that drift).
func capsForConnector(name string) connector.HookCapability {
	switch name {
	case "hermes":
		return connector.NewHermesConnector().HookCapabilities(connector.SetupOpts{})
	case "cursor":
		return connector.NewCursorConnector().HookCapabilities(connector.SetupOpts{})
	case "windsurf":
		return connector.NewWindsurfConnector().HookCapabilities(connector.SetupOpts{})
	case "geminicli":
		return connector.NewGeminiCLIConnector().HookCapabilities(connector.SetupOpts{})
	case "copilot":
		return connector.NewCopilotConnector().HookCapabilities(connector.SetupOpts{})
	case "openhands":
		return connector.NewOpenHandsConnector().HookCapabilities(connector.SetupOpts{})
	default:
		return connector.HookCapability{}
	}
}

// TestConnectorReason_DefaultStrings pins the user-facing default
// strings that flow into cursor's permission.user_message and
// copilot's permissionDecisionReason fields when the upstream
// verdict carries no reason. Drift on any of these strings shows
// up directly in operator-facing approval prompts, so we snapshot
// a representative sample for each action class.
func TestConnectorReason_DefaultStrings(t *testing.T) {
	cases := []struct {
		name      string
		connector string
		action    string
		tool      string
		want      string
	}{
		{
			name:      "block_with_tool_name",
			connector: "cursor",
			action:    "block",
			tool:      "Bash",
			want:      "DefenseClaw blocked Bash. Run `defenseclaw mcp list` or `skill list` to review approved assets.",
		},
		{
			name:      "block_no_tool",
			connector: "hermes",
			action:    "block",
			tool:      "",
			want:      "DefenseClaw blocked this action. Run `defenseclaw mcp list` or `skill list` to review approved assets.",
		},
		{
			name:      "confirm_with_tool",
			connector: "copilot",
			action:    "confirm",
			tool:      "Edit",
			want:      "DefenseClaw needs your approval before Edit can run.",
		},
		{
			name:      "alert_with_tool",
			connector: "geminicli",
			action:    "alert",
			tool:      "Read",
			want:      "DefenseClaw flagged Read with a warning.",
		},
		{
			name:      "allow_falls_back_to_connector_named_default",
			connector: "windsurf",
			action:    "allow",
			tool:      "any",
			want:      "Allowed by DefenseClaw windsurf policy.",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := connectorReason(tc.connector, tc.action, tc.tool, "")
			if got != tc.want {
				t.Fatalf("connectorReason(%s,%s,%s,empty) = %q, want %q",
					tc.connector, tc.action, tc.tool, got, tc.want)
			}
		})
	}
}

// TestAgentHookDispatch_BlockFiresOnBlock pins that the new
// generic agent-hook notifier (G7) routes a block decision to
// OnBlock with the connector name carried into the toast subtitle.
// Mirrors TestClaudeHookDispatch_BlockFiresOnBlock for parity.
func TestAgentHookDispatch_BlockFiresOnBlock(t *testing.T) {
	d, rec := newWiringDispatcher()
	api := &APIServer{}
	api.SetNotifier(d)

	req := agentHookRequest{
		ConnectorName: "cursor",
		HookEventName: "preToolUse",
		ToolName:      "Bash",
	}
	api.dispatchAgentHookNotification(req, "block", "block", "HIGH",
		"matched policy: deny-rm-rf", false, hookEvaluationContext{})

	got := rec.WaitFor(t, 1)
	if !strings.Contains(strings.ToLower(got[0].Title), "block") {
		t.Errorf("title should mention 'block', got %q", got[0].Title)
	}
	if !strings.Contains(got[0].Title, "Bash") {
		t.Errorf("title should reference target tool 'Bash', got %q", got[0].Title)
	}
	if !strings.Contains(got[0].Subtitle, "cursor") {
		t.Errorf("subtitle should carry connector 'cursor', got %q", got[0].Subtitle)
	}
}

// TestAgentHookDispatch_WouldBlockFiresOnWouldBlock mirrors the
// claude/codex would-block route on the generic helper.
func TestAgentHookDispatch_WouldBlockFiresOnWouldBlock(t *testing.T) {
	d, rec := newWiringDispatcher()
	api := &APIServer{}
	api.SetNotifier(d)

	api.dispatchAgentHookNotification(
		agentHookRequest{ConnectorName: "geminicli", HookEventName: "BeforeTool", ToolName: "Read"},
		"allow", "block", "MEDIUM", "observe-mode", true,
		hookEvaluationContext{},
	)
	got := rec.WaitFor(t, 1)
	if !strings.Contains(strings.ToLower(got[0].Title), "would") {
		t.Errorf("title should mention 'would', got %q", got[0].Title)
	}
}

// TestAgentHookDispatch_ConfirmCarriesConnectorAndEvent pins the
// regression fix where cursor (and the other hook-only connectors)
// fired an "Approval needed: <tool>" toast that did not surface
// the connector name or the hook event in the subtitle. Operators
// looking at the toast in isolation could not tell which framework
// raised it. The toast subtitle must now read "hook · HIGH ·
// cursor · beforeShellExecution · reply in chat" so attribution
// works without opening the audit log.
func TestAgentHookDispatch_ConfirmCarriesConnectorAndEvent(t *testing.T) {
	d, rec := newWiringDispatcher()
	api := &APIServer{}
	api.SetNotifier(d)

	api.dispatchAgentHookNotification(
		agentHookRequest{
			ConnectorName: "cursor",
			HookEventName: "beforeShellExecution",
			ToolName:      "shell",
		},
		"confirm", "confirm", "HIGH", "matched: deny-rm-rf", false,
		hookEvaluationContext{},
	)
	got := rec.WaitFor(t, 1)
	if !strings.Contains(got[0].Title, "Approval needed") {
		t.Fatalf("title should mention 'Approval needed', got %q", got[0].Title)
	}
	if !strings.Contains(got[0].Subtitle, "cursor") {
		t.Errorf("subtitle should carry connector 'cursor', got %q", got[0].Subtitle)
	}
	if !strings.Contains(got[0].Subtitle, "beforeShellExecution") {
		t.Errorf("subtitle should carry event 'beforeShellExecution', got %q", got[0].Subtitle)
	}
	if !strings.Contains(got[0].Subtitle, "reply in chat") {
		t.Errorf("native ask should keep the 'reply in chat' tail, got %q", got[0].Subtitle)
	}
}

// TestAgentHookDispatch_ConfirmDowngradedRewordsToast guards the
// fix for the misleading "Approval needed: ... reply in chat"
// toast when DefenseClaw verdict is "confirm" but the connector
// cannot natively ask for that event (cursor's beforeReadFile is
// blockable but not askable — see connector.NewCursorConnector).
// In that case mapHookAction demotes action to "alert" and the
// chat surface receives no ask. The toast must:
//
//   - read "DefenseClaw would ask about <target>" rather than
//     "Approval needed" with a "reply in chat" tail, AND
//   - flow through the would-block category so a single
//     notifications.block_would_block=false silences it (and every
//     other observe-mode hook toast) without affecting real
//     native asks routed through OnApprovalPending.
func TestAgentHookDispatch_ConfirmDowngradedRewordsToast(t *testing.T) {
	d, rec := newWiringDispatcher()
	api := &APIServer{}
	api.SetNotifier(d)

	api.dispatchAgentHookNotification(
		agentHookRequest{
			ConnectorName: "cursor",
			HookEventName: "beforeReadFile",
			ToolName:      "Read",
		},
		// rawAction stays "confirm" but mapHookAction has demoted
		// the surface action to "alert" because beforeReadFile is
		// not in cursor's AskEvents.
		"alert", "confirm", "HIGH", "matched: gateway.json access", false,
		hookEvaluationContext{},
	)
	got := rec.WaitFor(t, 1)
	if strings.Contains(got[0].Subtitle, "reply in chat") {
		t.Fatalf("downgraded approval must not promise a chat reply, got %q", got[0].Subtitle)
	}
	if !strings.Contains(strings.ToLower(got[0].Title), "would ask about") {
		t.Errorf("title should mention 'would ask about' for downgraded confirm, got %q", got[0].Title)
	}
	if !strings.Contains(got[0].Subtitle, "cursor") {
		t.Errorf("subtitle should still carry connector 'cursor', got %q", got[0].Subtitle)
	}
	if !strings.Contains(got[0].Subtitle, "observe") {
		t.Errorf("downgraded confirm goes through OnWouldBlock so subtitle must carry the observe tag, got %q", got[0].Subtitle)
	}
}

// TestAgentHookDispatch_ObserveModeConfirmRoutesThroughWouldBlock
// pins the routing contract that lets users running connectors in
// observe mode silence ALL hook noise with a single
// notifications.block_would_block=false. In observe mode
// mapHookAction returns ("allow", false) for a confirm verdict — the
// chat surface gets permission=allow and no ask is issued — so the
// toast must not promise a chat reply, and must flow through the
// would-block category gate (OnWouldBlock with WouldAsk=true) rather
// than OnApprovalPending. The recorder used by newWiringDispatcher
// has all categories on, so this test only locks the user-visible
// shape; the gate behavior is covered by the dispatcher's own tests.
func TestAgentHookDispatch_ObserveModeConfirmRoutesThroughWouldBlock(t *testing.T) {
	d, rec := newWiringDispatcher()
	api := &APIServer{}
	api.SetNotifier(d)

	// Observe-mode shape from mapHookAction: rawAction="confirm",
	// action="allow", wouldBlock=false. Same shape regardless of
	// whether the event is in caps.AskEvents because mode != action
	// short-circuits before the AskEvents check.
	api.dispatchAgentHookNotification(
		agentHookRequest{
			ConnectorName: "cursor",
			HookEventName: "beforeShellExecution",
			ToolName:      "Shell",
		},
		"allow", "confirm", "HIGH", "matched: rm -rf /", false,
		hookEvaluationContext{},
	)
	got := rec.WaitFor(t, 1)
	if strings.Contains(strings.ToLower(got[0].Title), "approval needed") {
		t.Fatalf("observe-mode confirm must not fire 'Approval needed' (no chat ask is issued), got %q", got[0].Title)
	}
	if strings.Contains(got[0].Subtitle, "reply in chat") {
		t.Fatalf("observe-mode confirm must not promise a chat reply, got %q", got[0].Subtitle)
	}
	if !strings.Contains(strings.ToLower(got[0].Title), "would ask about") {
		t.Errorf("title should mention 'would ask about' for observe-mode confirm, got %q", got[0].Title)
	}
	if !strings.Contains(got[0].Subtitle, "observe") {
		t.Errorf("observe-mode confirm must carry the observe tag, got %q", got[0].Subtitle)
	}
}

// TestAgentHookDispatch_RedactsReason locks the privacy posture on
// the generic helper: regex-shaped echoed user content (PII /
// secrets) must not land verbatim in the toast body. Same contract
// as the claude/codex/asset-policy helpers.
func TestAgentHookDispatch_RedactsReason(t *testing.T) {
	d, rec := newWiringDispatcher()
	api := &APIServer{}
	api.SetNotifier(d)

	api.dispatchAgentHookNotification(
		agentHookRequest{ConnectorName: "copilot", HookEventName: "PreToolUse", ToolName: "shell"},
		"block", "block", "HIGH",
		"prompt contained AKIAIOSFODNN7EXAMPLE", false,
		hookEvaluationContext{},
	)
	got := rec.WaitFor(t, 1)
	if strings.Contains(got[0].Body, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("toast body must not contain raw AWS-key-shaped secret; got %q", got[0].Body)
	}
}

// TestRefreshAuditEnvelopeFromHook_PropagatesPayloadCorrelation is the
// focused F2 unit test. The CorrelationMiddleware can only stamp
// fields the inbound request carries in headers, but hook payloads
// carry session_id / agent_id in the JSON body — every audit row
// written by logConnectorHookAuditEnvelope therefore dropped those
// fields. The helper introduced for F2 refreshes the audit envelope
// from req.SessionID + the resolved identity so downstream rows
// correlate.
func TestRefreshAuditEnvelopeFromHook_PropagatesPayloadCorrelation(t *testing.T) {
	// Header-derived envelope simulates CorrelationMiddleware
	// running first: it sees the trace/run/request ids the
	// gateway is willing to expose but no session/agent because
	// the hook scripts don't set X-DefenseClaw-Session-Id.
	headerEnv := audit.CorrelationEnvelope{
		RunID:     "run-abc",
		TraceID:   "trace-def",
		RequestID: "req-ghi",
	}
	ctx := audit.ContextWithEnvelope(context.Background(), headerEnv)

	req := agentHookRequest{
		ConnectorName: "codex",
		HookEventName: "Stop",
		SessionID:     "thread-123",
		AgentID:       "agent-001",
		AgentName:     "codex",
	}
	identity := AgentIdentity{
		AgentID:         "agent-001",
		AgentName:       "codex",
		AgentInstanceID: "agent-instance-zzz",
	}

	got := audit.EnvelopeFromContext(refreshAuditEnvelopeFromHook(ctx, req, identity))

	// Payload-derived fields must land on the envelope.
	if got.SessionID != "thread-123" {
		t.Errorf("SessionID = %q, want %q (payload-derived)", got.SessionID, "thread-123")
	}
	if got.AgentID != "agent-001" {
		t.Errorf("AgentID = %q, want %q (identity-resolved)", got.AgentID, "agent-001")
	}
	if got.AgentName != "codex" {
		t.Errorf("AgentName = %q, want %q", got.AgentName, "codex")
	}
	if got.AgentInstanceID != "agent-instance-zzz" {
		t.Errorf("AgentInstanceID = %q, want %q", got.AgentInstanceID, "agent-instance-zzz")
	}

	// Header-derived fields must NOT be clobbered.
	if got.RunID != "run-abc" {
		t.Errorf("RunID = %q, want %q (refresh must not drop header-derived)", got.RunID, "run-abc")
	}
	if got.TraceID != "trace-def" {
		t.Errorf("TraceID = %q, want %q", got.TraceID, "trace-def")
	}
	if got.RequestID != "req-ghi" {
		t.Errorf("RequestID = %q, want %q", got.RequestID, "req-ghi")
	}
}

// TestRefreshAuditEnvelopeFromHook_EmptyPayloadIsNoOp guards the
// inverse path: when the hook payload has nothing to add (an inbound
// header already populated everything, or the connector simply
// doesn't expose those fields), the helper must not zero out the
// envelope.
func TestRefreshAuditEnvelopeFromHook_EmptyPayloadIsNoOp(t *testing.T) {
	headerEnv := audit.CorrelationEnvelope{
		SessionID: "session-from-header",
		AgentID:   "agent-from-header",
		AgentName: "agent-name-from-header",
	}
	ctx := audit.ContextWithEnvelope(context.Background(), headerEnv)

	got := audit.EnvelopeFromContext(refreshAuditEnvelopeFromHook(
		ctx,
		agentHookRequest{ConnectorName: "codex"}, // no SessionID
		AgentIdentity{},                          // no AgentID
	))

	if got.SessionID != "session-from-header" {
		t.Errorf("SessionID = %q, want preserved %q", got.SessionID, "session-from-header")
	}
	if got.AgentID != "agent-from-header" {
		t.Errorf("AgentID = %q, want preserved %q", got.AgentID, "agent-from-header")
	}
}

// TestRefreshAuditEnvelopeFromHook_PayloadOverridesStale guards the
// synthetic-row case: when the inbound HTTP request carried a stale
// session id (or no session id) and the payload supplies a fresher
// one, the payload wins. This is what makes the connector-hook-
// synthetic row track the canonical codex.notify.* row by session.
func TestRefreshAuditEnvelopeFromHook_PayloadOverridesStale(t *testing.T) {
	headerEnv := audit.CorrelationEnvelope{
		SessionID: "stale-session",
	}
	ctx := audit.ContextWithEnvelope(context.Background(), headerEnv)

	got := audit.EnvelopeFromContext(refreshAuditEnvelopeFromHook(
		ctx,
		agentHookRequest{ConnectorName: "codex", SessionID: "thread-123"},
		AgentIdentity{},
	))

	if got.SessionID != "thread-123" {
		t.Errorf("SessionID = %q, want %q (payload must override stale header value)", got.SessionID, "thread-123")
	}
}

func TestHookAgentIdentityFromContext_PropagatesConnector(t *testing.T) {
	ctx := audit.ContextWithEnvelope(context.Background(), audit.CorrelationEnvelope{
		Connector: "codex",
		RunID:     "run-1",
		SessionID: "session-1",
	})

	got := hookAgentIdentityFromContext(ctx)
	if got.Connector != "codex" {
		t.Fatalf("Connector = %q, want codex", got.Connector)
	}
	if got.RunID != "run-1" || got.SessionID != "session-1" {
		t.Fatalf("correlation fields not preserved: RunID=%q SessionID=%q", got.RunID, got.SessionID)
	}
}

// TestRefreshAuditEnvelopeFromIdentity_BespokeHandlerParity guards the
// follow-up fix that wires the F2 envelope refresh into the bespoke
// claudecode + codex handlers (handleClaudeCodeHook /
// enrichCodexHookContext). The original F2 patch only covered the
// unified handleAgentHook path; live Splunk verification proved that
// every connector-hook audit row written by Claude Code — by far the
// most common connector in operator deployments — still landed with
// session_id=NULL and agent_id=NULL because the bespoke handler ran on
// a bare r.Context(). This test exercises the helper directly with
// the same shape the bespoke handlers feed it.
func TestRefreshAuditEnvelopeFromIdentity_BespokeHandlerParity(t *testing.T) {
	headerEnv := audit.CorrelationEnvelope{
		RunID:     "run-from-header",
		TraceID:   "trace-from-header",
		RequestID: "req-from-header",
	}
	ctx := audit.ContextWithEnvelope(context.Background(), headerEnv)

	identity := AgentIdentity{
		AgentID:         "agent-claude-001",
		AgentName:       "claudecode",
		AgentInstanceID: "instance-zzz",
	}

	got := audit.EnvelopeFromContext(
		refreshAuditEnvelopeFromIdentity(ctx, "session-from-payload", identity),
	)

	if got.SessionID != "session-from-payload" {
		t.Errorf("SessionID = %q, want %q (bespoke handler envelope refresh broken)", got.SessionID, "session-from-payload")
	}
	if got.AgentID != "agent-claude-001" {
		t.Errorf("AgentID = %q, want %q", got.AgentID, "agent-claude-001")
	}
	if got.AgentName != "claudecode" {
		t.Errorf("AgentName = %q, want %q", got.AgentName, "claudecode")
	}
	if got.AgentInstanceID != "instance-zzz" {
		t.Errorf("AgentInstanceID = %q, want %q", got.AgentInstanceID, "instance-zzz")
	}
	// Header-derived correlation must survive.
	if got.RunID != "run-from-header" {
		t.Errorf("RunID = %q, want %q (refresh must preserve header)", got.RunID, "run-from-header")
	}
	if got.TraceID != "trace-from-header" {
		t.Errorf("TraceID = %q, want %q", got.TraceID, "trace-from-header")
	}
	if got.RequestID != "req-from-header" {
		t.Errorf("RequestID = %q, want %q", got.RequestID, "req-from-header")
	}
}

// TestEnrichAgentHookContext_ClaudeCodeRefreshesEnvelope replaces
// the legacy TestEnrichClaudeCodeHookContext_RefreshesEnvelope from
// the bespoke per-connector pipeline. After deleting
// handleClaudeCodeHook + enrichClaudeCodeHookContext, the audit
// envelope refresh for Claude Code traffic now happens inside
// enrichAgentHookContext (the unified pipeline). This test pins
// that behaviour for the connector name "claudecode" so we notice
// immediately if a future refactor drops claudecode's correlation
// again.
//
// Splunk verification of an earlier iteration caught the original
// gap when 4 PreToolUse/PostToolUse/UserPromptSubmit rows arrived
// with session_id=NULL while the synthetic codex.notify row in the
// same test run carried session_id correctly — proving the envelope
// refresh only covered the unified path. We now verify the unified
// path IS that "covering" path for every connector.
func TestEnrichAgentHookContext_ClaudeCodeRefreshesEnvelope(t *testing.T) {
	ctx := audit.ContextWithEnvelope(context.Background(), audit.CorrelationEnvelope{
		RunID: "run-keep",
	})
	req := agentHookRequest{
		ConnectorName: "claudecode",
		HookEventName: "PreToolUse",
		SessionID:     "cc-session-xyz",
		AgentID:       "agent-cc-001",
		AgentType:     "claudecode",
	}
	got := audit.EnvelopeFromContext(enrichAgentHookContext(ctx, req))
	if got.SessionID != "cc-session-xyz" {
		t.Errorf("SessionID = %q, want %q (envelope refresh missing for claudecode)", got.SessionID, "cc-session-xyz")
	}
	if got.AgentID != "agent-cc-001" {
		t.Errorf("AgentID = %q, want %q", got.AgentID, "agent-cc-001")
	}
	if got.AgentName != "claudecode" {
		t.Errorf("AgentName = %q, want %q (default claudecode fallback)", got.AgentName, "claudecode")
	}
	if got.RunID != "run-keep" {
		t.Errorf("RunID = %q, want preserved %q (envelope refresh must not clobber base correlation)", got.RunID, "run-keep")
	}
}

// TestEnrichAgentHookContext_CodexRefreshesEnvelope guards the codex
// side of the same fix. Replaces the legacy
// TestEnrichCodexHookContext_RefreshesEnvelope from the bespoke
// per-connector pipeline.
func TestEnrichAgentHookContext_CodexRefreshesEnvelope(t *testing.T) {
	ctx := audit.ContextWithEnvelope(context.Background(), audit.CorrelationEnvelope{})
	req := agentHookRequest{
		ConnectorName: "codex",
		HookEventName: "pre-tool-use",
		SessionID:     "codex-session-abc",
		AgentID:       "agent-cdx-001",
		AgentType:     "codex",
	}
	got := audit.EnvelopeFromContext(enrichAgentHookContext(ctx, req))
	if got.SessionID != "codex-session-abc" {
		t.Errorf("SessionID = %q, want %q (envelope refresh missing for codex)", got.SessionID, "codex-session-abc")
	}
	if got.AgentID != "agent-cdx-001" {
		t.Errorf("AgentID = %q, want %q", got.AgentID, "agent-cdx-001")
	}
	if got.AgentName != "codex" {
		t.Errorf("AgentName = %q, want default %q", got.AgentName, "codex")
	}
}

// TestRuntimeAssetCanEnforce_HookOnlyEvents locks G6: the hook-only
// connectors use varied case/spacing for tool-inspection events
// (preToolUse, pre_tool_call, beforeMCPExecution, BeforeTool,
// pre_run_command, ...), and runtimeAssetCanEnforce must recognize
// all of them. A regression here would let a registered-MCP block
// "would-block" silently on the generic connectors even in action
// mode — which is the exact gap G6 closed.
func TestRuntimeAssetCanEnforce_HookOnlyEvents(t *testing.T) {
	enforceable := []string{
		// Claude/Codex baseline — kept literal in production code.
		"PreToolUse", "PermissionRequest", "UserPromptExpansion",
		// Hermes
		"pre_tool_call",
		// Cursor
		"preToolUse", "beforeShellExecution", "beforeMCPExecution", "beforeReadFile", "beforeTabFileRead",
		// Windsurf
		"pre_read_code", "pre_write_code", "pre_run_command", "pre_mcp_tool_use",
		// Gemini CLI
		"BeforeTool",
		// Copilot
		"permissionRequest",
	}
	for _, ev := range enforceable {
		if !runtimeAssetCanEnforce(ev) {
			t.Errorf("runtimeAssetCanEnforce(%q) = false, want true (hook-only connector tool-inspection event)", ev)
		}
	}
	// Negative cases — prompt and result events stay non-enforceable
	// so the merge logic correctly downgrades to would-block.
	nonEnforceable := []string{
		"UserPromptSubmit", "post_tool_call", "PostToolUse", "Stop", "BeforeAgent",
	}
	for _, ev := range nonEnforceable {
		if runtimeAssetCanEnforce(ev) {
			t.Errorf("runtimeAssetCanEnforce(%q) = true, want false", ev)
		}
	}
}

// TestConnectorReason_PreservesUpstreamReason pins the contract
// that operator-authored reasons (e.g. policy.reason from a
// regex-match or asset-policy verdict) flow through unchanged.
// We synthesize a default ONLY when the upstream is empty.
func TestConnectorReason_PreservesUpstreamReason(t *testing.T) {
	upstream := "ASSET-POLICY reason_code=not-in-approved-registry asset_type=mcp asset_name=github"
	got := connectorReason("cursor", "block", "Bash", upstream)
	if got != upstream {
		t.Fatalf("upstream reason mutated: got %q want %q", got, upstream)
	}
	// Whitespace-only is treated as empty so we still synthesize
	// the default (operators sometimes hand-edit policy reasons
	// down to a stray "  " when iterating).
	got = connectorReason("cursor", "block", "Bash", "   ")
	if !strings.Contains(got, "DefenseClaw blocked Bash") {
		t.Fatalf("whitespace reason should fall through to default, got %q", got)
	}
}

// TestAgentHookEnabled_MultiConnectorSetMembership pins the multi-connector
// fix: a secondary connector (a member of guardrail.connectors but NOT the
// singular guardrail.connector primary, and with no explicit connector_hooks
// flag) must be treated as enabled. Without this, the hook handler would
// short-circuit to allow-without-scan and leave the connector unguarded.
func TestAgentHookEnabled_MultiConnectorSetMembership(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Connector = "codex" // sorted-first primary mirror
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex":  {},
		"cursor": {},
	}
	a := &APIServer{scannerCfg: cfg}

	if !a.agentHookEnabled("codex") {
		t.Errorf("primary connector codex should be enabled")
	}
	if !a.agentHookEnabled("cursor") {
		t.Errorf("secondary connector cursor (in guardrail.connectors) should be enabled, got allow-without-scan")
	}
	if a.agentHookEnabled("windsurf") {
		t.Errorf("connector not in the active set must not be enabled")
	}
}

// TestAgentHookEnabled_SingleConnectorUnchanged asserts the membership check
// is a no-op for single-connector installs (empty guardrail.connectors): only
// the singular primary is enabled, exactly as before the multi-connector work.
func TestAgentHookEnabled_SingleConnectorUnchanged(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Connector = "codex"
	a := &APIServer{scannerCfg: cfg}

	if !a.agentHookEnabled("codex") {
		t.Errorf("single-connector primary codex should be enabled")
	}
	if a.agentHookEnabled("cursor") {
		t.Errorf("non-primary connector must be disabled when guardrail.connectors is empty")
	}
}

// TestAgentHookEnabled_PerConnectorDisableShortCircuits pins the
// defense-in-depth gate for `guardrail disable --connector X`: a connector
// that is still a member of guardrail.connectors but explicitly disabled
// (enabled=false) must gate to allow-without-scan, even though HasConnector
// would otherwise opt it in. Its still-enabled sibling is unaffected.
func TestAgentHookEnabled_PerConnectorDisableShortCircuits(t *testing.T) {
	off := false
	cfg := &config.Config{}
	cfg.Guardrail.Connector = "codex" // sorted-first primary mirror
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex":  {Enabled: &off}, // explicitly disabled
		"cursor": {},              // still active (unset pointer ⇒ default on)
	}
	a := &APIServer{scannerCfg: cfg}

	if a.agentHookEnabled("codex") {
		t.Errorf("explicitly disabled codex must gate to allow-without-scan despite map membership")
	}
	if !a.agentHookEnabled("cursor") {
		t.Errorf("sibling cursor should remain enabled when only codex is disabled")
	}
}

// TestAgentHookMode_HonorsPerConnectorOverride pins A2: agentHookMode resolves
// through GuardrailConfig.EffectiveMode so a per-connector guardrail.connectors
// override wins over the global mode. Connector A enforces, connector B only
// monitors (inherits global observe) — they must not collapse to one mode.
func TestAgentHookMode_HonorsPerConnectorOverride(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Connector = "codex"
	cfg.Guardrail.Mode = "observe" // global default
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex":  {Mode: "action"}, // per-connector override → enforce
		"cursor": {},               // inherits global → observe
	}
	a := &APIServer{scannerCfg: cfg}

	if got := a.agentHookMode("codex"); got != "action" {
		t.Errorf("codex per-connector mode override = %q, want action", got)
	}
	if got := a.agentHookMode("cursor"); got != "observe" {
		t.Errorf("cursor should inherit global observe, got %q", got)
	}
}

// TestGuardrailHasConnector_CaseInsensitiveAndNoopEmpty covers the new
// membership helper directly: case-insensitive match, false on empty map.
func TestGuardrailHasConnector_CaseInsensitiveAndNoopEmpty(t *testing.T) {
	g := &config.GuardrailConfig{
		Connectors: map[string]config.PerConnectorGuardrailConfig{"codex": {}},
	}
	if !g.HasConnector("codex") {
		t.Errorf("exact match should report true")
	}
	if !g.HasConnector("CODEX") {
		t.Errorf("case-insensitive match should report true")
	}
	if g.HasConnector("cursor") {
		t.Errorf("absent connector should report false")
	}
	empty := &config.GuardrailConfig{}
	if empty.HasConnector("codex") {
		t.Errorf("empty connectors map must be a no-op (single-connector install)")
	}
}
