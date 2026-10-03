// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

// GAP-2044: a foreign-hook guard denial is a guardrail block like any other.
// It reached only the audit row; now it also counts as a cursor block in the
// connector-hook metrics, logs a hook decision naming the user and records an
// apply_guardrail block span.
func TestForeignHookSessionDenialExportsAConnectorHookBlock(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"logs", "metrics", "traces"})
	sid := "S-1-5-21-1111-2222-3333-1001"
	ctx := context.WithValue(context.Background(), verifiedUserScopedIdentityContextKey{}, sid)
	ctx = ContextWithAgentIdentity(ctx, AgentIdentity{
		UserID: sid, UserIDKind: useridentity.KindForID(sid), UserName: "dcw-std1",
	})
	decision := enterprisepolicy.GuardDecision{Deny: true, Reason: "enterprise_foreign_hook_blocked: project hook"}
	api.auditForeignHookSessionDenial(ctx, "cursor", enterprisepolicy.SessionExchange{
		Key:          enterprisepolicy.SessionKey{Connector: "cursor", Session: "session-fh-1", Process: "process-1"},
		SessionStart: true, Decision: decision,
	}, decision)

	var points []hookModelV8MetricPoint
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		traces, requests := capture.snapshot()
		points = hookModelV8MetricPoints(requests, observability.TelemetryInstrumentDefenseClawConnectorHookInvocations)
		if len(points) > 0 && len(hookModelV8CapturedSpans(traces)) > 0 && len(hookModelV8CapturedLogs(capture.logSnapshot())) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	assertHookV8MetricPoint(t, points, map[string]string{
		"defenseclaw.connector.source": "cursor", "defenseclaw.metric.reason": "block",
		"defenseclaw.metric.result": "ok",
	}, 1)

	traces, _ := capture.snapshot()
	blockSpan := false
	for _, span := range hookModelV8CapturedSpans(traces) {
		attributes := inspectTraceV8ProtoAttributes(span.Attributes)
		if strings.HasPrefix(span.Name, "apply_guardrail") && attributes["defenseclaw.guardrail.decision"] == "block" &&
			attributes["defenseclaw.user.name"] == "dcw-std1" {
			blockSpan = true
		}
	}
	if !blockSpan {
		t.Fatalf("no apply_guardrail block span naming the user in %d spans", len(hookModelV8CapturedSpans(traces)))
	}

	logs := hookModelV8CapturedLogs(capture.logSnapshot())
	if len(logs) == 0 {
		t.Fatal("no hook decision log record")
	}
	var wire struct {
		Body map[string]any `json:"body"`
	}
	if err := json.Unmarshal([]byte(logs[0].Body.GetStringValue()), &wire); err != nil {
		t.Fatal(err)
	}
	if wire.Body["defenseclaw.user.name"] != "dcw-std1" || wire.Body["defenseclaw.guardrail.effective_action"] != "block" {
		t.Fatalf("hook decision record body=%v", wire.Body)
	}
}

// GAP-2142: a denied tool call is a blocked tool span (the decision on the
// tool span, which Galileo shows), and a session-start denial is an
// apply_guardrail span named for the session, not "tool_call".
func TestForeignHookSessionDenialNamesWhatWasDenied(t *testing.T) {
	if got, tool := foreignHookSessionDenialTarget(enterprisepolicy.SessionExchange{Event: "sessionEnd"}); got != "session" || tool != "" {
		t.Fatalf("sessionEnd target=%q tool=%q", got, tool)
	}
	if got, tool := foreignHookSessionDenialTarget(enterprisepolicy.SessionExchange{Event: "beforeShellExecution"}); got != "tool_call" || tool != "shell" {
		t.Fatalf("beforeShellExecution target=%q tool=%q", got, tool)
	}
	if got, _ := foreignHookSessionDenialTarget(enterprisepolicy.SessionExchange{Event: "beforeSubmitPrompt"}); got != "prompt" {
		t.Fatalf("beforeSubmitPrompt target=%q", got)
	}
	// GAP-2216: Cursor's other hook events are named for what they are,
	// never "inspect".
	for event, want := range map[string]string{
		"workspaceOpen": "session", "afterAgentThought": "completion", "afterAgentResponse": "completion",
		"stop": "completion", "preCompact": "compaction", "someNewEvent": "event",
	} {
		if got, tool := foreignHookSessionDenialTarget(enterprisepolicy.SessionExchange{Event: event}); got != want || tool != "" {
			t.Errorf("%s target=%q tool=%q, want %q", event, got, tool, want)
		}
	}

	api, capture := bindHookModelV8Runtime(t, []string{"logs", "traces"})
	sid := "S-1-5-21-1111-2222-3333-1001"
	ctx := context.WithValue(context.Background(), verifiedUserScopedIdentityContextKey{}, sid)
	ctx = ContextWithAgentIdentity(ctx, AgentIdentity{
		UserID: sid, UserIDKind: useridentity.KindForID(sid), UserName: "dcw-std1",
	})
	decision := enterprisepolicy.GuardDecision{Deny: true, Reason: "enterprise_foreign_hook_blocked: project hook"}
	key := enterprisepolicy.SessionKey{Connector: "cursor", Session: "session-fh-2", Process: "process-1"}
	api.auditForeignHookSessionDenial(ctx, "cursor", enterprisepolicy.SessionExchange{
		Key: key, SessionStart: true, Event: "sessionStart", Decision: decision,
	}, decision)
	api.auditForeignHookSessionDenial(ctx, "cursor", enterprisepolicy.SessionExchange{
		Key: key, Event: "preToolUse", Tool: "Write", Decision: decision,
	}, decision)

	var spans []*tracepb.Span
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		traces, _ := capture.snapshot()
		if spans = hookModelV8CapturedSpans(traces); len(spans) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	var names []string
	toolBlocked, sessionSpan := false, false
	for _, span := range spans {
		names = append(names, span.Name)
		if span.Name == "apply_guardrail inspect tool_call" {
			t.Fatalf("a denial is still labelled tool_call: %v", names)
		}
		if span.Name == "apply_guardrail inspect session" {
			sessionSpan = true
		}
		if strings.HasPrefix(span.Name, "invoke_agent") {
			if got := inspectTraceV8ProtoAttributes(span.Attributes)["defenseclaw.guardrail.rule_id"]; got != foreignHookDenialRuleID {
				t.Errorf("%s rule_id=%v, want %s (GAP-2610)", span.Name, got, foreignHookDenialRuleID)
			}
		}
		if strings.HasPrefix(span.Name, "execute_tool") && span.Status.GetCode() == tracepb.Status_STATUS_CODE_ERROR {
			if got := inspectTraceV8ProtoAttributes(span.Attributes)["defenseclaw.agent.lifecycle.event"]; got != "tool_start" {
				t.Errorf("blocked tool span lifecycle.event=%v, want tool_start (GAP-2216)", got)
			}
			// GAP-2610: the block names the foreign-hook guard as its rule,
			// so a dashboard can tell why the call was blocked.
			if got := inspectTraceV8ProtoAttributes(span.Attributes)["defenseclaw.guardrail.rule_id"]; got != foreignHookDenialRuleID {
				t.Errorf("blocked tool span rule_id=%v, want %s (GAP-2610)", got, foreignHookDenialRuleID)
			}
			for _, event := range span.Events {
				toolBlocked = toolBlocked || event.Name == "defenseclaw.guardrail.block"
			}
		}
	}
	if !toolBlocked || !sessionSpan {
		t.Fatalf("spans=%v, want a blocked execute_tool span and an apply_guardrail session span", names)
	}

	// The hook decision record of the tool denial names the real event too.
	// Logs export in their own batches, so wait for it as for the spans.
	toolDecision := false
	for deadline := time.Now().Add(5 * time.Second); !toolDecision && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		for _, record := range hookModelV8CapturedLogs(capture.logSnapshot()) {
			var wire struct {
				Body map[string]any `json:"body"`
			}
			if err := json.Unmarshal([]byte(record.Body.GetStringValue()), &wire); err != nil {
				t.Fatal(err)
			}
			if wire.Body["defenseclaw.agent.lifecycle.event"] == "tool_start" {
				toolDecision = true
			}
		}
	}
	if !toolDecision {
		t.Fatal("no hook decision record with lifecycle.event tool_start (GAP-2216)")
	}
}
