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
