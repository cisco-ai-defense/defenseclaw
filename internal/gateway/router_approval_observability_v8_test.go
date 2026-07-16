// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"go.opentelemetry.io/otel/trace"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

func eventRouterApprovalV8BootstrapRawWithLogs(
	dataDir, endpoint string,
	traces, complianceLogs bool,
) []byte {
	return []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\nobservability:\n  metric_policy:\n    export_interval_seconds: 1\n  buckets:\n    compliance.activity:\n      collect: {logs: %t, traces: true, metrics: true}\n    enforcement.action:\n      collect: {logs: true, traces: %t, metrics: true}\n  destinations:\n    - name: approval-otlp\n      kind: otlp\n      endpoint: %q\n      protocol: http/protobuf\n      tls:\n        insecure: true\n      network_safety:\n        allow_private_networks: true\n      batch:\n        max_export_batch_size: 16\n        scheduled_delay_ms: 10\n      send:\n        signals: [traces, metrics]\n        buckets: ['*']\n",
		dataDir, complianceLogs, traces, endpoint,
	))
}

func bindEventRouterApprovalV8Runtime(
	t *testing.T,
	traces bool,
) (*EventRouter, *hookModelV8OTLPCapture, string) {
	return bindEventRouterApprovalV8RuntimeWithLogs(t, traces, true)
}

func bindEventRouterApprovalV8RuntimeWithLogs(
	t *testing.T,
	traces, complianceLogs bool,
) (*EventRouter, *hookModelV8OTLPCapture, string) {
	t.Helper()
	capture := &hookModelV8OTLPCapture{}
	server := httptest.NewServer(http.HandlerFunc(capture.handler))
	t.Cleanup(server.Close)
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	router := &EventRouter{defaultPolicyID: "policy-1"}
	fixture.sidecar.setEventRouter(router)
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(
		t.Context(), fixture.configPath,
		eventRouterApprovalV8BootstrapRawWithLogs(fixture.dataDir, server.URL, traces, complianceLogs),
	)
	if err != nil || !bound {
		t.Fatalf("bootstrap approval runtime bound=%t error=%v", bound, err)
	}
	if runtime, authoritative := router.observabilityV8LifecycleSnapshot(); runtime == nil || !authoritative {
		t.Fatalf("approval runtime=%T authoritative=%t", runtime, authoritative)
	}
	return router, capture, fixture.store.DatabasePath()
}

func TestEventRouterApprovalV8EmitsGeneratedUnredactedTerminalTrace(t *testing.T) {
	router, capture, databasePath := bindEventRouterApprovalV8Runtime(t, true)
	started := time.Now().UTC().Add(-25 * time.Millisecond)
	observation := eventRouterApprovalObservation{
		id: "approval-1", commandName: "printf", command: "printf 'private approval marker'",
		argv: []string{"printf", "private approval marker"}, cwd: "/private/workspace",
		result: "approved", actorType: "automatic", dangerous: false,
		startedAt: started, finishedAt: time.Now().UTC(),
	}
	if result := router.emitApprovalRequestedV8(t.Context(), observation); result != eventRouterApprovalEmitted {
		t.Fatalf("approval request emission=%d want emitted", result)
	}
	result := router.emitApprovalResolutionV8(t.Context(), observation)
	if result != eventRouterApprovalEmitted {
		t.Fatalf("approval emission=%d want emitted", result)
	}

	var approval *tracepb.Span
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, span := range hookModelV8CapturedSpansFromCapture(capture) {
			if gatewayProtoAttribute(span.Attributes, "defenseclaw.span.family") ==
				observability.TelemetryFamilyApprovalResolve {
				approval = span
				break
			}
		}
		if approval != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if approval == nil {
		t.Fatal("generated approval trace was not exported")
	}
	attributes := hookModelV8ProtoAttributes(approval)
	for key, want := range map[string]string{
		"defenseclaw.approval.id":           "approval-1",
		"defenseclaw.approval.command_name": "printf",
		"defenseclaw.approval.command":      "printf 'private approval marker'",
		"defenseclaw.approval.cwd":          "/private/workspace",
		"defenseclaw.approval.result":       "approved",
		"defenseclaw.approval.actor_type":   "automatic",
	} {
		if got := attributes[key]; got != want {
			t.Errorf("approval attribute %s=%q want %q", key, got, want)
		}
	}
	if approval.Name != "exec.approval" ||
		gatewayProtoAttribute(approval.Attributes, "defenseclaw.outcome") != "approved" {
		t.Errorf("approval span name=%q outcome=%q", approval.Name,
			gatewayProtoAttribute(approval.Attributes, "defenseclaw.outcome"))
	}
	if len(approval.Events) != 2 || approval.Events[0].Name != "approval.requested" ||
		approval.Events[1].Name != "approval.resolved" {
		t.Fatalf("approval events=%+v", approval.Events)
	}
	for _, forbidden := range []string{
		"gen_ai.agent.id", "gen_ai.conversation.id", "defenseclaw.policy.id",
		"defenseclaw.request.id", "defenseclaw.turn.id", "defenseclaw.run.id",
		"defenseclaw.operation.id", "defenseclaw.destination.app", "defenseclaw.tool.id",
		"gen_ai.tool.call.id",
	} {
		if bytes.Contains(capture.traceBytes(), []byte(forbidden)) {
			t.Fatalf("request-bounded approval trace fabricated %s", forbidden)
		}
	}
	assertEventRouterApprovalLocalLogs(t, databasePath, "private approval marker")
	assertEventRouterApprovalMetrics(t, capture, "approved", "true", "false")
}

func TestEventRouterApprovalV8LogsRetainActiveW3CCorrelation(t *testing.T) {
	router, _, databasePath := bindEventRouterApprovalV8Runtime(t, true)
	traceID := trace.TraceID{1, 2, 3, 4}
	spanID := trace.SpanID{5, 6, 7, 8}
	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: spanID, TraceFlags: trace.FlagsSampled,
	}))
	now := time.Now().UTC()
	observation := eventRouterApprovalObservation{
		id: "approval-correlated", sessionID: "session-correlated", runID: "run-correlated",
		result: "approved", actorType: "automatic", startedAt: now.Add(-time.Millisecond), finishedAt: now,
	}
	if got := router.emitApprovalRequestedV8(ctx, observation); got != eventRouterApprovalEmitted {
		t.Fatalf("request emission=%d", got)
	}
	if got := router.emitApprovalResolutionV8(ctx, observation); got != eventRouterApprovalEmitted {
		t.Fatalf("resolution emission=%d", got)
	}
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	rows, err := database.QueryContext(t.Context(), `
		SELECT projected_record_json FROM audit_events
		WHERE event_name IN ('approval.requested', 'approval.resolved')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	correlated := 0
	for rows.Next() {
		var projected string
		if err := rows.Scan(&projected); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(projected, `"trace_id":"`+traceID.String()+`"`) &&
			strings.Contains(projected, `"span_id":"`+spanID.String()+`"`) {
			correlated++
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if correlated != 2 {
		t.Fatalf("W3C-correlated approval logs=%d want 2", correlated)
	}
}

func TestEventRouterApprovalV8PreservesConnectorAndCanonicalAgentLineage(t *testing.T) {
	router, capture, databasePath := bindEventRouterApprovalV8Runtime(t, true)
	now := time.Now().UTC()
	observation := eventRouterApprovalObservation{
		id: "approval-lineage", connector: "codex",
		sessionID: "session-leaf", rootSessionID: "session-root", parentSessionID: "session-parent",
		runID: "run-1", requestID: "request-1", turnID: "turn-1", operationID: "operation-1",
		agentID: "agent-leaf", agentName: "leaf", agentType: "subagent", agentInstanceID: "agent-instance-1",
		rootAgentID: "agent-root", parentAgentID: "agent-parent", lineageProvenance: "reported",
		lifecycleID: "lifecycle-leaf", executionID: "execution-leaf", phase: "approval",
		depth: 3, depthSet: true, sequence: 3, sequenceSet: true,
		userID: "user-1", userName: "operator", policyID: "policy-1", policyVersion: "policy-v1",
		destinationApp: "terminal", toolID: "tool-shell", toolName: "shell", toolType: "function",
		toolCallID: "tool-call-1", toolProvider: "builtin", toolSkillKey: "skill-shell",
		commandName: "printf", command: "printf lineage", argv: []string{"printf", "lineage"},
		result: "approved", actorType: "automatic",
		startedAt: now.Add(-time.Millisecond), finishedAt: now,
	}
	if got := router.emitApprovalRequestedV8(t.Context(), observation); got != eventRouterApprovalEmitted {
		t.Fatalf("request emission=%d", got)
	}
	observation.sequence = 4
	if got := router.emitApprovalResolutionV8(t.Context(), observation); got != eventRouterApprovalEmitted {
		t.Fatalf("resolution emission=%d", got)
	}

	var approval *tracepb.Span
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, span := range hookModelV8CapturedSpansFromCapture(capture) {
			if gatewayProtoAttribute(span.Attributes, "defenseclaw.span.family") ==
				observability.TelemetryFamilyApprovalResolve {
				approval = span
				break
			}
		}
		if approval != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if approval == nil {
		t.Fatal("generated approval trace was not exported")
	}
	attributes := hookModelV8ProtoAttributes(approval)
	for key, want := range map[string]string{
		"defenseclaw.connector.source":         "codex",
		"gen_ai.conversation.id":               "session-leaf",
		"gen_ai.agent.id":                      "agent-leaf",
		"defenseclaw.agent.root.id":            "agent-root",
		"defenseclaw.agent.parent.id":          "agent-parent",
		"defenseclaw.agent.lineage.provenance": "reported",
		"defenseclaw.session.root.id":          "session-root",
		"defenseclaw.session.parent.id":        "session-parent",
		"defenseclaw.agent.lifecycle.id":       "lifecycle-leaf",
		"defenseclaw.agent.execution.id":       "execution-leaf",
		"defenseclaw.agent.instance_id":        "agent-instance-1",
		"defenseclaw.agent.phase":              "approval",
		"defenseclaw.request.id":               "request-1",
		"defenseclaw.turn.id":                  "turn-1",
		"defenseclaw.run.id":                   "run-1",
		"defenseclaw.operation.id":             "operation-1",
		"defenseclaw.policy.id":                "policy-1",
		"defenseclaw.policy.version":           "policy-v1",
		"defenseclaw.destination.app":          "terminal",
		"defenseclaw.tool.id":                  "tool-shell",
		"gen_ai.tool.name":                     "shell",
		"gen_ai.tool.type":                     "function",
		"gen_ai.tool.call.id":                  "tool-call-1",
		"defenseclaw.tool.provider":            "builtin",
		"defenseclaw.tool.skill_key":           "skill-shell",
		"user.id":                              "user-1",
		"defenseclaw.user.name":                "operator",
	} {
		if got := attributes[key]; got != want {
			t.Errorf("approval attribute %s=%q want %q", key, got, want)
		}
	}
	if got := attributes["defenseclaw.agent.depth"]; got != `{"intValue":"3"}` {
		t.Errorf("approval depth=%q want 3", got)
	}
	if got := attributes["defenseclaw.agent.sequence"]; got != `{"intValue":"4"}` {
		t.Errorf("approval sequence=%q want 4", got)
	}

	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	rows, err := database.QueryContext(t.Context(), `
		SELECT projected_record_json FROM audit_events
		WHERE event_name IN ('approval.requested', 'approval.resolved')
		ORDER BY timestamp ASC`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	wantSequences := []string{"3", "4"}
	index := 0
	for rows.Next() {
		var projected string
		if err := rows.Scan(&projected); err != nil {
			t.Fatal(err)
		}
		for _, fragment := range []string{
			`"connector":"codex"`,
			`"defenseclaw.agent.root.id":"agent-root"`,
			`"defenseclaw.session.root.id":"session-root"`,
			`"defenseclaw.agent.lifecycle.id":"lifecycle-leaf"`,
			`"defenseclaw.agent.execution.id":"execution-leaf"`,
			`"defenseclaw.request.id":"request-1"`,
			`"defenseclaw.operation.id":"operation-1"`,
			`"defenseclaw.destination.app":"terminal"`,
			`"gen_ai.tool.call.id":"tool-call-1"`,
		} {
			if !strings.Contains(projected, fragment) {
				t.Errorf("approval log missing %s: %s", fragment, projected)
			}
		}
		if index >= len(wantSequences) || !strings.Contains(
			projected,
			`"defenseclaw.agent.sequence":`+wantSequences[index],
		) {
			t.Errorf("approval log %d has incorrect sequence: %s", index, projected)
		}
		index++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if index != 2 {
		t.Fatalf("approval lineage logs=%d want 2", index)
	}
}

func TestEventRouterApprovalV8RejectsInvalidFactsBeforeRuntime(t *testing.T) {
	router := &EventRouter{}
	runtime := &hookModelV8DeclineRuntime{}
	router.bindObservabilityV8Capabilities(nil, runtime)
	if got := router.emitApprovalResolutionV8(t.Context(), eventRouterApprovalObservation{
		id: "invalid approval id", result: "approved", actorType: "automatic",
		startedAt: time.Now().UTC(), finishedAt: time.Now().UTC(),
	}); got != eventRouterApprovalRejected {
		t.Fatalf("invalid approval emission=%d want rejected", got)
	}
}

func TestEventRouterApprovalTopologyRequiresExactSessionIncarnationAndAgent(t *testing.T) {
	now := time.Now().UTC()
	router := &EventRouter{
		agentRunTopologies: map[string]agentRunTopologyState{
			"agent:child:subagent:one": {
				topology: agentRunTopology{
					sessionKey: "agent:child:subagent:one", conversationID: "session-child-old",
					agentID: "agent-child", rootAgentID: "agent-root",
					lifecycleID: "lifecycle-old", executionID: "execution-old",
				},
				insertedAt: now,
			},
		},
		agentRunObservationNow: func() time.Time { return now },
	}
	for _, observation := range []eventRouterApprovalObservation{
		{sessionKey: "agent:child:subagent:one", sessionID: "session-child-new", agentID: "agent-child"},
		{sessionKey: "agent:child:subagent:one", sessionID: "session-child-old", agentID: "different-agent"},
		{sessionKey: "agent:child:subagent:one", agentID: "agent-child"},
	} {
		got := router.enrichEventRouterApprovalTopology(observation)
		if got.rootAgentID != "" || got.lifecycleID != "" || got.executionID != "" {
			t.Fatalf("inexact approval joined retained topology: %+v", got)
		}
	}
}

func TestEventRouterApprovalV8CollectionDisablementPreventsSpanConstruction(t *testing.T) {
	router, capture, _ := bindEventRouterApprovalV8Runtime(t, false)
	now := time.Now().UTC()
	if got := router.emitApprovalResolutionV8(t.Context(), eventRouterApprovalObservation{
		id: "approval-disabled", result: "denied", actorType: "policy", dangerous: true,
		startedAt: now, finishedAt: now,
	}); got != eventRouterApprovalDropped {
		t.Fatalf("disabled approval emission=%d want dropped", got)
	}
	time.Sleep(50 * time.Millisecond)
	if spans := hookModelV8CapturedSpansFromCapture(capture); len(spans) != 0 {
		t.Fatalf("disabled approval collection exported %d spans", len(spans))
	}
}

func TestEventRouterApprovalV8ResolutionFloorIsContentFreeAndMetricsRemainIndependent(t *testing.T) {
	router, capture, databasePath := bindEventRouterApprovalV8RuntimeWithLogs(t, false, false)
	now := time.Now().UTC()
	observation := eventRouterApprovalObservation{
		id: "approval-floor", commandName: "curl", command: "curl private-floor-marker",
		argv: []string{"curl", "private-floor-marker"}, result: "denied", actorType: "policy",
		reason: "private floor reason", ruleIDs: []string{"rule.floor"}, dangerous: true,
		startedAt: now.Add(-time.Millisecond), finishedAt: now,
	}
	if got := router.emitApprovalRequestedV8(t.Context(), observation); got != eventRouterApprovalEmitted {
		t.Fatalf("collection-disabled request emission=%d", got)
	}
	if got := router.emitApprovalResolutionV8(t.Context(), observation); got != eventRouterApprovalDropped {
		t.Fatalf("trace-disabled resolution emission=%d", got)
	}
	assertEventRouterApprovalMetrics(t, capture, "denied", "false", "true")
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var eventName, projected string
	if err := database.QueryRowContext(t.Context(), `
		SELECT event_name, projected_record_json FROM audit_events
		WHERE event_name IN ('approval.requested', 'approval.resolved')`).Scan(&eventName, &projected); err != nil {
		t.Fatal(err)
	}
	if eventName != observability.TelemetryEventApprovalResolved ||
		!strings.Contains(projected, `"floor_only":true`) ||
		strings.Contains(projected, "private-floor-marker") || strings.Contains(projected, "private floor reason") {
		t.Fatalf("approval floor event=%q projected=%s", eventName, projected)
	}
}

func TestEventRouterApprovalV8PendingKeepsLogsAndMetricsWithoutInventingResolution(t *testing.T) {
	router, capture, databasePath := bindEventRouterApprovalV8Runtime(t, false)
	started := time.Now().UTC()
	observation := eventRouterApprovalObservation{
		id: "approval-pending", commandName: "git", command: "git status",
		argv: []string{"git", "status"}, startedAt: started,
	}
	if got := router.emitApprovalRequestedV8(t.Context(), observation); got != eventRouterApprovalEmitted {
		t.Fatalf("requested emission=%d", got)
	}
	if got := router.emitApprovalPendingMetricsV8(t.Context(), observation); got != eventRouterApprovalEmitted {
		t.Fatalf("pending metric emission=%d", got)
	}
	assertEventRouterApprovalMetrics(t, capture, "pending", "false", "false")
	assertEventRouterApprovalLocalLogs(t, databasePath, "git status")
	if spans := hookModelV8CapturedSpansFromCapture(capture); len(spans) != 0 {
		t.Fatalf("pending approval invented %d terminal spans", len(spans))
	}
}

func TestEventRouterApprovalHandlerUsesGeneratedOperationWithoutLegacySpan(t *testing.T) {
	router, capture, databasePath := bindEventRouterApprovalV8Runtime(t, true)
	received := make(chan receivedRequest, 1)
	server := startMockGW(t, rpcRecordingLoop(received))
	router.client = connectToMockGW(t, server)
	router.autoApprove = true
	payload, err := json.Marshal(ApprovalRequestPayload{
		ID: "approval-handler",
		SystemRunPlan: &SystemRunPlan{
			RawCommand: "git status", Argv: []string{"git", "status"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	router.handleApprovalRequest(EventFrame{
		Type: "event", Event: "exec.approval.requested", Payload: payload,
	})
	rpc := drainRPC(t, received)
	if rpc.Method != "exec.approval.resolve" {
		t.Fatalf("approval RPC method=%q", rpc.Method)
	}
	assertEventRouterApprovalLocalLogs(t, databasePath, "git status")
	assertEventRouterApprovalMetrics(t, capture, "approved", "true", "false")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, span := range hookModelV8CapturedSpansFromCapture(capture) {
			if gatewayProtoAttribute(span.Attributes, "defenseclaw.span.family") ==
				observability.TelemetryFamilyApprovalResolve {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("approval handler did not export its generated terminal span")
}

func TestEventRouterApprovalHandlerPreservesWireCorrelationAndExactTopology(t *testing.T) {
	router, capture, databasePath := bindEventRouterApprovalV8Runtime(t, true)
	received := make(chan receivedRequest, 1)
	server := startMockGW(t, rpcRecordingLoop(received))
	router.client = connectToMockGW(t, server)
	router.autoApprove = true
	now := time.Now().UTC()
	router.agentRunTopologies = map[string]agentRunTopologyState{
		"agent:child:subagent:one": {
			topology: agentRunTopology{
				sessionKey: "agent:child:subagent:one", conversationID: "session-child-1",
				agentID: "agent-child", rootAgentID: "agent-root", parentAgentID: "agent-root",
				rootSessionID: "session-root-1", parentSessionID: "session-root-1",
				lifecycleID: "lifecycle-child", executionID: "execution-child",
				lineage: "inferred", depth: observability.Present[int64](1),
			},
			insertedAt: now,
		},
	}
	depth, sequence := int64(1), int64(7)
	payload, err := json.Marshal(ApprovalRequestPayload{
		ID:                         "approval-wire",
		ApprovalCorrelationPayload: ApprovalCorrelationPayload{RequestID: "request-wire"},
		Request: &ApprovalRequestRecord{
			Command: "git status", CommandArgv: []string{"git", "status"}, Cwd: "/workspace",
			ApprovalCorrelationPayload: ApprovalCorrelationPayload{
				RunID: "run-wire", TurnID: "turn-wire", OperationID: "operation-wire",
				SessionKey: "agent:child:subagent:one", SessionID: "session-child-1",
				AgentID: "agent-child", AgentName: "child", AgentType: "subagent",
				AgentInstanceID: "agent-instance-child", Depth: &depth, AgentPhase: "approval",
				AgentSequence: &sequence, PolicyID: "policy-wire", PolicyVersion: "policy-v1",
				UserID: "user-wire", UserName: "operator", DestinationApp: "terminal",
				ToolID: "tool-shell", ToolName: "shell", ToolType: "function",
				ToolCallID: "tool-call-wire", ToolProvider: "builtin", ToolSkillKey: "skill-shell",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	router.handleApprovalRequest(EventFrame{Type: "event", Event: "exec.approval.requested", Payload: payload})
	if rpc := drainRPC(t, received); rpc.Method != "exec.approval.resolve" {
		t.Fatalf("approval RPC method=%q", rpc.Method)
	}

	var approval *tracepb.Span
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, span := range hookModelV8CapturedSpansFromCapture(capture) {
			if gatewayProtoAttribute(span.Attributes, "defenseclaw.approval.id") == "approval-wire" {
				approval = span
				break
			}
		}
		if approval != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if approval == nil {
		t.Fatal("wire-correlated approval span was not exported")
	}
	attributes := hookModelV8ProtoAttributes(approval)
	for key, want := range map[string]string{
		"defenseclaw.request.id": "request-wire", "defenseclaw.turn.id": "turn-wire",
		"defenseclaw.run.id": "run-wire", "defenseclaw.operation.id": "operation-wire",
		"gen_ai.conversation.id": "session-child-1", "gen_ai.agent.id": "agent-child",
		"defenseclaw.agent.root.id": "agent-root", "defenseclaw.agent.parent.id": "agent-root",
		"defenseclaw.agent.lifecycle.id": "lifecycle-child",
		"defenseclaw.agent.execution.id": "execution-child",
		"defenseclaw.destination.app":    "terminal", "defenseclaw.tool.id": "tool-shell",
		"gen_ai.tool.call.id": "tool-call-wire",
	} {
		if attributes[key] != want {
			t.Errorf("approval attribute %s=%q want=%q", key, attributes[key], want)
		}
	}
	if attributes["gen_ai.tool.call.id"] == attributes["defenseclaw.approval.id"] {
		t.Fatal("approval id was inferred as tool call id")
	}
	assertEventRouterApprovalLocalLogs(t, databasePath, "git status")
}

func TestEventRouterObservabilityV8AuthorityIsStickyAcrossDetach(t *testing.T) {
	router := &EventRouter{}
	router.bindObservabilityV8Capabilities(nil, &hookModelV8DeclineRuntime{})
	router.bindObservabilityV8Capabilities(nil, nil)
	runtime, authoritative := router.observabilityV8LifecycleSnapshot()
	if runtime != nil || !authoritative {
		t.Fatalf("detached runtime=%T authoritative=%t want nil,true", runtime, authoritative)
	}
}

func assertEventRouterApprovalLocalLogs(t *testing.T, databasePath, content string) {
	t.Helper()
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	rows, err := database.QueryContext(t.Context(), `
		SELECT event_name, projected_record_json
		FROM audit_events
		WHERE event_name IN ('approval.requested', 'approval.resolved')
		ORDER BY timestamp ASC`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var names []string
	var projected strings.Builder
	for rows.Next() {
		var name, body string
		if err := rows.Scan(&name, &body); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
		projected.WriteString(body)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(names) == 0 || names[0] != observability.TelemetryEventApprovalRequested {
		t.Fatalf("approval log names=%v", names)
	}
	if !strings.Contains(projected.String(), content) {
		t.Fatalf("default-unredacted approval logs omit %q: %s", content, projected.String())
	}
}

func assertEventRouterApprovalMetrics(
	t *testing.T,
	capture *hookModelV8OTLPCapture,
	result, automatic, dangerous string,
) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, metricRequests := capture.snapshot()
		lifecycle := hookModelV8MetricPoints(
			metricRequests, observability.TelemetryInstrumentDefenseClawApprovalLifecycle,
		)
		compatibility := hookModelV8MetricPoints(
			metricRequests, observability.TelemetryInstrumentDefenseClawApprovalCount,
		)
		if approvalMetricPointMatches(lifecycle, map[string]string{
			"defenseclaw.approval.lifecycle.result": result,
			"defenseclaw.approval.surface":          "exec",
			"defenseclaw.connector.source":          "openclaw",
		}) && approvalMetricPointMatches(compatibility, map[string]string{
			"defenseclaw.metric.result":    result,
			"defenseclaw.metric.auto":      automatic,
			"defenseclaw.metric.dangerous": dangerous,
		}) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("generated approval lifecycle and compatibility metrics were not exported")
}

func approvalMetricPointMatches(points []hookModelV8MetricPoint, want map[string]string) bool {
	for _, point := range points {
		matched := true
		for key, value := range want {
			if point.attributes[key] != value {
				matched = false
				break
			}
		}
		if matched && point.value >= 1 {
			return true
		}
	}
	return false
}
