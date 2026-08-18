// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	oteltrace "go.opentelemetry.io/otel/trace"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

func TestInspectTraceV8ExportsRichGeneratedGuardrailSpanWithoutLegacyProvider(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"traces"})
	api.scannerCfg = &config.Config{Guardrail: config.GuardrailConfig{Connector: "codex"}}
	ctx := audit.ContextWithEnvelope(context.Background(), audit.CorrelationEnvelope{
		RunID: "run-inspect-1", RequestID: "request-inspect-1", SessionID: "session-inspect-1",
		TurnID: "turn-inspect-1", AgentID: "agent-inspect-1", AgentName: "Root Agent",
		AgentInstanceID: "agent-instance-inspect-1", PolicyID: "policy-inspect-1",
		DestinationApp: "mcp.example", ToolName: "write_file", ToolID: "tool-call-inspect-1",
	})
	spanContext := oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
		TraceID: oteltrace.TraceID{1, 3, 5, 7}, SpanID: oteltrace.SpanID{2, 4, 6, 8},
		TraceFlags: oteltrace.FlagsSampled, Remote: true,
	})
	ctx = oteltrace.ContextWithRemoteSpanContext(ctx, spanContext)
	api.rememberHookSessionState(ctx, llmEventMeta{
		Source: "codex", SessionID: "session-inspect-1", AgentID: "agent-inspect-1",
		AgentName: "Root Agent", AgentType: "root", RootAgentID: "agent-inspect-1",
		LineageProvenance: "reported", RootSessionID: "session-inspect-1",
		LifecycleID: "lifecycle-inspect-1", ExecutionID: "execution-inspect-1",
		LifecycleEvent: "tool_end", LifecycleState: "active", OperationID: "operation-inspect-1",
		Phase: "tool", PreviousPhase: "model", Sequence: 7, AgentDepth: 0,
		SessionSource: "startup", SessionResumed: false,
	})
	verdict := &ToolInspectVerdict{
		Action: "block", RawAction: "block", Severity: "HIGH", Confidence: 0.95,
		Reason: "matched: CG-EXEC-001", Mode: "action", WouldBlock: false,
		DetailedFindings: []RuleFinding{{RuleID: "CG-EXEC-001", Title: "Command execution", Severity: "HIGH"}},
	}
	input, inputOK := api.inspectTraceV8Input(
		ctx, "write_file", "tool_call", verdict, 12*time.Millisecond+500*time.Microsecond,
		hookEvaluationContext{EvaluationID: "evaluation-inspect-1", RuleIDs: []string{"CG-EXEC-001"}},
	)
	if !inputOK {
		t.Fatal("generated inspect trace input was rejected")
	}
	runtime, runtimeOK := api.observabilityV8RuntimeEmitter().(inspectTraceV8Runtime)
	if !runtimeOK {
		t.Fatalf("generated inspect trace runtime=%T", api.observabilityV8RuntimeEmitter())
	}
	_, generated, startErr := runtime.StartGuardrailApplyTrace(ctx, input)
	if startErr != nil || generated == nil {
		t.Fatalf("start generated inspect trace=%v error=%v", generated, startErr)
	}
	defer generated.Abort()
	if endErr := generated.End(input); endErr != nil {
		t.Fatalf("end generated inspect trace: %v", endErr)
	}

	var spans []*tracepb.Span
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		traces, _ := capture.snapshot()
		spans = hookModelV8CapturedSpans(traces)
		if len(spans) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(spans) != 1 {
		t.Fatalf("generated inspect spans=%d want=1", len(spans))
	}
	span := spans[0]
	if span.Name != "apply_guardrail inspect tool_call" ||
		span.Kind != tracepb.Span_SPAN_KIND_INTERNAL ||
		span.Status.GetCode() != tracepb.Status_STATUS_CODE_OK {
		t.Fatalf("generated inspect identity name=%q kind=%s status=%s", span.Name, span.Kind, span.Status.GetCode())
	}
	traceID, parentID := spanContext.TraceID(), spanContext.SpanID()
	if string(span.TraceId) != string(traceID[:]) || string(span.ParentSpanId) != string(parentID[:]) {
		t.Fatalf("generated inspect W3C trace=%x parent=%x want=%s/%s", span.TraceId, span.ParentSpanId, traceID, parentID)
	}
	attributes := inspectTraceV8ProtoAttributes(span.Attributes)
	for key, want := range map[string]string{
		"defenseclaw.span.family":                observability.TelemetryFamilyGuardrailApply,
		"defenseclaw.guardrail.name":             "inspect",
		"defenseclaw.guardrail.target_type":      "tool_call",
		"defenseclaw.guardrail.decision":         "block",
		"defenseclaw.guardrail.effective_action": "block",
		"defenseclaw.guardrail.mode":             "enforce",
		"defenseclaw.security.severity":          "HIGH",
		"defenseclaw.evaluation.id":              "evaluation-inspect-1",
		"gen_ai.agent.name":                      "root_agent",
		"defenseclaw.agent.root.id":              "agent-inspect-1",
		"defenseclaw.agent.lifecycle.id":         "lifecycle-inspect-1",
		"defenseclaw.agent.execution.id":         "execution-inspect-1",
		"defenseclaw.operation.id":               "operation-inspect-1",
		"defenseclaw.agent.phase":                "tool",
		"defenseclaw.agent.phase.previous":       "model",
		"defenseclaw.agent.sequence":             "7",
		"gen_ai.tool.name":                       "write_file",
		"gen_ai.tool.call.id":                    "tool-call-inspect-1",
		"defenseclaw.destination.app":            "mcp.example",
		"defenseclaw.guardrail.latency_ms":       "12.5",
		"defenseclaw.guardrail.finding_count":    "1",
	} {
		if got := attributes[key]; got != want {
			t.Errorf("generated inspect attribute %s=%q want=%q; attributes=%v", key, got, want, attributes)
		}
	}
}

func TestInspectTraceV8DirectionPreservesAllInspectSurfaces(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		targetType string
		want       string
	}{
		{targetType: "prompt", want: "input"},
		{targetType: "completion", want: "output"},
		{targetType: "tool_response", want: "tool"},
		{targetType: "tool_call", want: "tool"},
	} {
		test := test
		t.Run(test.targetType, func(t *testing.T) {
			t.Parallel()
			if got := inspectTraceV8Direction(test.targetType); got != test.want {
				t.Fatalf("inspect direction=%q want=%q", got, test.want)
			}
		})
	}
}

func TestInspectTraceV8AgentNameDoesNotFabricateIdentity(t *testing.T) {
	t.Parallel()
	if got := inspectTraceV8AgentName("  "); got.IsPresent() {
		t.Fatalf("empty source agent name became present: %+v", got)
	}
	got := inspectTraceV8AgentName("Root Agent")
	value, present := got.Get()
	if !present || value != "root_agent" {
		t.Fatalf("normalized agent name=%+v want=root_agent", got)
	}

	input, ok := (&APIServer{}).inspectTraceV8Input(
		context.Background(), "", "prompt",
		&ToolInspectVerdict{Action: "allow", Severity: "NONE"}, time.Millisecond,
		hookEvaluationContext{},
	)
	if !ok {
		t.Fatal("identity-free inspect input was rejected")
	}
	for name, optional := range map[string]observability.Optional[string]{
		"agent name": input.GenAIAgentName, "root agent": input.DefenseClawAgentRootID,
		"parent agent": input.DefenseClawAgentParentID,
		"lifecycle":    input.DefenseClawAgentLifecycleID,
		"execution":    input.DefenseClawAgentExecutionID,
	} {
		if optional.IsPresent() {
			t.Errorf("identity-free inspect fabricated %s: %+v", name, optional)
		}
	}
	if input.DefenseClawAgentDepth.IsPresent() {
		t.Errorf("identity-free inspect fabricated agent depth: %+v", input.DefenseClawAgentDepth)
	}
}

func inspectTraceV8ProtoAttributes(values []*commonpb.KeyValue) map[string]string {
	result := make(map[string]string, len(values))
	for _, value := range values {
		if value == nil || value.Value == nil {
			continue
		}
		switch item := value.Value.Value.(type) {
		case *commonpb.AnyValue_StringValue:
			result[value.Key] = item.StringValue
		case *commonpb.AnyValue_DoubleValue:
			result[value.Key] = strconv.FormatFloat(item.DoubleValue, 'f', -1, 64)
		case *commonpb.AnyValue_IntValue:
			result[value.Key] = strconv.FormatInt(item.IntValue, 10)
		case *commonpb.AnyValue_BoolValue:
			if item.BoolValue {
				result[value.Key] = "true"
			} else {
				result[value.Key] = "false"
			}
		}
	}
	return result
}
