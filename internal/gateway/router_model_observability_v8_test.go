// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"go.opentelemetry.io/otel/trace"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

func bindEventRouterModelV8Runtime(
	t *testing.T,
	signals []string,
) (*EventRouter, *hookModelV8OTLPCapture) {
	t.Helper()
	capture := &hookModelV8OTLPCapture{}
	server := httptest.NewServer(http.HandlerFunc(capture.handler))
	t.Cleanup(server.Close)
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	router := NewEventRouter(nil, fixture.store, fixture.logger, false)
	router.SetDefaultAgentName("openclaw")
	router.SetDefaultPolicyID("policy-model-1")
	fixture.sidecar.setEventRouter(router)
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(
		t.Context(), fixture.configPath,
		hookModelV8BootstrapRaw(fixture.dataDir, server.URL, signals),
	)
	if err != nil || !bound {
		t.Fatalf("bootstrap EventRouter model runtime bound=%t error=%v", bound, err)
	}
	return router, capture
}

func eventRouterAssistantMessagePayload(t *testing.T, sessionID, runID string) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"sessionKey": sessionID,
		"runId":      runID,
		"messageId":  "message-model-1",
		"messageSeq": 7,
		"message": map[string]any{
			"role": "assistant",
			"content": []map[string]any{
				{"type": "text", "text": "private model response"},
				{"type": "tool_use", "id": "tool-call-1", "name": "shell", "input": map[string]any{"command": "pwd"}},
			},
			"provider":   "openai",
			"model":      "gpt-5",
			"stopReason": "tool_use",
			"usage": map[string]any{
				"prompt_tokens": 23, "completion_tokens": 11,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func waitForEventRouterModelSpans(
	t *testing.T,
	capture *hookModelV8OTLPCapture,
	want int,
) []*tracepb.Span {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		spans := hookModelV8CapturedSpansFromCapture(capture)
		if len(spans) >= want {
			return spans
		}
		time.Sleep(10 * time.Millisecond)
	}
	return hookModelV8CapturedSpansFromCapture(capture)
}

func TestEventRouterModelV8SessionMessagePreservesContentMetricsAndW3CHierarchy(t *testing.T) {
	router, capture := bindEventRouterModelV8Runtime(t, []string{"traces", "metrics"})
	router.handleSessionMessage(EventFrame{
		Type: "event", Event: "session.message",
		Payload: eventRouterAssistantMessagePayload(t, "session-model-1", "run-model-1"),
	})

	spans := waitForEventRouterModelSpans(t, capture, 1)
	if len(spans) != 1 {
		t.Fatalf("model spans=%d want=1", len(spans))
	}
	model := spans[0]
	attributes := hookModelV8ProtoAttributes(model)
	for key, want := range map[string]string{
		"defenseclaw.span.family":       observability.TelemetryFamilyModelChat,
		"gen_ai.provider.name":          "openai",
		"gen_ai.request.model":          "gpt-5",
		"gen_ai.conversation.id":        "session-model-1",
		"defenseclaw.run.id":            "run-model-1",
		"defenseclaw.model.response.id": stableLLMEventID("response", "openclaw", "session-model-1", "message-model-1", "7"),
	} {
		if attributes[key] != want {
			t.Errorf("model attribute %s=%q want=%q", key, attributes[key], want)
		}
	}
	if !strings.Contains(attributes["gen_ai.output.messages"], "private model response") ||
		attributes["gen_ai.input.messages"] != "" ||
		!strings.Contains(attributes["defenseclaw.model.tool_call_count"], "1") {
		t.Fatalf("model content/tool attributes=%v", attributes)
	}
	if model.StartTimeUnixNano != model.EndTimeUnixNano {
		t.Fatalf("message-only model invented duration start=%d end=%d", model.StartTimeUnixNano, model.EndTimeUnixNano)
	}
	modelParent := trace.SpanContextFromContext(
		router.getToolParentCtx("session-model-1", "run-model-1"),
	)
	if !modelParent.IsValid() || modelParent.TraceID().String() != bytesToTraceID(model.TraceId) ||
		modelParent.SpanID().String() != bytesToSpanID(model.SpanId) {
		t.Fatalf("retained model parent=%s/%s span=%x/%x",
			modelParent.TraceID(), modelParent.SpanID(), model.TraceId, model.SpanId)
	}
	if trace.SpanContextFromContext(router.getToolParentCtx("another-session", "run-model-1")).IsValid() {
		t.Fatal("model context crossed session boundary")
	}

	routeEventRouterToolCall(t, router, ToolCallPayload{
		Tool: "shell", ID: "tool-call-1", SessionID: "session-model-1", RunID: "run-model-1",
		Args: json.RawMessage(`{"command":"pwd"}`),
	})
	zero := 0
	routeEventRouterToolResult(t, router, ToolResultPayload{
		Tool: "shell", ID: "tool-call-1", SessionID: "session-model-1", RunID: "run-model-1",
		Output: "workspace", ExitCode: &zero,
	})
	spans = waitForEventRouterModelSpans(t, capture, 2)
	if len(spans) != 2 {
		t.Fatalf("model+tool spans=%d want=2", len(spans))
	}
	var tool *tracepb.Span
	for _, span := range spans {
		if gatewayProtoAttribute(span.Attributes, "defenseclaw.span.family") == observability.TelemetryFamilyToolExecute {
			tool = span
		}
	}
	if tool == nil || !bytes.Equal(tool.TraceId, model.TraceId) || !bytes.Equal(tool.ParentSpanId, model.SpanId) {
		t.Fatalf("tool did not preserve model W3C parent model=%x/%x tool=%+v", model.TraceId, model.SpanId, tool)
	}

	deadline := time.Now().Add(3 * time.Second)
	var tokenPoints []hookModelV8MetricPoint
	for time.Now().Before(deadline) {
		_, metricRequests := capture.snapshot()
		tokenPoints = hookModelV8MetricPoints(metricRequests, observability.TelemetryInstrumentGenAIClientTokenUsage)
		if len(tokenPoints) >= 2 {
			if hookModelV8MetricPointCount(metricRequests, observability.TelemetryInstrumentGenAIClientOperationDuration) != 0 {
				t.Fatal("zero-duration message model emitted a fabricated duration metric")
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	wantTokens := map[string]float64{"input": 23, "output": 11}
	if len(tokenPoints) != 2 {
		t.Fatalf("model token points=%+v want=2", tokenPoints)
	}
	for _, point := range tokenPoints {
		if point.value != wantTokens[point.attributes["gen_ai.token.type"]] ||
			point.attributes["gen_ai.provider.name"] != "openai" ||
			point.attributes["gen_ai.request.model"] != "gpt-5" {
			t.Errorf("model token point=%+v", point)
		}
		if _, leaked := point.attributes["gen_ai.conversation.id"]; leaked {
			t.Errorf("model token conversation identity leaked=%+v", point)
		}
	}
}

func TestEventRouterModelV8MetricsDoNotDependOnTraceCollection(t *testing.T) {
	router, capture := bindEventRouterModelV8Runtime(t, []string{"metrics"})
	router.handleSessionMessage(EventFrame{
		Type: "event", Event: "session.message",
		Payload: eventRouterAssistantMessagePayload(t, "session-metrics", "run-metrics"),
	})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		spans := hookModelV8CapturedSpansFromCapture(capture)
		_, metricRequests := capture.snapshot()
		if len(spans) != 0 {
			t.Fatalf("metrics-only destination received %d traces", len(spans))
		}
		if hookModelV8MetricPointCount(metricRequests, observability.TelemetryInstrumentGenAIClientTokenUsage) == 2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("metrics-only model operation did not export token metrics")
}

func bytesToTraceID(value []byte) string { return hex.EncodeToString(value) }
func bytesToSpanID(value []byte) string  { return hex.EncodeToString(value) }
