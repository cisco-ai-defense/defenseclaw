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

	// GAP-1452: the model operation is the child of an "invoke_agent openclaw"
	// root, so Galileo and Tempo can attribute the turn to OpenClaw.
	spans := waitForEventRouterModelSpans(t, capture, 2)
	if len(spans) != 2 {
		t.Fatalf("agent+model spans=%d want=2", len(spans))
	}
	var agent, model *tracepb.Span
	for _, span := range spans {
		switch gatewayProtoAttribute(span.Attributes, "defenseclaw.span.family") {
		case observability.TelemetryFamilyModelChat:
			model = span
		case observability.TelemetryFamilyAgentInvoke:
			agent = span
		}
	}
	if agent == nil || model == nil || agent.Name != "invoke_agent openclaw" ||
		!bytes.Equal(model.TraceId, agent.TraceId) || !bytes.Equal(model.ParentSpanId, agent.SpanId) {
		t.Fatalf("model is not the child of an invoke_agent openclaw root: agent=%+v model=%+v", agent, model)
	}
	if got := gatewayProtoAttribute(agent.Attributes, "gen_ai.conversation.id"); got != "session-model-1" {
		t.Fatalf("agent root conversation=%q", got)
	}
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
	spans = waitForEventRouterModelSpans(t, capture, 3)
	if len(spans) != 3 {
		t.Fatalf("agent+model+tool spans=%d want=3", len(spans))
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

func eventRouterSessionMessageFrame(t *testing.T, sessionID string, seq int, role string, content any) EventFrame {
	t.Helper()
	message := map[string]any{"role": role, "content": content}
	if role == "assistant" {
		message["provider"], message["model"], message["stopReason"] = "openai", "gpt-5", "stop"
	}
	payload, err := json.Marshal(map[string]any{
		"sessionKey": sessionID, "messageId": "message-" + intString(seq), "messageSeq": seq, "message": message,
	})
	if err != nil {
		t.Fatal(err)
	}
	return EventFrame{Type: "event", Event: "session.message", Payload: payload}
}

// TestEventRouterBlockedPromptTurnCarriesThePrompt pins GAP-2408: the turn
// of an OpenClaw prompt the proxy blocked names that prompt as the input of
// its invoke_agent and chat spans, so Galileo shows which prompt was blocked
// and not only the block text. A later message of the session that answers
// something else does not repeat it.
func TestEventRouterBlockedPromptTurnCarriesThePrompt(t *testing.T) {
	openClawPromptBlocks.mu.Lock()
	openClawPromptBlocks.entries = nil
	openClawPromptBlocks.mu.Unlock()
	t.Cleanup(func() {
		openClawPromptBlocks.mu.Lock()
		openClawPromptBlocks.entries = nil
		openClawPromptBlocks.mu.Unlock()
	})
	router, capture := bindEventRouterModelV8Runtime(t, []string{"traces"})
	const prompt = "Reply with one word: ok. Reference dccert-prompt-marker"
	block := blockMessage("", "prompt", "matched: R9-PROMPT-MARKER:marker")
	rememberOpenClawPromptBlock(block, AgentIdentity{UserName: "dcr-oc9a"},
		&ScanVerdict{Action: "block", Severity: "HIGH", RuleIDs: []string{"R9-PROMPT-MARKER"}})

	router.handleSessionMessage(eventRouterSessionMessageFrame(t, "session-block", 1, "user",
		[]map[string]any{{"type": "text", "text": prompt}}))
	router.handleSessionMessage(eventRouterSessionMessageFrame(t, "session-block", 2, "assistant",
		[]map[string]any{{"type": "text", "text": block}}))
	router.handleSessionMessage(eventRouterSessionMessageFrame(t, "session-block", 3, "assistant",
		[]map[string]any{{"type": "text", "text": "later reply"}}))

	spans := waitForEventRouterModelSpans(t, capture, 4)
	if len(spans) != 4 {
		t.Fatalf("spans=%d want=4 (two agent+chat turns)", len(spans))
	}
	laterTrace := ""
	for _, span := range spans {
		if strings.Contains(hookModelV8ProtoAttributes(span)["gen_ai.output.messages"], "later reply") {
			laterTrace = bytesToTraceID(span.TraceId)
		}
	}
	withPrompt := map[string]int{}
	for _, span := range spans {
		attributes := hookModelV8ProtoAttributes(span)
		family := attributes["defenseclaw.span.family"]
		input := attributes["gen_ai.input.messages"]
		if bytesToTraceID(span.TraceId) == laterTrace {
			if input != "" {
				t.Errorf("%s of the later turn repeats an input: %s", family, input)
			}
			continue
		}
		if !strings.Contains(input, prompt) {
			t.Errorf("%s of the blocked turn has input %q, want the prompt", family, input)
			continue
		}
		if attributes["defenseclaw.outcome"] != string(observability.OutcomeBlocked) {
			t.Errorf("%s outcome=%q want blocked", family, attributes["defenseclaw.outcome"])
		}
		// GAP-2332: the blocked turn names the rule, as a tool span does.
		if attributes["defenseclaw.guardrail.action"] != "block" ||
			attributes["defenseclaw.guardrail.rule_id"] != "R9-PROMPT-MARKER" ||
			attributes["defenseclaw.guardrail.severity"] != "HIGH" {
			t.Errorf("%s guardrail=%q/%q/%q want block/R9-PROMPT-MARKER/HIGH", family,
				attributes["defenseclaw.guardrail.action"], attributes["defenseclaw.guardrail.rule_id"],
				attributes["defenseclaw.guardrail.severity"])
		}
		withPrompt[family]++
	}
	if withPrompt[observability.TelemetryFamilyAgentInvoke] != 1 || withPrompt[observability.TelemetryFamilyModelChat] != 1 {
		t.Fatalf("spans with the blocked prompt=%v, want one agent and one chat", withPrompt)
	}
}
