// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

func richHookToolV8Meta() llmEventMeta {
	meta := richHookModelV8Meta()
	meta.ToolID = "tool-call-1"
	meta.ToolName = "shell"
	meta.Phase = "tool"
	meta.PreviousPhase = "model"
	meta.OperationID = "operation-tool-1"
	meta.Sequence = 8
	return meta
}

func emitRichHookToolV8(t *testing.T, api *APIServer, exitCode int) {
	t.Helper()
	meta := richHookToolV8Meta()
	arguments := `{"command":"printf","email":"private.person@example.com"}`
	api.rememberHookToolInvocation(meta, "shell", arguments)
	api.emitHookToolSpan(t.Context(), meta, "shell", arguments,
		`{"stdout":"private.person@example.com"}`, &exitCode)
}

func TestHookToolV8EmitsGeneratedAgentToolHierarchyAndMetrics(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"traces", "metrics"})
	emitRichHookToolV8(t, api, 0)

	var spans []*tracepb.Span
	metricNames := map[string]struct{}{}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		traceRequests, metricRequests := capture.snapshot()
		spans = hookModelV8CapturedSpans(traceRequests)
		metricNames = hookModelV8CapturedMetricNames(metricRequests)
		if len(spans) == 2 && len(metricNames) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(spans) != 2 {
		t.Fatalf("captured spans=%d want generated agent+tool", len(spans))
	}
	var agent, tool *tracepb.Span
	for _, span := range spans {
		switch gatewayProtoAttribute(span.Attributes, "defenseclaw.span.family") {
		case observability.TelemetryFamilyAgentInvoke:
			agent = span
		case observability.TelemetryFamilyToolExecute:
			tool = span
		}
	}
	if agent == nil || tool == nil || tool.Name != "execute_tool shell" ||
		!bytes.Equal(agent.TraceId, tool.TraceId) || !bytes.Equal(agent.SpanId, tool.ParentSpanId) {
		t.Fatalf("generated hook tool hierarchy agent=%+v tool=%+v", agent, tool)
	}
	attributes := hookModelV8ProtoAttributes(tool)
	for key, want := range map[string]string{
		"gen_ai.tool.name": "shell", "gen_ai.tool.call.id": "tool-call-1",
		"gen_ai.conversation.id": "session-1", "gen_ai.agent.id": "agent-child",
		"defenseclaw.agent.root.id": "agent-root", "defenseclaw.agent.parent.id": "agent-root",
		"defenseclaw.agent.lifecycle.id": "lifecycle-1", "defenseclaw.agent.execution.id": "execution-1",
		"defenseclaw.tool.status": "completed", "defenseclaw.tool.provider": "hook",
	} {
		if got := attributes[key]; got != want {
			t.Errorf("tool attribute %s=%q want %q", key, got, want)
		}
	}
	if !strings.Contains(attributes["gen_ai.tool.call.arguments"], "private.person@example.com") ||
		!strings.Contains(attributes["gen_ai.tool.call.result"], "private.person@example.com") {
		t.Fatalf("default-unredacted tool content arguments=%q result=%q",
			attributes["gen_ai.tool.call.arguments"], attributes["gen_ai.tool.call.result"])
	}
	for _, name := range []string{
		observability.TelemetryInstrumentDefenseClawToolCalls,
		observability.TelemetryInstrumentDefenseClawToolDuration,
	} {
		if _, ok := metricNames[name]; !ok {
			t.Errorf("generated tool metric %q missing from %v", name, sortedHookModelV8Keys(metricNames))
		}
	}
	_, metricRequests := capture.snapshot()
	if got := hookModelV8MetricPointCount(metricRequests, observability.TelemetryInstrumentDefenseClawToolCalls); got != 1 {
		t.Errorf("tool call points=%d want=1", got)
	}
	if got := hookModelV8MetricPointCount(metricRequests, observability.TelemetryInstrumentDefenseClawToolDuration); got != 1 {
		t.Errorf("tool duration points=%d want=1", got)
	}

	// Without an exact profile-declared receipt, same-content completions remain
	// separate raw observations. The durable occurrence coordinator, not this
	// emitter, owns exact replay suppression.
	meta := richHookToolV8Meta()
	exitCode := 0
	api.emitHookToolSpan(t.Context(), meta, "shell", `{"command":"printf"}`,
		`{"stdout":"private.person@example.com"}`, &exitCode)
	time.Sleep(50 * time.Millisecond)
	traceRequests, _ := capture.snapshot()
	if got := len(hookModelV8CapturedSpans(traceRequests)); got != 4 {
		t.Fatalf("same-content completion emitted %d spans, want two independent agent+tool observations", got)
	}
}

func TestHookToolV8FailureAndMetricsRemainSourceBacked(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"traces", "metrics"})
	emitRichHookToolV8(t, api, 17)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		traceRequests, metricRequests := capture.snapshot()
		if len(hookModelV8CapturedSpans(traceRequests)) == 2 &&
			hookModelV8MetricPointCount(metricRequests, observability.TelemetryInstrumentDefenseClawToolErrors) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	traceRequests, metricRequests := capture.snapshot()
	var tool *tracepb.Span
	for _, candidate := range hookModelV8CapturedSpans(traceRequests) {
		if gatewayProtoAttribute(candidate.Attributes, "defenseclaw.span.family") == observability.TelemetryFamilyToolExecute {
			tool = candidate
		}
	}
	if tool == nil || tool.Status.GetCode() != tracepb.Status_STATUS_CODE_ERROR {
		t.Fatalf("failed tool span=%+v", tool)
	}
	attributes := hookModelV8ProtoAttributes(tool)
	if hookToolV8ProtoInt64(tool, "defenseclaw.tool.exit_code") != 17 ||
		attributes["defenseclaw.tool.status"] != "failed" || attributes["error.type"] != "nonzero_exit" {
		t.Fatalf("failed tool attributes=%v", attributes)
	}
	points := hookModelV8MetricPoints(metricRequests, observability.TelemetryInstrumentDefenseClawToolErrors)
	if len(points) != 1 || points[0].value != 1 || points[0].attributes["defenseclaw.tool.exit_code"] != "17" {
		t.Fatalf("tool error points=%+v", points)
	}
}

func TestHookToolV8EmitsCompletionWhenOutputIsNotReported(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"traces", "metrics"})
	meta := richHookToolV8Meta()
	arguments := `{"command":"printf"}`
	api.rememberHookToolInvocation(meta, "shell", arguments)
	api.emitHookToolSpan(t.Context(), meta, "shell", arguments, "", nil)

	var spans []*tracepb.Span
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		traceRequests, metricRequests := capture.snapshot()
		spans = hookModelV8CapturedSpans(traceRequests)
		if len(spans) == 2 &&
			hookModelV8MetricPointCount(
				metricRequests,
				observability.TelemetryInstrumentDefenseClawToolCalls,
			) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, metricRequests := capture.snapshot()
	if got := hookModelV8MetricPointCount(
		metricRequests,
		observability.TelemetryInstrumentDefenseClawToolCalls,
	); got != 1 {
		t.Fatalf("tool call points=%d want=1", got)
	}

	var tool *tracepb.Span
	for _, candidate := range spans {
		if gatewayProtoAttribute(
			candidate.Attributes,
			"defenseclaw.span.family",
		) == observability.TelemetryFamilyToolExecute {
			tool = candidate
		}
	}
	if tool == nil {
		t.Fatalf("tool completion without output emitted spans=%d, want generated tool span", len(spans))
	}
	attributes := hookModelV8ProtoAttributes(tool)
	outputReported := true
	outputReportedPresent := false
	for _, item := range tool.Attributes {
		if item != nil && item.Key == "defenseclaw.telemetry.output.reported" && item.Value != nil {
			outputReported = item.Value.GetBoolValue()
			outputReportedPresent = true
		}
	}
	if !outputReportedPresent || outputReported {
		t.Errorf("output reported present=%t value=%t want present false", outputReportedPresent, outputReported)
	}
	if _, present := attributes["gen_ai.tool.call.result"]; present {
		t.Errorf("unreported output created a tool result: %q", attributes["gen_ai.tool.call.result"])
	}
	if _, present := attributes["defenseclaw.tool.output_length"]; present {
		t.Errorf("unreported output created an observed zero length: %q", attributes["defenseclaw.tool.output_length"])
	}
}

func TestHookToolV8CompletionLogSharesGeneratedTrace(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"logs", "traces"})
	meta := richHookToolV8Meta()
	arguments := `{"command":"printf"}`
	result := `{"stdout":"ok"}`
	api.rememberHookToolInvocation(meta, "shell", arguments)
	completionContext := api.emitHookToolSpan(t.Context(), meta, "shell", arguments, result, nil)
	api.emitHookToolLogV8(completionContext, meta, "result", "shell", arguments, result, nil)

	var tool *tracepb.Span
	var completedTraceID, completedSpanID []byte
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		traceRequests, _ := capture.snapshot()
		for _, span := range hookModelV8CapturedSpans(traceRequests) {
			if gatewayProtoAttribute(span.Attributes, "defenseclaw.span.family") == observability.TelemetryFamilyToolExecute {
				tool = span
			}
		}
		for _, record := range hookModelV8CapturedLogs(capture.logSnapshot()) {
			if logStringAttribute(record.Attributes, "defenseclaw.event.name") == observability.TelemetryEventToolInvocationCompleted {
				completedTraceID = record.GetTraceId()
				completedSpanID = record.GetSpanId()
			}
		}
		if tool != nil && len(completedTraceID) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if tool == nil || !bytes.Equal(completedTraceID, tool.TraceId) || !bytes.Equal(completedSpanID, tool.SpanId) {
		t.Fatalf("tool completion correlation trace=%x span=%x generated=%x/%x", completedTraceID, completedSpanID, tool.GetTraceId(), tool.GetSpanId())
	}
}

func TestHookToolV8EndFailureKeepsInboundCorrelationAndMetrics(t *testing.T) {
	tests := []struct {
		name         string
		failAgentEnd bool
		failToolEnd  bool
		rootTool     bool
	}{
		{name: "tool", failToolEnd: true, rootTool: true},
		{name: "agent", failAgentEnd: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			api, capture := bindHookModelV8Runtime(t, []string{"traces", "metrics"})
			baseRuntime := api.observabilityV8LifecycleRuntime()
			metricRuntime, ok := baseRuntime.(hookLifecycleMetricV8Runtime)
			if !ok {
				t.Fatalf("runtime %T does not expose generated metrics", baseRuntime)
			}
			failing := &hookGeneratedSpanEndFailureRuntime{
				lifecycleV8Runtime: baseRuntime,
				failAgentEnd:       test.failAgentEnd,
				failToolEnd:        test.failToolEnd,
			}
			meta := richHookToolV8Meta()
			if test.rootTool {
				meta.AgentID = ""
			}
			arguments := `{"command":"printf"}`
			snapshot := hookToolInvocation{
				meta: meta, tool: "shell", arguments: arguments,
				argumentsOriginalBytes: int64(len(arguments)),
				startedAt:              time.Now().UTC().Add(-time.Second),
			}
			observation := newHookToolV8Observation(
				snapshot, meta, "shell", arguments, `{"stdout":"ok"}`, nil,
			)
			inbound := t.Context()

			correlated := emitGeneratedToolSpanV8(
				inbound, failing, metricRuntime, observation,
			)

			if failing.injectionErr != nil {
				t.Fatalf("inject %s End failure: %v", test.name, failing.injectionErr)
			}
			if test.rootTool && failing.toolBlocker == nil {
				t.Fatal("tool End failure was not injected")
			}
			if test.failAgentEnd && failing.agentBlocker == nil {
				t.Fatal("agent End failure was not injected")
			}
			if correlated != inbound {
				t.Fatalf("failed %s End returned generated correlation instead of inbound context", test.name)
			}

			points := 0
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				_, metricRequests := capture.snapshot()
				points = hookModelV8MetricPointCount(
					metricRequests,
					observability.TelemetryInstrumentDefenseClawToolCalls,
				)
				if points == 1 {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if points != 1 {
				t.Fatalf("tool call metric points=%d want=1 after %s End failure", points, test.name)
			}
		})
	}
}

func hookToolV8ProtoInt64(span *tracepb.Span, key string) int64 {
	if span == nil {
		return 0
	}
	for _, item := range span.Attributes {
		if item != nil && item.Key == key && item.Value != nil {
			return item.Value.GetIntValue()
		}
	}
	return 0
}

func TestHookToolV8MetricsRemainIndependentWithoutTraceExport(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"metrics"})
	emitRichHookToolV8(t, api, 0)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		traceRequests, metricRequests := capture.snapshot()
		if len(hookModelV8CapturedSpans(traceRequests)) != 0 {
			t.Fatal("metrics-only destination received a tool trace")
		}
		if hookModelV8MetricPointCount(metricRequests, observability.TelemetryInstrumentDefenseClawToolCalls) == 1 &&
			hookModelV8MetricPointCount(metricRequests, observability.TelemetryInstrumentDefenseClawToolDuration) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, metricRequests := capture.snapshot()
	if hookModelV8MetricPointCount(metricRequests, observability.TelemetryInstrumentDefenseClawToolCalls) != 1 ||
		hookModelV8MetricPointCount(metricRequests, observability.TelemetryInstrumentDefenseClawToolDuration) != 1 {
		t.Fatalf("metrics-only tool points calls=%d duration=%d",
			hookModelV8MetricPointCount(metricRequests, observability.TelemetryInstrumentDefenseClawToolCalls),
			hookModelV8MetricPointCount(metricRequests, observability.TelemetryInstrumentDefenseClawToolDuration))
	}
}

func TestHookToolV8UsesCentralDestinationRedaction(t *testing.T) {
	rawCapture := &hookModelV8OTLPCapture{}
	rawServer := httptest.NewServer(http.HandlerFunc(rawCapture.handler))
	t.Cleanup(rawServer.Close)
	strictCapture := &hookModelV8OTLPCapture{}
	strictServer := httptest.NewServer(http.HandlerFunc(strictCapture.handler))
	t.Cleanup(strictServer.Close)
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	api := &APIServer{}
	fixture.sidecar.setAPIServer(api)
	raw := []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\nobservability:\n  buckets:\n    agent.lifecycle:\n      collect: {logs: true, traces: true, metrics: true}\n    tool.activity:\n      collect: {logs: true, traces: true, metrics: true}\n  destinations:\n    - name: raw-otlp\n      kind: otlp\n      endpoint: %q\n      protocol: http/protobuf\n      tls: {insecure: true}\n      network_safety: {allow_private_networks: true}\n      batch: {max_export_batch_size: 8, scheduled_delay_ms: 10}\n      send: {signals: [traces], buckets: ['*'], redaction_profile: none}\n    - name: strict-otlp\n      kind: otlp\n      endpoint: %q\n      protocol: http/protobuf\n      tls: {insecure: true}\n      network_safety: {allow_private_networks: true}\n      batch: {max_export_batch_size: 8, scheduled_delay_ms: 10}\n      send: {signals: [traces], buckets: ['*'], redaction_profile: strict}\n",
		fixture.dataDir, rawServer.URL, strictServer.URL,
	))
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, raw)
	if err != nil || !bound {
		t.Fatalf("bootstrap tool redaction runtime bound=%t error=%v", bound, err)
	}
	emitRichHookToolV8(t, api, 0)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(hookModelV8CapturedSpansFromCapture(rawCapture)) == 2 &&
			len(hookModelV8CapturedSpansFromCapture(strictCapture)) == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	const secret = "private.person@example.com"
	if !bytes.Contains(rawCapture.traceBytes(), []byte(secret)) {
		t.Fatal("tool redaction_profile none did not preserve default-unredacted content")
	}
	if bytes.Contains(strictCapture.traceBytes(), []byte(secret)) {
		t.Fatal("strict destination leaked raw tool content")
	}
}

func TestHookToolV8StructuredFallbackPreservesReportedFacts(t *testing.T) {
	arguments, reported, state, originalBytes, mimeType := hookToolV8Arguments(
		strings.Repeat("x", 5000), 5000, false,
	)
	if !reported || state != "truncated" || originalBytes != 5000 || mimeType != "text/plain" {
		t.Fatalf("arguments reported=%t state=%q bytes=%d mime=%q", reported, state, originalBytes, mimeType)
	}
	if err := observability.ValidateTelemetryStructuredGenAIToolCallArguments(arguments); err != nil {
		t.Fatalf("bounded raw arguments: %v", err)
	}
	result, reported, state, originalBytes, mimeType := hookToolV8Result(`{"ok":true,"count":2}`)
	if !reported || state != "preserved" || originalBytes == 0 || mimeType != "application/json" {
		t.Fatalf("result reported=%t state=%q bytes=%d mime=%q", reported, state, originalBytes, mimeType)
	}
	if err := observability.ValidateTelemetryStructuredGenAIToolCallResult(result); err != nil {
		t.Fatalf("structured result: %v", err)
	}
}
