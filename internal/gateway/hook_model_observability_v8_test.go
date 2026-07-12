// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	oteltrace "go.opentelemetry.io/otel/trace"
	collectorlogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type hookModelV8OTLPCapture struct {
	mu        sync.Mutex
	logs      []*collectorlogspb.ExportLogsServiceRequest
	traces    []*collectortracepb.ExportTraceServiceRequest
	metrics   []*collectormetricspb.ExportMetricsServiceRequest
	rawTraces [][]byte
}

type hookModelV8DeclineRuntime struct {
	agentAttempted bool
	agentSampled   bool
	modelStarts    int
}

// hookGeneratedSpanEndFailureRuntime injects a live generated child so the
// producer's End call fails with children_active and the runtime aborts the
// hierarchy. Transition spans have no child seam, so that path is explicitly
// aborted before the producer attempts End.
type hookGeneratedSpanEndFailureRuntime struct {
	lifecycleV8Runtime
	failTransitionEnd bool
	failAgentEnd      bool
	failModelEnd      bool
	failToolEnd       bool

	transitionAborted bool
	agentBlocker      *observabilityruntime.ApprovalTrace
	modelBlocker      *observabilityruntime.ToolTrace
	toolBlocker       *observabilityruntime.ApprovalTrace
	injectionErr      error
}

func (runtime *hookGeneratedSpanEndFailureRuntime) StartAgentTrace(
	ctx context.Context,
	input observability.SpanAgentInvokeInput,
) (context.Context, *observabilityruntime.AgentTrace, error) {
	started, span, err := runtime.lifecycleV8Runtime.StartAgentTrace(ctx, input)
	if err == nil && span != nil && runtime.failAgentEnd {
		runtime.agentBlocker, runtime.injectionErr = span.StartApproval(
			observability.SpanApprovalResolveInput{
				Kind:              "INTERNAL",
				StartTimeUnixNano: input.StartTimeUnixNano,
			},
		)
	}
	return started, span, err
}

func (runtime *hookGeneratedSpanEndFailureRuntime) StartAgentTransitionTrace(
	ctx context.Context,
	input observability.SpanAgentTransitionInput,
) (context.Context, *observabilityruntime.AgentTransitionTrace, error) {
	started, span, err := runtime.lifecycleV8Runtime.StartAgentTransitionTrace(ctx, input)
	if err == nil && span != nil && runtime.failTransitionEnd {
		span.Abort()
		runtime.transitionAborted = true
	}
	return started, span, err
}

func (runtime *hookGeneratedSpanEndFailureRuntime) StartModelTrace(
	ctx context.Context,
	input observability.SpanModelChatInput,
) (context.Context, *observabilityruntime.ModelTrace, error) {
	started, span, err := runtime.lifecycleV8Runtime.StartModelTrace(ctx, input)
	if err == nil && span != nil && runtime.failModelEnd {
		runtime.modelBlocker, runtime.injectionErr = span.StartTool(
			observability.SpanToolExecuteInput{
				Kind:              "INTERNAL",
				StartTimeUnixNano: input.StartTimeUnixNano,
				GenAIToolName:     "end-failure-injection",
			},
		)
	}
	return started, span, err
}

func (runtime *hookGeneratedSpanEndFailureRuntime) StartToolTrace(
	ctx context.Context,
	input observability.SpanToolExecuteInput,
) (context.Context, *observabilityruntime.ToolTrace, error) {
	started, span, err := runtime.lifecycleV8Runtime.StartToolTrace(ctx, input)
	if err == nil && span != nil && runtime.failToolEnd {
		runtime.toolBlocker, runtime.injectionErr = span.StartApproval(
			observability.SpanApprovalResolveInput{
				Kind:              "INTERNAL",
				StartTimeUnixNano: input.StartTimeUnixNano,
			},
		)
	}
	return started, span, err
}

func (runtime *hookModelV8DeclineRuntime) StartAgentTrace(
	ctx context.Context,
	_ observability.SpanAgentInvokeInput,
) (context.Context, *observabilityruntime.AgentTrace, error) {
	if !runtime.agentAttempted {
		return ctx, nil, nil
	}
	config := oteltrace.SpanContextConfig{
		TraceID: oteltrace.TraceID{1}, SpanID: oteltrace.SpanID{2},
	}
	if runtime.agentSampled {
		config.TraceFlags = oteltrace.FlagsSampled
	}
	spanContext := oteltrace.NewSpanContext(config)
	return oteltrace.ContextWithSpanContext(ctx, spanContext), nil, nil
}

func (*hookModelV8DeclineRuntime) StartAgentTransitionTrace(
	ctx context.Context,
	_ observability.SpanAgentTransitionInput,
) (context.Context, *observabilityruntime.AgentTransitionTrace, error) {
	return ctx, nil, nil
}

func (runtime *hookModelV8DeclineRuntime) StartModelTrace(
	ctx context.Context,
	_ observability.SpanModelChatInput,
) (context.Context, *observabilityruntime.ModelTrace, error) {
	runtime.modelStarts++
	return ctx, nil, nil
}

func (*hookModelV8DeclineRuntime) StartToolTrace(
	ctx context.Context,
	_ observability.SpanToolExecuteInput,
) (context.Context, *observabilityruntime.ToolTrace, error) {
	return ctx, nil, nil
}

func (*hookModelV8DeclineRuntime) StartApprovalTrace(
	ctx context.Context,
	_ observability.SpanApprovalResolveInput,
) (context.Context, *observabilityruntime.ApprovalTrace, error) {
	return ctx, nil, nil
}

func (capture *hookModelV8OTLPCapture) handler(writer http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		http.Error(writer, "read", http.StatusBadRequest)
		return
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	switch request.URL.Path {
	case "/v1/logs":
		decoded := &collectorlogspb.ExportLogsServiceRequest{}
		if err := proto.Unmarshal(body, decoded); err != nil {
			http.Error(writer, "log protobuf", http.StatusBadRequest)
			return
		}
		capture.logs = append(capture.logs, decoded)
		response, _ := proto.Marshal(&collectorlogspb.ExportLogsServiceResponse{})
		writer.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = writer.Write(response)
	case "/v1/traces":
		decoded := &collectortracepb.ExportTraceServiceRequest{}
		if err := proto.Unmarshal(body, decoded); err != nil {
			http.Error(writer, "trace protobuf", http.StatusBadRequest)
			return
		}
		capture.traces = append(capture.traces, decoded)
		capture.rawTraces = append(capture.rawTraces, append([]byte(nil), body...))
		response, _ := proto.Marshal(&collectortracepb.ExportTraceServiceResponse{})
		writer.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = writer.Write(response)
	case "/v1/metrics":
		decoded := &collectormetricspb.ExportMetricsServiceRequest{}
		if err := proto.Unmarshal(body, decoded); err != nil {
			http.Error(writer, "metric protobuf", http.StatusBadRequest)
			return
		}
		capture.metrics = append(capture.metrics, decoded)
		response, _ := proto.Marshal(&collectormetricspb.ExportMetricsServiceResponse{})
		writer.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = writer.Write(response)
	default:
		http.NotFound(writer, request)
	}
}

func (capture *hookModelV8OTLPCapture) logSnapshot() []*collectorlogspb.ExportLogsServiceRequest {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]*collectorlogspb.ExportLogsServiceRequest(nil), capture.logs...)
}

func (capture *hookModelV8OTLPCapture) traceBytes() []byte {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return bytes.Join(append([][]byte(nil), capture.rawTraces...), nil)
}

func (capture *hookModelV8OTLPCapture) snapshot() (
	[]*collectortracepb.ExportTraceServiceRequest,
	[]*collectormetricspb.ExportMetricsServiceRequest,
) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]*collectortracepb.ExportTraceServiceRequest(nil), capture.traces...),
		append([]*collectormetricspb.ExportMetricsServiceRequest(nil), capture.metrics...)
}

func hookModelV8BootstrapRaw(dataDir, endpoint string, signals []string) []byte {
	return []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\nobservability:\n  metric_policy:\n    export_interval_seconds: 1\n  buckets:\n    agent.lifecycle:\n      collect: {logs: true, traces: true, metrics: true}\n    compliance.activity:\n      collect: {logs: true, traces: true, metrics: true}\n    guardrail.evaluation:\n      collect: {logs: true, traces: true, metrics: true}\n    model.io:\n      collect: {logs: true, traces: true, metrics: true}\n    platform.health:\n      collect: {logs: true, traces: true, metrics: true}\n    tool.activity:\n      collect: {logs: true, traces: true, metrics: true}\n  destinations:\n    - name: hook-otlp\n      kind: otlp\n      endpoint: %q\n      protocol: http/protobuf\n      tls:\n        insecure: true\n      network_safety:\n        allow_private_networks: true\n      batch:\n        max_export_batch_size: 16\n        scheduled_delay_ms: 10\n      send:\n        signals: [%s]\n        buckets: ['*']\n",
		dataDir, endpoint, strings.Join(signals, ", "),
	))
}

func richHookModelV8Meta() llmEventMeta {
	return llmEventMeta{
		Source: "codex", Provider: "openai", Model: "gpt-5", SessionID: "session-1",
		RequestID: "request-1", RunID: "run-1", TurnID: "turn-1",
		PromptID: "prompt-1", ResponseID: "response-1",
		AgentID: "agent-child", AgentName: "Child/Agent", AgentType: "subagent",
		RootAgentID: "agent-root", ParentAgentID: "agent-root", LineageProvenance: "reported",
		RootSessionID: "session-1", LifecycleID: "lifecycle-1", ExecutionID: "execution-1",
		LifecycleEvent: "turn_end", LifecycleState: "completed", Phase: "model",
		PreviousPhase: "planning", OperationID: "operation-1", Sequence: 7, AgentDepth: 1,
		FinishReasons: []string{"stop"},
	}
}

func bindHookModelV8Runtime(t *testing.T, signals []string) (*APIServer, *hookModelV8OTLPCapture) {
	t.Helper()
	capture := &hookModelV8OTLPCapture{}
	server := httptest.NewServer(http.HandlerFunc(capture.handler))
	t.Cleanup(server.Close)
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	api := &APIServer{}
	fixture.sidecar.setAPIServer(api)
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(
		t.Context(), fixture.configPath,
		hookModelV8BootstrapRaw(fixture.dataDir, server.URL, signals),
	)
	if err != nil || !bound || api.observabilityV8RuntimeEmitter() == nil ||
		api.observabilityV8LifecycleRuntime() == nil {
		t.Fatalf("bootstrap hook model runtime bound=%t emitter=%T lifecycle=%T error=%v",
			bound, api.observabilityV8RuntimeEmitter(), api.observabilityV8LifecycleRuntime(), err)
	}
	return api, capture
}

func emitRichHookModelV8(t *testing.T, api *APIServer) {
	t.Helper()
	meta := richHookModelV8Meta()
	api.rememberHookLLMSpanPrompt(meta, "private prompt marker")
	api.rememberHookLLMSpanUsage(meta, hookTokenUsage{
		Model: "gpt-5", PromptTokens: 321, CompletionTokens: 45,
	})
	api.emitHookLLMSpan(t.Context(), meta, "private response marker")
}

func TestHookModelV8EmitsGeneratedAgentModelHierarchyAndAllLegacyMetrics(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"traces", "metrics"})
	emitRichHookModelV8(t, api)

	var spans []*tracepb.Span
	metricNames := make(map[string]struct{})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		traceRequests, metricRequests := capture.snapshot()
		spans = hookModelV8CapturedSpans(traceRequests)
		metricNames = hookModelV8CapturedMetricNames(metricRequests)
		if len(spans) == 2 && len(metricNames) >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(spans) != 2 {
		t.Fatalf("captured spans=%d want generated agent+model", len(spans))
	}
	var agent, model *tracepb.Span
	for _, span := range spans {
		switch gatewayProtoAttribute(span.Attributes, "defenseclaw.span.family") {
		case observability.TelemetryFamilyAgentInvoke:
			agent = span
		case observability.TelemetryFamilyModelChat:
			model = span
		}
	}
	if agent == nil || model == nil || agent.Name != "invoke_agent subagent" || model.Name != "chat gpt-5" ||
		!bytes.Equal(agent.TraceId, model.TraceId) || !bytes.Equal(agent.SpanId, model.ParentSpanId) {
		t.Fatalf("generated hook hierarchy agent=%+v model=%+v", agent, model)
	}
	modelAttributes := hookModelV8ProtoAttributes(model)
	for key, want := range map[string]string{
		"gen_ai.provider.name": "openai", "gen_ai.request.model": "gpt-5",
		"gen_ai.conversation.id": "session-1", "gen_ai.agent.id": "agent-child",
		"defenseclaw.agent.root.id": "agent-root", "defenseclaw.agent.parent.id": "agent-root",
		"defenseclaw.agent.lifecycle.id": "lifecycle-1", "defenseclaw.agent.execution.id": "execution-1",
	} {
		if got := modelAttributes[key]; got != want {
			t.Errorf("model attribute %s=%q want %q", key, got, want)
		}
	}
	if !strings.Contains(modelAttributes["gen_ai.input.messages"], "private prompt marker") ||
		!strings.Contains(modelAttributes["gen_ai.output.messages"], "private response marker") {
		t.Fatalf("default unredacted model content input=%q output=%q",
			modelAttributes["gen_ai.input.messages"], modelAttributes["gen_ai.output.messages"])
	}
	for _, name := range []string{
		observability.TelemetryInstrumentDefenseClawAgentTokenUsage,
		observability.TelemetryInstrumentGenAIClientTokenUsage,
		observability.TelemetryInstrumentGenAIClientOperationDuration,
	} {
		if _, ok := metricNames[name]; !ok {
			t.Errorf("generated metric %q was not exported; got %v", name, sortedHookModelV8Keys(metricNames))
		}
	}
	_, metricRequests := capture.snapshot()
	for name, want := range map[string]int{
		observability.TelemetryInstrumentDefenseClawAgentTokenUsage:   2,
		observability.TelemetryInstrumentGenAIClientTokenUsage:        2,
		observability.TelemetryInstrumentGenAIClientOperationDuration: 1,
	} {
		if got := hookModelV8MetricPointCount(metricRequests, name); got != want {
			t.Errorf("generated metric %q points=%d want=%d", name, got, want)
		}
	}
	genericPoints := hookModelV8MetricPoints(metricRequests, observability.TelemetryInstrumentGenAIClientTokenUsage)
	if len(genericPoints) != 2 {
		t.Fatalf("generic token points=%d", len(genericPoints))
	}
	wantTokenValues := map[string]float64{"input": 321, "output": 45}
	for _, point := range genericPoints {
		if point.attributes["gen_ai.agent.name"] != "Child/Agent" ||
			point.attributes["gen_ai.agent.id"] != "agent-child" ||
			point.attributes["gen_ai.conversation.id"] != "session-1" {
			t.Errorf("generic token identity=%v", point.attributes)
		}
		kind := point.attributes["gen_ai.token.type"]
		if point.value != wantTokenValues[kind] {
			t.Errorf("generic token %q value=%v want=%v", kind, point.value, wantTokenValues[kind])
		}
	}
	agentPoints := hookModelV8MetricPoints(metricRequests, observability.TelemetryInstrumentDefenseClawAgentTokenUsage)
	for _, point := range agentPoints {
		if point.attributes["gen_ai.agent.name"] != "child_agent" {
			t.Errorf("Agent360 normalized name=%q want child_agent", point.attributes["gen_ai.agent.name"])
		}
	}

	// Completion retries are deduplicated before any generated signal is built.
	emitRichHookModelV8(t, api)
	time.Sleep(50 * time.Millisecond)
	traceRequests, _ := capture.snapshot()
	if got := len(hookModelV8CapturedSpans(traceRequests)); got != 2 {
		t.Fatalf("duplicate completion emitted %d spans, want 2", got)
	}
}

func TestHookModelV8ResponseLogSharesGeneratedTrace(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"logs", "traces"})
	meta := richHookModelV8Meta()
	api.rememberHookLLMSpanPrompt(meta, "correlated prompt")
	completionContext := api.emitHookLLMSpan(t.Context(), meta, "correlated response")
	api.emitHookModelResponseLogV8(completionContext, meta, "correlated response", []string{"stop"})

	var model *tracepb.Span
	var responseTraceID, responseSpanID []byte
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		traceRequests, _ := capture.snapshot()
		for _, span := range hookModelV8CapturedSpans(traceRequests) {
			if gatewayProtoAttribute(span.Attributes, "defenseclaw.span.family") == observability.TelemetryFamilyModelChat {
				model = span
			}
		}
		for _, record := range hookModelV8CapturedLogs(capture.logSnapshot()) {
			if logStringAttribute(record.Attributes, "defenseclaw.event.name") == observability.TelemetryEventModelResponse {
				responseTraceID = record.GetTraceId()
				responseSpanID = record.GetSpanId()
			}
		}
		if model != nil && len(responseTraceID) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if model == nil || !bytes.Equal(responseTraceID, model.TraceId) || !bytes.Equal(responseSpanID, model.SpanId) {
		t.Fatalf("model response correlation trace=%x span=%x generated=%x/%x", responseTraceID, responseSpanID, model.GetTraceId(), model.GetSpanId())
	}
}

func TestHookModelV8EndFailureKeepsInboundCorrelationAndMetrics(t *testing.T) {
	tests := []struct {
		name         string
		failAgentEnd bool
		failModelEnd bool
		rootModel    bool
	}{
		{name: "model", failModelEnd: true, rootModel: true},
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
				failModelEnd:       test.failModelEnd,
			}
			meta := richHookModelV8Meta()
			if test.rootModel {
				meta.AgentID = ""
			}
			snapshot := hookLLMSpanPrompt{
				meta: meta, content: "prompt", originalBytes: 6,
				startedAt: time.Now().UTC().Add(-time.Second),
			}
			inbound := t.Context()

			correlated := api.emitHookLLMSpanV8(
				inbound, failing, metricRuntime, snapshot, meta, "response",
			)

			if failing.injectionErr != nil {
				t.Fatalf("inject %s End failure: %v", test.name, failing.injectionErr)
			}
			if test.failModelEnd && failing.modelBlocker == nil {
				t.Fatal("model End failure was not injected")
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
					observability.TelemetryInstrumentGenAIClientOperationDuration,
				)
				if points == 1 {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if points != 1 {
				t.Fatalf("model duration metric points=%d want=1 after %s End failure", points, test.name)
			}
		})
	}
}

func TestHookModelV8MetricsRemainIndependentWhenTraceCollectionIsUnavailable(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"metrics"})
	emitRichHookModelV8(t, api)
	deadline := time.Now().Add(3 * time.Second)
	metricNames := map[string]struct{}{}
	for time.Now().Before(deadline) {
		traceRequests, metricRequests := capture.snapshot()
		if len(hookModelV8CapturedSpans(traceRequests)) != 0 {
			t.Fatal("metrics-only destination received a trace")
		}
		metricNames = hookModelV8CapturedMetricNames(metricRequests)
		if len(metricNames) >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, name := range []string{
		observability.TelemetryInstrumentDefenseClawAgentTokenUsage,
		observability.TelemetryInstrumentGenAIClientTokenUsage,
		observability.TelemetryInstrumentGenAIClientOperationDuration,
	} {
		if _, ok := metricNames[name]; !ok {
			t.Errorf("metrics-only runtime omitted %q; got %v", name, sortedHookModelV8Keys(metricNames))
		}
	}
}

func TestHookModelV8InvalidOptionalAgentIdentityCannotSuppressGenericMetrics(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"metrics"})
	meta := richHookModelV8Meta()
	meta.AgentID = "agent id@example.com"
	meta.RootAgentID = "root id@example.com"
	meta.ParentAgentID = "parent id@example.com"
	meta.LifecycleID = "lifecycle id@example.com"
	meta.ExecutionID = "execution id@example.com"
	api.rememberHookLLMSpanPrompt(meta, "prompt")
	api.rememberHookLLMSpanUsage(meta, hookTokenUsage{Model: meta.Model, PromptTokens: 3, CompletionTokens: 2})
	api.emitHookLLMSpan(t.Context(), meta, "response")
	deadline := time.Now().Add(3 * time.Second)
	metricNames := map[string]struct{}{}
	for time.Now().Before(deadline) {
		_, requests := capture.snapshot()
		metricNames = hookModelV8CapturedMetricNames(requests)
		if len(metricNames) >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, name := range []string{
		observability.TelemetryInstrumentDefenseClawAgentTokenUsage,
		observability.TelemetryInstrumentGenAIClientTokenUsage,
		observability.TelemetryInstrumentGenAIClientOperationDuration,
	} {
		if _, ok := metricNames[name]; !ok {
			t.Errorf("invalid optional agent identity suppressed %q; got %v", name, sortedHookModelV8Keys(metricNames))
		}
	}
}

func TestHookModelV8StructuredContentSplitsAtContractLimitWithoutDataLoss(t *testing.T) {
	content := strings.Repeat("界", 5000)
	parts := hookModelV8TextParts(content)
	var joined strings.Builder
	for index, part := range parts {
		textPart, ok := part.(observability.TelemetryStructuredArmGenAIMessagePartText)
		if !ok {
			t.Fatalf("part %d type=%T", index, part)
		}
		if len(textPart.Value.Content) > 4096 || !strings.Contains(content, textPart.Value.Content) {
			t.Fatalf("part %d bytes=%d", index, len(textPart.Value.Content))
		}
		joined.WriteString(textPart.Value.Content)
	}
	if joined.String() != content {
		t.Fatalf("split content bytes=%d want=%d", joined.Len(), len(content))
	}
}

func TestHookModelV8SchemaIdentifiersAndMissingModelRemainTruthful(t *testing.T) {
	model := "Model/Region:" + strings.Repeat("X", 180)
	meta := richHookModelV8Meta()
	meta.Model = model
	meta.AgentID = "Agent/Child:One"
	meta.RootAgentID = "Agent/Root:One"
	meta.ParentAgentID = "Agent/Root:One"
	meta.LifecycleID = "Lifecycle/One"
	meta.ExecutionID = "Execution:One"
	observation := (&APIServer{}).hookModelV8Observation(hookLLMSpanPrompt{
		meta: meta, content: "prompt", originalBytes: 6, startedAt: time.Now().Add(-time.Second),
	}, meta, "response")
	if observation.model != model || !hookModelV8Identifier(observation.agentID) {
		t.Fatalf("schema-valid identities were narrowed: model=%q agent=%q", observation.model, observation.agentID)
	}
	if _, ok := hookModelV8AgentInput(observation); !ok {
		t.Fatal("schema-valid mixed-case/slash/colon agent hierarchy was rejected")
	}

	meta.Model = ""
	observation = (&APIServer{}).hookModelV8Observation(hookLLMSpanPrompt{
		meta: meta, content: "prompt", originalBytes: 6, startedAt: time.Now(),
	}, meta, "response")
	if observation.model != "" || observation.responseModel != "" {
		t.Fatalf("absent model was fabricated as request=%q response=%q", observation.model, observation.responseModel)
	}
}

func TestHookModelV8AgentSamplingDeclineDoesNotResurrectRootModel(t *testing.T) {
	meta := richHookModelV8Meta()
	snapshot := hookLLMSpanPrompt{meta: meta, content: "prompt", originalBytes: 6, startedAt: time.Now()}
	attempted := &hookModelV8DeclineRuntime{agentAttempted: true}
	correlated := (&APIServer{}).emitHookLLMSpanV8(t.Context(), attempted, nil, snapshot, meta, "response")
	if attempted.modelStarts != 0 {
		t.Fatalf("sampled/route-declined agent resurrected %d root model spans", attempted.modelStarts)
	}
	spanContext := oteltrace.SpanContextFromContext(correlated)
	if !spanContext.IsValid() || spanContext.IsSampled() {
		t.Fatalf("intentional sampling decline correlation=%v want valid unsampled context", spanContext)
	}

	disabled := &hookModelV8DeclineRuntime{}
	(&APIServer{}).emitHookLLMSpanV8(t.Context(), disabled, nil, snapshot, meta, "response")
	if disabled.modelStarts != 1 {
		t.Fatalf("agent bucket collection disablement started %d model roots, want 1", disabled.modelStarts)
	}

	routeExcluded := &hookModelV8DeclineRuntime{agentAttempted: true, agentSampled: true}
	(&APIServer{}).emitHookLLMSpanV8(t.Context(), routeExcluded, nil, snapshot, meta, "response")
	if routeExcluded.modelStarts != 1 {
		t.Fatalf("sampled agent excluded by routing started %d model roots, want 1", routeExcluded.modelStarts)
	}
}

func TestHookModelV8ContentFitsEncodedContractAndPreservesOriginalPromptFacts(t *testing.T) {
	api := &APIServer{}
	meta := richHookModelV8Meta()
	original := strings.Repeat("\x00\\\"界", 9000)
	api.rememberHookLLMSpanPrompt(meta, original)
	snapshot, ok := api.takeHookLLMSpanPrompt(meta, "response")
	if !ok {
		t.Fatal("cached prompt was unavailable")
	}
	message, originalBytes, reported, state, structured := hookModelV8InputMessages(
		snapshot.content, snapshot.originalBytes, snapshot.truncated,
	)
	if !reported || !structured || state != "truncated" || originalBytes != int64(len(original)) {
		t.Fatalf("prompt facts reported=%t structured=%t state=%q bytes=%d want=%d",
			reported, structured, state, originalBytes, len(original))
	}
	if err := observability.ValidateTelemetryStructuredGenAIInputMessages(message); err != nil {
		t.Fatalf("fitted generated prompt: %v", err)
	}
}

func TestHookModelV8FinishReasonIsSourceBacked(t *testing.T) {
	meta := richHookModelV8Meta()
	meta.FinishReasons = []string{"length"}
	observation := (&APIServer{}).hookModelV8Observation(hookLLMSpanPrompt{
		meta: meta, content: "prompt", originalBytes: 6, startedAt: time.Now(),
	}, meta, "response")
	input := hookModelV8ModelInput(observation)
	reasons, present := input.GenAIResponseFinishReasons.Get()
	if !present || len(reasons) != 1 || reasons[0] != "length" {
		t.Fatalf("reported finish reasons=%v present=%t", reasons, present)
	}
	output, present := input.GenAIOutputMessages.Get()
	finishReason, finishPresent := output.Items[0].FinishReason.Get()
	if !present || !finishPresent || finishReason != "length" {
		t.Fatalf("structured finish reason=%v present=%t", output.Items, present)
	}

	meta.FinishReasons = nil
	observation = (&APIServer{}).hookModelV8Observation(hookLLMSpanPrompt{
		meta: meta, content: "prompt", originalBytes: 6, startedAt: time.Now(),
	}, meta, "response")
	input = hookModelV8ModelInput(observation)
	if _, present := input.GenAIResponseFinishReasons.Get(); present {
		t.Fatal("missing finish reason was fabricated")
	}
	output, present = input.GenAIOutputMessages.Get()
	if !present || len(output.Items) != 1 {
		t.Fatal("missing finish reason erased the structured output")
	}
	if _, finishPresent = output.Items[0].FinishReason.Get(); finishPresent {
		t.Fatal("missing finish reason was fabricated in structured output")
	}
	if !input.DefenseClawTelemetryOutputReported || input.DefenseClawContentOutputState != "preserved" {
		t.Fatal("optional finish reason changed the observed response fact")
	}
}

func TestHookModelV8AppliesDestinationRedactionAfterGeneratedConstruction(t *testing.T) {
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
		"config_version: 8\ndata_dir: %q\nobservability:\n  buckets:\n    agent.lifecycle:\n      collect: {logs: true, traces: true, metrics: true}\n    model.io:\n      collect: {logs: true, traces: true, metrics: true}\n  destinations:\n    - name: raw-otlp\n      kind: otlp\n      endpoint: %q\n      protocol: http/protobuf\n      tls: {insecure: true}\n      network_safety: {allow_private_networks: true}\n      batch: {max_export_batch_size: 8, scheduled_delay_ms: 10}\n      send: {signals: [traces], buckets: ['*'], redaction_profile: none}\n    - name: strict-otlp\n      kind: otlp\n      endpoint: %q\n      protocol: http/protobuf\n      tls: {insecure: true}\n      network_safety: {allow_private_networks: true}\n      batch: {max_export_batch_size: 8, scheduled_delay_ms: 10}\n      send: {signals: [traces], buckets: ['*'], redaction_profile: strict}\n",
		fixture.dataDir, rawServer.URL, strictServer.URL,
	))
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, raw)
	if err != nil || !bound {
		t.Fatalf("bootstrap redaction runtime bound=%t error=%v", bound, err)
	}
	meta := richHookModelV8Meta()
	const secret = "private.person@example.com"
	api.rememberHookLLMSpanPrompt(meta, "contact "+secret)
	api.emitHookLLMSpan(t.Context(), meta, "response for "+secret)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(hookModelV8CapturedSpansFromCapture(rawCapture)) == 2 &&
			len(hookModelV8CapturedSpansFromCapture(strictCapture)) == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !bytes.Contains(rawCapture.traceBytes(), []byte(secret)) {
		t.Fatal("redaction_profile none did not preserve default-unredacted content")
	}
	if bytes.Contains(strictCapture.traceBytes(), []byte(secret)) {
		t.Fatal("strict destination leaked raw content")
	}
}

func hookModelV8CapturedSpansFromCapture(capture *hookModelV8OTLPCapture) []*tracepb.Span {
	requests, _ := capture.snapshot()
	return hookModelV8CapturedSpans(requests)
}

func hookModelV8CapturedSpans(requests []*collectortracepb.ExportTraceServiceRequest) []*tracepb.Span {
	var spans []*tracepb.Span
	for _, request := range requests {
		spans = append(spans, gatewayTraceRequestSpans(request)...)
	}
	return spans
}

func hookModelV8CapturedMetricNames(
	requests []*collectormetricspb.ExportMetricsServiceRequest,
) map[string]struct{} {
	names := make(map[string]struct{})
	for _, request := range requests {
		for _, resource := range request.GetResourceMetrics() {
			for _, scope := range resource.GetScopeMetrics() {
				for _, metric := range scope.GetMetrics() {
					if metric != nil {
						names[metric.Name] = struct{}{}
					}
				}
			}
		}
	}
	return names
}

func hookModelV8MetricPointCount(
	requests []*collectormetricspb.ExportMetricsServiceRequest,
	name string,
) int {
	count := 0
	for _, request := range requests {
		for _, resource := range request.GetResourceMetrics() {
			for _, scope := range resource.GetScopeMetrics() {
				for _, metric := range scope.GetMetrics() {
					if metric == nil || metric.Name != name {
						continue
					}
					switch data := metric.Data.(type) {
					case *metricspb.Metric_Sum:
						count += len(data.Sum.DataPoints)
					case *metricspb.Metric_Histogram:
						count += len(data.Histogram.DataPoints)
					}
				}
			}
		}
	}
	return count
}

type hookModelV8MetricPoint struct {
	attributes map[string]string
	value      float64
}

func hookModelV8MetricPoints(
	requests []*collectormetricspb.ExportMetricsServiceRequest,
	name string,
) []hookModelV8MetricPoint {
	var points []hookModelV8MetricPoint
	for _, request := range requests {
		for _, resource := range request.GetResourceMetrics() {
			for _, scope := range resource.GetScopeMetrics() {
				for _, metric := range scope.GetMetrics() {
					if metric == nil || metric.Name != name {
						continue
					}
					switch data := metric.Data.(type) {
					case *metricspb.Metric_Sum:
						for _, point := range data.Sum.DataPoints {
							points = append(points, hookModelV8MetricPoint{
								attributes: hookModelV8MetricAttributes(point.Attributes),
								value:      float64(point.GetAsInt()),
							})
						}
					case *metricspb.Metric_Histogram:
						for _, point := range data.Histogram.DataPoints {
							points = append(points, hookModelV8MetricPoint{
								attributes: hookModelV8MetricAttributes(point.Attributes),
								value:      point.GetSum(),
							})
						}
					}
				}
			}
		}
	}
	return points
}

func hookModelV8MetricAttributes(attributes []*commonpb.KeyValue) map[string]string {
	result := make(map[string]string, len(attributes))
	for _, item := range attributes {
		if item != nil && item.Value != nil {
			switch value := item.Value.Value.(type) {
			case *commonpb.AnyValue_StringValue:
				result[item.Key] = value.StringValue
			case *commonpb.AnyValue_IntValue:
				result[item.Key] = strconv.FormatInt(value.IntValue, 10)
			case *commonpb.AnyValue_BoolValue:
				result[item.Key] = strconv.FormatBool(value.BoolValue)
			}
		}
	}
	return result
}

func hookModelV8CapturedLogs(requests []*collectorlogspb.ExportLogsServiceRequest) []*logspb.LogRecord {
	var result []*logspb.LogRecord
	for _, request := range requests {
		for _, resource := range request.GetResourceLogs() {
			for _, scope := range resource.GetScopeLogs() {
				result = append(result, scope.GetLogRecords()...)
			}
		}
	}
	return result
}

func hookModelV8ProtoAttributes(span *tracepb.Span) map[string]string {
	attributes := make(map[string]string)
	if span == nil {
		return attributes
	}
	for _, item := range span.Attributes {
		if item != nil && item.Value != nil {
			if value := item.Value.GetStringValue(); value != "" {
				attributes[item.Key] = value
			} else if encoded, err := protojson.Marshal(item.Value); err == nil {
				attributes[item.Key] = string(encoded)
			}
		}
	}
	return attributes
}

func sortedHookModelV8Keys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
