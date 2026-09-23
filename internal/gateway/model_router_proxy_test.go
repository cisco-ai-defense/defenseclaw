// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

type staticModelRouter struct {
	decision *ModelRouterDecision
}

func (r staticModelRouter) Route(context.Context, *ModelRouterInput) *ModelRouterDecision {
	return r.decision
}

type countingAllowInspector struct {
	promptInspections     int
	completionInspections int
	midstreamInspections  int
}

type terminalErrorReader struct {
	reader     *strings.Reader
	err        error
	onTerminal func()
}

func (r *terminalErrorReader) Read(buffer []byte) (int, error) {
	if r == nil || r.reader == nil {
		return 0, io.EOF
	}
	read, err := r.reader.Read(buffer)
	if read > 0 {
		return read, nil
	}
	if err == io.EOF && r.err != nil {
		if r.onTerminal != nil {
			r.onTerminal()
			r.onTerminal = nil
		}
		return 0, r.err
	}
	return read, err
}

type storedModelTerminalV8 struct {
	eventName       string
	outcome         string
	traceID         string
	spanID          string
	modelRequestID  string
	modelResponseID string
	attributes      map[string]any
}

func latestStoredModelTerminalV8(t *testing.T, capture *proxyCanonicalCapture) storedModelTerminalV8 {
	t.Helper()
	database, err := sql.Open("sqlite", capture.store.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var terminal storedModelTerminalV8
	var projectedJSON string
	if err := database.QueryRow(`
		SELECT event_name, projected_record_json
		FROM audit_events
		WHERE action = ?
		ORDER BY rowid DESC
		LIMIT 1`, string(gatewaylog.EventLLMResponse)).Scan(
		&terminal.eventName, &projectedJSON,
	); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(strings.NewReader(projectedJSON))
	decoder.UseNumber()
	var projected map[string]any
	if err := decoder.Decode(&projected); err != nil {
		t.Fatal(err)
	}
	terminal.outcome, _ = projected["outcome"].(string)
	if correlation, ok := projected["correlation"].(map[string]any); ok {
		terminal.traceID, _ = correlation["trace_id"].(string)
		terminal.spanID, _ = correlation["span_id"].(string)
		terminal.modelRequestID, _ = correlation["model_request_id"].(string)
		terminal.modelResponseID, _ = correlation["model_response_id"].(string)
	}
	if body, ok := projected["body"].(map[string]any); ok {
		terminal.attributes, _ = body["attributes"].(map[string]any)
		if terminal.attributes == nil {
			// Canonical logs project family attributes directly into body;
			// canonical trace records use body.attributes.
			terminal.attributes = body
		}
	}
	if terminal.attributes == nil {
		t.Fatalf("stored model terminal missing canonical body: %s", projectedJSON)
	}
	return terminal
}

func assertStoredModelRequestAndResponseCorrelation(
	t *testing.T,
	capture *proxyCanonicalCapture,
	wantTraceID, wantSpanID string,
) {
	t.Helper()
	database, err := sql.Open("sqlite", capture.store.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	canonicalRows, err := database.Query(`
		SELECT event_name, projected_record_json
		FROM audit_events
		WHERE event_name IN (?, ?)`,
		observability.TelemetryEventModelRequest,
		observability.TelemetryEventModelResponse,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer canonicalRows.Close()
	correlated := map[string]int{}
	for canonicalRows.Next() {
		var eventName, projectedJSON string
		if err := canonicalRows.Scan(&eventName, &projectedJSON); err != nil {
			t.Fatal(err)
		}
		var projected map[string]any
		if err := json.Unmarshal([]byte(projectedJSON), &projected); err != nil {
			t.Fatal(err)
		}
		correlation, _ := projected["correlation"].(map[string]any)
		if correlation["trace_id"] != wantTraceID || correlation["span_id"] != wantSpanID {
			t.Fatalf("routed %s correlation=%v want model=%s/%s",
				eventName, correlation, wantTraceID, wantSpanID)
		}
		correlated[eventName]++
	}
	if err := canonicalRows.Err(); err != nil {
		t.Fatal(err)
	}
	if correlated[observability.TelemetryEventModelRequest] != 1 ||
		correlated[observability.TelemetryEventModelResponse] != 1 {
		t.Fatalf("routed correlated model logs=%v", correlated)
	}
}

func (i *countingAllowInspector) Inspect(
	_ context.Context,
	direction string,
	_ string,
	_ []ChatMessage,
	_ string,
	_ string,
) *ScanVerdict {
	switch direction {
	case "prompt":
		i.promptInspections++
	case "completion":
		i.completionInspections++
	}
	return allowVerdict("counting")
}

func (i *countingAllowInspector) InspectMidStream(
	_ context.Context,
	_ string,
	_ string,
	_ []ChatMessage,
	_ string,
	_ string,
) *ScanVerdict {
	i.midstreamInspections++
	return allowVerdict("counting")
}

func (*countingAllowInspector) SetScannerMode(string) {}

func (*countingAllowInspector) SetHILTConfig(bool, string) {}

func TestSemanticRouterRawForwardRewritesModelAndClearsOriginalCredential(t *testing.T) {
	var forwardedBody []byte
	var forwardedAuthorization string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		forwardedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read upstream body: %v", err)
		}
		forwardedAuthorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-routed","object":"chat.completion","model":"qwen2.5:0.5b","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer upstream.Close()

	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	proxy.SetDefaultAgentName("zeptoclaw")
	proxy.bindObservabilityV8Trace(runtime)
	proxy.SetModelRouter(staticModelRouter{decision: &ModelRouterDecision{
		Provider:          "ollama",
		TargetURL:         upstream.URL,
		TargetURLOverride: true,
		Model:             "qwen2.5:0.5b",
		APIKeyOverride:    true,
		Reason:            "decision=small-route model=small confidence=1.00",
	}})

	body := mustJSON(t, map[string]interface{}{
		"model": "openai/gpt-4o",
		"messages": []map[string]interface{}{
			{"role": "user", "content": "Say hello."},
		},
		"parallel_tool_calls": true,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", "https://api.openai.com")
	req.Header.Set("X-AI-Auth", "Bearer original-provider-secret")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	proxy.handleChatCompletion(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("proxy status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if forwardedAuthorization != "" {
		t.Fatalf("router-selected keyless backend received original Authorization header %q", forwardedAuthorization)
	}
	var forwarded map[string]interface{}
	if err := json.Unmarshal(forwardedBody, &forwarded); err != nil {
		t.Fatalf("decode forwarded body: %v", err)
	}
	if got := forwarded["model"]; got != "qwen2.5:0.5b" {
		t.Fatalf("forwarded model = %#v, want qwen2.5:0.5b; body=%s", got, forwardedBody)
	}
	if got := forwarded["parallel_tool_calls"]; got != true {
		t.Fatalf("provider extension was not preserved: %#v", got)
	}
	if got := rec.Header().Get("X-Semantic-Router"); got != "routed" {
		t.Fatalf("X-Semantic-Router = %q, want routed", got)
	}
	agent, model := assertProxyGeneratedAgentModel(
		t, capture.snapshot(), observability.OutcomeCompleted, "Ok",
	)
	if agent.TraceID() != model.TraceID() {
		t.Fatalf("routed agent/model traces are disconnected: %s != %s", agent.TraceID(), model.TraceID())
	}
	attributes := proxyCanonicalAttributes(t, model.Record())
	if got := attributes["gen_ai.request.model"]; got != "qwen2.5:0.5b" {
		t.Fatalf("routed model trace request model = %#v, want qwen2.5:0.5b", got)
	}
	assertStoredModelRequestAndResponseCorrelation(
		t, capture, model.TraceID().String(), model.SpanID().String(),
	)
}

func TestSemanticRouterPreCallBlockEmitsNoModelTelemetry(t *testing.T) {
	provider := &mockProvider{}
	inspector := newMockInspector()
	inspector.setVerdict("prompt", &ScanVerdict{
		Action: "block", Severity: "CRITICAL", Reason: "prompt blocked before routing",
	})
	proxy := newTestProxy(t, provider, inspector, "action")
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	proxy.SetDefaultAgentName("zeptoclaw")
	proxy.bindObservabilityV8Trace(runtime)
	proxy.SetModelRouter(staticModelRouter{decision: &ModelRouterDecision{
		Provider: "ollama", TargetURL: "http://127.0.0.1:11434", TargetURLOverride: true,
		Model: "qwen2.5:0.5b", Reason: "decision=small-route",
	}})

	body := mustJSON(t, map[string]interface{}{
		"model": "openai/gpt-4o",
		"messages": []map[string]interface{}{
			{"role": "user", "content": "Block this before routing."},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	proxy.handleChatCompletion(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("pre-call block status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response ChatResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.DefenseClawBlocked == nil || !*response.DefenseClawBlocked ||
		len(response.Choices) != 1 || response.Choices[0].FinishReason == nil ||
		*response.Choices[0].FinishReason != "content_filter" {
		t.Fatalf("pre-call block did not preserve synthetic content_filter response: %+v", response)
	}
	if provider.getLastReq() != nil || rec.Header().Get("X-Semantic-Router") != "" {
		t.Fatalf("pre-call block reached routing/upstream: routed=%q upstream=%+v",
			rec.Header().Get("X-Semantic-Router"), provider.getLastReq())
	}

	spans := capture.snapshot()
	agents := proxyGeneratedSpansForFamily(spans, observability.TelemetryFamilyAgentInvoke)
	models := proxyGeneratedSpansForFamily(spans, observability.TelemetryFamilyModelChat)
	if len(agents) != 1 || len(models) != 0 {
		t.Fatalf("pre-call block agent/model spans=%d/%d", len(agents), len(models))
	}
	if agents[0].Record().Outcome() != observability.OutcomeBlocked ||
		agents[0].StatusCode().String() != "Ok" {
		t.Fatalf("pre-call block agent outcome/status=%s/%s",
			agents[0].Record().Outcome(), agents[0].StatusCode())
	}
	input := proxyGeneratedGuardrailSpan(t, spans, "input")
	parent, parentOK := input.ParentSpanID()
	if input.Record().Outcome() != observability.OutcomeBlocked ||
		input.StatusCode().String() != "Ok" || !parentOK || parent != agents[0].SpanID() ||
		input.TraceID() != agents[0].TraceID() {
		t.Fatalf("pre-call block guardrail outcome/status/parent=%s/%s/%s/%t agent=%s trace=%s/%s",
			input.Record().Outcome(), input.StatusCode(), parent, parentOK, agents[0].SpanID(),
			input.TraceID(), agents[0].TraceID())
	}
	inputAttributes := proxyCanonicalAttributes(t, input.Record())
	if inputAttributes["defenseclaw.guardrail.decision"] != "block" ||
		inputAttributes["defenseclaw.guardrail.effective_action"] != "block" ||
		inputAttributes["defenseclaw.guardrail.enforced"] != true {
		t.Fatalf("pre-call block guardrail attributes=%v", inputAttributes)
	}

	database, err := sql.Open("sqlite", capture.store.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var modelEvents int
	if err := database.QueryRow(`
		SELECT COUNT(*) FROM audit_events
		WHERE event_name IN (?, ?, ?)`,
		observability.TelemetryEventModelRequest,
		observability.TelemetryEventModelResponse,
		observability.TelemetryEventModelCallFailed,
	).Scan(&modelEvents); err != nil {
		t.Fatal(err)
	}
	if modelEvents != 0 {
		t.Fatalf("pre-call block emitted %d canonical model log(s)", modelEvents)
	}
	var blockedEnforcements int
	if err := database.QueryRow(`
		SELECT COUNT(*) FROM audit_events
		WHERE event_name = ?
		  AND json_extract(projected_record_json, '$.outcome') = ?`,
		observability.TelemetryEventEnforcementBlockApplied,
		string(observability.OutcomeBlocked),
	).Scan(&blockedEnforcements); err != nil {
		t.Fatal(err)
	}
	if blockedEnforcements != 1 {
		t.Fatalf("pre-call block enforcement rows=%d, want one blocked outcome", blockedEnforcements)
	}
}

func TestSemanticRouterRawForwardDropsOriginalCustomCredentialsAndUsesSelectedKey(t *testing.T) {
	allowRawForwardPrivateTargets(t)
	var forwardedHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwardedHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-routed","object":"chat.completion","model":"qwen2.5:0.5b","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer upstream.Close()

	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	proxy.bindObservabilityV8Trace(runtime)
	proxy.SetModelRouter(staticModelRouter{decision: &ModelRouterDecision{
		Provider:          "azure",
		TargetURL:         upstream.URL,
		TargetURLOverride: true,
		Model:             "qwen2.5:0.5b",
		APIKey:            "selected-provider-secret",
		APIKeyOverride:    true,
		Reason:            "decision=small-route model=small confidence=1.00",
	}})

	body := mustJSON(t, map[string]interface{}{
		"model": "openai/gpt-4o",
		"messages": []map[string]interface{}{
			{"role": "user", "content": "Say hello."},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", "https://api.openai.com")
	req.Header.Set("X-AI-Auth", "Bearer original-provider-secret")
	req.Header.Set("Cookie", "session=original-provider-cookie")
	req.Header.Set("Proxy-Authorization", "Basic original-proxy-secret")
	req.Header.Set("X-Goog-Api-Key", "original-google-secret")
	req.Header.Set("OpenAI-Organization", "original-openai-org")
	req.Header.Set("Accept", "application/original-provider+json")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	proxy.handleChatCompletion(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("proxy status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if got := forwardedHeaders.Get("api-key"); got != "selected-provider-secret" {
		t.Fatalf("selected Azure backend api-key = %q, want selected provider key", got)
	}
	if got := forwardedHeaders.Get("Authorization"); got != "" {
		t.Fatalf("selected Azure backend received bearer Authorization %q", got)
	}
	for _, name := range []string{
		"Cookie", "Proxy-Authorization", "X-Goog-Api-Key", "OpenAI-Organization", "Accept",
	} {
		if got := forwardedHeaders.Get(name); got != "" {
			t.Fatalf("router-selected backend received original %s header %q", name, got)
		}
	}
	for _, metric := range capture.metricSnapshot() {
		if metric.Descriptor().Name == observability.TelemetryInstrumentDefenseClawGatewayForwardedHeaders {
			t.Fatalf("routed request reported dropped custom headers as forwarded: %v", metric)
		}
	}
}

func TestSemanticRouterRawForwardStreamingKeepsSelectedProviderV8Identity(t *testing.T) {
	allowRawForwardPrivateTargets(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"id\":\"chatcmpl-stream-routed\",\"object\":\"chat.completion.chunk\",\"model\":\"qwen2.5:0.5b\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hello\"},\"finish_reason\":\"stop\"},{\"index\":1,\"delta\":{},\"finish_reason\":\"length\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer upstream.Close()

	inspector := &countingAllowInspector{}
	proxy := newTestProxy(t, &mockProvider{}, inspector, "action")
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	proxy.SetDefaultAgentName("zeptoclaw")
	proxy.bindObservabilityV8Trace(runtime)
	proxy.SetModelRouter(staticModelRouter{decision: &ModelRouterDecision{
		Provider:          "ollama",
		TargetURL:         upstream.URL,
		TargetURLOverride: true,
		Model:             "routed-small",
		Reason:            "decision=small-route model=small confidence=1.00",
	}})

	body := mustJSON(t, map[string]interface{}{
		"model":    "openai/gpt-4o",
		"messages": []map[string]interface{}{{"role": "user", "content": "Say hello."}},
		"stream":   true,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", "https://api.openai.com")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	proxy.handleChatCompletion(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("proxy status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if inspector.promptInspections != 1 || inspector.completionInspections != 1 {
		t.Fatalf(
			"final guardrail inspections prompt/completion=%d/%d, want 1/1",
			inspector.promptInspections, inspector.completionInspections,
		)
	}
	if inspector.midstreamInspections != 1 {
		t.Fatalf("midstream guardrail inspections=%d, want 1", inspector.midstreamInspections)
	}

	_, model := assertProxyGeneratedAgentModel(
		t, capture.snapshot(), observability.OutcomeCompleted, "Ok",
	)
	attributes := proxyCanonicalAttributes(t, model.Record())
	if attributes["gen_ai.provider.name"] != "ollama" ||
		attributes["gen_ai.request.model"] != "routed-small" ||
		attributes["gen_ai.response.model"] != "qwen2.5:0.5b" ||
		attributes["gen_ai.response.id"] != "chatcmpl-stream-routed" ||
		attributes["defenseclaw.model.streaming"] != true {
		t.Fatalf("routed streaming model identity=%v", attributes)
	}
	finishReasons, reasonsOK := attributes["gen_ai.response.finish_reasons"].([]interface{})
	if !reasonsOK || len(finishReasons) != 2 || finishReasons[0] != "stop" || finishReasons[1] != "length" {
		t.Fatalf("routed streaming finish reasons=%v", attributes["gen_ai.response.finish_reasons"])
	}
	inputTokens, inputOK := attributes["gen_ai.usage.input_tokens"].(json.Number)
	outputTokens, outputOK := attributes["gen_ai.usage.output_tokens"].(json.Number)
	if !inputOK || !outputOK || inputTokens.String() != "3" || outputTokens.String() != "2" {
		t.Fatalf("routed streaming usage input/output=%v/%v", inputTokens, outputTokens)
	}
	streamMetrics := map[string]int{}
	for _, metric := range capture.metricSnapshot() {
		switch metric.Descriptor().Name {
		case observability.TelemetryInstrumentDefenseClawStreamLifecycle,
			observability.TelemetryInstrumentDefenseClawStreamDurationMs,
			observability.TelemetryInstrumentDefenseClawStreamBytesSent:
			streamMetrics[metric.Descriptor().Name]++
			correlation := metric.CanonicalRecord().Correlation()
			if correlation.TraceID != model.TraceID().String() || correlation.SpanID != model.SpanID().String() {
				t.Fatalf("routed stream metric %s correlation=%+v model=%s/%s",
					metric.Descriptor().Name, correlation, model.TraceID(), model.SpanID())
			}
		}
	}
	if streamMetrics[observability.TelemetryInstrumentDefenseClawStreamLifecycle] != 2 ||
		streamMetrics[observability.TelemetryInstrumentDefenseClawStreamDurationMs] != 1 ||
		streamMetrics[observability.TelemetryInstrumentDefenseClawStreamBytesSent] != 1 {
		t.Fatalf("routed stream metrics=%v", streamMetrics)
	}

	rows, err := capture.store.ListEvents(20)
	if err != nil {
		t.Fatal(err)
	}
	promptRows := 0
	responseRows := 0
	for _, row := range rows {
		if row.Action == string(gatewaylog.EventLLMPrompt) {
			promptRows++
			if row.Structured["gen_ai.provider.name"] != "ollama" ||
				row.Structured["gen_ai.request.model"] != "routed-small" {
				t.Fatalf("routed streaming request identity=%+v", row.Structured)
			}
			continue
		}
		if row.Action != string(gatewaylog.EventLLMResponse) {
			continue
		}
		responseRows++
		if row.Structured["gen_ai.provider.name"] != "ollama" ||
			row.Structured["gen_ai.request.model"] != "routed-small" ||
			row.Structured["gen_ai.response.model"] != "qwen2.5:0.5b" {
			t.Fatalf("routed streaming response identity=%+v", row.Structured)
		}
	}
	if promptRows != 1 || responseRows != 1 {
		t.Fatalf("routed streaming request/response rows=%d/%d, want 1/1", promptRows, responseRows)
	}
	assertStoredModelRequestAndResponseCorrelation(
		t, capture, model.TraceID().String(), model.SpanID().String(),
	)
}

func TestSemanticRouterRawForwardStreamingObserveInspectsCompletionOnce(t *testing.T) {
	allowRawForwardPrivateTargets(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"id\":\"chatcmpl-observe\",\"object\":\"chat.completion.chunk\",\"model\":\"observe-actual\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hello\"},\"finish_reason\":\"stop\"}]}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer upstream.Close()

	inspector := &countingAllowInspector{}
	proxy := newTestProxy(t, &mockProvider{}, inspector, "observe")
	proxy.SetModelRouter(staticModelRouter{decision: &ModelRouterDecision{
		Provider: "ollama", TargetURL: upstream.URL, TargetURLOverride: true, Model: "observe-routed",
	}})
	body := mustJSON(t, map[string]interface{}{
		"model": "openai/gpt-4o", "stream": true,
		"messages": []map[string]interface{}{{"role": "user", "content": "Observe this."}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", "https://api.openai.com")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	proxy.handleChatCompletion(rec, req)

	if rec.Code != http.StatusOK || inspector.promptInspections != 1 ||
		inspector.completionInspections != 1 || inspector.midstreamInspections != 0 {
		t.Fatalf("status=%d inspections prompt/completion/midstream=%d/%d/%d body=%s",
			rec.Code, inspector.promptInspections, inspector.completionInspections,
			inspector.midstreamInspections, rec.Body.String())
	}
}

func TestSemanticRouterRawForwardStreamingBlockEmitsCorrelatedV8Terminal(t *testing.T) {
	allowRawForwardPrivateTargets(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"id\":\"chatcmpl-block-routed\",\"object\":\"chat.completion.chunk\",\"model\":\"blocked-actual\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"blocked output\"}}]}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer upstream.Close()

	inspector := newMockInspector()
	inspector.setVerdict("completion", &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "blocked"})
	proxy := newTestProxy(t, &mockProvider{}, inspector, "action")
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	proxy.SetDefaultAgentName("zeptoclaw")
	proxy.bindObservabilityV8Trace(runtime)
	proxy.SetModelRouter(staticModelRouter{decision: &ModelRouterDecision{
		Provider: "ollama", TargetURL: upstream.URL, TargetURLOverride: true, Model: "blocked-routed",
	}})
	body := mustJSON(t, map[string]interface{}{
		"model": "openai/gpt-4o", "stream": true,
		"messages": []map[string]interface{}{{"role": "user", "content": "Generate output."}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", "https://api.openai.com")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	proxy.handleChatCompletion(rec, req)

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "DefenseClaw") {
		t.Fatalf("blocked routed stream status=%d body=%s", rec.Code, rec.Body.String())
	}
	spans := capture.snapshot()
	_, model := assertProxyGeneratedAgentModel(t, spans, observability.OutcomeBlocked, "Ok")
	output := proxyGeneratedGuardrailSpan(t, spans, "output")
	parent, present := output.ParentSpanID()
	if !present || parent != model.SpanID() || output.TraceID() != model.TraceID() {
		t.Fatalf("routed midstream guardrail parent=%s/%t model=%s trace=%s/%s",
			parent, present, model.SpanID(), output.TraceID(), model.TraceID())
	}
	foundOverlay := false
	for _, event := range canonicalTraceEvents(t, model.Record()) {
		if event == observability.TelemetrySpanEventGuardrailDecision {
			foundOverlay = true
		}
	}
	if !foundOverlay {
		t.Fatalf("blocked routed model omitted guardrail overlay: %v", canonicalTraceEvents(t, model.Record()))
	}
	outputAttributes := proxyCanonicalAttributes(t, output.Record())
	enforcementID, _ := outputAttributes["defenseclaw.enforcement.id"].(string)
	if outputAttributes["defenseclaw.guardrail.enforced"] != true ||
		outputAttributes["defenseclaw.guardrail.effective_action"] != "block" ||
		enforcementID == "" {
		t.Fatalf("blocked routed final-text enforcement=%v", outputAttributes)
	}

	rows, err := capture.store.ListEvents(20)
	if err != nil {
		t.Fatal(err)
	}
	responseRows := 0
	foundEnforcement := false
	for _, row := range rows {
		if row.Structured["defenseclaw.enforcement.id"] == enforcementID &&
			row.Structured["defenseclaw.enforcement.effective_action"] == "block" {
			foundEnforcement = true
		}
		if row.Action != string(gatewaylog.EventLLMResponse) {
			continue
		}
		responseRows++
		payload, marshalErr := json.Marshal(row.Structured)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if row.Structured["gen_ai.provider.name"] != "ollama" ||
			row.Structured["gen_ai.request.model"] != "blocked-routed" ||
			row.Structured["gen_ai.response.model"] != "blocked-actual" ||
			!bytes.Contains(payload, []byte("blocked")) {
			t.Fatalf("blocked routed terminal=%s", payload)
		}
	}
	if responseRows != 1 {
		t.Fatalf("blocked routed response rows=%d, want 1", responseRows)
	}
	if !foundEnforcement {
		t.Fatalf("blocked routed final-text enforcement companion missing: %v", rows)
	}
}

func TestSemanticRouterFallbackKeepsRawTargetProviderV8Identity(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-fallback","object":"chat.completion","model":"qwen2.5:0.5b","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer upstream.Close()
	registerRawForwardProviderDomain(t, upstream.URL, "ollama")
	allowRawForwardPrivateTargets(t)

	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	proxy.SetDefaultAgentName("zeptoclaw")
	proxy.bindObservabilityV8Trace(runtime)
	proxy.SetModelRouter(staticModelRouter{})
	body := mustJSON(t, map[string]interface{}{
		"model":    "qwen2.5:0.5b",
		"messages": []map[string]interface{}{{"role": "user", "content": "Use the fallback."}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", upstream.URL)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	proxy.handleChatCompletion(rec, req)

	if rec.Code != http.StatusOK || rec.Header().Get("X-Semantic-Router") != "" {
		t.Fatalf("fallback status=%d routed=%q body=%s", rec.Code, rec.Header().Get("X-Semantic-Router"), rec.Body.String())
	}
	_, model := assertProxyGeneratedAgentModel(t, capture.snapshot(), observability.OutcomeCompleted, "Ok")
	if got := proxyCanonicalAttributes(t, model.Record())["gen_ai.provider.name"]; got != "ollama" {
		t.Fatalf("fallback model provider=%v, want ollama", got)
	}
	rows, err := capture.store.ListEvents(20)
	if err != nil {
		t.Fatal(err)
	}
	promptRows := 0
	for _, row := range rows {
		if row.Action == string(gatewaylog.EventLLMPrompt) {
			promptRows++
			if row.Structured["gen_ai.provider.name"] != "ollama" {
				t.Fatalf("fallback request provider=%v row=%+v", row.Structured["gen_ai.provider.name"], row.Structured)
			}
		}
	}
	if promptRows != 1 {
		t.Fatalf("fallback request rows=%d, want 1", promptRows)
	}
}

func TestSemanticRouterStructuredForwardKeepsSelectedProviderV8Identity(t *testing.T) {
	provider := &mockProvider{response: &ChatResponse{
		ID: "chatcmpl-structured-routed", Model: "deepseek-r1:8b-build-7",
		Choices: []ChatChoice{{
			Index: 0, Message: &ChatMessage{Role: "assistant", Content: "ok"}, FinishReason: strPtr("stop"),
		}},
	}}
	proxy := newTestProxy(t, provider, newMockInspector(), "action")
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	proxy.SetDefaultAgentName("zeptoclaw")
	proxy.bindObservabilityV8Trace(runtime)
	chatReq := ChatRequest{
		Model:    "deepseek-r1:8b",
		Messages: []ChatMessage{{Role: "user", Content: "Use the structured backend."}},
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	httpReq.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	traceResult := proxyV8DefaultResult(false)
	agentCtx, requestTrace := proxy.startProxyV8RequestTrace(
		httpReq.Context(), &chatReq, "", "",
	)

	proxy.handleNonStreamingRequest(
		rec, httpReq, &chatReq, "openrouter", "action", "", provider,
		agentCtx, "", nil, requestTrace, &traceResult,
	)
	requestTrace.Finish(traceResult)

	if rec.Code != http.StatusOK {
		t.Fatalf("structured route status=%d body=%s", rec.Code, rec.Body.String())
	}
	_, model := assertProxyGeneratedAgentModel(t, capture.snapshot(), observability.OutcomeCompleted, "Ok")
	attributes := proxyCanonicalAttributes(t, model.Record())
	if attributes["gen_ai.provider.name"] != "openrouter" ||
		attributes["gen_ai.request.model"] != "deepseek-r1:8b" ||
		attributes["gen_ai.response.model"] != "deepseek-r1:8b-build-7" {
		t.Fatalf("structured routed identity=%v", attributes)
	}
	terminal := latestStoredModelTerminalV8(t, capture)
	if terminal.eventName != observability.TelemetryEventModelResponse ||
		terminal.outcome != string(observability.OutcomeCompleted) ||
		terminal.traceID != model.TraceID().String() || terminal.spanID != model.SpanID().String() ||
		terminal.attributes["gen_ai.provider.name"] != "openrouter" ||
		terminal.attributes["gen_ai.request.model"] != "deepseek-r1:8b" ||
		terminal.attributes["gen_ai.response.model"] != "deepseek-r1:8b-build-7" {
		t.Fatalf("structured routed terminal=%+v model=%s/%s", terminal, model.TraceID(), model.SpanID())
	}
}

func TestSemanticRouterStructuredStreamingFailureEmitsCorrelatedV8Terminal(t *testing.T) {
	provider := &mockProvider{err: context.Canceled}
	proxy := newTestProxy(t, provider, newMockInspector(), "action")
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	proxy.SetDefaultAgentName("zeptoclaw")
	proxy.bindObservabilityV8Trace(runtime)
	chatReq := ChatRequest{
		Model:    "structured-cancel-routed",
		Stream:   true,
		Messages: []ChatMessage{{Role: "user", Content: "Cancel this stream."}},
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	httpReq.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	traceResult := proxyV8DefaultResult(true)
	agentCtx, requestTrace := proxy.startProxyV8RequestTrace(
		httpReq.Context(), &chatReq, "", "",
	)

	proxy.handleStreamingRequest(
		rec, httpReq, &chatReq, "openrouter", "action", "", provider,
		agentCtx, "", nil, requestTrace, &traceResult,
	)
	requestTrace.Finish(traceResult)

	_, model := assertProxyGeneratedAgentModel(
		t, capture.snapshot(), observability.OutcomeCancelled, "Ok",
	)
	attributes := proxyCanonicalAttributes(t, model.Record())
	if attributes["gen_ai.provider.name"] != "openrouter" ||
		attributes["gen_ai.request.model"] != "structured-cancel-routed" ||
		attributes["error.type"] != "upstream_error" ||
		attributes["defenseclaw.model.cancelled"] != true {
		t.Fatalf("structured cancelled model=%v", attributes)
	}
	if technicalFailure, reported := attributes["defenseclaw.condition.technical_failure"]; reported && technicalFailure != false {
		t.Fatalf("structured cancellation reported technical failure=%v", technicalFailure)
	}
	terminal := latestStoredModelTerminalV8(t, capture)
	if terminal.eventName != observability.TelemetryEventModelCallFailed ||
		terminal.outcome != string(observability.OutcomeCancelled) ||
		terminal.traceID != model.TraceID().String() || terminal.spanID != model.SpanID().String() ||
		terminal.attributes["gen_ai.provider.name"] != "openrouter" ||
		terminal.attributes["gen_ai.request.model"] != "structured-cancel-routed" {
		t.Fatalf("structured cancelled terminal=%+v model=%s/%s", terminal, model.TraceID(), model.SpanID())
	}
	if _, fabricated := terminal.attributes["gen_ai.response.finish_reasons"]; fabricated {
		t.Fatalf("structured cancelled terminal fabricated finish reasons: %+v", terminal.attributes)
	}
	for _, field := range []string{"gen_ai.response.id", "gen_ai.response.model"} {
		if _, fabricated := terminal.attributes[field]; fabricated {
			t.Fatalf("structured cancelled terminal fabricated %s: %+v", field, terminal.attributes)
		}
	}
	closeOutcome := ""
	for _, metric := range capture.metricSnapshot() {
		if metric.Descriptor().Name != observability.TelemetryInstrumentDefenseClawStreamLifecycle {
			continue
		}
		metricAttributes := metric.Attributes()
		if metricAttributes["defenseclaw.metric.transition"] == "close" {
			closeOutcome, _ = metricAttributes["defenseclaw.outcome"].(string)
		}
	}
	if closeOutcome != string(observability.OutcomeCancelled) {
		t.Fatalf("structured cancelled close outcome=%q", closeOutcome)
	}
}

func TestSemanticRouterStructuredNonStreamingFailureEmitsCorrelatedV8Terminal(t *testing.T) {
	provider := &mockProvider{err: errors.New("selected backend unavailable")}
	proxy := newTestProxy(t, provider, newMockInspector(), "action")
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	proxy.SetDefaultAgentName("zeptoclaw")
	proxy.bindObservabilityV8Trace(runtime)
	chatReq := ChatRequest{
		Model:    "structured-failed-routed",
		Messages: []ChatMessage{{Role: "user", Content: "Fail this request."}},
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	httpReq.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	traceResult := proxyV8DefaultResult(false)
	agentCtx, requestTrace := proxy.startProxyV8RequestTrace(
		httpReq.Context(), &chatReq, "", "",
	)

	proxy.handleNonStreamingRequest(
		rec, httpReq, &chatReq, "openrouter", "action", "", provider,
		agentCtx, "", nil, requestTrace, &traceResult,
	)
	requestTrace.Finish(traceResult)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("structured failed route status=%d body=%s", rec.Code, rec.Body.String())
	}
	_, model := assertProxyGeneratedAgentModel(
		t, capture.snapshot(), observability.OutcomeFailed, "Error",
	)
	attributes := proxyCanonicalAttributes(t, model.Record())
	if attributes["gen_ai.provider.name"] != "openrouter" ||
		attributes["gen_ai.request.model"] != "structured-failed-routed" ||
		attributes["error.type"] != "upstream_error" {
		t.Fatalf("structured failed model=%v", attributes)
	}
	terminal := latestStoredModelTerminalV8(t, capture)
	if terminal.eventName != observability.TelemetryEventModelCallFailed ||
		terminal.outcome != string(observability.OutcomeFailed) ||
		terminal.traceID != model.TraceID().String() || terminal.spanID != model.SpanID().String() ||
		terminal.attributes["gen_ai.provider.name"] != "openrouter" ||
		terminal.attributes["gen_ai.request.model"] != "structured-failed-routed" {
		t.Fatalf("structured failed terminal=%+v model=%s/%s", terminal, model.TraceID(), model.SpanID())
	}
	if _, fabricated := terminal.attributes["gen_ai.response.finish_reasons"]; fabricated {
		t.Fatalf("structured failed terminal fabricated finish reasons: %+v", terminal.attributes)
	}
	for _, field := range []string{"gen_ai.response.id", "gen_ai.response.model"} {
		if _, fabricated := terminal.attributes[field]; fabricated {
			t.Fatalf("structured failed terminal fabricated %s: %+v", field, terminal.attributes)
		}
	}
}

func TestSemanticRouterRawStreamingCancellationAlignsV8TerminalSignals(t *testing.T) {
	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	proxy.SetDefaultAgentName("zeptoclaw")
	proxy.bindObservabilityV8Trace(runtime)
	body := mustJSON(t, map[string]any{
		"model": "raw-cancel-routed", "stream": true,
		"messages": []map[string]any{{"role": "user", "content": "Cancel this raw stream."}},
	})
	chatReq := ChatRequest{
		Model: "raw-cancel-routed", Stream: true, RawBody: body,
		Messages: []ChatMessage{{Role: "user", Content: "Cancel this raw stream."}},
	}
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	defer cancelRequest()
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body)).WithContext(requestCtx)
	httpReq.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	traceResult := proxyV8DefaultResult(true)
	agentCtx, requestTrace := proxy.startProxyV8RequestTrace(
		httpReq.Context(), &chatReq, "", "",
	)
	modelInput := proxy.proxyV8ModelInput(agentCtx, &chatReq, "ollama", time.Now().UTC())
	llmCtx, modelTrace := requestTrace.StartModel(agentCtx, modelInput)
	stream := "data: {\"id\":\"chatcmpl-raw-cancel\",\"object\":\"chat.completion.chunk\",\"model\":\"qwen2.5:0.5b\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial\"}}]}\n\n"
	response := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body: io.NopCloser(&terminalErrorReader{
			reader: strings.NewReader(stream), err: context.Canceled, onTerminal: cancelRequest,
		}),
		Request: httpReq,
	}

	proxy.rawForwardChatCompletionStream(
		rec, httpReq, response, &chatReq, "action", "", llmCtx, "",
		"ollama", modelTrace, &traceResult, time.Now().Add(-time.Millisecond),
	)
	modelTrace.Finish(traceResult)
	requestTrace.Finish(traceResult)
	if !errors.Is(requestCtx.Err(), context.Canceled) {
		t.Fatalf("raw cancellation test did not cancel request context: %v", requestCtx.Err())
	}

	_, model := assertProxyGeneratedAgentModel(
		t, capture.snapshot(), observability.OutcomeCancelled, "Ok",
	)
	attributes := proxyCanonicalAttributes(t, model.Record())
	if attributes["gen_ai.provider.name"] != "ollama" ||
		attributes["gen_ai.request.model"] != "raw-cancel-routed" ||
		attributes["gen_ai.response.model"] != "qwen2.5:0.5b" ||
		attributes["gen_ai.response.id"] != "chatcmpl-raw-cancel" ||
		attributes["error.type"] != "upstream_stream_read" ||
		attributes["defenseclaw.model.cancelled"] != true {
		t.Fatalf("raw cancelled model=%v", attributes)
	}
	if technicalFailure, reported := attributes["defenseclaw.condition.technical_failure"]; reported && technicalFailure != false {
		t.Fatalf("raw cancellation reported technical failure=%v", technicalFailure)
	}
	if _, fabricated := attributes["gen_ai.response.finish_reasons"]; fabricated {
		t.Fatalf("raw cancelled model fabricated finish reasons: %v", attributes)
	}
	terminal := latestStoredModelTerminalV8(t, capture)
	if terminal.eventName != observability.TelemetryEventModelCallFailed ||
		terminal.outcome != string(observability.OutcomeCancelled) ||
		terminal.traceID != model.TraceID().String() || terminal.spanID != model.SpanID().String() ||
		terminal.attributes["gen_ai.provider.name"] != "ollama" ||
		terminal.attributes["gen_ai.request.model"] != "raw-cancel-routed" ||
		terminal.attributes["gen_ai.response.model"] != "qwen2.5:0.5b" {
		t.Fatalf("raw cancelled terminal=%+v model=%s/%s", terminal, model.TraceID(), model.SpanID())
	}
	if _, fabricated := terminal.attributes["gen_ai.response.finish_reasons"]; fabricated {
		t.Fatalf("raw cancelled terminal fabricated finish reasons: %+v", terminal.attributes)
	}
	closeOutcome := ""
	metricCounts := map[string]int{}
	for _, metric := range capture.metricSnapshot() {
		metricCounts[metric.Descriptor().Name]++
		if metric.Descriptor().Name != observability.TelemetryInstrumentDefenseClawStreamLifecycle {
			continue
		}
		metricAttributes := metric.Attributes()
		if metricAttributes["defenseclaw.metric.transition"] == "close" {
			closeOutcome, _ = metricAttributes["defenseclaw.outcome"].(string)
		}
	}
	if closeOutcome != string(observability.OutcomeCancelled) {
		t.Fatalf("raw cancelled close outcome=%q", closeOutcome)
	}
	if metricCounts[observability.TelemetryInstrumentDefenseClawGatewayErrors] != 1 ||
		metricCounts[observability.TelemetryInstrumentGenAIClientOperationDuration] != 1 {
		t.Fatalf("raw cancelled terminal metric counts=%v", metricCounts)
	}
}

func TestSemanticRouterRawHTTPFailureEmitsCorrelatedV8Terminal(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(map[bool]string{false: "non-stream", true: "stream"}[stream], func(t *testing.T) {
			allowRawForwardPrivateTargets(t)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"error":{"message":"unavailable"}}`))
			}))
			defer upstream.Close()

			proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
			runtime, capture := newProxyGeneratedTraceRuntime(t)
			proxy.SetDefaultAgentName("zeptoclaw")
			proxy.bindObservabilityV8Trace(runtime)
			proxy.SetModelRouter(staticModelRouter{decision: &ModelRouterDecision{
				Provider: "ollama", TargetURL: upstream.URL,
				TargetURLOverride: true, Model: "raw-http-failed-routed",
			}})
			body := mustJSON(t, map[string]any{
				"model": "openai/gpt-4o", "stream": stream,
				"messages": []map[string]any{{"role": "user", "content": "Fail upstream."}},
			})
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-DC-Target-URL", "https://api.openai.com")
			req.RemoteAddr = "127.0.0.1:12345"
			rec := httptest.NewRecorder()

			proxy.handleChatCompletion(rec, req)

			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("raw HTTP failure status=%d body=%s", rec.Code, rec.Body.String())
			}
			_, model := assertProxyGeneratedAgentModel(
				t, capture.snapshot(), observability.OutcomeFailed, "Error",
			)
			attributes := proxyCanonicalAttributes(t, model.Record())
			if attributes["gen_ai.provider.name"] != "ollama" ||
				attributes["gen_ai.request.model"] != "raw-http-failed-routed" ||
				attributes["error.type"] != "upstream_http_status" {
				t.Fatalf("raw HTTP failed model=%v", attributes)
			}
			terminal := latestStoredModelTerminalV8(t, capture)
			if terminal.eventName != observability.TelemetryEventModelCallFailed ||
				terminal.outcome != string(observability.OutcomeFailed) ||
				terminal.traceID != model.TraceID().String() || terminal.spanID != model.SpanID().String() ||
				terminal.attributes["gen_ai.provider.name"] != "ollama" ||
				terminal.attributes["gen_ai.request.model"] != "raw-http-failed-routed" {
				t.Fatalf("raw HTTP failed terminal=%+v model=%s/%s", terminal, model.TraceID(), model.SpanID())
			}
			if _, fabricated := terminal.attributes["gen_ai.response.finish_reasons"]; fabricated {
				t.Fatalf("raw HTTP failed terminal fabricated finish reasons: %+v", terminal.attributes)
			}
			for _, field := range []string{"gen_ai.response.id", "gen_ai.response.model"} {
				if _, fabricated := terminal.attributes[field]; fabricated {
					t.Fatalf("raw HTTP failed terminal fabricated %s: %+v", field, terminal.attributes)
				}
			}
		})
	}
}

func TestSemanticRouterRawForwardNonStreamingEmitsProposedToolV8Event(t *testing.T) {
	allowRawForwardPrivateTargets(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-tool-routed","object":"chat.completion","model":"qwen2.5:0.5b","choices":[{"index":0,"message":{"role":"assistant","tool_calls":[{"id":"call_weather","type":"function","function":{"name":"weather","arguments":"{\"city\":\"Austin\"}"}}]},"finish_reason":"tool_calls"}]}`))
	}))
	defer upstream.Close()

	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	proxy.SetDefaultAgentName("zeptoclaw")
	proxy.bindObservabilityV8Trace(runtime)
	proxy.SetModelRouter(staticModelRouter{decision: &ModelRouterDecision{
		Provider: "ollama", TargetURL: upstream.URL, TargetURLOverride: true, Model: "qwen2.5:0.5b",
	}})
	body := mustJSON(t, map[string]interface{}{
		"model":    "openai/gpt-4o",
		"messages": []map[string]interface{}{{"role": "user", "content": "Check the weather."}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", "https://api.openai.com")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	proxy.handleChatCompletion(rec, req)

	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "DefenseClaw") {
		t.Fatalf("tool route status=%d body=%s", rec.Code, rec.Body.String())
	}
	_, model := assertProxyGeneratedAgentModel(t, capture.snapshot(), observability.OutcomeCompleted, "Ok")
	toolCount, countErr := proxyCanonicalAttributes(t, model.Record())["defenseclaw.model.tool_call_count"].(json.Number).Int64()
	if countErr != nil || toolCount != 1 {
		t.Fatalf("tool route count=%d err=%v", toolCount, countErr)
	}
	rows, err := capture.store.ListEvents(30)
	if err != nil {
		t.Fatal(err)
	}
	toolRows := 0
	for _, row := range rows {
		if row.Action == string(gatewaylog.EventToolInvocation) {
			toolRows++
		}
	}
	if toolRows != 1 {
		t.Fatalf("routed proposed tool rows=%d, want 1", toolRows)
	}
}

func TestSemanticRouterRawForwardStreamingEmitsCorrelatedProposedToolV8Event(t *testing.T) {
	allowRawForwardPrivateTargets(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"id\":\"chatcmpl-tool-stream-routed\",\"object\":\"chat.completion.chunk\",\"model\":\"qwen2.5:0.5b\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"tool_calls\":[{\"index\":0,\"id\":\"call_weather_stream\",\"type\":\"function\",\"function\":{\"name\":\"weather\",\"arguments\":\"{\\\"city\\\":\\\"Austin\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer upstream.Close()

	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	proxy.SetDefaultAgentName("zeptoclaw")
	proxy.bindObservabilityV8Trace(runtime)
	proxy.SetModelRouter(staticModelRouter{decision: &ModelRouterDecision{
		Provider: "ollama", TargetURL: upstream.URL, TargetURLOverride: true, Model: "qwen2.5:0.5b",
	}})
	body := mustJSON(t, map[string]interface{}{
		"model": "openai/gpt-4o", "stream": true,
		"messages": []map[string]interface{}{{"role": "user", "content": "Check the weather."}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", "https://api.openai.com")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	proxy.handleChatCompletion(rec, req)

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "call_weather_stream") {
		t.Fatalf("streaming tool route status=%d body=%s", rec.Code, rec.Body.String())
	}
	_, model := assertProxyGeneratedAgentModel(t, capture.snapshot(), observability.OutcomeCompleted, "Ok")
	modelAttributes := proxyCanonicalAttributes(t, model.Record())
	if modelAttributes["gen_ai.provider.name"] != "ollama" ||
		modelAttributes["gen_ai.request.model"] != "qwen2.5:0.5b" ||
		modelAttributes["gen_ai.response.model"] != "qwen2.5:0.5b" ||
		modelAttributes["gen_ai.response.id"] != "chatcmpl-tool-stream-routed" {
		t.Fatalf("streaming tool model identity=%v", modelAttributes)
	}
	terminal := latestStoredModelTerminalV8(t, capture)

	database, err := sql.Open("sqlite", capture.store.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var eventName, projectedJSON string
	if err := database.QueryRow(`
		SELECT event_name, projected_record_json
		FROM audit_events
		WHERE action = ?
		ORDER BY rowid DESC
		LIMIT 1`, string(gatewaylog.EventToolInvocation)).Scan(&eventName, &projectedJSON); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(strings.NewReader(projectedJSON))
	decoder.UseNumber()
	var projected map[string]any
	if err := decoder.Decode(&projected); err != nil {
		t.Fatal(err)
	}
	correlation, _ := projected["correlation"].(map[string]any)
	if eventName != observability.TelemetryEventToolInvocationRequested ||
		correlation["trace_id"] != model.TraceID().String() ||
		correlation["span_id"] != model.SpanID().String() ||
		correlation["model_request_id"] != terminal.modelRequestID ||
		correlation["model_response_id"] != "chatcmpl-tool-stream-routed" ||
		correlation["tool_invocation_id"] != "call_weather_stream" {
		t.Fatalf("streaming tool correlation event=%q correlation=%v terminal=%+v", eventName, correlation, terminal)
	}
}

func TestSemanticRouterRawStreamIgnoresFramesAfterDone(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, `data: {"id":"chatcmpl-done-terminal","object":"chat.completion.chunk","model":"qwen2.5:0.5b","choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}]}`+"\n\n")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		_, _ = io.WriteString(w, `data: {"id":"chatcmpl-done-terminal","object":"chat.completion.chunk","model":"qwen2.5:0.5b","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_after_done","type":"function","function":{"name":"weather","arguments":"{\"city\":\"Austin\"}"}}]},"finish_reason":"tool_calls"}]}`+"\n\n")
	}))
	defer upstream.Close()

	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	proxy.SetDefaultAgentName("zeptoclaw")
	proxy.bindObservabilityV8Trace(runtime)
	proxy.SetModelRouter(staticModelRouter{decision: &ModelRouterDecision{
		Provider: "ollama", TargetURL: upstream.URL, TargetURLOverride: true, Model: "qwen2.5:0.5b",
	}})
	body := mustJSON(t, map[string]interface{}{
		"model": "openai/gpt-4o", "stream": true,
		"messages": []map[string]interface{}{{"role": "user", "content": "Say ok."}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	proxy.handleChatCompletion(rec, req)

	response := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(response, `"content":"ok"`) ||
		!strings.Contains(response, "data: [DONE]") {
		t.Fatalf("terminal stream status=%d body=%s", rec.Code, response)
	}
	if strings.Contains(response, "call_after_done") || strings.Count(response, "data: [DONE]") != 1 {
		t.Fatalf("post-DONE data was forwarded: %s", response)
	}
	_, model := assertProxyGeneratedAgentModel(
		t, capture.snapshot(), observability.OutcomeCompleted, "Ok",
	)
	toolCount, err := proxyCanonicalAttributes(t, model.Record())["defenseclaw.model.tool_call_count"].(json.Number).Int64()
	if err != nil || toolCount != 0 {
		t.Fatalf("post-DONE tool count=%d err=%v", toolCount, err)
	}
	rows, err := capture.store.ListEvents(30)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Action == string(gatewaylog.EventToolInvocation) {
			t.Fatalf("post-DONE tool emitted canonical event: %+v", row.Structured)
		}
	}
}

func TestSemanticRouterLongFinishReasonPreservesTerminalV8Trace(t *testing.T) {
	const responseModel = "qwen2.5:0.5b"
	longReason := strings.Repeat("f", hookModelV8MaxOutputFinishReasonBytes+1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"id": "chatcmpl-long-finish", "object": "chat.completion", "model": responseModel,
			"choices": []map[string]interface{}{{
				"index": 0, "message": map[string]string{"role": "assistant", "content": "ok"},
				"finish_reason": longReason,
			}},
		}); err != nil {
			t.Errorf("encode upstream response: %v", err)
		}
	}))
	defer upstream.Close()

	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	proxy.SetDefaultAgentName("zeptoclaw")
	proxy.bindObservabilityV8Trace(runtime)
	proxy.SetModelRouter(staticModelRouter{decision: &ModelRouterDecision{
		Provider: "ollama", TargetURL: upstream.URL, TargetURLOverride: true, Model: responseModel,
	}})
	body := mustJSON(t, map[string]interface{}{
		"model":    "openai/gpt-4o",
		"messages": []map[string]interface{}{{"role": "user", "content": "Return a response."}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	proxy.handleChatCompletion(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("long finish reason status=%d body=%s", rec.Code, rec.Body.String())
	}
	_, model := assertProxyGeneratedAgentModel(
		t, capture.snapshot(), observability.OutcomeCompleted, "Ok",
	)
	finishReasons, ok := proxyCanonicalAttributes(t, model.Record())["gen_ai.response.finish_reasons"].([]interface{})
	if !ok || len(finishReasons) != 1 || finishReasons[0] != longReason {
		t.Fatalf("long list-level finish reason=%v", finishReasons)
	}
}

func TestSemanticRouterRejectedTargetIsBlockedWithoutModelRequestTelemetry(t *testing.T) {
	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	proxy.SetDefaultAgentName("zeptoclaw")
	proxy.bindObservabilityV8Trace(runtime)
	proxy.SetModelRouter(staticModelRouter{decision: &ModelRouterDecision{
		Provider:          "vllm",
		TargetURL:         "http://10.0.0.8:8000",
		TargetURLOverride: true,
		Model:             "private-route",
		Reason:            "decision=private-route",
	}})

	body := mustJSON(t, map[string]interface{}{
		"model": "openai/gpt-4o",
		"messages": []map[string]interface{}{
			{"role": "user", "content": "Route this request."},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	proxy.handleChatCompletion(rec, req)

	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "private address") {
		t.Fatalf("rejected route status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Semantic-Router"); got != "routed" {
		t.Fatalf("semantic router header=%q", got)
	}
	agents := proxyGeneratedSpansForFamily(
		capture.snapshot(), observability.TelemetryFamilyAgentInvoke,
	)
	models := proxyGeneratedSpansForFamily(
		capture.snapshot(), observability.TelemetryFamilyModelChat,
	)
	if len(agents) != 1 || len(models) != 0 {
		t.Fatalf("rejected route agent/model spans=%d/%d", len(agents), len(models))
	}
	if agents[0].Record().Outcome() != observability.OutcomeBlocked ||
		agents[0].StatusCode().String() != "Ok" {
		t.Fatalf("rejected route agent outcome/status=%s/%s",
			agents[0].Record().Outcome(), agents[0].StatusCode())
	}
	if attributes := proxyCanonicalAttributes(t, agents[0].Record()); attributes["error.type"] != nil {
		t.Fatalf("intentional target block reported technical error=%v", attributes["error.type"])
	}

	rows, err := capture.store.ListEvents(30)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Action == string(gatewaylog.EventLLMPrompt) {
			t.Fatalf("rejected, undispatched route emitted model.request telemetry: %+v", row.Structured)
		}
	}
}

func TestTrustedRoutedLoopbackTargetIsNarrow(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/v1/chat/completions", nil)
	tests := []struct {
		name     string
		target   string
		provider string
		want     bool
	}{
		{name: "ollama alternate port", target: "http://127.0.0.1:11435", provider: "ollama", want: true},
		{name: "vllm ipv6 loopback", target: "http://[::1]:8000", provider: "vllm", want: true},
		{name: "proxy recursion", target: "http://127.0.0.1:8787", provider: "ollama", want: false},
		{name: "unrelated local service", target: "http://127.0.0.1:5432", provider: "openai", want: false},
		{name: "private network", target: "http://10.0.0.8:8000", provider: "vllm", want: false},
		{name: "userinfo", target: "http://user:pass@127.0.0.1:11435", provider: "ollama", want: false},
		{name: "missing port", target: "http://localhost", provider: "ollama", want: false},
		{name: "non http", target: "file://127.0.0.1:11435/tmp/model", provider: "ollama", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTrustedRoutedLoopbackTarget(request, tt.target, tt.provider); got != tt.want {
				t.Fatalf("isTrustedRoutedLoopbackTarget(%q, %q) = %t, want %t", tt.target, tt.provider, got, tt.want)
			}
		})
	}
}
