// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

func ciscoCorrelatedContext(t *testing.T) (context.Context, trace.SpanContext) {
	t.Helper()
	spanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		SpanID:  trace.SpanID{17, 18, 19, 20, 21, 22, 23, 24},
	})
	ctx := audit.ContextWithEnvelope(t.Context(), audit.CorrelationEnvelope{
		RequestID: "request-cisco", SessionID: "session-cisco", TurnID: "turn-cisco",
		AgentID: "agent-cisco", Connector: "codex",
	})
	return trace.ContextWithSpanContext(ctx, spanContext), spanContext
}

func ciscoMetricMap(metrics []telemetry.V8ProjectedMetric) map[string][]telemetry.V8ProjectedMetric {
	result := make(map[string][]telemetry.V8ProjectedMetric)
	for _, metric := range metrics {
		name := metric.Descriptor().Name
		if name == observability.TelemetryInstrumentDefenseClawCiscoErrors ||
			name == observability.TelemetryInstrumentDefenseClawCiscoInspectLatency {
			result[name] = append(result[name], metric)
		}
	}
	return result
}

func TestRecordCiscoInspectV8PreservesCorrelationAndCanonicalDimensions(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	ctx, spanContext := ciscoCorrelatedContext(t)
	recordCiscoInspectV8(
		ctx, runtime, 1500*time.Microsecond, observability.OutcomeFailed,
		gatewaylog.ErrCodeInvalidResponse,
	)

	metrics := ciscoMetricMap(capture.metricSnapshot())
	if len(metrics[observability.TelemetryInstrumentDefenseClawCiscoInspectLatency]) != 1 ||
		len(metrics[observability.TelemetryInstrumentDefenseClawCiscoErrors]) != 1 {
		t.Fatalf("Cisco generated metric families=%v", metrics)
	}
	latency := metrics[observability.TelemetryInstrumentDefenseClawCiscoInspectLatency][0]
	if latency.Attributes()["defenseclaw.outcome"] != string(observability.OutcomeFailed) {
		t.Fatalf("latency attributes=%v", latency.Attributes())
	}
	errorMetric := metrics[observability.TelemetryInstrumentDefenseClawCiscoErrors][0]
	if errorMetric.Attributes()["defenseclaw.metric.code"] != string(gatewaylog.ErrCodeInvalidResponse) {
		t.Fatalf("error attributes=%v", errorMetric.Attributes())
	}
	for _, metric := range []telemetry.V8ProjectedMetric{latency, errorMetric} {
		correlation := metric.CanonicalRecord().Correlation()
		if correlation.TraceID != spanContext.TraceID().String() ||
			correlation.SpanID != spanContext.SpanID().String() ||
			correlation.RequestID != "request-cisco" || correlation.TurnID != "turn-cisco" ||
			metric.CanonicalRecord().Connector() != "codex" {
			t.Fatalf("metric %s correlation=%+v connector=%q", metric.Descriptor().Name, correlation, metric.CanonicalRecord().Connector())
		}
	}
}

func TestCiscoInspectClientHTTPErrorEmitsGeneratedFailureMetrics(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, `{"detail":"bad"}`)
	}))
	t.Cleanup(srv.Close)

	runtime, capture := newProxyGeneratedTraceRuntime(t)
	client := newCiscoInspectTestClient(t, srv.URL, "TEST_CISCO_HTTP_ERROR")
	client.client = srv.Client()
	client.bindObservabilityV8(runtime)

	ctx, _ := ciscoCorrelatedContext(t)
	if verdict := client.Inspect(ctx, []ChatMessage{{Role: "user", Content: "hi"}}); verdict != nil {
		t.Fatalf("HTTP error verdict=%+v, want nil", verdict)
	}
	metrics := ciscoMetricMap(capture.metricSnapshot())
	if len(metrics[observability.TelemetryInstrumentDefenseClawCiscoInspectLatency]) != 1 ||
		len(metrics[observability.TelemetryInstrumentDefenseClawCiscoErrors]) != 1 ||
		metrics[observability.TelemetryInstrumentDefenseClawCiscoInspectLatency][0].Attributes()["defenseclaw.outcome"] != string(observability.OutcomeFailed) {
		t.Fatalf("HTTP error generated metrics=%v", metrics)
	}
}

func TestCiscoInspectClientInvalidJSONEmitsGeneratedFailureMetrics(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `not-json`)
	}))
	t.Cleanup(srv.Close)

	runtime, capture := newProxyGeneratedTraceRuntime(t)
	client := newCiscoInspectTestClient(t, srv.URL, "TEST_CISCO_INVALID_JSON")
	client.client = srv.Client()
	client.bindObservabilityV8(runtime)

	ctx, _ := ciscoCorrelatedContext(t)
	if verdict := client.Inspect(ctx, []ChatMessage{{Role: "user", Content: "x"}}); verdict != nil {
		t.Fatalf("invalid JSON verdict=%+v, want nil", verdict)
	}
	metrics := ciscoMetricMap(capture.metricSnapshot())
	if len(metrics[observability.TelemetryInstrumentDefenseClawCiscoInspectLatency]) != 1 ||
		len(metrics[observability.TelemetryInstrumentDefenseClawCiscoErrors]) != 1 {
		t.Fatalf("invalid JSON generated metrics=%v", metrics)
	}
}

func TestCiscoInspectClientNetworkErrorUsesGeneratedUpstreamCode(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	client := newCiscoInspectTestClient(t, "http://127.0.0.1:1", "TEST_CISCO_NETWORK_ERROR")
	client.client = &http.Client{Timeout: 200 * time.Millisecond}
	client.bindObservabilityV8(runtime)

	ctx, _ := ciscoCorrelatedContext(t)
	if verdict := client.Inspect(ctx, []ChatMessage{{Role: "user", Content: "x"}}); verdict != nil {
		t.Fatalf("network error verdict=%+v, want nil", verdict)
	}
	metrics := ciscoMetricMap(capture.metricSnapshot())
	if len(metrics[observability.TelemetryInstrumentDefenseClawCiscoErrors]) != 1 ||
		metrics[observability.TelemetryInstrumentDefenseClawCiscoErrors][0].Attributes()["defenseclaw.metric.code"] != string(gatewaylog.ErrCodeUpstreamError) {
		t.Fatalf("network error generated metrics=%v", metrics)
	}
}

func TestCiscoInspectClientSuccessRecordsCanonicalLatencyOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"is_safe":true,"action":"allow"}`)
	}))
	t.Cleanup(srv.Close)

	runtime, capture := newProxyGeneratedTraceRuntime(t)
	client := newCiscoInspectTestClient(t, srv.URL, "TEST_CISCO_SUCCESS")
	client.client = srv.Client()
	client.bindObservabilityV8(runtime)

	ctx, _ := ciscoCorrelatedContext(t)
	verdict := client.Inspect(ctx, []ChatMessage{{Role: "user", Content: "ok"}})
	if verdict == nil || !strings.Contains(verdict.Scanner, "ai-defense") {
		t.Fatalf("success verdict=%+v", verdict)
	}
	metrics := ciscoMetricMap(capture.metricSnapshot())
	latencies := metrics[observability.TelemetryInstrumentDefenseClawCiscoInspectLatency]
	if len(latencies) != 1 || len(metrics[observability.TelemetryInstrumentDefenseClawCiscoErrors]) != 0 ||
		latencies[0].Attributes()["defenseclaw.outcome"] != string(observability.OutcomeCompleted) {
		t.Fatalf("success generated metrics=%v", metrics)
	}
	if spans := capture.snapshot(); len(spans) != 0 {
		t.Fatalf("Cisco client fabricated %d standalone spans; phase owner must construct the span", len(spans))
	}
}

func TestCiscoInspectGeneratedLatencyJoinsExactAIDPhaseSpan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"is_safe":true,"action":"allow"}`)
	}))
	t.Cleanup(srv.Close)

	runtime, capture := newProxyGeneratedTraceRuntime(t)
	client := newCiscoInspectTestClient(t, srv.URL, "TEST_CISCO_PHASE_JOIN")
	client.client = srv.Client()
	inspector := NewGuardrailInspector("remote", client, nil, "")
	configureGuardrailInspectorObservabilityV8(inspector, runtime, func() string { return "codex" })

	ctx, _ := ciscoCorrelatedContext(t)
	verdict := inspector.Inspect(
		ctx, "prompt", "ordinary prompt",
		[]ChatMessage{{Role: "user", Content: "ordinary prompt"}}, "gpt-4", "action",
	)
	if verdict == nil {
		t.Fatal("generated Cisco inspection returned nil verdict")
	}

	var phase telemetry.V8CanonicalEndedSpan
	for _, span := range capture.snapshot() {
		attributes := proxyCanonicalAttributes(t, span.Record())
		if attributes["defenseclaw.guardrail.phase"] == "ai_defense" {
			phase = span
		}
		if span.Name() == "cisco.inspect.chat" {
			t.Fatal("legacy standalone Cisco span was emitted")
		}
	}
	if phase.Name() == "" {
		t.Fatalf("generated spans missing ai_defense phase: %v", capture.snapshot())
	}
	metrics := ciscoMetricMap(capture.metricSnapshot())
	latencies := metrics[observability.TelemetryInstrumentDefenseClawCiscoInspectLatency]
	if len(latencies) != 1 {
		t.Fatalf("generated Cisco latency metrics=%v", metrics)
	}
	correlation := latencies[0].CanonicalRecord().Correlation()
	if correlation.TraceID != phase.TraceID().String() || correlation.SpanID != phase.SpanID().String() {
		t.Fatalf(
			"Cisco latency correlation=%s/%s want phase=%s/%s",
			correlation.TraceID, correlation.SpanID, phase.TraceID(), phase.SpanID(),
		)
	}
}

func TestCiscoInspectClientRequestContextCancelsUpstream(t *testing.T) {
	requestStarted := make(chan struct{}, 1)
	requestCancelled := make(chan struct{}, 1)
	client := newCiscoInspectTestClient(t, "https://inspect.example.test", "TEST_CISCO_CANCEL")
	client.client = &http.Client{Transport: ciscoRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requestStarted <- struct{}{}
		<-request.Context().Done()
		requestCancelled <- struct{}{}
		return nil, request.Context().Err()
	})}
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan *ScanVerdict, 1)
	go func() {
		result <- client.Inspect(ctx, []ChatMessage{{Role: "user", Content: "cancel"}})
	}()
	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("Cisco request did not reach the test server")
	}
	cancel()
	select {
	case <-requestCancelled:
	case <-time.After(time.Second):
		t.Fatal("Cisco upstream request did not observe caller cancellation")
	}
	select {
	case verdict := <-result:
		if verdict != nil {
			t.Fatalf("cancelled request verdict=%+v, want nil", verdict)
		}
	case <-time.After(time.Second):
		t.Fatal("Cisco inspection did not return after caller cancellation")
	}
}

type ciscoRoundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip ciscoRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func newCiscoInspectTestClient(t *testing.T, endpoint, environment string) *CiscoInspectClient {
	t.Helper()
	t.Setenv(environment, "test-key")
	client := NewCiscoInspectClient(&config.CiscoAIDefenseConfig{
		Endpoint: endpoint, TimeoutMs: 5000, APIKeyEnv: environment,
	}, "")
	if client == nil {
		t.Fatal("expected Cisco AI Defense client")
	}
	return client
}

// TestCiscoInspectClient_WireParity is the G2 golden-request test. It
// pins the opensource / API-key inspection client's outbound HTTP shape
// so any accidental drift in URL suffix, header order/values, or JSON
// payload structure fails the test immediately. Non-managed users must
// see byte-identical requests regardless of internal refactors.
func TestCiscoInspectClient_WireParity(t *testing.T) {
	var (
		gotMethod   string
		gotURLPath  string
		gotHeaders  http.Header
		gotBody     []byte
		gotContent  string
		gotAccept   string
		gotAPIKey   string
		gotBearer   string
		requestSeen bool
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotURLPath = r.URL.Path
		gotHeaders = r.Header.Clone()
		gotContent = r.Header.Get("Content-Type")
		gotAccept = r.Header.Get("Accept")
		gotAPIKey = r.Header.Get("X-Cisco-AI-Defense-API-Key")
		gotBearer = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		gotBody = body
		requestSeen = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"is_safe":true,"action":"Allow"}`)
	}))
	t.Cleanup(srv.Close)

	c := NewCiscoInspectClient(&config.CiscoAIDefenseConfig{
		Endpoint:  srv.URL,
		APIKey:    "test-golden-key",
		TimeoutMs: 3000,
		// Rely on the default enabledRules to lock the payload shape.
	}, "")
	if c == nil {
		t.Fatal("expected non-nil client with APIKey set")
	}

	verdict := c.Inspect(t.Context(), []ChatMessage{
		{Role: "system", Content: "You are a helpful assistant."},
		{Role: "user", Content: "hello"},
	})
	if !requestSeen {
		t.Fatal("expected server to receive at least one request")
	}
	if verdict == nil {
		t.Fatal("expected non-nil verdict on 200 response")
	}

	// URL and method: /api/v1/inspect/chat, POST.
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotURLPath != "/api/v1/inspect/chat" {
		t.Errorf("url path = %q, want /api/v1/inspect/chat", gotURLPath)
	}
	// Headers: exact values, API-key path uses X-Cisco-AI-Defense-API-Key.
	if gotContent != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContent)
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept = %q, want application/json", gotAccept)
	}
	if gotAPIKey != "test-golden-key" {
		t.Errorf("X-Cisco-AI-Defense-API-Key = %q, want test-golden-key", gotAPIKey)
	}
	if gotBearer != "" {
		t.Errorf("Authorization header must NOT be set on opensource path, got %q", gotBearer)
	}
	// Sanity: verify no unexpected headers snuck in on the request. We
	// only assert absence of managed-mode-specific headers here.
	for k := range gotHeaders {
		low := strings.ToLower(k)
		if low == "authorization" {
			t.Errorf("unexpected Authorization header present: %q", k)
		}
	}
	// Body shape: messages[].content is a plain STRING (not
	// {"text": ...}), and there is no device_id / dc_metadata. This is
	// what distinguishes /api/v1/inspect/chat from the managed
	// /api/v1/inspect/defense_claw payload.
	bodyStr := string(gotBody)
	if !strings.Contains(bodyStr, `"messages":`) {
		t.Errorf("body missing messages array: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, `"content":"You are a helpful assistant."`) {
		t.Errorf("content field must be a plain string on the API-key path; body = %s", bodyStr)
	}
	if strings.Contains(bodyStr, `"device_id"`) {
		t.Errorf("device_id must NOT appear in the opensource payload; body = %s", bodyStr)
	}
	if strings.Contains(bodyStr, `"dc_metadata"`) {
		t.Errorf("dc_metadata must NOT appear in the opensource payload; body = %s", bodyStr)
	}
	if !strings.Contains(bodyStr, `"enabled_rules":`) {
		t.Errorf("body missing config.enabled_rules; body = %s", bodyStr)
	}
	// The default enabledRules list is 12 entries; the exact set is
	// deliberately not asserted here so operators can add rules without
	// breaking this test, but the format-invariant is that each entry
	// is a {"rule_name": "..."} object.
	if !strings.Contains(bodyStr, `{"rule_name":"Prompt Injection"}`) {
		t.Errorf("first default rule not present in enabled_rules; body = %s", bodyStr)
	}
}
