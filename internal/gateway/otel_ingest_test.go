// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// TestOTLPIngest_Logs_AcceptsValidPayload pins the success path: a
// well-formed OTLP-JSON logs body produces an HTTP 200 with the
// canonical empty-success body so the OTel exporter does NOT
// retry. We also assert the response Content-Type is
// application/json so OTel SDKs that validate the response can
// parse it.
func TestOTLPIngest_Logs_AcceptsValidPayload(t *testing.T) {
	a := &APIServer{}
	body := `{
		"resourceLogs": [{
			"resource": {
				"attributes": [{"key": "service.name", "value": {"stringValue": "codex"}}]
			},
			"scopeLogs": [{
				"logRecords": [
					{"timeUnixNano": "1700000000000000000", "body": {"stringValue": "hello"}},
					{"timeUnixNano": "1700000000100000000", "body": {"stringValue": "world"}}
				]
			}]
		}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-defenseclaw-source", "codex")
	w := httptest.NewRecorder()

	a.handleOTLPLogs(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "{}" {
		t.Errorf("body = %q, want canonical OTLP empty-success body \"{}\" (else exporter retries)", got)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestOTLPIngest_Logs_EnrichesHTTPSpanWithConversationID(t *testing.T) {
	gatewaylog.SetProcessRunID("run-otlp-123")
	t.Cleanup(func() { gatewaylog.SetProcessRunID("") })

	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exp),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	defer otel.SetTracerProvider(prev)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	api := &APIServer{}
	handler := otelHTTPServerMiddleware("sidecar-api", http.HandlerFunc(api.handleOTLPLogs))

	body := `{
		"resourceLogs": [{
			"resource": {
				"attributes": [{"key": "service.name", "value": {"stringValue": "codex-cli"}}]
			},
			"scopeLogs": [{
				"logRecords": [{
					"attributes": [
						{"key": "event.name", "value": {"stringValue": "codex.sse_event"}},
						{"key": "event.kind", "value": {"stringValue": "response.completed"}},
						{"key": "conversation.id", "value": {"stringValue": "session-123"}},
						{"key": "input_token_count", "value": {"stringValue": "123"}},
						{"key": "output_token_count", "value": {"stringValue": "45"}}
					]
				}]
			}]
		}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-defenseclaw-source", "codex")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%s", w.Code, w.Body.String())
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans want 1", len(spans))
	}
	s := spans[0]
	if s.Name != "POST /v1/logs" {
		t.Fatalf("span name=%q want POST /v1/logs", s.Name)
	}
	for key, want := range map[string]string{
		"gen_ai.conversation.id": "session-123",
		"gen_ai.agent.type":      "codex",
		"defenseclaw.run.id":     "run-otlp-123",
	} {
		got, ok := attrByKey(s.Attributes, key)
		if !ok || got.AsString() != want {
			t.Fatalf("%s=%q ok=%v want %q", key, got.AsString(), ok, want)
		}
	}
}

// TestOTLPIngest_Logs_RejectsNonJSONContentType pins the 415
// contract. Codex and Claude Code both emit OTLP-JSON; protobuf
// is intentionally not yet supported. A wrong-Content-Type
// request must surface a structured 415 (rather than parse
// failure) so the operator's exporter logs make the protocol
// mismatch obvious.
func TestOTLPIngest_Logs_RejectsNonJSONContentType(t *testing.T) {
	a := &APIServer{}
	req := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(`payload`))
	req.Header.Set("Content-Type", "application/x-protobuf")
	w := httptest.NewRecorder()

	a.handleOTLPLogs(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want 415; body=%q", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "application/json") {
		t.Errorf("error body should mention application/json so operator knows the supported shape; got %q", w.Body.String())
	}
}

// TestOTLPIngest_Logs_RejectsNonPOST guards the method contract.
// OTLP-HTTP is POST-only per the spec; GET/PUT/DELETE etc. must
// 405 so a misconfigured exporter (or a probing scanner) gets a
// clear answer.
func TestOTLPIngest_Logs_RejectsNonPOST(t *testing.T) {
	a := &APIServer{}
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/v1/logs", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		a.handleOTLPLogs(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want 405", method, w.Code)
		}
	}
}

// TestOTLPIngest_Logs_MalformedBody_StillReturns200 guards a
// counter-intuitive but important invariant: a malformed body
// (parse error after content-type passes) must still return 200.
// Otherwise OTel exporters retry the same broken batch
// indefinitely, generating sustained load on a degraded gateway.
// We rely on the audit log to surface the parse failure for
// operator investigation.
func TestOTLPIngest_Logs_MalformedBody_StillReturns200(t *testing.T) {
	a := &APIServer{}
	req := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(`{not-json`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	a.handleOTLPLogs(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (malformed bodies must not trigger exporter retry storms)", w.Code)
	}
}

// TestOTLPIngest_Metrics_AcceptsValidPayload mirrors the logs
// happy path but exercises the metrics envelope shape so we
// don't regress on the resourceMetrics/scopeMetrics/metrics
// nested keys.
func TestOTLPIngest_Metrics_AcceptsValidPayload(t *testing.T) {
	a := &APIServer{}
	body := `{
		"resourceMetrics": [{
			"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "claudecode"}}]},
			"scopeMetrics": [{
				"metrics": [
					{"name": "claude.tokens", "sum": {"dataPoints": [{"asInt": "100"}]}},
					{"name": "claude.latency_ms", "histogram": {"dataPoints": [{}]}}
				]
			}]
		}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/metrics", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-defenseclaw-source", "claudecode")
	w := httptest.NewRecorder()

	a.handleOTLPMetrics(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
}

func TestOTLPIngest_Logs_PromotesCodexTokenUsage(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	otelProvider, err := telemetry.NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer otelProvider.Shutdown(context.Background())

	a := &APIServer{}
	a.SetOTelProvider(otelProvider)
	body := `{
		"resourceLogs": [{
			"resource": {
				"attributes": [{"key": "service.name", "value": {"stringValue": "codex-cli"}}]
			},
			"scopeLogs": [{
				"logRecords": [{
					"attributes": [
						{"key": "event.name", "value": {"stringValue": "codex.sse_event"}},
						{"key": "event.kind", "value": {"stringValue": "response.completed"}},
						{"key": "model", "value": {"stringValue": "gpt-5-codex"}},
						{"key": "input_tokens", "value": {"stringValue": "123"}},
						{"key": "gen_ai.usage", "value": {"kvlistValue": {"values": [
							{"key": "output_tokens", "value": {"stringValue": "45"}}
						]}}},
						{"key": "cached_token_count", "value": {"stringValue": "7"}},
						{"key": "reasoning_token_count", "value": {"stringValue": "11"}}
					]
				}]
			}]
		}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-defenseclaw-source", "codex")
	w := httptest.NewRecorder()

	a.handleOTLPLogs(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	tokenMetric := findMetric(rm, "gen_ai.client.token.usage")
	if tokenMetric == nil {
		t.Fatal("expected gen_ai.client.token.usage metric")
		return
	}
	tokenHist, ok := tokenMetric.Data.(metricdata.Histogram[float64])
	if !ok {
		t.Fatalf("expected Histogram[float64], got %T", tokenMetric.Data)
	}

	var gotInput, gotOutput bool
	for _, dp := range tokenHist.DataPoints {
		var tokenType, agentName string
		for _, attr := range dp.Attributes.ToSlice() {
			switch string(attr.Key) {
			case "gen_ai.token.type":
				tokenType = attr.Value.AsString()
			case "gen_ai.agent.name":
				agentName = attr.Value.AsString()
			}
		}
		if agentName != "codex" {
			t.Fatalf("gen_ai.agent.name = %q, want codex", agentName)
		}
		switch tokenType {
		case "input":
			gotInput = dp.Sum == 123
		case "output":
			gotOutput = dp.Sum == 45
		}
	}
	if !gotInput || !gotOutput {
		t.Fatalf("token histogram missing input/output sums: input=%v output=%v", gotInput, gotOutput)
	}
}

func TestOTLPIngest_Metrics_PromotesClaudeCodeTokenUsage(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	otelProvider, err := telemetry.NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer otelProvider.Shutdown(context.Background())

	a := &APIServer{}
	a.SetOTelProvider(otelProvider)
	body := `{
		"resourceMetrics": [{
			"resource": {
				"attributes": [{"key": "service.name", "value": {"stringValue": "claude-code"}}]
			},
			"scopeMetrics": [{
				"metrics": [{
					"name": "claude_code.token.usage",
					"sum": {
						"dataPoints": [
							{
								"attributes": [
									{"key": "type", "value": {"stringValue": "input"}},
									{"key": "model", "value": {"stringValue": "claude-sonnet-4-5"}}
								],
								"asInt": "321"
							},
							{
								"attributes": [
									{"key": "type", "value": {"stringValue": "cacheRead"}},
									{"key": "model", "value": {"stringValue": "claude-sonnet-4-5"}}
								],
								"asDouble": 17
							}
						]
					}
				}]
			}]
		}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/metrics", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-defenseclaw-source", "claudecode")
	w := httptest.NewRecorder()

	a.handleOTLPMetrics(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	tokenMetric := findMetric(rm, "gen_ai.client.token.usage")
	if tokenMetric == nil {
		t.Fatal("expected gen_ai.client.token.usage metric")
		return
	}
	tokenHist, ok := tokenMetric.Data.(metricdata.Histogram[float64])
	if !ok {
		t.Fatalf("expected Histogram[float64], got %T", tokenMetric.Data)
	}

	got := map[string]float64{}
	for _, dp := range tokenHist.DataPoints {
		var tokenType, agentName string
		for _, attr := range dp.Attributes.ToSlice() {
			switch string(attr.Key) {
			case "gen_ai.token.type":
				tokenType = attr.Value.AsString()
			case "gen_ai.agent.name":
				agentName = attr.Value.AsString()
			}
		}
		if agentName != "claudecode" {
			t.Fatalf("gen_ai.agent.name = %q, want claudecode", agentName)
		}
		got[tokenType] = dp.Sum
	}
	if got["input"] != 321 || got["cacheRead"] != 17 {
		t.Fatalf("token histogram sums = %#v, want input=321 cacheRead=17", got)
	}
}

func TestOTLPIngest_Logs_PromotesCodexOperationDuration(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	otelProvider, err := telemetry.NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer otelProvider.Shutdown(context.Background())

	a := &APIServer{}
	a.SetOTelProvider(otelProvider)
	body := `{
		"resourceLogs": [{
			"resource": {
				"attributes": [{"key": "service.name", "value": {"stringValue": "codex-cli"}}]
			},
			"scopeLogs": [{
				"logRecords": [{
					"attributes": [
						{"key": "event.name", "value": {"stringValue": "codex.sse_event"}},
						{"key": "event.kind", "value": {"stringValue": "response.completed"}},
						{"key": "model", "value": {"stringValue": "gpt-5-codex"}},
						{"key": "duration_ms", "value": {"intValue": "2500"}}
					]
				}]
			}]
		}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-defenseclaw-source", "codex")
	w := httptest.NewRecorder()

	a.handleOTLPLogs(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	durationMetric := findMetric(rm, "gen_ai.client.operation.duration")
	if durationMetric == nil {
		t.Fatal("expected gen_ai.client.operation.duration metric")
		return
	}
	durationHist, ok := durationMetric.Data.(metricdata.Histogram[float64])
	if !ok {
		t.Fatalf("expected Histogram[float64], got %T", durationMetric.Data)
	}
	var got bool
	for _, dp := range durationHist.DataPoints {
		var agentName string
		for _, attr := range dp.Attributes.ToSlice() {
			if string(attr.Key) == "gen_ai.agent.name" {
				agentName = attr.Value.AsString()
			}
		}
		if agentName == "codex" && dp.Sum == 2.5 {
			got = true
		}
	}
	if !got {
		t.Fatalf("duration histogram missing codex 2.5s sample: %#v", durationHist.DataPoints)
	}
}

func TestOTLPIngest_Metrics_PromotesNativeOperationDuration(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	otelProvider, err := telemetry.NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer otelProvider.Shutdown(context.Background())

	a := &APIServer{}
	a.SetOTelProvider(otelProvider)
	body := `{
		"resourceMetrics": [{
			"resource": {
				"attributes": [{"key": "service.name", "value": {"stringValue": "claude-code"}}]
			},
			"scopeMetrics": [{
				"metrics": [{
					"name": "gen_ai.client.operation.duration",
					"unit": "ms",
					"histogram": {
						"dataPoints": [{
							"attributes": [
								{"key": "model", "value": {"stringValue": "claude-sonnet-4-5"}}
							],
							"sum": 5000,
							"count": "2"
						}]
					}
				}]
			}]
		}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/metrics", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-defenseclaw-source", "claudecode")
	w := httptest.NewRecorder()

	a.handleOTLPMetrics(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	durationMetric := findMetric(rm, "gen_ai.client.operation.duration")
	if durationMetric == nil {
		t.Fatal("expected gen_ai.client.operation.duration metric")
		return
	}
	durationHist, ok := durationMetric.Data.(metricdata.Histogram[float64])
	if !ok {
		t.Fatalf("expected Histogram[float64], got %T", durationMetric.Data)
	}
	var got bool
	for _, dp := range durationHist.DataPoints {
		var agentName string
		for _, attr := range dp.Attributes.ToSlice() {
			if string(attr.Key) == "gen_ai.agent.name" {
				agentName = attr.Value.AsString()
			}
		}
		if agentName == "claudecode" && dp.Sum == 2.5 {
			got = true
		}
	}
	if !got {
		t.Fatalf("duration histogram missing claudecode 2.5s sample: %#v", durationHist.DataPoints)
	}
}

// TestOTLPIngest_Traces_AcceptsValidPayload mirrors the logs path
// for trace bodies (resourceSpans/scopeSpans/spans).
func TestOTLPIngest_Traces_AcceptsValidPayload(t *testing.T) {
	a := &APIServer{}
	body := `{
		"resourceSpans": [{
			"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "codex"}}]},
			"scopeSpans": [{
				"spans": [
					{"name": "codex.run", "spanId": "abc", "traceId": "def"},
					{"name": "codex.exec_command", "spanId": "ghi", "traceId": "def"}
				]
			}]
		}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/traces", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	a.handleOTLPTraces(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
}

// TestOTLPIngest_IsOTLPJSONContentType_AcceptsParameters guards the
// content-type matcher: the OTel SDK in some languages appends
// "; charset=utf-8" or similar parameters, and our matcher must
// strip those before comparing. Without this, a perfectly valid
// JSON payload would 415 because its Content-Type wasn't an
// exact-string match.
func TestOTLPIngest_IsOTLPJSONContentType_AcceptsParameters(t *testing.T) {
	cases := []struct {
		ct   string
		want bool
	}{
		{"application/json", true},
		{"application/json; charset=utf-8", true},
		{"application/json;charset=utf-8", true},
		{"  application/json  ", true},
		{"APPLICATION/JSON", true},
		{"application/x-protobuf", false},
		{"text/plain", false},
		{"", false},
	}
	for _, c := range cases {
		got := isOTLPJSONContentType(c.ct)
		if got != c.want {
			t.Errorf("isOTLPJSONContentType(%q) = %v, want %v", c.ct, got, c.want)
		}
	}
}

// TestOTLPIngest_SummarizeLogs_CountsResourcesAndRecords pins the
// audit summary contract. The Details column for /v1/logs events
// must include the resource count and the leaf record count so a
// SIEM rule can alert on "service X went silent for 5 minutes" or
// "batch sizes spiked 10x".
func TestOTLPIngest_SummarizeLogs_CountsResourcesAndRecords(t *testing.T) {
	body := []byte(`{
		"resourceLogs": [
			{
				"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "codex"}}]},
				"scopeLogs": [{"logRecords": [{}, {}, {}]}]
			},
			{
				"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "codex"}}]},
				"scopeLogs": [{"logRecords": [{}]}]
			}
		]
	}`)
	got, stats, err := summarizeOTLPPayload(body, otelSignalLogs)
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	if !strings.Contains(got, "resources=2") {
		t.Errorf("summary missing resources=2; got %q", got)
	}
	if !strings.Contains(got, "logRecords=4") {
		t.Errorf("summary missing logRecords=4; got %q", got)
	}
	if !strings.Contains(got, "codex=2") {
		t.Errorf("summary missing service grouping codex=2; got %q", got)
	}
	if stats.Records != 4 {
		t.Errorf("stats.Records = %d, want 4 (one per leaf logRecord) — used by the otel.ingest.records counter", stats.Records)
	}
	if stats.Resources != 2 {
		t.Errorf("stats.Resources = %d, want 2", stats.Resources)
	}
}

// TestCodexNotify_AcceptsValidPayload pins the notify-bridge happy
// path: a JSON arg with a known type produces an audit event under
// codex.notify.<type> and returns 200.
func TestCodexNotify_AcceptsValidPayload(t *testing.T) {
	a := &APIServer{}
	body := `{"type": "agent-turn-complete", "turn_id": "turn-123", "model": "gpt-5"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/notify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	a.handleCodexNotify(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "{}" {
		t.Errorf("body = %q, want \"{}\"", got)
	}
}

// TestCodexNotify_RejectsNonJSONContentType pins the 415 contract.
// The notify bridge always sets Content-Type: application/json; a
// bypass attempt with form-encoded or text/plain must be rejected
// loud rather than silently audited.
func TestCodexNotify_RejectsNonJSONContentType(t *testing.T) {
	a := &APIServer{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/notify",
		strings.NewReader(`type=agent-turn-complete`))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	a.handleCodexNotify(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want 415", w.Code)
	}
}

// TestCodexNotify_SanitizesNotifyType ensures sanitizeNotifyType
// can't produce an audit Action key with hostile characters
// (slashes, newlines, etc.) that downstream SIEM regex queries
// might match against. The transformation is destructive but
// safe: any disallowed character becomes a dash.
func TestCodexNotify_SanitizesNotifyType(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"agent-turn-complete", "agent-turn-complete"},
		{"AgentTurnComplete", "agentturncomplete"},
		{"foo bar/baz", "foo-bar-baz"},
		{"with\nnewline", "with-newline"},
		{"  whitespace  ", "whitespace"},
		{"", "unknown"},
		{"/////", "-----"},
	}
	for _, c := range cases {
		got := sanitizeNotifyType(c.in)
		if got != c.want {
			t.Errorf("sanitizeNotifyType(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// newOTLPIngestTestStore wires a temp SQLite store + Logger so the
// ingest handler tests can read back audit rows. The audit logger
// is the only path through which persistAuditEvent observes whether
// the typed action constants survived sanitizeEvent / store.LogEvent.
func newOTLPIngestTestStore(t *testing.T) (*audit.Store, *audit.Logger) {
	t.Helper()
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	logger := audit.NewLogger(store)
	t.Cleanup(func() { logger.Close() })
	return store, logger
}

// TestOTLPIngest_PersistsTypedAuditAction pins the registry contract:
// the OTLP handler must NOT smuggle freeform action keys through the
// audit DB. Every row emitted from the happy path on /v1/logs must
// match audit.ActionOTelIngestLogs verbatim so dashboards filtering
// on action="otel.ingest.logs" stay green and the strict JSON-schema
// gate doesn't drop the row.
func TestOTLPIngest_PersistsTypedAuditAction(t *testing.T) {
	store, logger := newOTLPIngestTestStore(t)
	a := &APIServer{store: store, logger: logger}

	body := `{
		"resourceLogs": [{
			"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "codex"}}]},
			"scopeLogs": [{"logRecords": [{}]}]
		}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-defenseclaw-source", "codex")
	w := httptest.NewRecorder()
	a.handleOTLPLogs(w, req)
	logger.Close() // flush

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}

	// Allow background goroutines to complete (sinks, structured emitter).
	time.Sleep(50 * time.Millisecond)

	rows, err := store.ListEvents(10)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%d want 1; rows=%+v", len(rows), rows)
	}
	if got, want := rows[0].Action, string(audit.ActionOTelIngestLogs); got != want {
		t.Errorf("audit Action = %q, want %q (typed constant from internal/audit/actions.go)", got, want)
	}
	if !audit.IsKnownAction(rows[0].Action) {
		t.Errorf("audit Action %q is not in AllActions(); the action enum must reject unknown values", rows[0].Action)
	}
}

// TestOTLPIngest_MalformedPersistsTypedAuditAction guards the failure
// branch: a body that fails to parse must still hit the audit DB
// under audit.ActionOTelIngestMalformed (not "malformed" or any
// other freeform key). Operators rely on filtering by this exact
// constant to spot connector schema drift.
func TestOTLPIngest_MalformedPersistsTypedAuditAction(t *testing.T) {
	store, logger := newOTLPIngestTestStore(t)
	a := &APIServer{store: store, logger: logger}

	req := httptest.NewRequest(http.MethodPost, "/v1/metrics", strings.NewReader(`{not-json`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-defenseclaw-source", "claudecode")
	w := httptest.NewRecorder()
	a.handleOTLPMetrics(w, req)
	logger.Close()

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d (malformed must still 200 to prevent retry storms)", w.Code)
	}

	time.Sleep(50 * time.Millisecond)

	rows, err := store.ListEvents(10)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%d want 1", len(rows))
	}
	if got, want := rows[0].Action, string(audit.ActionOTelIngestMalformed); got != want {
		t.Errorf("malformed Action = %q, want %q", got, want)
	}
	if rows[0].Severity != "WARN" {
		t.Errorf("malformed Severity = %q, want WARN", rows[0].Severity)
	}
}

// TestCodexNotify_PersistsDynamicSuffixAction pins the dynamic
// codex.notify.<sanitized-type> family. The static enum lists
// codex.notify.agent-turn-complete explicitly; everything else
// must still pass IsKnownActionPrefix so future codex notify types
// don't get rejected by audit-event validators.
func TestCodexNotify_PersistsDynamicSuffixAction(t *testing.T) {
	store, logger := newOTLPIngestTestStore(t)
	a := &APIServer{store: store, logger: logger}

	body := `{"type": "agent-turn-complete", "turn-id": "turn-abc", "model": "gpt-5", "status": "success"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/notify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.handleCodexNotify(w, req)
	logger.Close()

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}

	time.Sleep(50 * time.Millisecond)

	rows, err := store.ListEvents(10)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%d want 1", len(rows))
	}
	if got, want := rows[0].Action, "codex.notify.agent-turn-complete"; got != want {
		t.Errorf("Action = %q, want %q", got, want)
	}
	// Must satisfy *either* the static enum OR the prefix matcher.
	// audit-event.json validators in downstream SIEMs use the same
	// disjunction.
	if !audit.IsKnownAction(rows[0].Action) && !audit.IsKnownActionPrefix(rows[0].Action) {
		t.Errorf("audit Action %q matches neither IsKnownAction nor IsKnownActionPrefix", rows[0].Action)
	}
	if rows[0].SessionID != "turn-abc" {
		t.Errorf("SessionID = %q, want %q (codex notify rows must fall back to turn-id when thread-id is absent)", rows[0].SessionID, "turn-abc")
	}
	if strings.Contains(rows[0].Details, body) {
		t.Fatalf("Details stored raw notify body: %q", rows[0].Details)
	}
	if !strings.Contains(rows[0].Details, "body_sha256") || !strings.Contains(rows[0].Details, "body_len") {
		t.Fatalf("Details missing redacted notify summary fields: %q", rows[0].Details)
	}
}

func TestCodexNotifyAuditDetails_RedactsRawPayload(t *testing.T) {
	redaction.SetDisableAll(false)
	t.Cleanup(func() { redaction.SetDisableAll(false) })

	body := []byte(`{"type":"agent-turn-complete","turn-id":"turn-secret-123","model":"gpt-5","status":"ok","prompt":"please leak sk-secret-token"}`)
	details := codexNotifyAuditDetails(codexNotifyPayload{
		Type:   "agent-turn-complete",
		TurnID: "turn-secret-123",
		Model:  "gpt-5",
		Status: "ok",
	}, body, "agent-turn-complete", "ok", nil)

	for _, forbidden := range []string{"please leak", "sk-secret-token", string(body)} {
		if strings.Contains(details, forbidden) {
			t.Fatalf("notify details leaked raw payload content %q: %s", forbidden, details)
		}
	}
	for _, want := range []string{"body_len", "body_sha256", "agent-turn-complete"} {
		if !strings.Contains(details, want) {
			t.Fatalf("notify details missing %q: %s", want, details)
		}
	}
}

func TestCodexNotifyAuditDetails_IncludesRawPayloadWhenRedactionDisabled(t *testing.T) {
	redaction.SetDisableAll(true)
	t.Cleanup(func() { redaction.SetDisableAll(false) })

	body := []byte(`{"type":"agent-turn-complete","prompt":"please log raw"}`)
	details := codexNotifyAuditDetails(codexNotifyPayload{
		Type: "agent-turn-complete",
	}, body, "agent-turn-complete", "ok", nil)

	if !strings.Contains(details, `raw_body="{\"type\":\"agent-turn-complete\",\"prompt\":\"please log raw\"}"`) {
		t.Fatalf("notify details missing raw body in raw mode: %s", details)
	}
}

// TestCodexNotify_NoTypePersistsBareAction ensures a notify payload
// without a `type` field produces audit.ActionCodexNotify (the bare
// "codex.notify" key) rather than "codex.notify." with an empty
// suffix that would slip past the prefix matcher.
func TestCodexNotify_NoTypePersistsBareAction(t *testing.T) {
	store, logger := newOTLPIngestTestStore(t)
	a := &APIServer{store: store, logger: logger}

	body := `{"turn-id": "turn-xyz"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/notify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.handleCodexNotify(w, req)
	logger.Close()

	time.Sleep(50 * time.Millisecond)

	rows, err := store.ListEvents(10)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%d want 1", len(rows))
	}
	if got, want := rows[0].Action, string(audit.ActionCodexNotify); got != want {
		t.Errorf("Action = %q, want %q (no type → bare codex.notify)", got, want)
	}
}

func TestCodexNotify_PrefersThreadIDForSessionCorrelation(t *testing.T) {
	store, logger := newOTLPIngestTestStore(t)
	a := &APIServer{store: store, logger: logger}

	body := `{"type":"agent-turn-complete","thread-id":"thread-123","turn-id":"turn-abc","model":"gpt-5","status":"success"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/notify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.handleCodexNotify(w, req)
	logger.Close()

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}

	time.Sleep(50 * time.Millisecond)

	rows, err := store.ListEvents(10)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%d want 1", len(rows))
	}
	if got, want := rows[0].SessionID, "thread-123"; got != want {
		t.Fatalf("SessionID = %q, want %q", got, want)
	}
	if !strings.Contains(rows[0].Details, "thread_id=") {
		t.Fatalf("Details missing thread_id summary: %q", rows[0].Details)
	}
	if !strings.Contains(rows[0].Details, "turn_id=") {
		t.Fatalf("Details missing turn_id summary: %q", rows[0].Details)
	}
}
