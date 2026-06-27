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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	collectorlogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"
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

func TestOTLPLogRecordsForSplunkHEC_FlattensCodexLogRecord(t *testing.T) {
	body := []byte(`{
		"resourceLogs": [{
			"resource": {"attributes": [
				{"key": "service.name", "value": {"stringValue": "codex-app-server"}},
				{"key": "host.name", "value": {"stringValue": "ADIAGNE-M-H9T4"}}
			]},
			"scopeLogs": [{"logRecords": [{
				"timeUnixNano": "0",
				"observedTimeUnixNano": "1778152115531514000",
				"severityNumber": 9,
				"severityText": "INFO",
				"traceId": "trace-1",
				"spanId": "span-1",
				"body": {"stringValue": "raw prompt body"},
				"attributes": [
					{"key": "event.name", "value": {"stringValue": "codex.user_prompt"}},
					{"key": "conversation.id", "value": {"stringValue": "sess-1"}},
					{"key": "model", "value": {"stringValue": "gpt-5.4"}},
					{"key": "prompt", "value": {"stringValue": "summarize a secret customer note"}},
					{"key": "user.email", "value": {"stringValue": "user@example.com"}}
				]
			}]}]
		}]
	}`)

	events := otlpLogRecordsForSplunkHEC(body, "codex", time.Unix(1700000000, 0).UTC())
	if len(events) != 1 {
		t.Fatalf("events=%d want 1", len(events))
	}
	if got := events[0]["sourcetype"]; got != "otel:log" {
		t.Fatalf("sourcetype=%v want otel:log", got)
	}
	if got := events[0]["source"]; got != "otel" {
		t.Fatalf("source=%v want otel", got)
	}
	event, ok := events[0]["event"].(map[string]any)
	if !ok {
		t.Fatalf("event payload missing: %+v", events[0])
	}
	if got := event["session_id"]; got != "sess-1" {
		t.Fatalf("session_id=%v want sess-1", got)
	}
	if got := event["action"]; got != "codex.user_prompt" {
		t.Fatalf("action=%v want codex.user_prompt", got)
	}
	if got := event["request_model"]; got != "gpt-5.4" {
		t.Fatalf("request_model=%v want gpt-5.4", got)
	}
	if got := event["timestamp"]; got != "2026-05-07T11:08:35.531514Z" {
		t.Fatalf("timestamp=%v", got)
	}
	if got := event["body"]; got != "raw prompt body" {
		t.Fatalf("body=%v want raw prompt body", got)
	}
	attrs := event["attributes"].(map[string]interface{})
	if got := attrs["prompt"]; got != "summarize a secret customer note" {
		t.Fatalf("prompt=%v want raw prompt", got)
	}
	if got := attrs["user.email"]; got != "user@example.com" {
		t.Fatalf("user.email=%v want raw email", got)
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

func TestOTLPIngest_Logs_AcceptsProtobufContentType(t *testing.T) {
	a := &APIServer{}
	req := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(`payload`))
	req.Header.Set("Content-Type", "application/x-protobuf")
	w := httptest.NewRecorder()

	a.handleOTLPLogs(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body=%q", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "{}" {
		t.Errorf("body = %q, want canonical OTLP empty-success body", got)
	}
}

func TestOTLPIngest_Logs_DecodesProtobufSessionAndPromotesTokens(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	otelProvider, err := telemetry.NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	defer otelProvider.Shutdown(context.Background())

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
	api.SetOTelProvider(otelProvider)
	handler := otelHTTPServerMiddleware("sidecar-api", http.HandlerFunc(api.handleOTLPLogs))
	payload := &collectorlogspb.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{{
			Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
				otlpStringKV("service.name", "copilot-cli"),
			}},
			ScopeLogs: []*logspb.ScopeLogs{{
				LogRecords: []*logspb.LogRecord{{
					Attributes: []*commonpb.KeyValue{
						otlpStringKV("event.name", "copilot.sse_event"),
						otlpStringKV("event.kind", "response.completed"),
						otlpStringKV("conversation.id", "session-protobuf"),
						otlpStringKV("gen_ai.operation.name", "chat.completions.with.user-supplied-suffix"),
						otlpStringKV("gen_ai.provider.name", "attacker-controlled-provider-name"),
						otlpStringKV("model", "gpt-5"),
						otlpStringKV("gen_ai.agent.name", "copilot"),
						otlpIntKV("input_tokens", 17),
						otlpIntKV("output_tokens", 23),
					},
				}},
			}},
		}},
	}
	body, err := proto.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal protobuf OTLP logs: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("x-defenseclaw-source", "copilot")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%s", w.Code, w.Body.String())
	}

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans want 1", len(spans))
	}
	for key, want := range map[string]string{
		"gen_ai.conversation.id": "session-protobuf",
		"gen_ai.agent.type":      "copilot",
	} {
		got, ok := attrByKey(spans[0].Attributes, key)
		if !ok || got.AsString() != want {
			t.Fatalf("%s=%q ok=%v want %q", key, got.AsString(), ok, want)
		}
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	tokenMetric := findMetric(rm, "gen_ai.client.token.usage")
	if tokenMetric == nil {
		t.Fatal("expected gen_ai.client.token.usage metric from protobuf logs")
		return
	}
	tokenHist, ok := tokenMetric.Data.(metricdata.Histogram[float64])
	if !ok {
		t.Fatalf("expected Histogram[float64], got %T", tokenMetric.Data)
	}
	got := map[string]float64{}
	for _, dp := range tokenHist.DataPoints {
		var tokenType, agentName, operationName, providerName, model string
		for _, attr := range dp.Attributes.ToSlice() {
			switch string(attr.Key) {
			case "gen_ai.token.type":
				tokenType = attr.Value.AsString()
			case "gen_ai.agent.name":
				agentName = attr.Value.AsString()
			case "gen_ai.operation.name":
				operationName = attr.Value.AsString()
			case "gen_ai.provider.name":
				providerName = attr.Value.AsString()
			case "gen_ai.request.model":
				model = attr.Value.AsString()
			}
		}
		if agentName != "copilot" {
			t.Fatalf("gen_ai.agent.name = %q, want copilot", agentName)
		}
		if operationName != "other" || providerName != "other" || model != "gpt-5" {
			t.Fatalf("promoted gen_ai labels = operation=%q provider=%q model=%q, want other/other/gpt-5",
				operationName, providerName, model)
		}
		got[tokenType] = dp.Sum
	}
	if got["input"] != 17 || got["output"] != 23 {
		t.Fatalf("token histogram sums = %#v, want input=17 output=23", got)
	}
}

func otlpStringKV(key, value string) *commonpb.KeyValue {
	return &commonpb.KeyValue{
		Key: key,
		Value: &commonpb.AnyValue{
			Value: &commonpb.AnyValue_StringValue{StringValue: value},
		},
	}
}

func otlpIntKV(key string, value int64) *commonpb.KeyValue {
	return &commonpb.KeyValue{
		Key: key,
		Value: &commonpb.AnyValue{
			Value: &commonpb.AnyValue_IntValue{IntValue: value},
		},
	}
}

func TestDecodeOTLPAnyValue_DepthCap(t *testing.T) {
	shallow := decodeOTLPAnyValue(json.RawMessage(`{"kvlistValue":{"values":[{"key":"k","value":{"stringValue":"leaf"}}]}}`))
	if got := shallow.(map[string]interface{})["k"]; got != "leaf" {
		t.Fatalf("shallow kvlist decode = %#v, want leaf", shallow)
	}

	raw := json.RawMessage(`{"stringValue":"leaf"}`)
	for i := 0; i < maxOTLPAnyValueDepth+3; i++ {
		raw = json.RawMessage(`{"kvlistValue":{"values":[{"key":"k","value":` + string(raw) + `}]}}`)
	}
	got := decodeOTLPAnyValue(raw)
	var containsCappedNil func(interface{}) bool
	containsCappedNil = func(v interface{}) bool {
		switch x := v.(type) {
		case nil:
			return true
		case map[string]interface{}:
			for _, child := range x {
				if containsCappedNil(child) {
					return true
				}
			}
		case []interface{}:
			for _, child := range x {
				if containsCappedNil(child) {
					return true
				}
			}
		}
		return false
	}
	if !containsCappedNil(got) {
		t.Fatalf("deep kvlist decode did not hit depth cap: %#v", got)
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

	rootMeta := hookLLMEventMeta(
		"codex", "codex-session-usage", "", "", "codex", "native-codex-root", "codex", "codex",
		map[string]interface{}{"hook_event_name": "SessionStart"},
	)
	rootKey := hookSessionTraceKey(rootMeta)
	a := &APIServer{
		hookSessionTraces:     map[string]hookSessionTrace{rootKey: {meta: rootMeta}},
		hookSessionTraceOrder: []string{rootKey},
	}
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
						{"key": "conversation.id", "value": {"stringValue": "codex-session-usage"}},
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
	spanUsage := a.takeHookLLMSpanUsage(llmEventMeta{Source: "codex", SessionID: "codex-session-usage"})
	if spanUsage.promptTokens != 123 || spanUsage.completionTokens != 45 || spanUsage.model != "gpt-5-codex" {
		t.Fatalf("correlated span usage=%+v, want input=123 output=45 model=gpt-5-codex", spanUsage)
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

	var gotInput, gotOutput, gotAgentID bool
	for _, dp := range tokenHist.DataPoints {
		var tokenType, agentName, agentID string
		for _, attr := range dp.Attributes.ToSlice() {
			switch string(attr.Key) {
			case "gen_ai.token.type":
				tokenType = attr.Value.AsString()
			case "gen_ai.agent.name":
				agentName = attr.Value.AsString()
			case "gen_ai.agent.id":
				agentID = attr.Value.AsString()
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
		gotAgentID = gotAgentID || agentID == "native-codex-root"
	}
	if !gotInput || !gotOutput || !gotAgentID {
		t.Fatalf("token histogram missing correlation: input=%v output=%v agent_id=%v", gotInput, gotOutput, gotAgentID)
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

func TestDeltaOTLPCumulativeTokenUsage(t *testing.T) {
	a := &APIServer{}
	base := otelTokenUsage{
		cumulative: true,
		seriesKey:  "claude-input",
		startTime:  "1000",
		tokens:     100,
	}
	got, ok := a.deltaOTLPCumulativeTokenUsage(base)
	if !ok || got.tokens != 100 {
		t.Fatalf("first cumulative point = (%+v,%v), want 100,true", got, ok)
	}
	if _, ok := a.deltaOTLPCumulativeTokenUsage(base); ok {
		t.Fatal("duplicate cumulative point must not emit a second usage observation")
	}
	base.tokens = 145
	got, ok = a.deltaOTLPCumulativeTokenUsage(base)
	if !ok || got.tokens != 45 {
		t.Fatalf("cumulative delta = (%+v,%v), want 45,true", got, ok)
	}
	base.startTime = "2000"
	base.tokens = 12
	got, ok = a.deltaOTLPCumulativeTokenUsage(base)
	if !ok || got.tokens != 12 {
		t.Fatalf("reset cumulative point = (%+v,%v), want 12,true", got, ok)
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

func TestOTLPIngest_IsOTLPContentType_AcceptsJSONAndProtobuf(t *testing.T) {
	for _, ct := range []string{"application/json", "application/x-protobuf", "application/x-protobuf; charset=utf-8"} {
		if !isOTLPContentType(ct) {
			t.Errorf("isOTLPContentType(%q) = false, want true", ct)
		}
	}
}

// TestSanitizeRouteForTelemetry pins the contract that the OTLP
// path-token segment is replaced with a fixed "_token_" placeholder
// before reaching telemetry. If this test ever regresses, the master
// gateway bearer token will leak from /otlp/<source>/<token>/v1/<signal>
// URLs into whatever OTel backend the sidecar exports to (and into the
// gateway's own otel.http.* metrics, which then get exported again).
func TestSanitizeRouteForTelemetry(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "geminicli logs path-token redacted",
			in:   "/otlp/geminicli/sk-dc-supersecret-master-token/v1/logs",
			want: "/otlp/geminicli/_token_/v1/logs",
		},
		{
			name: "metrics signal redacted",
			in:   "/otlp/cursor/abcdef0123456789/v1/metrics",
			want: "/otlp/cursor/_token_/v1/metrics",
		},
		{
			name: "traces signal redacted",
			in:   "/otlp/codex/raw.token.value/v1/traces",
			want: "/otlp/codex/_token_/v1/traces",
		},
		{
			name: "url-escaped token still scrubbed",
			in:   "/otlp/geminicli/sk%2Ddc%2Dabc/v1/logs",
			want: "/otlp/geminicli/_token_/v1/logs",
		},
		{
			name: "non-otlp route untouched",
			in:   "/api/v1/agents/discover",
			want: "/api/v1/agents/discover",
		},
		{
			name: "shared otlp endpoint untouched (no path-token)",
			in:   "/v1/logs",
			want: "/v1/logs",
		},
		{
			name: "malformed otlp path untouched",
			in:   "/otlp/geminicli/v1/logs",
			want: "/otlp/geminicli/v1/logs",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeRouteForTelemetry(tc.in)
			if got != tc.want {
				t.Fatalf("sanitizeRouteForTelemetry(%q) = %q, want %q", tc.in, got, tc.want)
			}
			// Defensive: ensure the original token (if any) does not
			// survive in the output. We use a representative secret
			// pattern; if the implementation regresses to a substring
			// match this assertion will still catch the token leak.
			if strings.Contains(tc.in, "supersecret") && strings.Contains(got, "supersecret") {
				t.Fatalf("sanitized route still contains the master token: %q", got)
			}
		})
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

func TestCodexNotify_EmitsFirstClassLLMEvents(t *testing.T) {
	redaction.SetDisableAll(true)
	t.Cleanup(func() { redaction.SetDisableAll(false) })
	events := captureGatewayEvents(t)
	a := &APIServer{}

	body := `{
		"type": "agent-turn-complete",
		"thread-id": "thread-123",
		"turn-id": "turn-abc",
		"model": "gpt-5",
		"status": "success",
		"input-messages": ["first prompt", "second prompt"],
		"last-assistant-message": "assistant response",
		"finish-reason": "stop"
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/notify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	a.handleCodexNotify(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}
	var llmEvents []gatewaylog.Event
	for _, event := range *events {
		if event.EventType == gatewaylog.EventLLMPrompt || event.EventType == gatewaylog.EventLLMResponse {
			llmEvents = append(llmEvents, event)
		}
	}
	if len(llmEvents) != 2 {
		t.Fatalf("LLM events=%d want 2; all=%+v", len(llmEvents), *events)
	}
	prompt := llmEvents[0]
	if prompt.EventType != gatewaylog.EventLLMPrompt || prompt.LLMPrompt == nil {
		t.Fatalf("first event = %+v, want llm_prompt", prompt)
	}
	if prompt.SessionID != "thread-123" || prompt.Model != "gpt-5" || prompt.AgentName != "codex" || prompt.AgentType != "codex" {
		t.Fatalf("prompt envelope wrong: %+v", prompt)
	}
	if prompt.LLMPrompt.TurnID != "turn-abc" || prompt.LLMPrompt.Prompt != "second prompt" {
		t.Fatalf("prompt payload wrong: %+v", prompt.LLMPrompt)
	}
	if prompt.LLMPrompt.Source != codexNotifyTurnCompleteSource {
		t.Fatalf("prompt source=%q want %q", prompt.LLMPrompt.Source, codexNotifyTurnCompleteSource)
	}
	if prompt.LLMPrompt.RawRequestBody != "" {
		t.Fatalf("notify llm_prompt should not duplicate raw body: %q", prompt.LLMPrompt.RawRequestBody)
	}

	response := llmEvents[1]
	if response.EventType != gatewaylog.EventLLMResponse || response.LLMResponse == nil {
		t.Fatalf("second event = %+v, want llm_response", response)
	}
	if response.SessionID != "thread-123" || response.Model != "gpt-5" || response.AgentName != "codex" || response.AgentType != "codex" {
		t.Fatalf("response envelope wrong: %+v", response)
	}
	if response.LLMResponse.TurnID != "turn-abc" || response.LLMResponse.Response != "assistant response" {
		t.Fatalf("response payload wrong: %+v", response.LLMResponse)
	}
	if response.LLMResponse.ReplyToPromptID == "" || response.LLMResponse.ReplyToPromptID != prompt.LLMPrompt.PromptID {
		t.Fatalf("response did not link to prompt: response=%+v prompt=%+v", response.LLMResponse, prompt.LLMPrompt)
	}
	if response.LLMResponse.RawResponseBody != "" {
		t.Fatalf("notify llm_response should not duplicate raw body: %q", response.LLMResponse.RawResponseBody)
	}
	if got := response.LLMResponse.FinishReasons; len(got) != 1 || got[0] != "stop" {
		t.Fatalf("finish_reasons=%v want [stop]", got)
	}
}

func TestCodexNotify_LLMEventsUseRedactionPath(t *testing.T) {
	redaction.SetDisableAll(false)
	t.Cleanup(func() { redaction.SetDisableAll(false) })
	events := captureGatewayEvents(t)
	a := &APIServer{}

	body := `{
		"type": "agent-turn-complete",
		"thread-id": "thread-secret",
		"turn-id": "turn-secret",
		"model": "gpt-5",
		"input-messages": ["please leak sk-secret-token"],
		"last-assistant-message": "secret response"
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/notify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	a.handleCodexNotify(w, req)

	var llmEvents []gatewaylog.Event
	for _, event := range *events {
		if event.EventType == gatewaylog.EventLLMPrompt || event.EventType == gatewaylog.EventLLMResponse {
			llmEvents = append(llmEvents, event)
		}
	}
	if len(llmEvents) != 2 {
		t.Fatalf("LLM events=%d want 2; all=%+v", len(llmEvents), *events)
	}
	if got := llmEvents[0].LLMPrompt.Prompt; strings.Contains(got, "sk-secret-token") || strings.Contains(got, "please leak") {
		t.Fatalf("prompt bypassed redaction: %q", got)
	}
	if got := llmEvents[1].LLMResponse.Response; strings.Contains(got, "secret response") {
		t.Fatalf("response bypassed redaction: %q", got)
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
//
// The unified hook collector always synthesizes a parallel Stop
// event for the notify payload, so this test also asserts the
// presence of exactly one connector-hook-synthetic row alongside
// the canonical notify row. SIEM rules pinned on
// `action LIKE 'codex.notify%'` continue to see a single match.
func TestCodexNotify_PersistsDynamicSuffixAction(t *testing.T) {
	store, logger := newOTLPIngestTestStore(t)
	a := &APIServer{store: store, logger: logger}

	body := `{"type": "agent-turn-complete", "turn-id": "turn-abc", "model": "gpt-5", "status": "success"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/notify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(audit.ContextWithEnvelope(req.Context(), audit.CorrelationEnvelope{
		TraceID:        "trace-123",
		RequestID:      "req-123",
		RunID:          "run-123",
		PolicyID:       "policy-123",
		DestinationApp: "codex",
	}))
	w := httptest.NewRecorder()
	a.handleCodexNotify(w, req)
	logger.Close()

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}

	time.Sleep(50 * time.Millisecond)

	canonical, synthetic := splitCodexNotifyAuditRows(t, store)
	if len(canonical) != 1 {
		t.Fatalf("codex.notify rows=%d want 1", len(canonical))
	}
	if len(synthetic) != 1 {
		t.Fatalf("connector-hook-synthetic rows=%d want 1", len(synthetic))
	}
	if got, want := canonical[0].Action, "codex.notify.agent-turn-complete"; got != want {
		t.Errorf("Action = %q, want %q", got, want)
	}
	// Must satisfy *either* the static enum OR the prefix matcher.
	// audit-event.json validators in downstream SIEMs use the same
	// disjunction.
	if !audit.IsKnownAction(canonical[0].Action) && !audit.IsKnownActionPrefix(canonical[0].Action) {
		t.Errorf("audit Action %q matches neither IsKnownAction nor IsKnownActionPrefix", canonical[0].Action)
	}
	if canonical[0].SessionID != "turn-abc" {
		t.Errorf("SessionID = %q, want %q (codex notify rows must fall back to turn-id when thread-id is absent)", canonical[0].SessionID, "turn-abc")
	}
	if canonical[0].TraceID != "trace-123" || canonical[0].RequestID != "req-123" ||
		canonical[0].RunID != "run-123" || canonical[0].PolicyID != "policy-123" ||
		canonical[0].DestinationApp != "codex" {
		t.Errorf("canonical notify row missing correlation envelope: trace=%q request=%q run=%q policy=%q destination=%q",
			canonical[0].TraceID, canonical[0].RequestID, canonical[0].RunID, canonical[0].PolicyID, canonical[0].DestinationApp)
	}
	// F2: synthetic row must carry the same SessionID as the
	// canonical row so SIEM joins on session_id correlate the
	// pair. The synthetic row used to drop session_id because
	// CorrelationMiddleware only sees the inbound HTTP headers
	// (no X-DefenseClaw-Session-Id from notify-bridge.sh) and the
	// payload-derived value was never threaded into the audit
	// envelope. enrichAgentHookContext now refreshes the envelope
	// so this assertion passes.
	if synthetic[0].SessionID != "turn-abc" {
		t.Errorf("synthetic row SessionID = %q, want %q (F2: must inherit from req.SessionID)", synthetic[0].SessionID, "turn-abc")
	}
	if strings.Contains(canonical[0].Details, body) {
		t.Fatalf("Details stored raw notify body: %q", canonical[0].Details)
	}
	if !strings.Contains(canonical[0].Details, "body_sha256") || !strings.Contains(canonical[0].Details, "body_len") {
		t.Fatalf("Details missing redacted notify summary fields: %q", canonical[0].Details)
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

	canonical, synthetic := splitCodexNotifyAuditRows(t, store)
	if len(canonical) != 1 {
		t.Fatalf("codex.notify rows=%d want 1", len(canonical))
	}
	if len(synthetic) != 1 {
		t.Fatalf("connector-hook-synthetic rows=%d want 1", len(synthetic))
	}
	if got, want := canonical[0].Action, string(audit.ActionCodexNotify); got != want {
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

	canonical, synthetic := splitCodexNotifyAuditRows(t, store)
	if len(canonical) != 1 {
		t.Fatalf("codex.notify rows=%d want 1", len(canonical))
	}
	if len(synthetic) != 1 {
		t.Fatalf("connector-hook-synthetic rows=%d want 1", len(synthetic))
	}
	if got, want := canonical[0].SessionID, "thread-123"; got != want {
		t.Fatalf("SessionID = %q, want %q", got, want)
	}
	// F2: synthetic row must carry the SAME session id as the
	// canonical row, even when thread-id is preferred over
	// turn-id. enrichAgentHookContext reads req.SessionID which
	// codexNotifyToAgentHookRequest set from codexNotifySessionID,
	// so the two rows MUST agree.
	if got, want := synthetic[0].SessionID, "thread-123"; got != want {
		t.Fatalf("synthetic row SessionID = %q, want %q (F2)", got, want)
	}
	if !strings.Contains(canonical[0].Details, "thread_id=") {
		t.Fatalf("Details missing thread_id summary: %q", canonical[0].Details)
	}
	if !strings.Contains(canonical[0].Details, "turn_id=") {
		t.Fatalf("Details missing turn_id summary: %q", canonical[0].Details)
	}
}

// splitCodexNotifyAuditRows fetches the audit-store contents and
// partitions them into the two row classes the codex notify
// pipeline produces:
//
//   - canonical: action == "codex.notify[.suffix]" — the row the
//     SIEM has always seen, one per inbound notify;
//   - synthetic: action == ActionConnectorHookSynthetic — the
//     visibility row written by the unified hook collector when it
//     synthesizes a Stop event from the same payload.
//
// Centralizing the split in a helper means every test asserting
// the contract reads the same way and a future SIEM rule writer
// can grep for one symbol to discover the row taxonomy.
func splitCodexNotifyAuditRows(t *testing.T, store *audit.Store) (canonical, synthetic []audit.Event) {
	t.Helper()
	rows, err := store.ListEvents(10)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	for _, r := range rows {
		switch {
		case strings.HasPrefix(r.Action, string(audit.ActionCodexNotify)):
			canonical = append(canonical, r)
		case r.Action == string(audit.ActionConnectorHookSynthetic):
			synthetic = append(synthetic, r)
		default:
			t.Fatalf("unexpected audit Action=%q (test fixture should only produce codex.notify* + %s)",
				r.Action, audit.ActionConnectorHookSynthetic)
		}
	}
	return canonical, synthetic
}

// TestSanitizeCodexNotifySpanString_StripsAndCaps pins the contract
// codex notify span enrichment depends on: control / CR / LF / ANSI
// runes are stripped before stamping onto span attributes, and
// oversized inputs are truncated on a UTF-8 rune boundary so the
// resulting attribute is always valid UTF-8 (OTLP exporters drop
// spans with invalid-UTF-8 string attributes).
//
// The UTF-8 truncation case is the regression guard: a naive
// `value[:maxLen]` would have split the trailing 3-byte rune
// mid-sequence, producing 0xE0 0xA4 with no continuation byte and
// breaking the OTLP wire encoding.
func TestSanitizeCodexNotifySpanString_StripsAndCaps(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		maxLen int
		want   string
	}{
		{name: "empty", in: "", maxLen: 128, want: ""},
		{name: "trims whitespace", in: "  gpt-5  ", maxLen: 128, want: "gpt-5"},
		{name: "strips CRLF", in: "gpt-5\r\nclaude", maxLen: 128, want: "gpt-5  claude"},
		{name: "strips ANSI ESC", in: "gpt-5\x1b[31mRED", maxLen: 128, want: "gpt-5 [31mRED"},
		{name: "strips other control runes", in: "gpt-5\x00\x07\x08", maxLen: 128, want: "gpt-5   "},
		{name: "preserves tab", in: "gpt-5\tturbo", maxLen: 128, want: "gpt-5\tturbo"},
		{name: "strips 0x7F", in: "gpt-5\x7f", maxLen: 128, want: "gpt-5 "},
		{name: "byte-cap respected", in: strings.Repeat("a", 200), maxLen: 64, want: strings.Repeat("a", 64)},
		// "नमस्ते" is 18 bytes (six 3-byte runes). A naive
		// value[:16] would split the 6th rune mid-sequence and
		// emit invalid UTF-8. truncateToRuneBoundary lands on the
		// 6th rune's leader at offset 15, sees a 3-byte rune won't
		// fit in 16 bytes, and returns the 5-rune (15-byte) prefix.
		{name: "utf8 boundary truncate", in: "नमस्ते", maxLen: 16, want: "नमस्त"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeCodexNotifySpanString(tc.in, tc.maxLen)
			if got != tc.want {
				t.Fatalf("sanitizeCodexNotifySpanString(%q, %d) = %q, want %q", tc.in, tc.maxLen, got, tc.want)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("sanitizeCodexNotifySpanString returned invalid UTF-8: %q", got)
			}
		})
	}
}

// TestEnrichCodexNotifySpan_SanitizesAttributes proves a hostile
// codex notify payload (CRLF + ANSI in Status, oversized Model)
// reaches the active span as sanitized + length-capped attributes
// rather than as raw user-controlled bytes. This is the regression
// guard for the log-injection / span-storage-DoS surface: an OTel
// trace viewer rendering raw span attributes from this code path
// would otherwise see attacker-supplied terminal escapes.
func TestEnrichCodexNotifySpan_SanitizesAttributes(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSyncer(exp),
	)
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "codex.notify")

	p := codexNotifyPayload{
		Status: "ok\r\n\x1b[31mFAKE-ALERT",
		Model:  strings.Repeat("m", 256),
	}
	enrichCodexNotifySpan(ctx, p, "agent-turn-complete", "ok")
	span.End()

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("spans=%d want 1", len(spans))
	}
	attrs := map[string]string{}
	for _, kv := range spans[0].Attributes {
		attrs[string(kv.Key)] = kv.Value.AsString()
	}

	statusAttr := attrs["defenseclaw.codex.notify.status"]
	if statusAttr == "" {
		t.Fatalf("missing defenseclaw.codex.notify.status; attrs=%v", attrs)
	}
	if strings.ContainsAny(statusAttr, "\r\n\x1b") {
		t.Fatalf("status attr leaks CR/LF/ESC: %q", statusAttr)
	}

	modelAttr := attrs["gen_ai.response.model"]
	if modelAttr == "" {
		t.Fatalf("missing gen_ai.response.model; attrs=%v", attrs)
	}
	if len(modelAttr) > 128 {
		t.Fatalf("model attr not capped: len=%d", len(modelAttr))
	}
	if !utf8.ValidString(modelAttr) {
		t.Fatalf("model attr is invalid UTF-8: %q", modelAttr)
	}
}
