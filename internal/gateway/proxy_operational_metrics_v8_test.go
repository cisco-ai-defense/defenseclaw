// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

func TestProxyOperationalMetricsUseGeneratedFamiliesAndCorrelation(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	proxy := newTestProxy(t, &mockProvider{}, NewGuardrailInspector("local", nil, nil, ""), "action")
	proxy.bindObservabilityV8Trace(runtime)

	spanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1, 3, 5, 7, 9, 11, 13, 15, 2, 4, 6, 8, 10, 12, 14, 16},
		SpanID:  trace.SpanID{17, 19, 21, 23, 18, 20, 22, 24},
	})
	ctx := audit.ContextWithEnvelope(t.Context(), audit.CorrelationEnvelope{
		RequestID: "request-operational", SessionID: "session-operational",
		TurnID: "turn-operational", AgentID: "agent-operational", Connector: "unknown",
	})
	ctx = trace.ContextWithSpanContext(ctx, spanContext)

	proxy.recordProxyRateLimitV8(ctx, "/caller-controlled/123")
	proxy.recordProxyForwardedHeadersV8(ctx, "chat-completions", "ok", 3)
	proxy.recordProxyStreamV8(
		ctx, runtime, "/v1/chat/completions", "open", observability.OutcomeAttempted, 0, 0,
	)
	proxy.recordProxyStreamV8(
		ctx, runtime, "/v1/chat/completions", "close", observability.OutcomeCompleted,
		1500*time.Microsecond, 42,
	)

	byName := make(map[string][]telemetry.V8ProjectedMetric)
	for _, metric := range capture.metricSnapshot() {
		byName[metric.Descriptor().Name] = append(byName[metric.Descriptor().Name], metric)
		correlation := metric.CanonicalRecord().Correlation()
		if correlation.TraceID != spanContext.TraceID().String() ||
			correlation.SpanID != spanContext.SpanID().String() ||
			correlation.RequestID != "request-operational" || correlation.TurnID != "turn-operational" {
			t.Fatalf("metric %s correlation=%+v", metric.Descriptor().Name, correlation)
		}
	}
	wantCounts := map[string]int{
		observability.TelemetryInstrumentDefenseClawHTTPRateLimitBreaches:   1,
		observability.TelemetryInstrumentDefenseClawGatewayForwardedHeaders: 1,
		observability.TelemetryInstrumentDefenseClawStreamLifecycle:         2,
		observability.TelemetryInstrumentDefenseClawStreamDurationMs:        1,
		observability.TelemetryInstrumentDefenseClawStreamBytesSent:         1,
	}
	if len(byName) != len(wantCounts) {
		t.Fatalf("generated operational metric families=%v", byName)
	}
	for name, count := range wantCounts {
		if len(byName[name]) != count {
			t.Fatalf("metric %s count=%d want=%d all=%v", name, len(byName[name]), count, byName)
		}
	}
	if attributes := byName[observability.TelemetryInstrumentDefenseClawHTTPRateLimitBreaches][0].Attributes(); attributes["http.route"] != "passthrough" || attributes["defenseclaw.metric.client.kind"] != "global" {
		t.Fatalf("rate-limit attributes=%v", attributes)
	}
	forwarded := byName[observability.TelemetryInstrumentDefenseClawGatewayForwardedHeaders][0]
	if attributes := forwarded.Attributes(); attributes["defenseclaw.metric.path"] != "chat-completions" ||
		attributes["defenseclaw.metric.result"] != "ok" {
		t.Fatalf("forwarded-header attributes=%v", attributes)
	}
	if value, ok := forwarded.Value().Int64(); !ok || value != 3 {
		t.Fatalf("forwarded-header value=%v", forwarded.Value())
	}
	duration := byName[observability.TelemetryInstrumentDefenseClawStreamDurationMs][0]
	if value, ok := duration.Value().Double(); !ok || value != 1.5 ||
		duration.Attributes()["defenseclaw.outcome"] != string(observability.OutcomeCompleted) {
		t.Fatalf("stream duration value/attributes=%v/%v", duration.Value(), duration.Attributes())
	}
	bytes := byName[observability.TelemetryInstrumentDefenseClawStreamBytesSent][0]
	if value, ok := bytes.Value().Int64(); !ok || value != 42 {
		t.Fatalf("stream bytes value=%v", bytes.Value())
	}
}

func TestProxyOperationalMetricsRequireV8Runtime(t *testing.T) {
	proxy := newTestProxy(t, &mockProvider{}, NewGuardrailInspector("local", nil, nil, ""), "action")
	proxy.recordProxyRateLimitV8(context.Background(), "/v1/chat/completions")
	proxy.recordProxyForwardedHeadersV8(context.Background(), "passthrough", "ok", 1)
	proxy.recordProxyStreamV8(
		context.Background(), nil, "/v1/chat/completions", "close",
		observability.OutcomeCompleted, time.Millisecond, 1,
	)
}
