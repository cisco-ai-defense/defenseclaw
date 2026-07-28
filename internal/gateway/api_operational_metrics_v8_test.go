// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestRecordAPIRequestV8PreservesDimensionsFractionalDurationAndCorrelation(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	ctx, spanContext := platformHealthCorrelatedContext(t)

	recordAPIRequestV8(ctx, runtime, http.MethodPost, "/v1/widgets/{id}", http.StatusCreated, 1500*time.Microsecond)

	counts := generatedMetricByName(
		capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawHTTPRequestCount,
	)
	durations := generatedMetricByName(
		capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawHTTPRequestDuration,
	)
	if len(counts) != 1 || len(durations) != 1 {
		t.Fatalf("generated HTTP metric counts=%d/%d", len(counts), len(durations))
	}
	for _, metric := range append(counts, durations...) {
		attributes := metric.Attributes()
		if metric.CanonicalRecord().Source() != observability.SourceGateway ||
			attributes["http.request.method"] != http.MethodPost ||
			attributes["http.route"] != "/v1/widgets/{id}" ||
			fmt.Sprint(attributes["http.response.status_code"]) != "201" {
			t.Fatalf("HTTP metric %s record=%s attributes=%v",
				metric.Descriptor().Name, metric.CanonicalRecord().Source(), attributes)
		}
		correlation := metric.CanonicalRecord().Correlation()
		if correlation.TraceID != spanContext.TraceID().String() ||
			correlation.SpanID != spanContext.SpanID().String() ||
			correlation.RequestID != "request-platform" || correlation.SessionID != "session-platform" ||
			correlation.TurnID != "turn-platform" || correlation.AgentID != "agent-platform" {
			t.Fatalf("HTTP metric %s correlation=%+v", metric.Descriptor().Name, correlation)
		}
	}
	if value, ok := counts[0].Value().Int64(); !ok || value != 1 {
		t.Fatalf("HTTP count value=%v", counts[0].Value())
	}
	if value, ok := durations[0].Value().Double(); !ok || value != 1.5 {
		t.Fatalf("HTTP duration value=%v", durations[0].Value())
	}
}

func TestMetricsMiddlewareUsesGeneratedRuntimeAndBoundsUnmatchedPaths(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	api := &APIServer{}
	api.bindObservabilityV8Runtimes(runtime, nil, nil, runtime)
	handler := api.metricsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest("BREW", "/otlp/codex/supersecret-token/v1/logs", nil)
	req = req.WithContext(platformHealthRequestContext(t))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, req)

	if response.Code != http.StatusNoContent {
		t.Fatalf("middleware status=%d", response.Code)
	}
	for _, name := range []string{
		observability.TelemetryInstrumentDefenseClawHTTPRequestCount,
		observability.TelemetryInstrumentDefenseClawHTTPRequestDuration,
	} {
		metrics := generatedMetricByName(capture.metricSnapshot(), name)
		if len(metrics) != 1 {
			t.Fatalf("middleware metric %s count=%d", name, len(metrics))
		}
		attributes := metrics[0].Attributes()
		if attributes["http.request.method"] != "_OTHER" ||
			attributes["http.route"] != "unmatched" ||
			fmt.Sprint(attributes["http.response.status_code"]) != "204" {
			t.Fatalf("middleware metric %s attributes=%v", name, attributes)
		}
	}
}

func platformHealthRequestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, _ := platformHealthCorrelatedContext(t)
	return ctx
}
