// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	oteltrace "go.opentelemetry.io/otel/trace"
)

func TestProxyAuthenticationFailureV8ExportsCanonicalLogAndDashboardMetric(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"logs", "metrics"})
	proxy := &GuardrailProxy{}
	proxy.bindObservabilityV8TraceMode(api.observabilityV8LifecycleRuntime(), true)

	spanContext := oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
		TraceID: oteltrace.TraceID{1, 2, 3, 4},
		SpanID:  oteltrace.SpanID{5, 6, 7, 8},
		Remote:  true,
	})
	ctx := oteltrace.ContextWithRemoteSpanContext(t.Context(), spanContext)
	ctx = ContextWithRequestID(ctx, "proxy-auth-request")
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/chat/completions/private-path-token?credential=query-secret",
		nil,
	).WithContext(ctx)
	request.RemoteAddr = "203.0.113.91:49152"
	request.Header.Set("Authorization", "Bearer proxy-auth-secret")
	request.Header.Set("User-Agent", "private-proxy-user-agent")

	proxy.emitProxyAuthFailure(request, "invalid_token")

	var logsCount, metricCount int
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		logsCount = len(hookModelV8CapturedLogs(capture.logSnapshot()))
		_, metrics := capture.snapshot()
		metricCount = hookModelV8MetricPointCount(
			metrics, observability.TelemetryInstrumentDefenseClawHTTPAuthFailures,
		)
		if logsCount == 1 && metricCount == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if logsCount != 1 || metricCount != 1 {
		t.Fatalf("proxy authentication exports logs=%d metrics=%d want=1/1", logsCount, metricCount)
	}
	logRecord := hookModelV8CapturedLogs(capture.logSnapshot())[0]
	traceID, spanID := spanContext.TraceID(), spanContext.SpanID()
	if got := logRecord.GetTraceId(); !bytes.Equal(got, traceID[:]) {
		t.Errorf("proxy authentication trace_id=%x want=%s", got, traceID)
	}
	if got := logRecord.GetSpanId(); !bytes.Equal(got, spanID[:]) {
		t.Errorf("proxy authentication span_id=%x want=%s", got, spanID)
	}
	attributes := hookModelV8MetricAttributes(logRecord.Attributes)
	for key, want := range map[string]string{
		"defenseclaw.event.name": observability.TelemetryEventAuthenticationFailed,
		"defenseclaw.bucket":     string(observability.BucketComplianceActivity),
	} {
		if got := attributes[key]; got != want {
			t.Errorf("proxy authentication log %s=%q want=%q attributes=%v", key, got, want, attributes)
		}
	}
	serialized := logRecord.Body.GetStringValue()
	for _, want := range []string{
		`"source":"gateway"`,
		`"defenseclaw.admin.operation":"api-auth-failure"`,
		`"defenseclaw.admin.reason":"invalid_token"`,
		`"request_id":"proxy-auth-request"`,
	} {
		if !strings.Contains(serialized, want) {
			t.Errorf("proxy authentication log missing %q: %s", want, serialized)
		}
	}
	for _, forbidden := range []string{
		"private-path-token", "query-secret", "proxy-auth-secret",
		"203.0.113.91", "private-proxy-user-agent",
	} {
		if strings.Contains(serialized, forbidden) {
			t.Errorf("proxy authentication log retained %q: %s", forbidden, serialized)
		}
	}

	_, metrics := capture.snapshot()
	points := hookModelV8MetricPoints(
		metrics, observability.TelemetryInstrumentDefenseClawHTTPAuthFailures,
	)
	assertHookV8MetricPoint(t, points, map[string]string{
		"http.route":                "guardrail-proxy",
		"defenseclaw.metric.reason": "invalid_token",
	}, 1)
	for _, point := range points {
		if strings.Contains(point.attributes["http.route"], "private") ||
			strings.Contains(point.attributes["http.route"], "token") {
			t.Fatalf("proxy authentication metric leaked request path: %+v", point)
		}
	}

	// Once v8 has owned the producer, detaching consumers cannot write to the
	// retiring graph. Shutdown may intentionally lose this final diagnostic.
	proxy.bindObservabilityV8TraceMode(nil, true)
	proxy.emitProxyAuthFailure(request, "missing_token")
	time.Sleep(50 * time.Millisecond)
	if got := len(hookModelV8CapturedLogs(capture.logSnapshot())); got != 1 {
		t.Fatalf("detached proxy authentication exported logs=%d want=1", got)
	}
}
