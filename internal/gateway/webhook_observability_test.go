// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestWebhookCircuitBreakerOpensAndRecovers(t *testing.T) {
	t.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")
	oldTh := webhookCircuitFailureThreshold
	oldDur := webhookCircuitOpenDuration
	t.Cleanup(func() {
		webhookCircuitFailureThreshold = oldTh
		webhookCircuitOpenDuration = oldDur
	})
	webhookCircuitFailureThreshold = 2
	webhookCircuitOpenDuration = 150 * time.Millisecond

	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n <= 8 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)

	runtime, capture := newProxyGeneratedTraceRuntime(t)

	d := NewWebhookDispatcher([]config.WebhookConfig{
		{URL: srv.URL, Type: "generic", Enabled: true, CooldownSeconds: intPtr(0)},
	})
	if d == nil {
		t.Fatal("dispatcher nil")
		return
	}
	d.BindObservabilityV8(runtime)
	d.retryBackoff = time.Millisecond

	evt := testEvent()
	for i := 0; i < 2; i++ {
		d.Dispatch(evt)
		d.wg.Wait()
	}
	// Third dispatch while circuit open — no additional HTTP attempts beyond what
	// the open window allows; we only assert breaker blocked at least once by checking
	// attempts did not grow unbounded.
	before := atomic.LoadInt32(&attempts)
	d.Dispatch(evt)
	d.wg.Wait()
	afterBlock := atomic.LoadInt32(&attempts)
	if afterBlock != before {
		t.Fatalf("expected circuit block (no new HTTP), before=%d after=%d", before, afterBlock)
	}

	time.Sleep(200 * time.Millisecond)
	d.Dispatch(evt)
	d.Close()

	final := atomic.LoadInt32(&attempts)
	if final <= afterBlock {
		t.Fatalf("expected recovery attempt after cooldown, attempts=%d", final)
	}

	transitions := generatedMetricByName(
		capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawWebhookCircuitBreaker,
	)
	var opened, closed bool
	for _, metric := range transitions {
		switch metric.Attributes()["defenseclaw.webhook.circuit.state"] {
		case "opened":
			opened = true
		case "closed":
			closed = true
		}
	}
	if !opened || !closed {
		t.Fatalf("canonical circuit transitions opened=%t closed=%t metrics=%v", opened, closed, transitions)
	}
}

func TestWebhookCooldownEmitsMetric(t *testing.T) {
	t.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)

	runtime, capture := newProxyGeneratedTraceRuntime(t)
	d := NewWebhookDispatcher([]config.WebhookConfig{
		{URL: srv.URL, Type: "generic", Enabled: true, CooldownSeconds: intPtr(300)},
	})
	d.BindObservabilityV8(runtime)
	d.retryBackoff = 0

	evt := testEvent()
	d.Dispatch(evt)
	d.wg.Wait()
	d.Dispatch(evt)
	d.Close()

	if atomic.LoadInt32(&attempts) != 1 {
		t.Fatalf("expected 1 HTTP request, got %d", attempts)
	}

	suppressed := generatedMetricByName(
		capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawWebhookCooldownSuppressed,
	)
	if len(suppressed) != 1 {
		t.Fatalf("expected one canonical cooldown metric, got %d", len(suppressed))
	}
	if got := suppressed[0].Attributes()["defenseclaw.metric.webhook.kind"]; got != "generic" {
		t.Fatalf("cooldown webhook kind=%v", got)
	}
	dispatches := generatedMetricByName(
		capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawWebhookDispatches,
	)
	var sawSkipped bool
	for _, metric := range dispatches {
		if metric.Attributes()["defenseclaw.outcome"] == string(observability.OutcomeSkipped) {
			sawSkipped = true
		}
	}
	if !sawSkipped {
		t.Fatalf("canonical cooldown dispatch outcome missing from %v", dispatches)
	}
}

func TestWebhookLatencyHistogramAttributes(t *testing.T) {
	t.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(201)
	}))
	t.Cleanup(srv.Close)

	runtime, capture := newProxyGeneratedTraceRuntime(t)
	d := NewWebhookDispatcher([]config.WebhookConfig{
		{URL: srv.URL, Type: "slack", Enabled: true, CooldownSeconds: intPtr(0)},
	})
	d.BindObservabilityV8(runtime)
	d.retryBackoff = 0

	d.Dispatch(audit.Event{
		ID: "e1", Timestamp: time.Now().UTC(), Action: "block", Target: "t1",
		Actor: "a", Details: "d", Severity: "HIGH", RunID: "run-webhook",
		TraceID: "00112233445566778899aabbccddeeff", SpanID: "0011223344556677",
		RequestID: "request-webhook", SessionID: "session-webhook", TurnID: "turn-webhook",
		AgentID: "agent-webhook", AgentInstanceID: "agent-instance-webhook",
		PolicyID: "policy-webhook", ToolID: "tool-webhook", Connector: "codex",
	})
	d.Close()

	metrics := generatedMetricByName(
		capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawWebhookLatency,
	)
	if len(metrics) != 1 {
		t.Fatalf("canonical webhook latency metrics=%d", len(metrics))
	}
	metric := metrics[0]
	if attributes := metric.Attributes(); fmt.Sprint(attributes["http.response.status_code"]) != "201" ||
		attributes["defenseclaw.metric.webhook.kind"] != "slack" {
		t.Fatalf("webhook latency attributes=%v", attributes)
	}
	correlation := metric.CanonicalRecord().Correlation()
	if correlation.TraceID != "00112233445566778899aabbccddeeff" ||
		correlation.SpanID != "0011223344556677" || correlation.RequestID != "request-webhook" ||
		correlation.SessionID != "session-webhook" || correlation.TurnID != "turn-webhook" ||
		correlation.AgentID != "agent-webhook" || correlation.AgentInstanceID != "agent-instance-webhook" ||
		correlation.PolicyID != "policy-webhook" || correlation.ToolInvocationID != "tool-webhook" ||
		correlation.ConnectorID != "codex" {
		t.Fatalf("webhook latency correlation=%+v", correlation)
	}
}

func TestWebhookGeneratedMetricUsesCanonicalOutcomeAndKeyedTarget(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	dispatcher := &WebhookDispatcher{}
	dispatcher.BindObservabilityV8(runtime)
	targetHash := "hmac-sha256:" + strings.Repeat("a", 64)

	dispatcher.recordDeliveryV8(t.Context(), "generic", targetHash, "delivered", 204, 3, false)

	dispatches := generatedMetricByName(
		capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawWebhookDispatches,
	)
	latencies := generatedMetricByName(
		capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawWebhookLatency,
	)
	if len(dispatches) != 1 || len(latencies) != 1 {
		t.Fatalf("canonical webhook metrics dispatches=%d latencies=%d", len(dispatches), len(latencies))
	}
	if got := dispatches[0].Attributes()["defenseclaw.outcome"]; got != string(observability.OutcomeCompleted) {
		t.Fatalf("canonical webhook outcome=%v", got)
	}
	if got := latencies[0].Attributes()["defenseclaw.metric.webhook.target_hash"]; got != targetHash {
		t.Fatalf("canonical webhook target hash=%v", got)
	}
}
