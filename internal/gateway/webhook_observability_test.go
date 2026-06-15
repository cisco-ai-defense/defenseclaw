// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
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

	reader := sdkmetric.NewManualReader()
	otelProv, err := telemetry.NewProviderForTest(reader)
	if err != nil {
		t.Fatal(err)
	}

	d := NewWebhookDispatcher([]config.WebhookConfig{
		{URL: srv.URL, Type: "generic", Enabled: true, CooldownSeconds: intPtr(0)},
	})
	if d == nil {
		t.Fatal("dispatcher nil")
		return
	}
	d.BindObservability(otelProv)
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

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var cbOpen, cbClosed int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "defenseclaw.webhook.circuit_breaker" {
				continue
			}
			sum := m.Data.(metricdata.Sum[int64])
			for _, dp := range sum.DataPoints {
				for _, a := range dp.Attributes.ToSlice() {
					if a.Key == "state" && a.Value.AsString() == "opened" {
						cbOpen += dp.Value
					}
					if a.Key == "state" && a.Value.AsString() == "closed" {
						cbClosed += dp.Value
					}
				}
			}
		}
	}
	if cbOpen < 1 {
		t.Fatalf("expected circuit opened metric, got %d", cbOpen)
	}
	if cbClosed < 1 {
		t.Fatalf("expected circuit closed metric after success, got %d", cbClosed)
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

	reader := sdkmetric.NewManualReader()
	otelProv, err := telemetry.NewProviderForTest(reader)
	if err != nil {
		t.Fatal(err)
	}
	d := NewWebhookDispatcher([]config.WebhookConfig{
		{URL: srv.URL, Type: "generic", Enabled: true, CooldownSeconds: intPtr(300)},
	})
	d.BindObservability(otelProv)
	d.retryBackoff = 0

	evt := testEvent()
	d.Dispatch(evt)
	d.wg.Wait()
	d.Dispatch(evt)
	d.Close()

	if atomic.LoadInt32(&attempts) != 1 {
		t.Fatalf("expected 1 HTTP request, got %d", attempts)
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var suppressed int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "defenseclaw.webhook.cooldown.suppressed" {
				continue
			}
			sum := m.Data.(metricdata.Sum[int64])
			for _, dp := range sum.DataPoints {
				suppressed += dp.Value
			}
		}
	}
	if suppressed < 1 {
		t.Fatalf("expected cooldown suppressed counter, got %d", suppressed)
	}
}

func TestWebhookLatencyHistogramAttributes(t *testing.T) {
	t.Setenv("DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST", "1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(201)
	}))
	t.Cleanup(srv.Close)

	reader := sdkmetric.NewManualReader()
	otelProv, err := telemetry.NewProviderForTest(reader)
	if err != nil {
		t.Fatal(err)
	}
	d := NewWebhookDispatcher([]config.WebhookConfig{
		{URL: srv.URL, Type: "slack", Enabled: true, CooldownSeconds: intPtr(0)},
	})
	d.BindObservability(otelProv)
	d.retryBackoff = 0

	d.Dispatch(audit.Event{
		ID: "e1", Timestamp: time.Now().UTC(), Action: "block", Target: "t1",
		Actor: "a", Details: "d", Severity: "HIGH",
	})
	d.Close()

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var found bool
outer:
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "defenseclaw.webhook.latency" {
				continue
			}
			hist, ok := m.Data.(metricdata.Histogram[float64])
			if !ok {
				continue
			}
			for _, dp := range hist.DataPoints {
				for _, a := range dp.Attributes.ToSlice() {
					if a.Key == "http.status_code" && a.Value.AsInt64() == 201 {
						found = true
						break outer
					}
				}
			}
		}
	}
	if !found {
		t.Fatal("expected webhook latency histogram with http.status_code=201")
	}
}
