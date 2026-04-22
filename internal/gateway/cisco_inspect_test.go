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

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

func TestEmitCiscoErrorIncrementsCounter(t *testing.T) {
	r := sdkmetric.NewManualReader()
	p, err := telemetry.NewProviderForTest(r)
	if err != nil {
		t.Fatal(err)
	}
	EmitCiscoError(context.Background(), p, gatewaylog.ErrCodeInvalidResponse, "test detail")

	var rm metricdata.ResourceMetrics
	if err := r.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var n int64
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "defenseclaw.cisco.errors" {
				continue
			}
			sum := m.Data.(metricdata.Sum[int64])
			for _, dp := range sum.DataPoints {
				n += dp.Value
			}
		}
	}
	if n < 1 {
		t.Fatalf("expected cisco errors counter, got %d", n)
	}
}

func TestCiscoInspectClient_HTTPErrorEmitsInvalidResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(502)
		_, _ = io.WriteString(w, `{"detail":"bad"}`)
	}))
	t.Cleanup(srv.Close)

	r := sdkmetric.NewManualReader()
	tel, err := telemetry.NewProviderForTest(r)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.CiscoAIDefenseConfig{
		Endpoint:  srv.URL,
		TimeoutMs: 5000,
		APIKeyEnv: "TEST_CISCO_KEY",
	}
	t.Setenv("TEST_CISCO_KEY", "k-test")
	c := NewCiscoInspectClient(cfg, "")
	if c == nil {
		t.Fatal("expected client")
	}
	c.SetTelemetry(tel)

	prev := EventWriter()
	gw, err := gatewaylog.New(gatewaylog.Config{})
	if err != nil {
		t.Fatal(err)
	}
	SetEventWriter(gw)
	t.Cleanup(func() { SetEventWriter(prev) })

	v := c.Inspect([]ChatMessage{{Role: "user", Content: "hi"}})
	if v != nil {
		t.Fatal("expected nil verdict on HTTP error")
	}
}

func TestCiscoInspectClient_InvalidJSONEmitsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, `not-json`)
	}))
	t.Cleanup(srv.Close)

	r := sdkmetric.NewManualReader()
	tel, err := telemetry.NewProviderForTest(r)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.CiscoAIDefenseConfig{
		Endpoint:  srv.URL,
		TimeoutMs: 5000,
		APIKeyEnv: "TEST_CISCO_KEY2",
	}
	t.Setenv("TEST_CISCO_KEY2", "k2")
	c := NewCiscoInspectClient(cfg, "")
	c.SetTelemetry(tel)

	prev := EventWriter()
	gw, err := gatewaylog.New(gatewaylog.Config{})
	if err != nil {
		t.Fatal(err)
	}
	SetEventWriter(gw)
	t.Cleanup(func() { SetEventWriter(prev) })

	_ = c.Inspect([]ChatMessage{{Role: "user", Content: "x"}})

	var rm metricdata.ResourceMetrics
	if err := r.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "defenseclaw.cisco.errors" {
				found = true
			}
			if m.Name == "defenseclaw.cisco_inspect.latency" {
				h, ok := m.Data.(metricdata.Histogram[float64])
				if ok && len(h.DataPoints) > 0 {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("expected cisco metrics")
	}
}

func TestCiscoInspectClient_NetworkErrorUsesUpstreamCode(t *testing.T) {
	cfg := &config.CiscoAIDefenseConfig{
		Endpoint:  "http://127.0.0.1:1",
		TimeoutMs: 200,
		APIKeyEnv: "TEST_CISCO_KEY3",
	}
	t.Setenv("TEST_CISCO_KEY3", "k3")
	c := NewCiscoInspectClient(cfg, "")
	c.SetTelemetry(nil)
	v := c.Inspect([]ChatMessage{{Role: "user", Content: "x"}})
	if v != nil {
		t.Fatal("expected nil")
	}
}

func TestCiscoInspectClient_SuccessRecordsLatency(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"is_safe":true,"action":"allow"}`)
	}))
	t.Cleanup(srv.Close)

	r := sdkmetric.NewManualReader()
	tel, err := telemetry.NewProviderForTest(r)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.CiscoAIDefenseConfig{
		Endpoint:  srv.URL,
		TimeoutMs: 5000,
		APIKeyEnv: "TEST_CISCO_KEY4",
	}
	t.Setenv("TEST_CISCO_KEY4", "k4")
	c := NewCiscoInspectClient(cfg, "")
	c.SetTelemetry(tel)
	v := c.Inspect([]ChatMessage{{Role: "user", Content: "ok"}})
	if v == nil || !strings.Contains(v.Scanner, "ai-defense") {
		t.Fatalf("unexpected verdict: %+v", v)
	}
	var rm metricdata.ResourceMetrics
	if err := r.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	var latPoints int
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "defenseclaw.cisco_inspect.latency" {
				continue
			}
			h := m.Data.(metricdata.Histogram[float64])
			latPoints += len(h.DataPoints)
		}
	}
	if latPoints < 1 {
		t.Fatal("expected latency histogram point")
	}
}
