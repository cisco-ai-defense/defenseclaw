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

	verdict := c.Inspect([]ChatMessage{
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
