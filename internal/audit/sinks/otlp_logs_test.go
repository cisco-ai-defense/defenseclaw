// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package sinks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	otellog "go.opentelemetry.io/otel/log"
)

// TestNewOTLPLogsSink_ValidatesEndpoint exercises fast-fail paths that
// do not spin up an exporter — these assert the config contract, not the
// OTel SDK behaviour (which we trust the upstream test suite to cover).
func TestNewOTLPLogsSink_ValidatesEndpoint(t *testing.T) {
	if _, err := NewOTLPLogsSink(context.Background(),
		OTLPLogsConfig{Protocol: "grpc"}); err == nil {
		t.Fatal("expected error when endpoint missing")
	}
}

func TestNewOTLPLogsSink_AppliesDefaultsAndBuilds(t *testing.T) {
	// Use HTTP + Insecure so the exporter constructor succeeds without a
	// live collector. We shut down immediately so nothing is actually
	// sent; we only care that config validation + SDK wiring succeed.
	sink, err := NewOTLPLogsSink(context.Background(), OTLPLogsConfig{
		Name:     "otlp",
		Endpoint: "127.0.0.1:4318",
		Protocol: "http",
		Insecure: true,
		Headers:  map[string]string{"X-Token": "${DC_NOT_SET}"},
	})
	if err != nil {
		t.Fatalf("NewOTLPLogsSink err=%v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	if sink.Name() != "otlp" || sink.Kind() != "otlp_logs" {
		t.Fatalf("name/kind wrong: %s/%s", sink.Name(), sink.Kind())
	}
	// LoggerName default must have been applied.
	if sink.cfg.LoggerName != "defenseclaw.audit" {
		t.Fatalf("default LoggerName not applied: %q", sink.cfg.LoggerName)
	}
	// Batch defaults applied.
	if sink.cfg.BatchSizeMx == 0 || sink.cfg.QueueSize == 0 || sink.cfg.IntervalMs == 0 {
		t.Fatalf("defaults not applied: %+v", sink.cfg)
	}
}

func TestOTLPLogsSink_Forward_FilterSuppressesLowSeverity(t *testing.T) {
	sink, err := NewOTLPLogsSink(context.Background(), OTLPLogsConfig{
		Endpoint: "127.0.0.1:4318",
		Protocol: "http",
		Insecure: true,
		Filter:   SinkFilter{MinSeverity: "HIGH"},
	})
	if err != nil {
		t.Fatalf("NewOTLPLogsSink err=%v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	// Neither Forward call should error. The filter rejects the first
	// silently (no receiver needed) — this is a smoke test for the
	// hot-path early return.
	if err := sink.Forward(context.Background(),
		Event{ID: "low", Severity: "LOW"}); err != nil {
		t.Fatalf("Forward LOW err=%v (filter must drop silently)", err)
	}
	if err := sink.Forward(context.Background(),
		Event{ID: "hi", Severity: "HIGH",
			Timestamp: time.Unix(1700000000, 0)}); err != nil {
		t.Fatalf("Forward HIGH err=%v", err)
	}
}

func TestOTLPLogsSink_HTTPURLFormEndpointFlushes(t *testing.T) {
	type requestInfo struct {
		path   string
		header string
	}
	reqC := make(chan requestInfo, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqC <- requestInfo{
			path:   r.URL.Path,
			header: r.Header.Get("X-Test"),
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewOTLPLogsSink(context.Background(), OTLPLogsConfig{
		Name:       "otlp",
		Endpoint:   srv.URL,
		Protocol:   "http",
		Headers:    map[string]string{"X-Test": "sink-header"},
		TimeoutS:   2,
		LoggerName: "defenseclaw.audit.test",
	})
	if err != nil {
		t.Fatalf("NewOTLPLogsSink err=%v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	if err := sink.Forward(context.Background(), Event{
		ID:        "evt-1",
		Timestamp: time.Now().UTC(),
		Action:    "guardrail-verdict",
		Target:    "prompt",
		Actor:     "defenseclaw",
		Details:   "blocked",
		Severity:  "HIGH",
	}); err != nil {
		t.Fatalf("Forward err=%v", err)
	}
	if err := sink.Flush(context.Background()); err != nil {
		t.Fatalf("Flush err=%v", err)
	}

	select {
	case got := <-reqC:
		if got.path != "/v1/logs" {
			t.Fatalf("request path=%q want /v1/logs", got.path)
		}
		if got.header != "sink-header" {
			t.Fatalf("X-Test header=%q want sink-header", got.header)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for OTLP logs request")
	}
}

func TestSeverityToOTel(t *testing.T) {
	cases := []struct {
		in   string
		want otellog.Severity
	}{
		{"CRITICAL", otellog.SeverityFatal},
		{"HIGH", otellog.SeverityError},
		{"MEDIUM", otellog.SeverityWarn},
		{"LOW", otellog.SeverityInfo},
		{"INFO", otellog.SeverityInfo},
		{"", otellog.SeverityInfo},
		{"bogus", otellog.SeverityInfo}, // unknown → info (fail-open)
	}
	for _, tt := range cases {
		t.Run(tt.in, func(t *testing.T) {
			if got := severityToOTel(tt.in); got != tt.want {
				t.Fatalf("severityToOTel(%q)=%v want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestBuildBody_PrefersStructuredOverDetails(t *testing.T) {
	ev := Event{
		Action:     "guardrail-verdict",
		Target:     "prompt",
		Details:    "legacy string",
		Structured: map[string]any{"stage": "guardrail", "severity": "HIGH"},
	}
	got := buildBody(ev)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("not JSON: %v (%s)", err, got)
	}
	if parsed["stage"] != "guardrail" {
		t.Fatalf("structured payload not preserved: %v", parsed)
	}
	if _, hasLegacy := parsed["details"]; hasLegacy {
		t.Fatalf("legacy details leaked when structured present: %v", parsed)
	}
}

func TestBuildBody_FallsBackToDetails(t *testing.T) {
	ev := Event{Action: "scan", Target: "mcp", Details: "plain text"}
	got := buildBody(ev)
	if !strings.Contains(got, `"details":"plain text"`) ||
		!strings.Contains(got, `"action":"scan"`) {
		t.Fatalf("details fallback missing: %s", got)
	}
}

func TestBuildBody_MinimalWhenNothingProvided(t *testing.T) {
	ev := Event{Action: "x", Target: "y"}
	got := buildBody(ev)
	if !strings.Contains(got, `"action":"x"`) ||
		!strings.Contains(got, `"target":"y"`) {
		t.Fatalf("minimal body missing required fields: %s", got)
	}
	// Must still be valid JSON so receivers don't blow up on parse.
	var parsed map[string]string
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("not JSON: %v (%s)", err, got)
	}
}

func TestLoadTLSConfig_ErrorsOnMissingFile(t *testing.T) {
	if _, err := loadTLSConfig("/does/not/exist.pem"); err == nil {
		t.Fatal("expected error on missing CA cert")
	}
}

func TestLoadTLSConfig_ErrorsOnInvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bogus.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := loadTLSConfig(path); err == nil {
		t.Fatal("expected error on invalid PEM")
	}
}
