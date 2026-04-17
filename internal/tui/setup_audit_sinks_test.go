// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestFmtOTelHeaders_EmptyReturnsNone(t *testing.T) {
	if got := fmtOTelHeaders(nil); got != "(none)" {
		t.Fatalf("nil headers=%q want (none)", got)
	}
	if got := fmtOTelHeaders(map[string]string{}); got != "(none)" {
		t.Fatalf("empty headers=%q want (none)", got)
	}
}

func TestFmtOTelHeaders_RedactsValuesAndSortsKeys(t *testing.T) {
	// Key ordering must be deterministic so the TUI view doesn't
	// flicker on refresh; values must never appear verbatim since
	// they frequently carry bearer tokens.
	in := map[string]string{
		"X-SF-Token":    "super-secret-token",
		"Authorization": "Bearer sk-live-xyz",
	}
	got := fmtOTelHeaders(in)

	for _, secret := range []string{"super-secret-token", "sk-live-xyz", "Bearer"} {
		if strings.Contains(got, secret) {
			t.Errorf("rendered header contains raw value %q: %q", secret, got)
		}
	}
	// Keys must appear sorted (Authorization < X-SF-Token lexically).
	authIdx := strings.Index(got, "Authorization")
	sfIdx := strings.Index(got, "X-SF-Token")
	if authIdx < 0 || sfIdx < 0 || authIdx > sfIdx {
		t.Fatalf("expected sorted keys: %q", got)
	}
	if !strings.Contains(got, "values redacted") {
		t.Fatalf("missing redaction marker: %q", got)
	}
}

func TestAuditSinkSummaryFields_EmptyShowsStatusAndHint(t *testing.T) {
	c := &config.Config{}
	fields := auditSinkSummaryFields(c)
	if len(fields) != 2 {
		t.Fatalf("got %d fields want 2 (status+hint): %+v", len(fields), fields)
	}
	if fields[0].Key != "audit_sinks.summary" ||
		!strings.Contains(fields[0].Value, "no sinks configured") {
		t.Errorf("status row wrong: %+v", fields[0])
	}
	if fields[1].Key != "audit_sinks.hint" ||
		!strings.Contains(fields[1].Value, "config.yaml") {
		t.Errorf("hint row wrong: %+v", fields[1])
	}
}

func TestAuditSinkSummaryFields_RendersEndpointPerKind(t *testing.T) {
	c := &config.Config{
		AuditSinks: []config.AuditSink{
			{
				Name: "splunk-prod", Kind: config.SinkKindSplunkHEC, Enabled: true,
				SplunkHEC: &config.SplunkHECSinkConfig{Endpoint: "https://splunk.example.com:8088/services/collector"},
			},
			{
				Name: "otel-dev", Kind: config.SinkKindOTLPLogs, Enabled: false,
				OTLPLogs: &config.OTLPLogsSinkConfig{Endpoint: "otel-collector:4317"},
			},
			{
				Name: "webhook", Kind: config.SinkKindHTTPJSONL, Enabled: true,
				HTTPJSONL: &config.HTTPJSONLSinkConfig{URL: "https://siem.example.com/ingest"},
			},
		},
	}

	fields := auditSinkSummaryFields(c)
	// 3 sinks + 1 hint
	if len(fields) != 4 {
		t.Fatalf("got %d fields want 4: %+v", len(fields), fields)
	}

	// The last entry must always be the edit hint.
	if fields[len(fields)-1].Key != "audit_sinks.hint" {
		t.Fatalf("last field must be hint, got %+v", fields[len(fields)-1])
	}

	// Assertions per sink row.
	rows := map[string]configField{}
	for _, f := range fields {
		rows[f.Label] = f
	}

	if v := rows["splunk-prod"].Value; !strings.Contains(v, "[splunk_hec]") ||
		!strings.Contains(v, "enabled") ||
		!strings.Contains(v, "splunk.example.com") {
		t.Errorf("splunk row wrong: %q", v)
	}

	if v := rows["otel-dev"].Value; !strings.Contains(v, "[otlp_logs]") ||
		!strings.Contains(v, "disabled") ||
		!strings.Contains(v, "otel-collector:4317") {
		t.Errorf("otel row wrong: %q", v)
	}

	if v := rows["webhook"].Value; !strings.Contains(v, "[http_jsonl]") ||
		!strings.Contains(v, "enabled") ||
		!strings.Contains(v, "siem.example.com/ingest") {
		t.Errorf("webhook row wrong: %q", v)
	}
}

func TestAuditSinkSummaryFields_OmitsEndpointWhenKindBlockIsNil(t *testing.T) {
	// Defensive: the TUI must not panic if a malformed sink made it
	// past validation (shouldn't happen in practice, but the UI is
	// render-only and must degrade gracefully).
	c := &config.Config{
		AuditSinks: []config.AuditSink{
			{Name: "broken", Kind: config.SinkKindSplunkHEC, Enabled: true},
		},
	}
	fields := auditSinkSummaryFields(c)
	if len(fields) != 2 {
		t.Fatalf("got %d fields want 2 (broken+hint): %+v", len(fields), fields)
	}
	row := fields[0]
	if !strings.Contains(row.Value, "[splunk_hec]") {
		t.Errorf("expected kind tag, got %q", row.Value)
	}
	if strings.Contains(row.Value, "→") {
		t.Errorf("must not render arrow when kind block is nil: %q", row.Value)
	}
}
