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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

// TestOTLPIngest_Logs_RejectsNonJSONContentType pins the 415
// contract. Codex and Claude Code both emit OTLP-JSON; protobuf
// is intentionally not yet supported. A wrong-Content-Type
// request must surface a structured 415 (rather than parse
// failure) so the operator's exporter logs make the protocol
// mismatch obvious.
func TestOTLPIngest_Logs_RejectsNonJSONContentType(t *testing.T) {
	a := &APIServer{}
	req := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(`payload`))
	req.Header.Set("Content-Type", "application/x-protobuf")
	w := httptest.NewRecorder()

	a.handleOTLPLogs(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want 415; body=%q", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "application/json") {
		t.Errorf("error body should mention application/json so operator knows the supported shape; got %q", w.Body.String())
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
	got, err := summarizeOTLPPayload(body, otelSignalLogs)
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
