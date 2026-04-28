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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
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
	got, stats, err := summarizeOTLPPayload(body, otelSignalLogs)
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
	if stats.Records != 4 {
		t.Errorf("stats.Records = %d, want 4 (one per leaf logRecord) — used by the otel.ingest.records counter", stats.Records)
	}
	if stats.Resources != 2 {
		t.Errorf("stats.Resources = %d, want 2", stats.Resources)
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

// newOTLPIngestTestStore wires a temp SQLite store + Logger so the
// ingest handler tests can read back audit rows. The audit logger
// is the only path through which persistAuditEvent observes whether
// the typed action constants survived sanitizeEvent / store.LogEvent.
func newOTLPIngestTestStore(t *testing.T) (*audit.Store, *audit.Logger) {
	t.Helper()
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	logger := audit.NewLogger(store)
	t.Cleanup(func() { logger.Close() })
	return store, logger
}

// TestOTLPIngest_PersistsTypedAuditAction pins the registry contract:
// the OTLP handler must NOT smuggle freeform action keys through the
// audit DB. Every row emitted from the happy path on /v1/logs must
// match audit.ActionOTelIngestLogs verbatim so dashboards filtering
// on action="otel.ingest.logs" stay green and the strict JSON-schema
// gate doesn't drop the row.
func TestOTLPIngest_PersistsTypedAuditAction(t *testing.T) {
	store, logger := newOTLPIngestTestStore(t)
	a := &APIServer{store: store, logger: logger}

	body := `{
		"resourceLogs": [{
			"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "codex"}}]},
			"scopeLogs": [{"logRecords": [{}]}]
		}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-defenseclaw-source", "codex")
	w := httptest.NewRecorder()
	a.handleOTLPLogs(w, req)
	logger.Close() // flush

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}

	// Allow background goroutines to complete (sinks, structured emitter).
	time.Sleep(50 * time.Millisecond)

	rows, err := store.ListEvents(10)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%d want 1; rows=%+v", len(rows), rows)
	}
	if got, want := rows[0].Action, string(audit.ActionOTelIngestLogs); got != want {
		t.Errorf("audit Action = %q, want %q (typed constant from internal/audit/actions.go)", got, want)
	}
	if !audit.IsKnownAction(rows[0].Action) {
		t.Errorf("audit Action %q is not in AllActions(); the action enum must reject unknown values", rows[0].Action)
	}
}

// TestOTLPIngest_MalformedPersistsTypedAuditAction guards the failure
// branch: a body that fails to parse must still hit the audit DB
// under audit.ActionOTelIngestMalformed (not "malformed" or any
// other freeform key). Operators rely on filtering by this exact
// constant to spot connector schema drift.
func TestOTLPIngest_MalformedPersistsTypedAuditAction(t *testing.T) {
	store, logger := newOTLPIngestTestStore(t)
	a := &APIServer{store: store, logger: logger}

	req := httptest.NewRequest(http.MethodPost, "/v1/metrics", strings.NewReader(`{not-json`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-defenseclaw-source", "claudecode")
	w := httptest.NewRecorder()
	a.handleOTLPMetrics(w, req)
	logger.Close()

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d (malformed must still 200 to prevent retry storms)", w.Code)
	}

	time.Sleep(50 * time.Millisecond)

	rows, err := store.ListEvents(10)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%d want 1", len(rows))
	}
	if got, want := rows[0].Action, string(audit.ActionOTelIngestMalformed); got != want {
		t.Errorf("malformed Action = %q, want %q", got, want)
	}
	if rows[0].Severity != "WARN" {
		t.Errorf("malformed Severity = %q, want WARN", rows[0].Severity)
	}
}

// TestCodexNotify_PersistsDynamicSuffixAction pins the dynamic
// codex.notify.<sanitized-type> family. The static enum lists
// codex.notify.agent-turn-complete explicitly; everything else
// must still pass IsKnownActionPrefix so future codex notify types
// don't get rejected by audit-event validators.
func TestCodexNotify_PersistsDynamicSuffixAction(t *testing.T) {
	store, logger := newOTLPIngestTestStore(t)
	a := &APIServer{store: store, logger: logger}

	body := `{"type": "agent-turn-complete", "turn_id": "turn-abc", "model": "gpt-5", "status": "success"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/notify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.handleCodexNotify(w, req)
	logger.Close()

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}

	time.Sleep(50 * time.Millisecond)

	rows, err := store.ListEvents(10)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%d want 1", len(rows))
	}
	if got, want := rows[0].Action, "codex.notify.agent-turn-complete"; got != want {
		t.Errorf("Action = %q, want %q", got, want)
	}
	// Must satisfy *either* the static enum OR the prefix matcher.
	// audit-event.json validators in downstream SIEMs use the same
	// disjunction.
	if !audit.IsKnownAction(rows[0].Action) && !audit.IsKnownActionPrefix(rows[0].Action) {
		t.Errorf("audit Action %q matches neither IsKnownAction nor IsKnownActionPrefix", rows[0].Action)
	}
	if rows[0].SessionID != "turn-abc" {
		t.Errorf("SessionID = %q, want %q (codex notify rows must carry turn_id for SIEM rollups)", rows[0].SessionID, "turn-abc")
	}
}

// TestCodexNotify_NoTypePersistsBareAction ensures a notify payload
// without a `type` field produces audit.ActionCodexNotify (the bare
// "codex.notify" key) rather than "codex.notify." with an empty
// suffix that would slip past the prefix matcher.
func TestCodexNotify_NoTypePersistsBareAction(t *testing.T) {
	store, logger := newOTLPIngestTestStore(t)
	a := &APIServer{store: store, logger: logger}

	body := `{"turn_id": "turn-xyz"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/notify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.handleCodexNotify(w, req)
	logger.Close()

	time.Sleep(50 * time.Millisecond)

	rows, err := store.ListEvents(10)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%d want 1", len(rows))
	}
	if got, want := rows[0].Action, string(audit.ActionCodexNotify); got != want {
		t.Errorf("Action = %q, want %q (no type → bare codex.notify)", got, want)
	}
}
