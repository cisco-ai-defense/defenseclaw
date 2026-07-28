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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestNormalizeConnectorTelemetrySourceIncludesHookOnlyBuiltins(t *testing.T) {
	for _, source := range []string{"opencode", "omnigent"} {
		if got := normalizeConnectorTelemetrySource(source); got != source {
			t.Errorf("normalizeConnectorTelemetrySource(%q) = %q", source, got)
		}
	}
}

func TestDecodeOTLPAnyValue_DepthCap(t *testing.T) {
	shallow := decodeOTLPAnyValue(json.RawMessage(`{"kvlistValue":{"values":[{"key":"k","value":{"stringValue":"leaf"}}]}}`))
	if got := shallow.(map[string]interface{})["k"]; got != "leaf" {
		t.Fatalf("shallow kvlist decode = %#v, want leaf", shallow)
	}

	raw := json.RawMessage(`{"stringValue":"leaf"}`)
	for i := 0; i < maxOTLPAnyValueDepth+3; i++ {
		raw = json.RawMessage(`{"kvlistValue":{"values":[{"key":"k","value":` + string(raw) + `}]}}`)
	}
	got := decodeOTLPAnyValue(raw)
	var containsCappedNil func(interface{}) bool
	containsCappedNil = func(v interface{}) bool {
		switch x := v.(type) {
		case nil:
			return true
		case map[string]interface{}:
			for _, child := range x {
				if containsCappedNil(child) {
					return true
				}
			}
		case []interface{}:
			for _, child := range x {
				if containsCappedNil(child) {
					return true
				}
			}
		}
		return false
	}
	if !containsCappedNil(got) {
		t.Fatalf("deep kvlist decode did not hit depth cap: %#v", got)
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

func TestDeltaOTLPCumulativeTokenUsage(t *testing.T) {
	a := &APIServer{}
	base := otelTokenUsage{
		cumulative: true,
		seriesKey:  "claude-input",
		startTime:  "1000",
		tokens:     100,
	}
	got, ok := a.deltaOTLPCumulativeTokenUsage(base)
	if !ok || got.tokens != 100 {
		t.Fatalf("first cumulative point = (%+v,%v), want 100,true", got, ok)
	}
	if _, ok := a.deltaOTLPCumulativeTokenUsage(base); ok {
		t.Fatal("duplicate cumulative point must not emit a second usage observation")
	}
	base.tokens = 145
	got, ok = a.deltaOTLPCumulativeTokenUsage(base)
	if !ok || got.tokens != 45 {
		t.Fatalf("cumulative delta = (%+v,%v), want 45,true", got, ok)
	}
	base.tokens = 120
	if _, ok := a.deltaOTLPCumulativeTokenUsage(base); ok {
		t.Fatal("lower out-of-order cumulative point must not emit a fresh delta")
	}
	base.tokens = 150
	got, ok = a.deltaOTLPCumulativeTokenUsage(base)
	if !ok || got.tokens != 5 {
		t.Fatalf("delta after out-of-order point = (%+v,%v), want 5,true", got, ok)
	}
	base.startTime = "2000"
	base.tokens = 12
	got, ok = a.deltaOTLPCumulativeTokenUsage(base)
	if !ok || got.tokens != 12 {
		t.Fatalf("reset cumulative point = (%+v,%v), want 12,true", got, ok)
	}
}

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

func TestOTLPIngest_IsOTLPContentType_AcceptsJSONAndProtobuf(t *testing.T) {
	for _, ct := range []string{"application/json", "application/x-protobuf", "application/x-protobuf; charset=utf-8"} {
		if !isOTLPContentType(ct) {
			t.Errorf("isOTLPContentType(%q) = false, want true", ct)
		}
	}
}

// TestSanitizeRouteForTelemetry pins the contract that the OTLP
// path-token segment is replaced with a fixed "_token_" placeholder
// before reaching telemetry. If this test ever regresses, the master
// gateway bearer token will leak from /otlp/<source>/<token>/v1/<signal>
// URLs into whatever OTel backend the sidecar exports to (and into the
// gateway's own otel.http.* metrics, which then get exported again).
func TestSanitizeRouteForTelemetry(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "geminicli logs path-token redacted",
			in:   "/otlp/geminicli/sk-dc-supersecret-master-token/v1/logs",
			want: "/otlp/geminicli/_token_/v1/logs",
		},
		{
			name: "metrics signal redacted",
			in:   "/otlp/cursor/abcdef0123456789/v1/metrics",
			want: "/otlp/cursor/_token_/v1/metrics",
		},
		{
			name: "traces signal redacted",
			in:   "/otlp/codex/raw.token.value/v1/traces",
			want: "/otlp/codex/_token_/v1/traces",
		},
		{
			name: "url-escaped token still scrubbed",
			in:   "/otlp/geminicli/sk%2Ddc%2Dabc/v1/logs",
			want: "/otlp/geminicli/_token_/v1/logs",
		},
		{
			name: "non-otlp route untouched",
			in:   "/api/v1/agents/discover",
			want: "/api/v1/agents/discover",
		},
		{
			name: "shared otlp endpoint untouched (no path-token)",
			in:   "/v1/logs",
			want: "/v1/logs",
		},
		{
			name: "malformed otlp path untouched",
			in:   "/otlp/geminicli/v1/logs",
			want: "/otlp/geminicli/v1/logs",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeRouteForTelemetry(tc.in)
			if got != tc.want {
				t.Fatalf("sanitizeRouteForTelemetry(%q) = %q, want %q", tc.in, got, tc.want)
			}
			// Defensive: ensure the original token (if any) does not
			// survive in the output. We use a representative secret
			// pattern; if the implementation regresses to a substring
			// match this assertion will still catch the token leak.
			if strings.Contains(tc.in, "supersecret") && strings.Contains(got, "supersecret") {
				t.Fatalf("sanitized route still contains the master token: %q", got)
			}
		})
	}
}

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
	store, logger := testStoreAndLogger(t)
	t.Cleanup(func() { logger.Close() })
	return store, logger
}

// TestOTLPIngest_PersistsTypedAuditAction pins the registry contract:
// the OTLP handler must NOT smuggle freeform action keys through the
// audit DB. Every row emitted from the happy path on /v1/logs must
// match audit.ActionOTelIngestLogs verbatim so dashboards filtering
// on action="otel.ingest.logs" stay green and the strict JSON-schema
// gate doesn't drop the row.
func TestCodexNotify_PersistsDynamicSuffixAction(t *testing.T) {
	store, logger := newOTLPIngestTestStore(t)
	a := &APIServer{store: store, logger: logger}

	body := `{"type": "agent-turn-complete", "turn-id": "turn-abc", "model": "gpt-5", "status": "success"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/notify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(audit.ContextWithEnvelope(req.Context(), audit.CorrelationEnvelope{
		TraceID:        "trace-123",
		RequestID:      "req-123",
		RunID:          "run-123",
		PolicyID:       "policy-123",
		DestinationApp: "codex",
	}))
	w := httptest.NewRecorder()
	a.handleCodexNotify(w, req)
	logger.Close()

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}

	time.Sleep(50 * time.Millisecond)

	canonical, synthetic := splitCodexNotifyAuditRows(t, store)
	if len(canonical) != 1 {
		t.Fatalf("codex.notify rows=%d want 1", len(canonical))
	}
	if len(synthetic) != 1 {
		t.Fatalf("connector-hook-synthetic rows=%d want 1", len(synthetic))
	}
	if got, want := canonical[0].Action, "codex.notify.agent-turn-complete"; got != want {
		t.Errorf("Action = %q, want %q", got, want)
	}
	// Must satisfy *either* the static enum OR the prefix matcher.
	// audit-event.json validators in downstream SIEMs use the same
	// disjunction.
	if !audit.IsKnownAction(canonical[0].Action) && !audit.IsKnownActionPrefix(canonical[0].Action) {
		t.Errorf("audit Action %q matches neither IsKnownAction nor IsKnownActionPrefix", canonical[0].Action)
	}
	if canonical[0].SessionID != "turn-abc" {
		t.Errorf("SessionID = %q, want %q (codex notify rows must fall back to turn-id when thread-id is absent)", canonical[0].SessionID, "turn-abc")
	}
	if canonical[0].TraceID != "trace-123" || canonical[0].RequestID != "req-123" ||
		canonical[0].RunID != "run-123" || canonical[0].PolicyID != "policy-123" ||
		canonical[0].DestinationApp != "codex" {
		t.Errorf("canonical notify row missing correlation envelope: trace=%q request=%q run=%q policy=%q destination=%q",
			canonical[0].TraceID, canonical[0].RequestID, canonical[0].RunID, canonical[0].PolicyID, canonical[0].DestinationApp)
	}
	// F2: synthetic row must carry the same SessionID as the
	// canonical row so SIEM joins on session_id correlate the
	// pair. The synthetic row used to drop session_id because
	// CorrelationMiddleware only sees the inbound HTTP headers
	// (no X-DefenseClaw-Session-Id from notify-bridge.sh) and the
	// payload-derived value was never threaded into the audit
	// envelope. enrichAgentHookContext now refreshes the envelope
	// so this assertion passes.
	if synthetic[0].SessionID != "turn-abc" {
		t.Errorf("synthetic row SessionID = %q, want %q (F2: must inherit from req.SessionID)", synthetic[0].SessionID, "turn-abc")
	}
	if strings.Contains(canonical[0].Details, body) {
		t.Fatalf("Details stored raw notify body: %q", canonical[0].Details)
	}
	if !strings.Contains(canonical[0].Details, "body_sha256") || !strings.Contains(canonical[0].Details, "body_len") {
		t.Fatalf("Details missing redacted notify summary fields: %q", canonical[0].Details)
	}
}

func TestCodexNotifyAuditDetails_RedactsRawPayload(t *testing.T) {
	body := []byte(`{"type":"agent-turn-complete","turn-id":"turn-secret-123","model":"gpt-5","status":"ok","prompt":"please leak sk-secret-token"}`)
	details := codexNotifyAuditDetails(codexNotifyPayload{
		Type:   "agent-turn-complete",
		TurnID: "turn-secret-123",
		Model:  "gpt-5",
		Status: "ok",
	}, body, "agent-turn-complete", "ok", nil)

	for _, forbidden := range []string{"please leak", "sk-secret-token", string(body)} {
		if strings.Contains(details, forbidden) {
			t.Fatalf("notify details leaked raw payload content %q: %s", forbidden, details)
		}
	}
	for _, want := range []string{"body_len", "body_sha256", "agent-turn-complete"} {
		if !strings.Contains(details, want) {
			t.Fatalf("notify details missing %q: %s", want, details)
		}
	}
}

// TestCodexNotify_NoTypePersistsBareAction ensures a notify payload
// without a `type` field produces audit.ActionCodexNotify (the bare
// "codex.notify" key) rather than "codex.notify." with an empty
// suffix that would slip past the prefix matcher.
func TestCodexNotify_NoTypePersistsBareAction(t *testing.T) {
	store, logger := newOTLPIngestTestStore(t)
	a := &APIServer{store: store, logger: logger}

	body := `{"turn-id": "turn-xyz"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/notify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.handleCodexNotify(w, req)
	logger.Close()

	time.Sleep(50 * time.Millisecond)

	canonical, synthetic := splitCodexNotifyAuditRows(t, store)
	if len(canonical) != 1 {
		t.Fatalf("codex.notify rows=%d want 1", len(canonical))
	}
	if len(synthetic) != 1 {
		t.Fatalf("connector-hook-synthetic rows=%d want 1", len(synthetic))
	}
	if got, want := canonical[0].Action, string(audit.ActionCodexNotify); got != want {
		t.Errorf("Action = %q, want %q (no type → bare codex.notify)", got, want)
	}
}

func TestCodexNotify_PrefersThreadIDForSessionCorrelation(t *testing.T) {
	store, logger := newOTLPIngestTestStore(t)
	a := &APIServer{store: store, logger: logger}

	body := `{"type":"agent-turn-complete","thread-id":"thread-123","turn-id":"turn-abc","model":"gpt-5","status":"success"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/notify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.handleCodexNotify(w, req)
	logger.Close()

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}

	time.Sleep(50 * time.Millisecond)

	canonical, synthetic := splitCodexNotifyAuditRows(t, store)
	if len(canonical) != 1 {
		t.Fatalf("codex.notify rows=%d want 1", len(canonical))
	}
	if len(synthetic) != 1 {
		t.Fatalf("connector-hook-synthetic rows=%d want 1", len(synthetic))
	}
	if got, want := canonical[0].SessionID, "thread-123"; got != want {
		t.Fatalf("SessionID = %q, want %q", got, want)
	}
	// F2: synthetic row must carry the SAME session id as the
	// canonical row, even when thread-id is preferred over
	// turn-id. enrichAgentHookContext reads req.SessionID which
	// codexNotifyToAgentHookRequest set from codexNotifySessionID,
	// so the two rows MUST agree.
	if got, want := synthetic[0].SessionID, "thread-123"; got != want {
		t.Fatalf("synthetic row SessionID = %q, want %q (F2)", got, want)
	}
	if !strings.Contains(canonical[0].Details, "thread_id=") {
		t.Fatalf("Details missing thread_id summary: %q", canonical[0].Details)
	}
	if !strings.Contains(canonical[0].Details, "turn_id=") {
		t.Fatalf("Details missing turn_id summary: %q", canonical[0].Details)
	}
}

// splitCodexNotifyAuditRows fetches the audit-store contents and
// partitions them into the two row classes the codex notify
// pipeline produces:
//
//   - canonical: action == "codex.notify[.suffix]" — the row the
//     SIEM has always seen, one per inbound notify;
//   - synthetic: action == ActionConnectorHookSynthetic — the
//     visibility row written by the unified hook collector when it
//     synthesizes a Stop event from the same payload.
//
// Centralizing the split in a helper means every test asserting
// the contract reads the same way and a future SIEM rule writer
// can grep for one symbol to discover the row taxonomy.
func splitCodexNotifyAuditRows(t *testing.T, store *audit.Store) (canonical, synthetic []audit.Event) {
	t.Helper()
	rows, err := store.ListEvents(10)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	for _, r := range rows {
		switch {
		case strings.HasPrefix(r.Action, string(audit.ActionCodexNotify)):
			canonical = append(canonical, r)
		case r.Action == string(audit.ActionConnectorHookSynthetic):
			synthetic = append(synthetic, r)
		default:
			t.Fatalf("unexpected audit Action=%q (test fixture should only produce codex.notify* + %s)",
				r.Action, audit.ActionConnectorHookSynthetic)
		}
	}
	return canonical, synthetic
}

// TestSanitizeCodexNotifySpanString_StripsAndCaps pins the contract
// codex notify span enrichment depends on: control / CR / LF / ANSI
// runes are stripped before stamping onto span attributes, and
// oversized inputs are truncated on a UTF-8 rune boundary so the
// resulting attribute is always valid UTF-8 (OTLP exporters drop
// spans with invalid-UTF-8 string attributes).
//
// The UTF-8 truncation case is the regression guard: a naive
// `value[:maxLen]` would have split the trailing 3-byte rune
// mid-sequence, producing 0xE0 0xA4 with no continuation byte and
// breaking the OTLP wire encoding.
func TestSanitizeCodexNotifySpanString_StripsAndCaps(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		maxLen int
		want   string
	}{
		{name: "empty", in: "", maxLen: 128, want: ""},
		{name: "trims whitespace", in: "  gpt-5  ", maxLen: 128, want: "gpt-5"},
		{name: "strips CRLF", in: "gpt-5\r\nclaude", maxLen: 128, want: "gpt-5  claude"},
		{name: "strips ANSI ESC", in: "gpt-5\x1b[31mRED", maxLen: 128, want: "gpt-5 [31mRED"},
		{name: "strips other control runes", in: "gpt-5\x00\x07\x08", maxLen: 128, want: "gpt-5   "},
		{name: "preserves tab", in: "gpt-5\tturbo", maxLen: 128, want: "gpt-5\tturbo"},
		{name: "strips 0x7F", in: "gpt-5\x7f", maxLen: 128, want: "gpt-5 "},
		{name: "byte-cap respected", in: strings.Repeat("a", 200), maxLen: 64, want: strings.Repeat("a", 64)},
		// "नमस्ते" is 18 bytes (six 3-byte runes). A naive
		// value[:16] would split the 6th rune mid-sequence and
		// emit invalid UTF-8. truncateToRuneBoundary lands on the
		// 6th rune's leader at offset 15, sees a 3-byte rune won't
		// fit in 16 bytes, and returns the 5-rune (15-byte) prefix.
		{name: "utf8 boundary truncate", in: "नमस्ते", maxLen: 16, want: "नमस्त"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeCodexNotifySpanString(tc.in, tc.maxLen)
			if got != tc.want {
				t.Fatalf("sanitizeCodexNotifySpanString(%q, %d) = %q, want %q", tc.in, tc.maxLen, got, tc.want)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("sanitizeCodexNotifySpanString returned invalid UTF-8: %q", got)
			}
		})
	}
}

// TestEnrichCodexNotifySpan_SanitizesAttributes proves a hostile
// codex notify payload (CRLF + ANSI in Status, oversized Model)
// reaches the active span as sanitized + length-capped attributes
// rather than as raw user-controlled bytes. This is the regression
// guard for the log-injection / span-storage-DoS surface: an OTel
// trace viewer rendering raw span attributes from this code path
// would otherwise see attacker-supplied terminal escapes.
func TestEnrichCodexNotifySpan_SanitizesAttributes(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSyncer(exp),
	)
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "codex.notify")

	p := codexNotifyPayload{
		Status: "ok\r\n\x1b[31mFAKE-ALERT",
		Model:  strings.Repeat("m", 256),
	}
	enrichCodexNotifySpan(ctx, p, "agent-turn-complete", "ok")
	span.End()

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("spans=%d want 1", len(spans))
	}
	attrs := map[string]string{}
	for _, kv := range spans[0].Attributes {
		attrs[string(kv.Key)] = kv.Value.AsString()
	}

	statusAttr := attrs["defenseclaw.codex.notify.status"]
	if statusAttr == "" {
		t.Fatalf("missing defenseclaw.codex.notify.status; attrs=%v", attrs)
	}
	if strings.ContainsAny(statusAttr, "\r\n\x1b") {
		t.Fatalf("status attr leaks CR/LF/ESC: %q", statusAttr)
	}

	modelAttr := attrs["gen_ai.response.model"]
	if modelAttr == "" {
		t.Fatalf("missing gen_ai.response.model; attrs=%v", attrs)
	}
	if len(modelAttr) > 128 {
		t.Fatalf("model attr not capped: len=%d", len(modelAttr))
	}
	if !utf8.ValidString(modelAttr) {
		t.Fatalf("model attr is invalid UTF-8: %q", modelAttr)
	}
}
