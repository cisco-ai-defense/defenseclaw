// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// stubPanicLogger captures audit envelopes written via logger.LogActionCtx
// so the panic-path assertions can verify that the synthetic
// result="panic" row reached the audit sink.
type stubPanicLogger struct {
	rows []map[string]interface{}
}

func (s *stubPanicLogger) entries() []map[string]interface{} {
	out := make([]map[string]interface{}, len(s.rows))
	copy(out, s.rows)
	return out
}

// TestSafeEvaluateHook_RecoversAndReturnsFailOpen exercises
// safeEvaluateHook directly: a panicking evaluator must not propagate
// the panic, must mark panicked=true, and must return a fail-open
// response with would_block=true and a stable Reason so SIEM dashboards
// can find it.
func TestSafeEvaluateHook_RecoversAndReturnsFailOpen(t *testing.T) {
	api := &APIServer{}

	req := agentHookRequest{HookEventName: "PreToolUse"}
	evalResp, panicked := api.safeEvaluateHook(context.Background(), "codex", req, nil, nil, hookProfileRuntime{
		Evaluate: func(*APIServer, context.Context, agentHookRequest, []byte, map[string]interface{}) agentHookResponse {
			panic("safeEvaluateHook test panic")
		},
	})
	if !panicked {
		t.Fatal("safeEvaluateHook panicked=false, want true")
	}
	if evalResp.Action != "allow" || !evalResp.WouldBlock {
		t.Fatalf("safeEvaluateHook panic response = %+v, want fail-open allow + would_block", evalResp)
	}

	resp := safeHookPanicResponse("codex", "PreToolUse", "stack trace would go here")
	if resp.Action != "allow" {
		t.Errorf("panic action = %q, want allow", resp.Action)
	}
	if !resp.WouldBlock {
		t.Errorf("panic WouldBlock = false, want true (deny posture in stricter mode)")
	}
	if resp.Severity != "WARN" {
		t.Errorf("panic Severity = %q, want WARN", resp.Severity)
	}
	if !strings.Contains(resp.Reason, "internal evaluator error") {
		t.Errorf("panic Reason = %q, want substring 'internal evaluator error'", resp.Reason)
	}
	if !strings.Contains(resp.AdditionalContext, "codex") || !strings.Contains(resp.AdditionalContext, "PreToolUse") {
		t.Errorf("panic AdditionalContext = %q, want connector + event names", resp.AdditionalContext)
	}

	// handleHookPanic is a no-op when api.otel is nil; just verify
	// that calling it on a nil-otel APIServer doesn't blow up
	// (defensive: panic recovery must itself be panic-safe).
	api.handleHookPanic(context.Background(), "codex", "PreToolUse", "stack trace")
}

// TestHandleAgentHook_PanicReturnsSafeResponse drives a full HTTP
// request through handleAgentHook with an evaluator that panics. The
// HTTP response must remain 200 with a valid JSON body so the agent
// CLI continues; downstream audit/metric pipelines must label the
// row as result="panic".
//
// The test forces a panic through the profile-runtime dispatch by
// triggering the generic evaluateAgentHook path. Since evaluateAgentHook
// is used for profile-only connectors, we use a registered generic
// connector name and inject a panic via a custom test hook on APIServer.
func TestHandleAgentHook_PanicReturnsSafeResponse(t *testing.T) {
	prev := hookEvaluatorPanicHook
	hookEvaluatorPanicHook = func() { panic("synthetic evaluator panic for test") }
	defer func() { hookEvaluatorPanicHook = prev }()

	api := &APIServer{}
	handler := http.HandlerFunc(api.handleAgentHook("hermes"))
	body, _ := json.Marshal(map[string]interface{}{
		"hook_event_name": "pre_tool_call",
		"session_id":      "session-panic",
		"agent_id":        "hermes-test",
		"tool_name":       "shell",
		"tool_input": map[string]interface{}{
			"command": "echo hello",
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hermes/hook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 (panic must fail-open, not fail the request) body=%s",
			w.Code, w.Body.String())
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("response body is not valid JSON after panic: %v body=%s", err, w.Body.String())
	}
	if got, _ := parsed["action"].(string); got != "allow" {
		t.Errorf("response action = %q, want allow (panic fail-open)", got)
	}
	if got, _ := parsed["would_block"].(bool); !got {
		t.Errorf("response would_block = false, want true (panic carries guardrail intent)")
	}
	if reason, _ := parsed["reason"].(string); !strings.Contains(reason, "internal evaluator error") {
		t.Errorf("response reason = %q, want 'internal evaluator error' substring", reason)
	}
}

func TestHandleAgentHook_EmitPanicReturnsSafeResponse(t *testing.T) {
	prev, had := hookProfileRuntimes["hermes"]
	hookProfileRuntimes["hermes"] = func(profile connector.HookProfile) hookProfileRuntime {
		runtime := defaultHookProfileRuntime(profile)
		runtime.EmitLLMEvent = func(*APIServer, context.Context, agentHookRequest, []byte, map[string]interface{}, []string) {
			panic("synthetic emit panic for test")
		}
		return runtime
	}
	defer func() {
		if had {
			hookProfileRuntimes["hermes"] = prev
		} else {
			delete(hookProfileRuntimes, "hermes")
		}
	}()

	api := &APIServer{}
	handler := http.HandlerFunc(api.handleAgentHook("hermes"))
	body := `{"hook_event_name":"pre_tool_call","session_id":"session-emit-panic","tool_name":"shell"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hermes/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%s", w.Code, w.Body.String())
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("response body is not valid JSON after emit panic: %v body=%s", err, w.Body.String())
	}
	if got, _ := parsed["action"].(string); got != "allow" {
		t.Errorf("response action = %q, want allow", got)
	}
	if got, _ := parsed["would_block"].(bool); !got {
		t.Errorf("response would_block = false, want true")
	}
}

// TestEnrichAgentHookSpanPanic_MarksErrorAndAttribute verifies the
// panic enrichment helper does BOTH things its godoc promises:
//
//  1. Sets `defenseclaw.hook.panic=true` so per-span drill-downs can
//     distinguish DefenseClaw evaluator panics from ordinary upstream
//     errors.
//  2. Sets span status to Error so trace backends (Tempo, Jaeger,
//     Honeycomb) surface the failure via their built-in
//     `status=error` filters and error-rate panels, even though the
//     HTTP response itself is 200 (we fail-open with
//     would_block=true — see safeEvaluateHook for the rationale).
//
// Regressing either half would silently swallow panic-recovered
// hook spans from the operator's error dashboards.
func TestEnrichAgentHookSpanPanic_MarksErrorAndAttribute(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exp),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	defer otel.SetTracerProvider(prev)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	tracer := otel.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test-span")
	enrichAgentHookSpanPanic(ctx)
	span.End()

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if spans[0].Status.Code != codes.Error {
		t.Errorf("span status code=%v want Error (operators rely on status=error filters)", spans[0].Status.Code)
	}
	if spans[0].Status.Description == "" {
		t.Errorf("span status description empty; want a human-readable panic marker for drill-downs")
	}
	attr, ok := attrByKey(spans[0].Attributes, "defenseclaw.hook.panic")
	if !ok {
		t.Errorf("defenseclaw.hook.panic attribute missing; per-span drill-downs cannot split panic from upstream errors")
	} else if !attr.AsBool() {
		t.Errorf("defenseclaw.hook.panic=%v want true", attr.AsBool())
	}
}

// TestEnrichAgentHookSpanPanic_NoOpOnNonRecordingSpan guards the
// defensive nil + non-recording short-circuit: callers may invoke
// the helper from a ctx with no span (e.g. handleAgentHookSynthetic
// running outside an HTTP wrapper), and panicking inside a panic-
// recovery code path would defeat the whole fail-open contract.
func TestEnrichAgentHookSpanPanic_NoOpOnNonRecordingSpan(t *testing.T) {
	// No tracer provider installed → SpanFromContext returns a
	// non-recording span. The helper must short-circuit safely.
	enrichAgentHookSpanPanic(context.Background())
}

// TestNormalizeHookReasonLabel_BoundsCardinality is the L2 regression
// test: any free-form action string must collapse to "other" so the
// `reason` Prometheus label cardinality stays bounded. The allowlist
// values pass through unchanged.
func TestNormalizeHookReasonLabel_BoundsCardinality(t *testing.T) {
	cases := []struct {
		name       string
		action     string
		wouldBlock bool
		want       string
	}{
		{"allow", "allow", false, "allow"},
		{"block", "block", false, "block"},
		{"alert", "alert", false, "alert"},
		{"confirm", "confirm", false, "confirm"},
		{"wouldBlockWins", "block", true, "would_block"},
		{"wouldBlockWinsOverAllow", "allow", true, "would_block"},
		{"upper", "ALLOW", false, "allow"},
		{"empty", "", false, "none"},
		{"freeform", "policy:lifted-redaction-window-2024-07-12", false, "other"},
		{"verboseFreeForm", "block-because-pii-detected-in-tool-args-with-redaction-pattern-9b3", false, "other"},
		{"hostile", "../../etc/passwd", false, "other"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeHookReasonLabel(tc.action, tc.wouldBlock)
			if got != tc.want {
				t.Errorf("normalizeHookReasonLabel(%q, %v) = %q, want %q", tc.action, tc.wouldBlock, got, tc.want)
			}
		})
	}
}

func TestNormalizeHookEventLabel_BoundsCardinality(t *testing.T) {
	cases := []struct {
		event string
		want  string
	}{
		{"PreToolUse", "tool_call"},
		{"beforeShellExecution", "tool_call"},
		{"UserPromptSubmit", "prompt"},
		{"PostToolUse", "tool_result"},
		{"Stop", "stop"},
		{"Notification", "notification"},
		{"attacker-event-2026-05-18-with-freeform-suffix", "other"},
		{"", "unknown"},
	}
	for _, tc := range cases {
		if got := normalizeHookEventLabel(tc.event); got != tc.want {
			t.Errorf("normalizeHookEventLabel(%q) = %q, want %q", tc.event, got, tc.want)
		}
	}
}

// TestAttachRawPayload_TruncatesAndAnnotates is the M3 regression
// test: when redaction is disabled (operator override) and the body
// exceeds hookPanicRawPayloadCap, RawPayload must be truncated to
// the cap, env.Extra must carry the truncation flag, the full byte
// count, and a SHA-256 short digest so SIEM rules can deduplicate
// replays without ingesting the full body.
func TestAttachRawPayload_TruncatesAndAnnotates(t *testing.T) {
	redaction.SetDisableAll(true)
	defer redaction.SetDisableAll(false)

	// Body well over the cap. We pick exactly cap+128 so the
	// boundary math is verifiable.
	body := bytes.Repeat([]byte("A"), hookPanicRawPayloadCap+128)

	var env HookAuditEnvelope
	attachRawPayload(&env, body)

	if len(env.RawPayload) != hookPanicRawPayloadCap {
		t.Errorf("RawPayload length = %d, want %d (truncation cap)", len(env.RawPayload), hookPanicRawPayloadCap)
	}
	if env.Extra == nil {
		t.Fatal("Extra is nil; truncation markers missing")
	}
	if env.Extra["raw_payload_truncated"] != "true" {
		t.Errorf("Extra[raw_payload_truncated] = %q, want \"true\"", env.Extra["raw_payload_truncated"])
	}
	wantFull := hookPanicRawPayloadCap + 128
	if env.Extra["raw_payload_full_bytes"] != itoa(wantFull) {
		t.Errorf("Extra[raw_payload_full_bytes] = %q, want %d", env.Extra["raw_payload_full_bytes"], wantFull)
	}
	if len(env.Extra["raw_payload_sha256"]) != 16 {
		t.Errorf("Extra[raw_payload_sha256] length = %d, want 16 (8-byte prefix hex)", len(env.Extra["raw_payload_sha256"]))
	}
}

// TestAttachRawPayload_NoOpWhenRedactionEnabled verifies that the raw
// body never reaches the envelope when redaction is on (the default).
// Forgetting this guard would silently exfiltrate sensitive content
// to every audit sink.
func TestAttachRawPayload_NoOpWhenRedactionEnabled(t *testing.T) {
	redaction.SetDisableAll(false)
	var env HookAuditEnvelope
	attachRawPayload(&env, []byte("hello"))
	if env.RawPayload != "" {
		t.Errorf("RawPayload = %q, want empty (redaction enabled by default)", env.RawPayload)
	}
	if env.Extra != nil {
		t.Errorf("Extra = %v, want nil (no truncation markers when no payload attached)", env.Extra)
	}
}

// hookEvaluatorPanicHook is declared in agent_hook.go as a no-op
// test seam; agent_hook_panic_test.go just swaps it for the duration
// of TestHandleAgentHook_PanicReturnsSafeResponse and restores nil
// afterwards. See the godoc at the declaration site for the
// rationale.

// panicOnWriteResponseWriter implements http.ResponseWriter and
// panics from Write to simulate a failure inside writeJSON AFTER
// the main handleAgentHook flow has already called finalizeAgentHook
// successfully. The recovery defer in handleAgentHook must then NOT
// re-run finalizeAgentHook a second time — otherwise a transient
// io.Writer failure (or a malformed response value, or a panicking
// custom Marshaler embedded in an extra map) would double every
// audit row, hook-outcome metric, and connector telemetry log for
// the affected request.
type panicOnWriteResponseWriter struct {
	header http.Header
	status int
}

func (w *panicOnWriteResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *panicOnWriteResponseWriter) WriteHeader(code int) { w.status = code }

func (w *panicOnWriteResponseWriter) Write([]byte) (int, error) {
	panic("synthetic writeJSON panic after finalizeAgentHook completed")
}

// TestHandleAgentHook_PostFinalizePanicDoesNotDoubleAudit pins the
// post-finalize defer guard. If the recovery defer in handleAgentHook
// re-runs finalizeAgentHook after the main flow has already finalized,
// the audit store would carry TWO connector-hook rows for a single
// hook request — corrupting compliance reporting and metric counts.
//
// The test triggers a panic from writeJSON (via a custom
// http.ResponseWriter that panics on Write) and asserts the audit
// store has exactly one connector-hook entry.
func TestHandleAgentHook_PostFinalizePanicDoesNotDoubleAudit(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	api := &APIServer{
		store:  store,
		logger: logger,
	}

	handler := http.HandlerFunc(api.handleAgentHook("hermes"))
	body := `{"hook_event_name":"pre_tool_call","session_id":"sess-post-finalize","tool_name":"shell"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hermes/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := &panicOnWriteResponseWriter{}
	handler.ServeHTTP(w, req)

	events, err := store.ListEvents(100)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	connectorHookRows := 0
	for _, ev := range events {
		if ev.Action == "connector-hook" {
			connectorHookRows++
		}
	}
	if connectorHookRows != 1 {
		t.Fatalf("connector-hook audit row count = %d, want exactly 1 (post-finalize panic must not re-run finalizeAgentHook)", connectorHookRows)
	}
}
