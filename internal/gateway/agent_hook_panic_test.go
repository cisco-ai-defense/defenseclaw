// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// TestSafeEvaluateHook_ObserveRecovery exercises safeEvaluateHook directly:
// a recovered evaluation error denies a blockable event even in observe mode.
func TestSafeEvaluateHook_ObserveRecovery(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	api := &APIServer{}
	api.bindObservabilityV8Runtimes(runtime, nil, nil, runtime)

	req := agentHookRequest{HookEventName: "PreToolUse"}
	evalResp, panicked := api.safeEvaluateHook(context.Background(), "codex", req, nil, nil, hookProfileRuntime{
		Evaluate: func(*APIServer, context.Context, agentHookRequest, []byte, map[string]interface{}) agentHookResponse {
			panic("safeEvaluateHook test panic")
		},
	})
	if !panicked {
		t.Fatal("safeEvaluateHook panicked=false, want true")
	}
	if evalResp.Action != "block" || evalResp.Mode != "action" || evalResp.WouldBlock {
		t.Fatalf("safeEvaluateHook panic response = %+v, want fail-closed block", evalResp)
	}

	resp := safeHookPanicResponse("codex", "PreToolUse")
	if resp.Severity != "WARN" {
		t.Errorf("panic Severity = %q, want WARN", resp.Severity)
	}
	if !strings.Contains(resp.Reason, "internal evaluator error") {
		t.Errorf("panic Reason = %q, want substring 'internal evaluator error'", resp.Reason)
	}
	if !strings.Contains(resp.AdditionalContext, "codex") || !strings.Contains(resp.AdditionalContext, "PreToolUse") {
		t.Errorf("panic AdditionalContext = %q, want connector + event names", resp.AdditionalContext)
	}

	panicMetrics := generatedMetricByName(
		capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawPanicsTotal,
	)
	if len(panicMetrics) != 1 {
		t.Fatalf("generated panic metrics=%d; recovered hook must not require a legacy Provider", len(panicMetrics))
	}
}

func TestSafeEvaluateHookManagedStandalonePanicReturnsNativeDeny(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
	cfg.Enterprise.Profile = managed.ProfileStandalone
	// The default observe mode: a missing verdict still fails closed on a
	// managed device.
	cfg.Guardrail.Mode = "observe"
	api := &APIServer{scannerCfg: cfg}
	for _, tc := range []struct {
		connector, toolEvent, nativeField string
	}{
		{"cursor", "beforeShellExecution", "permission"},
		{"copilot", "preToolUse", "permissionDecision"},
		{"devin", "PreToolUse", "decision"},
		{"kiro", "PreToolUse", "decision"},
		{"opencode", "tool.execute.before", "decision"},
	} {
		req := agentHookRequest{ConnectorName: tc.connector, HookEventName: tc.toolEvent}
		resp, panicked := api.safeEvaluateHook(context.Background(), tc.connector, req, nil, nil, hookProfileRuntime{
			Evaluate: func(*APIServer, context.Context, agentHookRequest, []byte, map[string]interface{}) agentHookResponse {
				panic("managed evaluator panic")
			},
		})
		if !panicked || resp.Action != "block" || resp.WouldBlock || len(resp.HookOutput) == 0 {
			t.Errorf("%s: panic response = %+v, panicked=%v", tc.connector, resp, panicked)
			continue
		}
		if _, ok := resp.HookOutput[tc.nativeField]; !ok {
			t.Errorf("%s: native output = %+v, missing %s", tc.connector, resp.HookOutput, tc.nativeField)
		}
		for _, event := range hookexec.LifecycleEvents(tc.connector) {
			stop := api.hookPanicResponse(context.Background(), tc.connector,
				agentHookRequest{HookEventName: event}, nil, nil)
			if stop.Action != "allow" || !stop.WouldBlock || lifecycleAnswerRepeats(stop.HookOutput) {
				t.Errorf("%s %s: lifecycle panic response = %+v, want a non-repeating neutral allow", tc.connector, event, stop)
			}
		}
	}
	for _, connectorName := range []string{"claudecode", "codex", "antigravity"} {
		for _, event := range hookexec.LifecycleEvents(connectorName) {
			resp := api.hookPanicResponse(context.Background(), connectorName,
				agentHookRequest{HookEventName: event}, nil, nil)
			if terminalLifecycleEvent(connectorName, event) {
				if resp.Action != "block" || resp.Mode != "action" || resp.HookOutput["continue"] != false {
					t.Errorf("%s %s: lifecycle panic response = %+v, want the terminal closed answer", connectorName, event, resp)
				}
				continue
			}
			if resp.Action != "allow" || !resp.WouldBlock || lifecycleAnswerRepeats(resp.HookOutput) {
				t.Errorf("%s %s: lifecycle panic response = %+v, want a non-repeating neutral allow", connectorName, event, resp)
			}
		}
	}
	kiro := api.hookPanicResponse(context.Background(), "kiro",
		agentHookRequest{HookEventName: "UserPromptSubmit"}, nil, nil)
	if kiro.Action != "block" || kiro.WouldBlock {
		t.Errorf("Kiro UserPromptSubmit panic = %+v, want native block", kiro)
	}
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
		t.Fatalf("status=%d want 200 with a valid response body=%s",
			w.Code, w.Body.String())
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("response body is not valid JSON after panic: %v body=%s", err, w.Body.String())
	}
	if got, _ := parsed["action"].(string); got != "block" {
		t.Errorf("response action = %q, want closed block", got)
	}
	if got, _ := parsed["mode"].(string); got != "action" {
		t.Errorf("response mode = %q, want action", got)
	}
	if got, _ := parsed["would_block"].(bool); got {
		t.Errorf("response would_block = true, want enforced block")
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
	if got, _ := parsed["action"].(string); got != "block" {
		t.Errorf("response action = %q, want closed block", got)
	}
	if got, _ := parsed["mode"].(string); got != "action" {
		t.Errorf("response mode = %q, want action", got)
	}
	if got, _ := parsed["would_block"].(bool); got {
		t.Errorf("response would_block = true, want enforced block")
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
//     HTTP response itself is 200 and carries the configured verdict.
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
// the helper from a ctx with no span (a handler running outside an
// HTTP wrapper), and panicking inside a recovery path would defeat the
// configured fail-mode response.
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

func TestHandleAgentHook_NotificationPanicDoesNotFinalizeTwice(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	api := &APIServer{store: store, logger: logger}
	api.webhookSource = func() *WebhookDispatcher { panic("synthetic notification panic after finalization") }
	previous := hookEvaluatorPanicHook
	hookEvaluatorPanicHook = func() { panic("synthetic evaluator panic to produce a block") }
	t.Cleanup(func() { hookEvaluatorPanicHook = previous })

	req := httptest.NewRequest(http.MethodPost, "/api/v1/hermes/hook", strings.NewReader(
		`{"hook_event_name":"pre_tool_call","session_id":"sess-notify-panic","tool_name":"shell"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handleAgentHook("hermes").ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	events, err := store.ListEvents(100)
	if err != nil {
		t.Fatal(err)
	}
	var decisions int
	for _, event := range events {
		if event.Action == string(audit.ActionConnectorHook) {
			decisions++
		}
	}
	if decisions != 1 {
		t.Fatalf("notification panic persisted %d connector decisions, want one", decisions)
	}
}

func TestHandleAgentHook_AntigravityConfirmSurvivesOutputEncodingFailure(t *testing.T) {
	previous, had := hookProfileRuntimes["antigravity"]
	hookProfileRuntimes["antigravity"] = func(profile connector.HookProfile) hookProfileRuntime {
		runtime := defaultHookProfileRuntime(profile)
		runtime.Evaluate = func(*APIServer, context.Context, agentHookRequest, []byte, map[string]interface{}) agentHookResponse {
			return agentHookResponse{
				Action: "confirm", RawAction: "confirm", Mode: "action", Reason: "review this command",
				HookOutput: map[string]interface{}{"decision": "force_ask", "bad": math.NaN()},
			}
		}
		return runtime
	}
	t.Cleanup(func() {
		if had {
			hookProfileRuntimes["antigravity"] = previous
		} else {
			delete(hookProfileRuntimes, "antigravity")
		}
	})
	store, logger := testStoreAndLogger(t)
	api := &APIServer{store: store, logger: logger}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/antigravity/hook", strings.NewReader(
		`{"hook_event_name":"PreToolUse","session_id":"encoding-confirm","toolCall":{"name":"run_command","args":{"CommandLine":"echo ok"}}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Antigravity-Event", "PreToolUse")
	w := httptest.NewRecorder()
	api.handleAgentHook("antigravity").ServeHTTP(w, req)
	var answer struct {
		Action string `json:"action"`
		Output struct {
			Decision string `json:"decision"`
		} `json:"hook_output"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil {
		t.Fatalf("native hook cannot decode finalized confirmation: status=%d body=%q: %v", w.Code, w.Body.String(), err)
	}
	if answer.Action != "confirm" || answer.Output.Decision != "force_ask" {
		t.Fatalf("native answer=%+v, want audited confirm with force_ask", answer)
	}
	row := soleHookDecisionForTest(t, store)
	if row.Structured["action"] != "confirm" || row.Enforced {
		t.Fatalf("audit row=%+v, want confirmation matching native answer", row)
	}
}

// TestHandleAgentHook_SandboxPanicFailsClosed: a request authenticated with
// a sandbox binding is blocked, with a reason that says DefenseClaw failed,
// when the evaluator panics or when a panic after evaluation reaches the
// handler's outer recover. The sandbox hook is the only gate on the tool call.
func TestHandleAgentHook_SandboxPanicFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		inject func(t *testing.T)
	}{
		{"evaluator", func(t *testing.T) {
			prev := hookEvaluatorPanicHook
			hookEvaluatorPanicHook = func() { panic("synthetic evaluator panic for sandbox test") }
			t.Cleanup(func() { hookEvaluatorPanicHook = prev })
		}},
		// Managed enterprise mode defers EmitLLMEvent until after
		// safeEvaluateHook returns, so its panic takes the outer recover.
		{"post-evaluation", func(t *testing.T) {
			prev := managedEnterpriseActive.Load()
			managedEnterpriseActive.Store(true)
			prevRuntime, had := hookProfileRuntimes["hermes"]
			hookProfileRuntimes["hermes"] = func(profile connector.HookProfile) hookProfileRuntime {
				runtime := defaultHookProfileRuntime(profile)
				runtime.EmitLLMEvent = func(*APIServer, context.Context, agentHookRequest, []byte, map[string]interface{}, []string) {
					panic("synthetic post-evaluation panic for sandbox test")
				}
				return runtime
			}
			t.Cleanup(func() {
				managedEnterpriseActive.Store(prev)
				if had {
					hookProfileRuntimes["hermes"] = prevRuntime
				} else {
					delete(hookProfileRuntimes, "hermes")
				}
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.inject(t)
			body, _ := json.Marshal(map[string]interface{}{
				"hook_event_name": "pre_tool_call", "session_id": "session-sandbox-panic-" + tc.name,
				"agent_id": "hermes-test", "tool_name": "shell", "tool_input": map[string]interface{}{"command": "echo marker"},
			})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/hermes/hook", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			binding := sandboxauth.Binding{ID: "sb_panic", Connector: sandboxauth.CanonicalConnector("hermes")}
			req = req.WithContext(sandboxauth.WithRequest(req.Context(), binding, nil))
			w := httptest.NewRecorder()
			http.HandlerFunc((&APIServer{}).handleAgentHook("hermes")).ServeHTTP(w, req)
			var parsed map[string]interface{}
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &parsed) != nil {
				t.Fatalf("status=%d body=%s, want a 200 JSON verdict", w.Code, w.Body.String())
			}
			if parsed["action"] != "block" || parsed["reason"] != sandboxInternalErrorReason {
				t.Fatalf("sandbox panic verdict = %v, want a block with %q", parsed, sandboxInternalErrorReason)
			}
		})
	}
}

func postDecisionForTest(t *testing.T, api *APIServer, connectorName, event, command string) map[string]any {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"hook_event_name": event, "session_id": "statement-test-" + t.Name(),
		"tool_name": "Bash", "cwd": t.TempDir(),
		"tool_input": map[string]any{"command": command},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+connectorName+"/hook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if command != "" && connectorName == "codex" {
		req.Header.Set(hookpaths.Header, hookpaths.Resolve(body))
	}
	if connectorName == "codex" {
		setTestCodexHookBinding(req, event, defaultTestCodexHookContract)
	}
	w := httptest.NewRecorder()
	api.handleAgentHook(connectorName).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var parsed map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return parsed
}

func soleHookDecisionForTest(t *testing.T, store *audit.Store) audit.Event {
	t.Helper()
	events, err := store.ListEvents(100)
	if err != nil {
		t.Fatal(err)
	}
	var rows []audit.Event
	for _, event := range events {
		if event.Action == string(audit.ActionConnectorHook) || event.Action == string(audit.ActionConnectorHookSynthetic) {
			rows = append(rows, event)
		}
	}
	if len(rows) != 1 {
		t.Fatalf("hook decision rows=%d, want one", len(rows))
	}
	return rows[0]
}

func decisionIsDenied(output any) bool {
	m, ok := output.(map[string]any)
	if !ok {
		return false
	}
	if m["permissionDecision"] == "deny" || m["decision"] == "deny" || m["decision"] == "block" {
		return true
	}
	for _, value := range m {
		if decisionIsDenied(value) {
			return true
		}
	}
	return false
}

func TestHandleAgentHook_RecoveredEvaluationUsesFailMode(t *testing.T) {
	for _, tc := range []struct {
		connector, event, mode, failMode, wantAction string
	}{
		{"claudecode", "PreToolUse", "action", "closed", "block"},
		{"codex", "PreToolUse", "action", "closed", "block"},
		{"hermes", "pre_tool_call", "action", "closed", "block"},
		{"claudecode", "PreToolUse", "action", "open", "block"},
		{"codex", "PreToolUse", "action", "open", "block"},
		{"hermes", "pre_tool_call", "action", "open", "block"},
		{"claudecode", "PreToolUse", "observe", "closed", "block"},
		{"codex", "PreToolUse", "observe", "closed", "block"},
		{"hermes", "pre_tool_call", "observe", "closed", "block"},
		{"claudecode", "PostToolUse", "action", "closed", "block"},
	} {
		t.Run(strings.Join([]string{tc.connector, tc.event, tc.mode, tc.failMode}, "/"), func(t *testing.T) {
			previous, had := hookProfileRuntimes[tc.connector]
			hookProfileRuntimes[tc.connector] = func(profile connector.HookProfile) hookProfileRuntime {
				runtime := defaultHookProfileRuntime(profile)
				runtime.Evaluate = func(*APIServer, context.Context, agentHookRequest, []byte, map[string]interface{}) agentHookResponse {
					panic("injected evaluator error")
				}
				return runtime
			}
			t.Cleanup(func() {
				if had {
					hookProfileRuntimes[tc.connector] = previous
				} else {
					delete(hookProfileRuntimes, tc.connector)
				}
			})
			store, logger := testStoreAndLogger(t)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = tc.mode
			cfg.Guardrail.HookFailMode = tc.failMode
			cfg.Guardrail.Connector = tc.connector
			api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
			response := postDecisionForTest(t, api, tc.connector, tc.event, "echo done")
			wantWouldBlock := tc.wantAction != "block"
			wantMode := tc.mode
			if tc.wantAction == "block" {
				wantMode = "action"
			}
			if response["action"] != tc.wantAction || response["raw_action"] != "block" || response["mode"] != wantMode || response["would_block"] != wantWouldBlock {
				t.Fatalf("response=%v, want %s/%s/would_block=%v", response, tc.wantAction, wantMode, wantWouldBlock)
			}
			if tc.wantAction == "block" && tc.event == "PreToolUse" {
				field := "hook_output"
				switch tc.connector {
				case "claudecode":
					field = "claude_code_output"
				case "codex":
					field = "codex_output"
				}
				if !decisionIsDenied(response[field]) {
					t.Fatalf("%s=%v, want a denial", field, response[field])
				}
			}
			row := soleHookDecisionForTest(t, store)
			if row.Structured["result"] != "panic" || row.Structured["action"] != tc.wantAction || row.Structured["would_block"] != wantWouldBlock {
				t.Fatalf("audit=%v, want panic/%s/would_block=%v", row.Structured, tc.wantAction, wantWouldBlock)
			}
			if tc.event == "PostToolUse" && !decisionIsDenied(response["claude_code_output"]) {
				t.Fatalf("post-tool output=%v, want a closed-failure denial", response["claude_code_output"])
			}
			extra, _ := row.Structured["extra"].(map[string]any)
			if extra["panic"] != "true" {
				t.Fatalf("audit extra=%v, want panic=true", extra)
			}
		})
	}
}

func TestHookPanicResponse_PerUserOpenStillCloses(t *testing.T) {
	for _, tc := range []struct {
		name, connectorFail, globalFail, want string
		managedStandalone                     bool
	}{
		{"observe connector default", "", "", "block", false},
		{"per-user global open", "", "open", "block", false},
		{"per-user connector open", "open", "", "block", false},
		{"connector closed over global open", "closed", "open", "block", false},
		// An evaluator panic is no gateway outage: the administrator's
		// outage-open does not let the call through.
		{"managed administrator global open", "", "open", "block", true},
		{"managed administrator connector open", "open", "", "block", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			if tc.managedStandalone {
				cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
				cfg.Enterprise.Profile = managed.ProfileStandalone
			}
			cfg.Guardrail.Mode = "observe"
			cfg.Codex.Mode = "action"
			cfg.Guardrail.HookFailMode = tc.globalFail
			cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
				"codex": {HookFailMode: tc.connectorFail},
			}
			api := &APIServer{scannerCfg: cfg}
			resp, panicked := api.safeEvaluateHook(t.Context(), "codex", agentHookRequest{
				HookEventName: "PreToolUse", ConnectorName: "codex",
			}, nil, nil, hookProfileRuntime{Evaluate: func(*APIServer, context.Context, agentHookRequest, []byte, map[string]interface{}) agentHookResponse {
				panic("injected evaluator error")
			}})
			if !panicked || resp.Mode != "action" || resp.Action != tc.want || resp.RawAction != "block" {
				t.Fatalf("response=%+v, want %s/action", resp, tc.want)
			}
		})
	}
}

func TestHandleAgentHookSynthetic_RecoveredEvaluationUsesFailMode(t *testing.T) {
	previous := hookEvaluatorPanicHook
	hookEvaluatorPanicHook = func() { panic("injected synthetic error") }
	defer func() { hookEvaluatorPanicHook = previous }()

	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
	req := agentHookRequest{
		ConnectorName: "codex", HookEventName: "PreToolUse", SessionID: "synthetic-panic",
		Payload: map[string]interface{}{"hook_event_name": "PreToolUse"},
	}
	resp := api.handleAgentHookSynthetic(t.Context(), "codex", req, nil)
	if resp.Action != "block" || resp.RawAction != "block" || resp.Mode != "action" || resp.WouldBlock {
		t.Fatalf("synthetic response=%+v, want closed block/action", resp)
	}
	row := soleHookDecisionForTest(t, store)
	if row.Structured["result"] != "panic" || row.Structured["action"] != "block" {
		t.Fatalf("synthetic audit=%v, want panic/block", row.Structured)
	}
}

// A synthetic Codex Stop that panics on every call must not block: Codex would
// continue the turn and run the failing Stop hook again (#1140).
func TestHandleAgentHookSynthetic_RecoveredStopDoesNotRepeat(t *testing.T) {
	previous := hookEvaluatorPanicHook
	hookEvaluatorPanicHook = func() { panic("injected synthetic error") }
	defer func() { hookEvaluatorPanicHook = previous }()

	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.HookFailMode = "closed"
	cfg.Guardrail.Connector = "codex"
	for attempt := 0; attempt < 3; attempt++ {
		store, logger := testStoreAndLogger(t)
		api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
		req := agentHookRequest{
			ConnectorName: "codex", HookEventName: "Stop", SessionID: "synthetic-panic",
			Payload: map[string]interface{}{"hook_event_name": "Stop", "stop_hook_active": attempt > 0},
		}
		resp := api.handleAgentHookSynthetic(t.Context(), "codex", req, nil)
		if resp.Action != "allow" || resp.RawAction != "block" || !resp.WouldBlock || lifecycleAnswerRepeats(resp.HookOutput) {
			t.Fatalf("attempt %d: synthetic Stop response=%+v, want a non-repeating allow", attempt, resp)
		}
		row := soleHookDecisionForTest(t, store)
		if row.Structured["result"] != "panic" || row.Structured["action"] != "allow" || row.Enforced {
			t.Fatalf("attempt %d: synthetic Stop audit=%+v, want an unenforced panic row", attempt, row)
		}
	}
}

// lifecycleAnswerRepeats reports a native answer that keeps an agent running
// on a stop, session-end or idle event: a denial or block decision, a veto
// ("continue"), a follow-up prompt or a terminal continue:false.
func lifecycleAnswerRepeats(output map[string]interface{}) bool {
	if panicWireDenies(output) {
		return true
	}
	for key, value := range output {
		switch key {
		case "followup_message", "followupMessage":
			return true
		case "decision":
			if value != "allow" && value != "approve" {
				return true
			}
		}
		if nested, ok := value.(map[string]interface{}); ok && lifecycleAnswerRepeats(nested) {
			return true
		}
	}
	return false
}

func TestHandleAgentHook_PostEvaluationRecoveryUsesFailMode(t *testing.T) {
	previousManaged := managedEnterpriseActive.Load()
	managedEnterpriseActive.Store(true)
	defer managedEnterpriseActive.Store(previousManaged)
	previous, had := hookProfileRuntimes["hermes"]
	hookProfileRuntimes["hermes"] = func(profile connector.HookProfile) hookProfileRuntime {
		runtime := defaultHookProfileRuntime(profile)
		runtime.EmitLLMEvent = func(*APIServer, context.Context, agentHookRequest, []byte, map[string]interface{}, []string) {
			panic("injected post-evaluation error")
		}
		return runtime
	}
	defer func() {
		if had {
			hookProfileRuntimes["hermes"] = previous
		} else {
			delete(hookProfileRuntimes, "hermes")
		}
	}()
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
	cfg.Enterprise.Profile = managed.ProfileSecureClient
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "hermes"
	api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
	response := postDecisionForTest(t, api, "hermes", "pre_tool_call", "echo done")
	if response["action"] != "allow" || response["raw_action"] != "block" || response["would_block"] != true || decisionIsDenied(response["hook_output"]) {
		t.Fatalf("response=%v, want Secure Client allow with would_block", response)
	}
	row := soleHookDecisionForTest(t, store)
	if row.Action != string(audit.ActionConnectorHook) || row.Enforced {
		t.Fatalf("audit=%+v, want one non-enforcing connector-hook row", row)
	}
}

// TestHookPanicResponseFailModeMatrix pins the recovered-evaluation verdict
// for every registered connector that can block, in every guardrail mode and
// for each place hook_fail_mode: open can come from. Closed installs, per-user
// and standalone managed alike, deny failed blockable checks even in observe
// mode and answer a stop or session-end event neutrally. Saved per-user open
// and managed outage-open do not apply to local evaluation failures. Secure
// Client's unset default and explicit open retain their failure behavior;
// an explicit closed denies under Secure Client too.
func TestHookPanicResponseFailModeMatrix(t *testing.T) {
	type deployment int
	const (
		perUser deployment = iota
		standalone
		secureClient
	)
	deployments := map[deployment]string{perUser: "per-user", standalone: "standalone", secureClient: "secure-client"}
	failSources := []string{"closed", "global-open", "connector-open", "app-protection-open"}
	newConfig := func(t *testing.T, d deployment, mode, failSource, connectorName string) *config.Config {
		cfg := config.DefaultConfig()
		cfg.DataDir = t.TempDir()
		switch d {
		case standalone:
			cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
			cfg.Enterprise.Profile = managed.ProfileStandalone
		case secureClient:
			cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
			cfg.Enterprise.Profile = managed.ProfileSecureClient
		}
		cfg.Guardrail.Mode = mode
		cfg.Guardrail.HookFailMode = "closed"
		switch failSource {
		case "global-open":
			cfg.Guardrail.HookFailMode = "open"
		case "connector-open":
			cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{connectorName: {HookFailMode: "open"}}
		case "app-protection-open":
			cfg.ApplicationProtection.Enabled = true
			cfg.ApplicationProtection.Guardrail = config.PerConnectorGuardrailConfig{Mode: mode, HookFailMode: "open"}
		}
		return cfg
	}
	panicking := hookProfileRuntime{Evaluate: func(*APIServer, context.Context, agentHookRequest, []byte, map[string]interface{}) agentHookResponse {
		panic("injected evaluator error")
	}}

	covered := map[string]bool{}
	for _, connectorName := range sharedDefaultRegistry().Names() {
		// Resolve the same unversioned contract the per-case temporary
		// deployment uses. A cached agent version in the developer's home
		// can select a different contract and make this matrix depend on
		// whatever agent happened to run on the test host.
		profileConfig := config.DefaultConfig()
		profileConfig.DataDir = t.TempDir()
		profile := (&APIServer{scannerCfg: profileConfig}).hookProfileForConnector(connectorName)
		if !profile.Capabilities.CanBlock {
			continue
		}
		var blocking []string
		if connectorName == "claudecode" {
			blocking = append(blocking, "PostToolBatch")
		}
		for _, event := range profile.Capabilities.BlockEvents {
			action, _ := mapHookActionForProfile("block", "action", event, profile.Capabilities, profile, nil)
			if action == "block" && !hookexec.NeutralLifecycleEvent(connectorName, event) {
				blocking = append(blocking, event)
			}
		}
		if len(blocking) == 0 {
			continue
		}
		covered[connectorName] = true
		lifecycle := hookexec.LifecycleEvents(connectorName)
		for d, dName := range deployments {
			for _, mode := range []string{"observe", "action"} {
				for _, failSource := range failSources {
					cfg := newConfig(t, d, mode, failSource, connectorName)
					api := &APIServer{scannerCfg: cfg}
					// Only Secure Client can open a local evaluation failure.
					// The managed administrator's open choice is for a verified
					// gateway connection outage, which this panic is not.
					open := failSource != "closed" && d == secureClient
					for _, event := range append(append([]string{}, blocking...), lifecycle...) {
						name := strings.Join([]string{dName, connectorName, event, mode, failSource}, "/")
						req := agentHookRequest{ConnectorName: connectorName, HookEventName: event}
						resp, panicked := api.safeEvaluateHook(t.Context(), connectorName, req, nil, nil, panicking)
						if !panicked || resp.RawAction != "block" {
							t.Errorf("%s: panicked=%v response=%+v", name, panicked, resp)
							continue
						}
						// Each fixture uses its own data directory. Its cached agent
						// contract may differ from the host profile that supplied the
						// candidate event list (notably Claude PostToolBatch).
						effectiveProfile := api.hookProfileForRequest(t.Context(), connectorName)
						capable, _ := mapHookActionForProfile("block", "action", event,
							effectiveProfile.Capabilities, effectiveProfile, nil)
						wantAction, wantMode := "allow", mode
						neutral := hookexec.LifecycleEvent(connectorName, event) && !terminalLifecycleEvent(connectorName, event)
						if !open && !neutral {
							wantAction, wantMode = "block", "action"
						}
						if neutral && lifecycleAnswerRepeats(resp.HookOutput) {
							t.Errorf("%s: lifecycle answer repeats the hook: %v", name, resp.HookOutput)
						}
						if resp.Action != wantAction || resp.Mode != wantMode || resp.WouldBlock != (wantAction != "block") {
							t.Errorf("%s: action=%q mode=%q would_block=%v, want %s/%s", name, resp.Action, resp.Mode, resp.WouldBlock, wantAction, wantMode)
						}
						// The Amp plugin reads the action field itself.
						// An ordinary Claude Code denial that uses exit 2 has
						// no output to render. A recovered TeammateIdle panic
						// instead ends the teammate with continue:false.
						exitTwoDenial := connectorName == "claudecode" &&
							!terminalLifecycleEvent(connectorName, event) &&
							claudeCodeOutput(claudeCodeHookRequest{HookEventName: event}, "block", "block", "", "") == nil
						if wantAction == "block" && exitTwoDenial && len(resp.HookOutput) != 0 {
							t.Errorf("%s: an exit-2 denial rendered output %v", name, resp.HookOutput)
						}
						if wantAction == "block" && capable == "block" && len(resp.HookOutput) == 0 && !exitTwoDenial && connectorName != "amp" {
							t.Errorf("%s: block without the connector's native output: %+v", name, resp)
						}
					}
				}
			}
		}
	}
	for _, name := range []string{"amp", "antigravity", "claudecode", "codex", "copilot", "cursor", "devin", "hermes", "kiro", "opencode"} {
		if !covered[name] {
			t.Errorf("connector %s has no blockable panic event in the matrix (covered: %v)", name, covered)
		}
	}
}

// One recovered-panic rule holds for every registered connector and event,
// per-user and standalone managed, in observe and action mode, under closed
// fail mode: an enforcement event blocks, even when ordinary policy cannot
// block it or a versioned contract is absent; a lifecycle event never gets an
// answer that keeps the agent running and repeats the hook. Claude Code's
// Stop, SubagentStop and TeammateIdle end the turn with continue:false.
func TestHookEvaluatorPanicRuleForEveryRegisteredEvent(t *testing.T) {
	api := &APIServer{}
	profiles := panicTestProfiles(t, api)
	panicking := hookProfileRuntime{Evaluate: func(*APIServer, context.Context, agentHookRequest, []byte, map[string]interface{}) agentHookResponse {
		panic("injected evaluator error")
	}}
	lifecycleCovered := map[string]bool{}
	for connectorName, profile := range profiles {
		for _, event := range profile.SupportedEvents {
			lifecycle := hookexec.LifecycleEvent(connectorName, event)
			if lifecycle {
				lifecycleCovered[connectorName] = true
			}
			for _, deployment := range []struct{ name, mode, profile string }{
				{"per-user", "", ""},
				{"standalone", managed.DeploymentModeManagedEnterprise, managed.ProfileStandalone},
			} {
				for _, mode := range []string{"observe", "action"} {
					t.Run(connectorName+"/"+event+"/"+deployment.name+"/"+mode, func(t *testing.T) {
						cfg := config.DefaultConfig()
						cfg.DeploymentMode, cfg.Enterprise.Profile = deployment.mode, deployment.profile
						cfg.Guardrail.Mode = mode
						cfg.Guardrail.HookFailMode = "closed"
						server := &APIServer{scannerCfg: cfg}
						req := agentHookRequest{ConnectorName: connectorName, HookEventName: event}
						resp, panicked := server.safeEvaluateHook(t.Context(), connectorName, req, nil, nil, panicking)
						if !panicked || resp.RawAction != "block" {
							t.Fatalf("panic response=%+v, panicked=%v", resp, panicked)
						}
						switch {
						case terminalLifecycleEvent(connectorName, event):
							if resp.Action != "block" || resp.Mode != "action" || resp.WouldBlock ||
								resp.HookOutput["continue"] != false || resp.HookOutput["stopReason"] == "" || len(resp.HookOutput) != 2 {
								t.Fatalf("panic response=%+v, want the terminal continue:false answer", resp)
							}
						case lifecycle:
							if resp.Action != "allow" || !resp.WouldBlock || lifecycleAnswerRepeats(resp.HookOutput) {
								t.Fatalf("panic response=%+v, want a neutral allow that does not repeat the hook", resp)
							}
						default:
							if resp.Action != "block" || resp.Mode != "action" || resp.WouldBlock {
								t.Fatalf("panic response=%+v, want closed block/action", resp)
							}
						}
					})
				}
			}
		}
	}
	for _, name := range []string{"antigravity", "claudecode", "codex", "copilot", "cursor", "devin", "kiro", "opencode"} {
		if !lifecycleCovered[name] {
			t.Errorf("%s: no registered lifecycle event reached the rule", name)
		}
	}
}

// The audit row of a lifecycle panic agrees with what the agent does: the
// neutral allow is an unenforced panic row with would_block, the Claude Code
// terminal answer an enforced block. Covers every connector's lifecycle
// events through the HTTP handler, per-user and standalone managed.
func TestLifecycleEvaluatorPanicAuditMatchesNativeAnswer(t *testing.T) {
	profiles := panicTestProfiles(t, &APIServer{})
	for _, name := range []string{"antigravity", "claudecode", "codex", "copilot", "cursor", "devin", "kiro", "opencode"} {
		for _, event := range hookexec.LifecycleEvents(name) {
			if !eventIn(event, profiles[name].SupportedEvents) ||
				(name == "copilot" && strings.ToLower(event[:1]) != event[:1]) {
				// The VS Code Local spellings of Copilot's stop events do not
				// reach the CLI hook route; the safeEvaluateHook matrix
				// covers them.
				continue
			}
			for _, deployment := range []struct{ name, mode, profile string }{
				{"per-user", "", ""},
				{"standalone", managed.DeploymentModeManagedEnterprise, managed.ProfileStandalone},
			} {
				t.Run(name+"/"+event+"/"+deployment.name, func(t *testing.T) {
					injectPanicForProfile(t, name)
					store, logger := testStoreAndLogger(t)
					cfg := config.DefaultConfig()
					cfg.DataDir = t.TempDir()
					cfg.DeploymentMode, cfg.Enterprise.Profile = deployment.mode, deployment.profile
					cfg.Guardrail.Mode, cfg.Guardrail.HookFailMode, cfg.Guardrail.Connector = "action", "closed", name
					server := &APIServer{scannerCfg: cfg, store: store, logger: logger}
					response, _ := postPanicTestHook(t, server, name, event)
					output, _ := panicTestOutput(name, response).(map[string]interface{})
					row := soleHookDecisionForTest(t, store)
					if row.Structured["result"] != "panic" {
						t.Fatalf("audit=%+v, want a panic row", row)
					}
					if terminalLifecycleEvent(name, event) {
						if response["action"] != "block" || output["continue"] != false || row.Structured["action"] != "block" || !row.Enforced {
							t.Fatalf("response=%v audit=%+v, want an enforced terminal answer", response, row)
						}
						return
					}
					if response["action"] != "allow" || response["would_block"] != true || lifecycleAnswerRepeats(output) {
						t.Fatalf("response=%v, want a neutral allow that does not repeat the hook", response)
					}
					if row.Structured["action"] != "allow" || row.Structured["would_block"] != true || row.Enforced {
						t.Fatalf("audit=%+v, want an unenforced allow with would_block", row)
					}
				})
			}
		}
	}
}

func TestClaudeStopPersistentEvaluatorPanicTerminatesTurn(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Guardrail.HookFailMode = "closed"
	api := &APIServer{scannerCfg: cfg}
	panicking := hookProfileRuntime{Evaluate: func(*APIServer, context.Context, agentHookRequest, []byte, map[string]interface{}) agentHookResponse {
		panic("persistent Stop evaluator error")
	}}
	for _, event := range []string{"Stop", "SubagentStop", "TeammateIdle"} {
		for attempt := 0; attempt < 3; attempt++ {
			req := agentHookRequest{
				ConnectorName: "claudecode", HookEventName: event, SessionID: "persistent-panic",
				Payload: map[string]interface{}{"stop_hook_active": attempt > 0},
			}
			resp, panicked := api.safeEvaluateHook(t.Context(), "claudecode", req, nil, nil, panicking)
			if !panicked || resp.Action != "block" || resp.Mode != "action" {
				t.Fatalf("%s attempt %d: panic response=%+v, panicked=%v", event, attempt, resp, panicked)
			}
			if resp.HookOutput["continue"] != false || resp.HookOutput["stopReason"] == "" {
				t.Fatalf("%s attempt %d: native output=%v, want terminal closed failure", event, attempt, resp.HookOutput)
			}
		}
	}
}

// Antigravity's only Stop veto ("continue") re-enters the agent loop, so a
// recovered panic allows termination, and the audit says so.
func TestAntigravityStopEvaluatorPanicAllowsTermination(t *testing.T) {
	injectPanicForProfile(t, "antigravity")
	for _, deployment := range []struct{ name, mode, profile string }{
		{"per-user", "", ""},
		{"standalone", managed.DeploymentModeManagedEnterprise, managed.ProfileStandalone},
	} {
		t.Run(deployment.name, func(t *testing.T) {
			store, logger := testStoreAndLogger(t)
			cfg := config.DefaultConfig()
			cfg.DataDir = t.TempDir()
			cfg.DeploymentMode, cfg.Enterprise.Profile = deployment.mode, deployment.profile
			cfg.Guardrail.HookFailMode = "closed"
			api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
			for attempt := 0; attempt < 3; attempt++ {
				response, _ := postPanicTestHook(t, api, "antigravity", "Stop")
				output, _ := response["hook_output"].(map[string]interface{})
				if response["action"] != "allow" || response["would_block"] != true || output["decision"] != "allow" {
					t.Fatalf("attempt %d: Stop panic response=%v, want the native allow of termination", attempt, response)
				}
			}
			rows, err := store.ListEvents(100)
			if err != nil {
				t.Fatal(err)
			}
			hookRows := 0
			for _, row := range rows {
				if row.Action != string(audit.ActionConnectorHook) {
					continue
				}
				hookRows++
				if row.Structured["result"] != "panic" || row.Structured["action"] != "allow" || row.Structured["would_block"] != true || row.Enforced {
					t.Fatalf("Stop panic audit=%+v, want an unenforced panic allow", row)
				}
			}
			if hookRows != 3 {
				t.Fatalf("hook audit rows=%d, want 3", hookRows)
			}
		})
	}
}

func TestClaudePostToolBatchEvaluatorPanicStopsContinuation(t *testing.T) {
	// This regression needs the unversioned Claude Code contract. Keep the
	// process home and the DefenseClaw version cache out of the operator's
	// installed Claude Code state on every OS.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, ".claude"))
	for _, deployment := range []struct{ name, mode, profile string }{
		{"per-user", "", ""},
		{"standalone", managed.DeploymentModeManagedEnterprise, managed.ProfileStandalone},
		{"secure-client", managed.DeploymentModeManagedEnterprise, managed.ProfileSecureClient},
	} {
		for _, mode := range []string{"observe", "action"} {
			t.Run(deployment.name+"/"+mode, func(t *testing.T) {
				injectPanicForProfile(t, "claudecode")
				store, logger := testStoreAndLogger(t)
				cfg := config.DefaultConfig()
				cfg.DataDir = t.TempDir()
				cfg.DeploymentMode, cfg.Enterprise.Profile = deployment.mode, deployment.profile
				cfg.Guardrail.Mode, cfg.Guardrail.HookFailMode = mode, "closed"
				if version := connector.LoadCachedAgentVersion(cfg.DataDir, "claudecode"); version != "" {
					t.Fatalf("PostToolBatch test requires no Claude Code version cache; got %q", version)
				}
				server := &APIServer{scannerCfg: cfg, store: store, logger: logger}
				response, _ := postPanicTestHook(t, server, "claudecode", "PostToolBatch")
				if response["action"] != "block" || response["raw_action"] != "block" || response["mode"] != "action" || response["would_block"] != false {
					t.Fatalf("PostToolBatch panic response=%v, want closed block/action", response)
				}
				if !panicWireDenies(response["claude_code_output"]) {
					t.Fatalf("PostToolBatch panic has no native denial: %v", response)
				}
				row := soleHookDecisionForTest(t, store)
				if row.Structured["result"] != "panic" || row.Structured["action"] != "block" {
					t.Fatalf("PostToolBatch audit=%v, want panic/block", row.Structured)
				}
			})
		}
	}
}
