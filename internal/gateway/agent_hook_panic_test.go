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
		for _, event := range hookexec.NeutralLifecycleEvents(tc.connector) {
			stop := api.hookPanicResponse(context.Background(), tc.connector,
				agentHookRequest{HookEventName: event}, nil, nil)
			if stop.Action != "allow" {
				t.Errorf("%s %s: lifecycle panic action = %q, want allow", tc.connector, event, stop.Action)
			}
		}
	}
	for _, connectorName := range []string{"claudecode", "codex"} {
		for _, event := range hookexec.NeutralLifecycleEvents(connectorName) {
			resp := api.hookPanicResponse(context.Background(), connectorName,
				agentHookRequest{HookEventName: event}, nil, nil)
			if resp.Action != "allow" {
				t.Errorf("%s %s: lifecycle panic action = %q, want allow", connectorName, event, resp.Action)
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
		{"claudecode", "PostToolUse", "action", "closed", "allow"},
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
			if tc.event == "PostToolUse" {
				if decisionIsDenied(response["claude_code_output"]) {
					t.Fatalf("post-tool output=%v, want a nonblocking advisory", response["claude_code_output"])
				}
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
	}{
		{"observe connector default", "", "", "block"},
		{"global open", "", "open", "block"},
		{"connector open", "open", "", "block"},
		{"connector closed over global open", "closed", "open", "block"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
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
		ConnectorName: "codex", HookEventName: "Stop", SessionID: "synthetic-panic",
		Payload: map[string]interface{}{"hook_event_name": "Stop"},
	}
	resp := api.handleAgentHookSynthetic(t.Context(), "codex", req, nil)
	if resp.Action != "allow" || resp.RawAction != "block" || resp.Mode != "action" || !resp.WouldBlock {
		t.Fatalf("synthetic response=%+v, want neutral lifecycle allow/action", resp)
	}
	row := soleHookDecisionForTest(t, store)
	if row.Structured["result"] != "panic" || row.Structured["action"] != "allow" {
		t.Fatalf("synthetic audit=%v, want panic/allow", row.Structured)
	}
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
		lifecycle := hookexec.NeutralLifecycleEvents(connectorName)
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
						isLifecycle := hookexec.NeutralLifecycleEvent(connectorName, event)
						capable, _ := mapHookActionForProfile("block", "action", event, profile.Capabilities, profile, nil)
						wantAction, wantMode := "allow", mode
						switch {
						case isLifecycle:
						case open:
						case capable == "block":
							wantAction, wantMode = "block", "action"
						}
						if resp.Action != wantAction || resp.Mode != wantMode || resp.WouldBlock != (wantAction != "block") {
							t.Errorf("%s: action=%q mode=%q would_block=%v, want %s/%s", name, resp.Action, resp.Mode, resp.WouldBlock, wantAction, wantMode)
						}
						// The Amp plugin reads the action field itself.
						// A Claude Code event whose native denial is exit 2 with
						// the reason on stderr (TaskCreated, TaskCompleted,
						// TeammateIdle) has no output to render.
						exitTwoDenial := connectorName == "claudecode" &&
							claudeCodeOutput(claudeCodeHookRequest{HookEventName: event}, "block", "block", "", "") == nil
						if wantAction == "block" && exitTwoDenial && len(resp.HookOutput) != 0 {
							t.Errorf("%s: an exit-2 denial rendered output %v", name, resp.HookOutput)
						}
						if wantAction == "block" && len(resp.HookOutput) == 0 && !exitTwoDenial && connectorName != "amp" {
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
