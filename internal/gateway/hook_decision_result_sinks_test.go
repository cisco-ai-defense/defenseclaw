// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// Review of Port-0440 loop round 3 (P2, audit truth): a panic recovered
// outside the evaluator (artifact promotion, the tool-call chains, the
// sandbox reason and kernel-notice decorators, the finalization identity
// section) set the audit row and the hook_decision log to result=panic,
// while the hook invocation and latency metrics took the evaluator-only flag
// and said result=ok. One real Claude Code hook call per stage, through the
// handler, with a recording span: the audit row, the hook_decision log, the
// invocation and latency metrics and the span carry one result. A panic in
// the bookkeeping after the row (finalize_health) changes none of them, and
// neither does a failure after the finalized answer (round 4, GAP-1014): a
// panic before the write, or a connector output the encoder cannot write.
// The native hook still reads the answer the row records.
func TestSecondaryPanicHasOneResultOnEverySink(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
	injectAuditTruthEvaluator(t, "claudecode")
	injectStagePanic(t, auditTruthStage)
	for _, tc := range []struct{ stage, want string }{
		{"none", "ok"},
		{"evaluator", "panic"},
		{"artifact", "panic"},
		{"chain", "panic"},
		{"sandbox_reason", "panic"},
		{"kernel_notice", "panic"},
		{"finalize_identity", "panic"},
		{"finalize_health", "ok"},
		{"finalized", "ok"},
		{"render", "ok"},
		{"render_error", "ok"},
	} {
		t.Run(tc.stage, func(t *testing.T) {

			// One audit store for the hook and the observability runtime, as
			// in the sidecar.
			capture := &hookModelV8OTLPCapture{}
			collector := httptest.NewServer(http.HandlerFunc(capture.handler))
			t.Cleanup(collector.Close)
			fixture := newSidecarV8BootstrapFixture(t, 8, "")
			store := fixture.store
			cfg := config.DefaultConfig()
			cfg.DataDir = t.TempDir()
			cfg.Guardrail.Mode, cfg.Guardrail.HookFailMode, cfg.Guardrail.Connector = "action", "closed", "claudecode"
			api := &APIServer{scannerCfg: cfg, store: store, logger: fixture.logger}
			fixture.sidecar.setAPIServer(api)
			if bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath,
				hookModelV8BootstrapRaw(fixture.dataDir, collector.URL, []string{"logs", "metrics"})); err != nil || !bound {
				t.Fatalf("bootstrap observability runtime bound=%t error=%v", bound, err)
			}

			session := "sinks--" + tc.stage
			payload, _ := panicTestPayload("claudecode", "PreToolUse", t.TempDir())
			payload["session_id"] = session
			body, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			spans := tracetest.NewInMemoryExporter()
			provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(spans), sdktrace.WithSampler(sdktrace.AlwaysSample()))
			t.Cleanup(func() { _ = provider.Shutdown(t.Context()) })
			ctx, span := provider.Tracer("hook-result-sinks").Start(t.Context(), "agent-hook")
			req := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)).WithContext(ctx)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			api.handleAgentHook("claudecode").ServeHTTP(w, req)
			span.End()
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}

			var answer map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil {
				t.Fatalf("%s: the native hook cannot read the answer %q: %v", tc.stage, w.Body.String(), err)
			}
			row := newestHookDecision(t, store, session)
			if answer["action"] != row.Structured["action"] {
				t.Errorf("%s: answer action=%v, row action=%v", tc.stage, answer["action"], row.Structured["action"])
			}
			sinks := map[string]string{"audit row": hookResultText(row.Structured["result"])}
			if ended := spans.GetSpans(); len(ended) == 1 {
				if value, ok := attrByKey(ended[0].Attributes, "defenseclaw.connector.result"); ok {
					sinks["span"] = value.AsString()
				}
			}
			deadline := time.Now().Add(5 * time.Second)
			for {
				_, metrics := capture.snapshot()
				for _, instrument := range []string{
					observability.TelemetryInstrumentDefenseClawConnectorHookInvocations,
					observability.TelemetryInstrumentDefenseClawConnectorHookLatency,
				} {
					for _, point := range hookModelV8MetricPoints(metrics, instrument) {
						if point.attributes["defenseclaw.connector.source"] == "claudecode" {
							sinks[instrument] = point.attributes["defenseclaw.metric.result"]
						}
					}
				}
				for _, record := range hookModelV8CapturedLogs(capture.logSnapshot()) {
					if hookModelV8MetricAttributes(record.Attributes)["defenseclaw.event.name"] != observability.TelemetryEventHookDecision {
						continue
					}
					var wire struct {
						Body map[string]interface{} `json:"body"`
					}
					if json.Unmarshal([]byte(record.Body.GetStringValue()), &wire) == nil {
						sinks["hook_decision log"] = hookResultText(wire.Body["defenseclaw.hook.result"])
					}
				}
				if len(sinks) == 5 {
					break
				}
				if time.Now().After(deadline) {
					t.Logf("exported metrics: %v", hookModelV8CapturedMetricNames(metrics))
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			for _, sink := range []string{
				"audit row", "span", "hook_decision log",
				observability.TelemetryInstrumentDefenseClawConnectorHookInvocations,
				observability.TelemetryInstrumentDefenseClawConnectorHookLatency,
			} {
				if got, ok := sinks[sink]; !ok || got != tc.want {
					t.Errorf("%s: %s result=%q (recorded %t), want %s; sinks=%v", tc.stage, sink, got, ok, tc.want, sinks)
				}
			}
		})
	}
}

func hookResultText(value interface{}) string {
	text, _ := value.(string)
	return text
}
