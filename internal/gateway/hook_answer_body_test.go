// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// panickingJSONValue is a connector output value whose encoding panics.
type panickingJSONValue struct{}

func (panickingJSONValue) MarshalJSON() ([]byte, error) {
	panic("injected hook output encode panic")
}

// unencodableHookOutputs are connector outputs the answer's encoder cannot
// write: one panics, one fails with an error.
var unencodableHookOutputs = map[string]interface{}{
	"panicking marshaler": panickingJSONValue{},
	"unencodable value":   math.NaN(),
}

// injectAuditTruthEvaluator replaces name's evaluator for the audit-truth
// tables: a call whose session stage (auditTruthStage) is "evaluator" panics,
// "render" and "render_error" answer a healthy allow whose native output
// cannot be encoded, and every other call answers a healthy allow.
func injectAuditTruthEvaluator(t *testing.T, name string) {
	t.Helper()
	injectAnswerEvaluator(t, name, func(session string) agentHookResponse {
		resp := agentHookResponse{Action: "allow", RawAction: "allow", Severity: "NONE", Mode: "action", Reason: "healthy allow"}
		switch auditTruthStage(session) {
		case "evaluator":
			panic("injected evaluator error")
		case "render":
			resp.HookOutput = map[string]interface{}{"value": panickingJSONValue{}}
		case "render_error":
			resp.HookOutput = map[string]interface{}{"value": math.NaN()}
		}
		return resp
	})
}

// injectAnswerEvaluator replaces name's evaluator with answer.
func injectAnswerEvaluator(t *testing.T, name string, answer func(session string) agentHookResponse) {
	t.Helper()
	previous, had := hookProfileRuntimes[name]
	hookProfileRuntimes[name] = func(profile connector.HookProfile) hookProfileRuntime {
		runtime := defaultHookProfileRuntime(profile)
		runtime.Evaluate = func(_ *APIServer, _ context.Context, req agentHookRequest, _ []byte, _ map[string]interface{}) agentHookResponse {
			return answer(req.SessionID)
		}
		return runtime
	}
	t.Cleanup(func() {
		if had {
			hookProfileRuntimes[name] = previous
		} else {
			delete(hookProfileRuntimes, name)
		}
	})
}

// Review of Port-0440 loop round 4 (GAP-1014, P2, audit truth): once the
// call's row was written, a render panic or an encoding failure of the
// connector's output left the native hook an empty body, and the hook applied
// its own fail mode: a closed hook denied the allow the row, the export and
// the metrics recorded, and an open one ran the call they recorded as a
// block. For every registered connector and event, an answer whose output
// cannot be encoded goes out with its own action, raw action, reason,
// would_block and correlation keys, and with the callback-free native output
// of that action. An encodable answer's body is the one writeJSON wrote.
//
// Loop round 2 of the continuation (P2): an output whose encoding panics is
// counted once in defenseclaw.panics.total, as the handler's outer recovery
// counted it before; an encoding error and a healthy answer count none.
func TestHookAnswerBodyKeepsTheAnswerOnEveryConnectorEvent(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	server := &APIServer{scannerCfg: cfg}
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	server.bindObservabilityV8Runtimes(runtime, nil, nil, runtime)
	panicsCounted := func() int {
		return len(generatedMetricByName(capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawPanicsTotal))
	}
	profiles := panicTestProfiles(t, server)
	answers := []agentHookResponse{
		{Action: "allow", RawAction: "allow", Severity: "NONE", Mode: "action", Reason: "healthy allow", EvaluationID: "eval-allow"},
		{Action: "block", RawAction: "block", Severity: "HIGH", Mode: "action", Reason: "policy block", EvaluationID: "eval-block", RuleIDs: []string{"R-1"}, Findings: []string{"finding"}},
		{Action: "allow", RawAction: "block", Severity: "HIGH", Mode: "action", WouldBlock: true, Reason: "advisory block", AdditionalContext: "advisory context"},
	}
	cells := 0
	for name, profile := range profiles {
		field := strings.TrimSpace(profile.ResponseFieldName)
		if field == "" {
			field = hookOutputFieldName(profile.Name)
		}
		for _, event := range profile.SupportedEvents {
			req := agentHookRequest{ConnectorName: name, HookEventName: event, ToolName: "Bash"}
			for _, answer := range answers {
				healthy := answer
				healthy.HookOutput = map[string]interface{}{"decision": answer.Action}
				var encoded bytes.Buffer
				if err := json.NewEncoder(&encoded).Encode(renderAgentHookResponseForProfile(profile, healthy)); err != nil {
					t.Fatal(err)
				}
				before := panicsCounted()
				if got := server.hookAnswerBody(t.Context(), profile, name, req, healthy); !bytes.Equal(got, encoded.Bytes()) {
					t.Errorf("%s/%s %s: body %q, want the writeJSON body %q", name, event, answer.Reason, got, encoded.Bytes())
				}
				if counted := panicsCounted() - before; counted != 0 {
					t.Errorf("%s/%s %s: a healthy answer counted %d panics", name, event, answer.Reason, counted)
				}
				want := jsonRoundTrip(t, failedCheckFallbackOutput(profile, req, answer.Action, answer.RawAction, answer.Reason, answer.AdditionalContext))
				for label, value := range unencodableHookOutputs {
					cell := name + "/" + event + "/" + answer.Reason + "/" + label
					resp := answer
					resp.HookOutput = map[string]interface{}{"value": value}
					var got map[string]interface{}
					before := panicsCounted()
					body := server.hookAnswerBody(t.Context(), profile, name, req, resp)
					wantPanics := 0
					if _, panics := value.(panickingJSONValue); panics {
						wantPanics = 1
					}
					if counted := panicsCounted() - before; counted != wantPanics {
						t.Errorf("%s: defenseclaw.panics.total counted %d, want %d", cell, counted, wantPanics)
					}
					if err := json.Unmarshal(body, &got); err != nil {
						t.Errorf("%s: the native hook cannot read the body: %v", cell, err)
						continue
					}
					cells++
					if got["action"] != answer.Action || got["raw_action"] != answer.RawAction || got["reason"] != answer.Reason ||
						got["would_block"] != answer.WouldBlock || got["mode"] != answer.Mode || got["severity"] != answer.Severity {
						t.Errorf("%s: body %v, want the answer %+v", cell, got, answer)
					}
					if answer.EvaluationID != "" && got["evaluation_id"] != answer.EvaluationID {
						t.Errorf("%s: evaluation_id=%v, want %s", cell, got["evaluation_id"], answer.EvaluationID)
					}
					if len(answer.Findings) > 0 && !reflect.DeepEqual(got["findings"], jsonRoundTrip(t, answer.Findings)) {
						t.Errorf("%s: findings=%v, want %v", cell, got["findings"], answer.Findings)
					}
					if output, ok := got[field]; ok != (want != nil) || !reflect.DeepEqual(output, want) {
						t.Errorf("%s: %s=%v, want the native fallback output %v", cell, field, output, want)
					}
				}
			}
		}
	}
	if cells == 0 {
		t.Fatal("no connector event was checked")
	}
}

// jsonRoundTrip is value as a decoded wire body sees it; nil for an empty
// output, which the body omits.
func jsonRoundTrip(t *testing.T, value interface{}) interface{} {
	t.Helper()
	if output, ok := value.(map[string]interface{}); ok && len(output) == 0 {
		return nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var decoded interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

// Review of Port-0440 loop round 4 (GAP-1014, P2): end to end through the
// native hook runner, the hook applies the answer its call's row records,
// also when that answer cannot be rendered as the connector wrote it, or a
// panic follows the finalized answer. Before, a closed hook denied the
// recorded allow and an open hook ran the recorded block. The row is
// written once, with result=ok: the late failure changes no verdict.
func TestNativeHookAppliesTheAuditedAnswerAfterALateFailure(t *testing.T) {
	for _, tc := range []struct {
		name, failMode, action, stage string
		output                        interface{}
	}{
		{"closed allow, output encode panics", "closed", "allow", "", panickingJSONValue{}},
		{"closed allow, output encode fails", "closed", "allow", "", math.NaN()},
		{"open block, output encode panics", "open", "block", "", panickingJSONValue{}},
		{"open block, output encode fails", "open", "block", "", math.NaN()},
		{"closed allow, panic after finalization", "closed", "allow", "finalized", nil},
		{"open block, panic after finalization", "open", "block", "finalized", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newAuditFailureHookFixture(t, tc.failMode)
			injectAnswerEvaluator(t, "claudecode", func(string) agentHookResponse {
				resp := agentHookResponse{Action: tc.action, RawAction: tc.action, Severity: "HIGH", Mode: "action", Reason: "policy " + tc.action}
				if tc.output != nil {
					resp.HookOutput = map[string]interface{}{"value": tc.output}
				}
				return resp
			})
			if tc.stage != "" {
				injectStagePanic(t, everyCallAt(tc.stage))
			}
			home := t.TempDir()
			hookDir := filepath.Join(home, "hooks")
			if err := os.MkdirAll(hookDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(hookDir, ".token"), []byte("DEFENSECLAW_GATEWAY_TOKEN=\"tkn\"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			code := hookexec.Run(t.Context(), hookexec.Options{
				Connector:  "claudecode",
				Event:      "PreToolUse",
				APIAddr:    "127.0.0.1:8787",
				FailMode:   tc.failMode,
				Home:       home,
				HookDir:    hookDir,
				Stdin:      bytes.NewReader(preToolUseBody(t, "toolu-late")),
				Stdout:     &stdout,
				Stderr:     &stderr,
				HTTPClient: &http.Client{Transport: handlerTransport{handler: fixture.api.handleAgentHook("claudecode")}},
			})
			var output map[string]interface{}
			if text := bytes.TrimSpace(stdout.Bytes()); len(text) > 0 {
				if err := json.Unmarshal(text, &output); err != nil {
					t.Fatalf("hook exit %d stdout %q stderr %q: %v", code, stdout.String(), stderr.String(), err)
				}
			}
			denied := code != 0 || panicWireDenies(output)
			if denied != (tc.action == "block") {
				t.Fatalf("native hook exit %d stdout %q stderr %q: denied=%t, want the recorded %s", code, stdout.String(), stderr.String(), denied, tc.action)
			}
			row := newestHookDecision(t, fixture.api.store, "s-audit-toolu-late")
			if row.Structured["action"] != tc.action || row.Structured["result"] != "ok" || row.Enforced != (tc.action == "block") {
				t.Fatalf("row action=%v result=%v enforced=%t, want %s/ok", row.Structured["action"], row.Structured["result"], row.Enforced, tc.action)
			}
		})
	}
}

// Loop round 2 of the continuation (P2): once hookAnswerBody recovered an
// answer-encoding panic itself, the panic no longer reached the handler's
// outer recovery and was logged as a render error only, missing from
// defenseclaw.panics.total. Through the handler, a Claude Code call whose
// finalized allow has an output whose encoding panics counts one panic, and
// its row and its answer keep the finalized allow with result=ok. An output
// the encoder rejects without a panic, a healthy call and a panic after
// finalization (counted by the outer recovery) are counted as they are.
func TestAnswerRenderPanicIsCountedAndKeepsTheFinalizedDecision(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
	injectAuditTruthEvaluator(t, "claudecode")
	injectStagePanic(t, auditTruthStage)
	for _, tc := range []struct {
		stage  string
		panics int
	}{
		{"none", 0},
		{"render", 1},
		{"render_error", 0},
		{"finalized", 1},
	} {
		t.Run(tc.stage, func(t *testing.T) {
			store, logger := testStoreAndLogger(t)
			cfg := config.DefaultConfig()
			cfg.DataDir = t.TempDir()
			cfg.Guardrail.Mode, cfg.Guardrail.HookFailMode, cfg.Guardrail.Connector = "action", "closed", "claudecode"
			api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
			runtime, _ := newProxyGeneratedTraceRuntime(t)
			metrics := &panicCountingRuntime{Runtime: runtime}
			api.bindObservabilityV8Runtimes(runtime, nil, nil, metrics)
			session := "count--" + tc.stage
			answer, _ := postAuditTruthHook(t, api, "claudecode", "PreToolUse", session)
			row := newestHookDecision(t, store, session)
			if answer["action"] != "allow" || row.Structured["action"] != "allow" || row.Structured["result"] != "ok" {
				t.Errorf("answer action=%v, row action=%v result=%v; want the finalized allow, result ok",
					answer["action"], row.Structured["action"], row.Structured["result"])
			}
			if counted := int(metrics.panics.Load()); counted != tc.panics {
				t.Errorf("defenseclaw.panics.total counted %d, want %d", counted, tc.panics)
			}
		})
	}
}

// panicCountingRuntime counts the defenseclaw.panics.total points the gateway
// records through it, before the runtime builds and delivers them.
type panicCountingRuntime struct {
	*observabilityruntime.Runtime
	panics atomic.Int64
}

func (r *panicCountingRuntime) RecordGeneratedMetricBatch(
	ctx context.Context,
	items []observabilityruntime.GeneratedMetricBatchItem,
) ([]telemetry.V8MetricRecordResult, error) {
	for _, item := range items {
		if item.Family == observability.EventName(observability.TelemetryInstrumentDefenseClawPanicsTotal) {
			r.panics.Add(1)
		}
	}
	return r.Runtime.RecordGeneratedMetricBatch(ctx, items)
}
