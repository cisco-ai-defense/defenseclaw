// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// finalizeAgentHook finalizes a verdict that is not yet on the wire, as the
// handler does for an answer it writes after finalization.
func (a *APIServer) finalizeAgentHook(
	ctx context.Context,
	connectorName string,
	req agentHookRequest,
	resp agentHookResponse,
	rawEventIDs []string,
	rawBody []byte,
	elapsed time.Duration,
	panicked bool,
	extra map[string]string,
) hookFinalizationResult {
	return a.finalizeAgentHookAnswer(ctx, connectorName, req, resp, rawEventIDs, rawBody, elapsed, panicked, extra, false)
}

// injectHealthyAllowForProfile makes name's evaluator answer a healthy
// allow, so a panic injected after it (hookStagePanicHook) is the only
// failure of the call.
func injectHealthyAllowForProfile(t *testing.T, name string) {
	t.Helper()
	injectRoutedEvaluator(t, name, func(string) bool { return false })
}

// injectRoutedEvaluator replaces name's evaluator: it panics for a call
// whose session panics names, and otherwise answers a healthy allow.
func injectRoutedEvaluator(t *testing.T, name string, panics func(session string) bool) {
	t.Helper()
	previous, had := hookProfileRuntimes[name]
	hookProfileRuntimes[name] = func(profile connector.HookProfile) hookProfileRuntime {
		runtime := defaultHookProfileRuntime(profile)
		runtime.Evaluate = func(_ *APIServer, _ context.Context, req agentHookRequest, _ []byte, _ map[string]interface{}) agentHookResponse {
			if panics(req.SessionID) {
				panic("injected evaluator error")
			}
			return agentHookResponse{Action: "allow", RawAction: "allow", Severity: "NONE", Mode: "action", Reason: "healthy allow"}
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

// injectStagePanic panics at a named stage of a hook answer: the stage
// returned by stageOf for the call's session.
func injectStagePanic(t *testing.T, stageOf func(session string) string) {
	t.Helper()
	previous := hookStagePanicHook
	hookStagePanicHook = func(ctx context.Context, at string) {
		if at == stageOf(SessionIDFromContext(ctx)) {
			panic("injected " + at + " panic")
		}
	}
	t.Cleanup(func() { hookStagePanicHook = previous })
}

func everyCallAt(stage string) func(string) string {
	return func(string) string { return stage }
}

// auditTruthStage is the stage a table call names after "--" in its session.
func auditTruthStage(session string) string {
	_, stage, _ := strings.Cut(session, "--")
	return stage
}

// panickingResponderRegistry registers name with a response renderer that
// panics on every call.
func panickingResponderRegistry(t *testing.T, name string, panicked *bool) *connector.Registry {
	t.Helper()
	original, ok := sharedDefaultRegistry().Get(name)
	if !ok {
		t.Fatalf("missing registered %s connector", name)
	}
	provider, ok := original.(connector.HookProfileProvider)
	if !ok {
		t.Fatalf("%s has no hook profile", name)
	}
	registry := connector.NewRegistry()
	registry.RegisterBuiltin(panickingResponderConnector{Connector: original, provider: provider, panicked: panicked})
	return registry
}

// postAuditTruthHook posts one hook call with its own session, so no call is
// a deduplicated second delivery of another.
func postAuditTruthHook(t *testing.T, api *APIServer, name, event, session string) (map[string]interface{}, agentHookRequest) {
	t.Helper()
	payload, registeredEvent := panicTestPayload(name, event, t.TempDir())
	switch name {
	case "antigravity":
		payload["conversationId"] = session
	case "copilot":
		payload["sessionId"] = session
	default:
		payload["session_id"] = session
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	profile := api.hookProfileForConnector(name)
	decoded := normalizeAgentHookRequestWithRawProfileEvent(name, payload, body, profile, registeredEvent, "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+name+"/hook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	switch name {
	case "codex":
		setTestCodexHookBinding(req, event, defaultTestCodexHookContract)
	case "copilot":
		req.Header.Set("X-DefenseClaw-Copilot-Event", event)
	case "antigravity":
		req.Header.Set("X-DefenseClaw-Antigravity-Event", event)
	}
	w := httptest.NewRecorder()
	api.handleAgentHook(name).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%s/%s status=%d body=%s", name, event, w.Code, w.Body.String())
	}
	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response, decoded
}

// newestHookDecision returns the newest connector-hook row of store: the
// row of session's call, written once (the row before it is another call's).
func newestHookDecision(t *testing.T, store *audit.Store, session string) audit.Event {
	t.Helper()
	events, err := store.ListEvents(4)
	if err != nil {
		t.Fatal(err)
	}
	var rows []audit.Event
	for _, event := range events {
		if event.Action == string(audit.ActionConnectorHook) {
			rows = append(rows, event)
		}
	}
	if len(rows) == 0 || rows[0].SessionID != session || (len(rows) > 1 && rows[1].SessionID == session) {
		t.Fatalf("newest hook decision rows=%+v, want one row of session %s", rows, session)
	}
	return rows[0]
}

// recoveredPanicAnswer is the one table of a recovered panic's answer under
// closed fail mode, built from the capability matrix independently of the
// gateway: the event's native control on an enforcement event, Claude Code's
// terminal answer on its turn-ending lifecycle events, and the neutral allow
// on every other lifecycle event.
func recoveredPanicAnswer(name, event string, profile connector.HookProfile) (action string, wouldBlock, lifecycle, terminal bool) {
	if hookexec.LifecycleEvent(name, event) {
		if terminalLifecycleEvent(name, event) {
			return "block", false, true, true
		}
		return "allow", true, true, false
	}
	action = panicNativeActionOracle(name, event, profile)
	return action, action == "allow", false, false
}

// Review of Port-0440 loop round 1 (P2, audit truth): the answer and the
// audit row of a recovered panic, for every registered connector and event,
// per-user and standalone managed, with the panic injected at each place the
// hook path recovers one: the evaluator, the evaluator and then the
// connector's response renderer, artifact promotion and the tool-call chains
// after a healthy evaluation (both answer the panic's fail-mode verdict), and
// the sandbox-reason and kernel-notice decorators (both keep the healthy
// verdict). The answer follows the one table (recoveredPanicAnswer) and
// carries the native control a healthy answer of that verdict carries; the
// audit row has the answer's action, would_block and enforced flag, and
// records the evaluator failure (result=panic) wherever it was recovered
// (GAP-0900: the secondary recoveries were audited result=ok).
func TestRecoveredPanicAnswerAndAuditRowForEveryEvent(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
	profiles := panicTestProfiles(t, &APIServer{})
	// The injections are installed once and routed by the call's session, so
	// the connector groups run in parallel.
	for name := range profiles {
		injectRoutedEvaluator(t, name, func(session string) bool {
			stage := auditTruthStage(session)
			return stage == "evaluator" || stage == "responder"
		})
	}
	injectStagePanic(t, auditTruthStage)
	type stage struct {
		name         string
		panicVerdict bool
		everyEvent   bool
	}
	stages := []stage{
		// The evaluator and the connector's renderer: every event.
		{"evaluator", true, true},
		{"responder", true, true},
		// The additive checks answer the panic's fail-mode verdict and the
		// decorators keep the healthy verdict. Their recovery does not
		// depend on the event: a blockable, an advisory and a lifecycle
		// event of each connector.
		{"artifact", true, false},
		{"chain", true, false},
		{"sandbox_reason", false, false},
		{"kernel_notice", false, false},
	}
	var cells atomic.Int64
	for name, profile := range profiles {
		representative := map[string]bool{}
		for _, event := range []string{panicTestEvent(profile, true), panicTestEvent(profile, false)} {
			representative[event] = true
		}
		for _, event := range profile.SupportedEvents {
			if hookexec.LifecycleEvent(name, event) {
				representative[event] = true
				break
			}
		}
		for _, deployment := range []struct{ name, mode, profile string }{
			{"per-user", "", ""},
			{"standalone", managed.DeploymentModeManagedEnterprise, managed.ProfileStandalone},
		} {
			t.Run(name+"/"+deployment.name, func(t *testing.T) {
				t.Parallel()
				store, logger := testStoreAndLogger(t)
				cfg := config.DefaultConfig()
				cfg.DataDir = t.TempDir()
				cfg.DeploymentMode, cfg.Enterprise.Profile = deployment.mode, deployment.profile
				cfg.Guardrail.Mode, cfg.Guardrail.HookFailMode, cfg.Guardrail.Connector = "action", "closed", name
				for _, event := range profile.SupportedEvents {
					if name == "copilot" && strings.ToLower(event[:1]) != event[:1] {
						// The VS Code Local spellings do not reach the CLI hook
						// route; TestHookEvaluatorPanicActionFollowsNativeControl
						// covers them.
						continue
					}
					want, wantWouldBlock, lifecycle, terminal := recoveredPanicAnswer(name, event, profile)
					for _, stage := range stages {
						if !stage.everyEvent && !representative[event] {
							continue
						}
						if stage.name == "responder" && (name == "claudecode" || name == "codex") {
							// Claude Code and Codex render with the gateway's
							// own callback-free renderers; there is no
							// connector responder to fail.
							continue
						}
						func() {
							cells.Add(1)
							cell := event + "/" + stage.name
							server := &APIServer{scannerCfg: cfg, store: store, logger: logger}
							responderPanicked := false
							if stage.name == "responder" {
								server.connectorRegistry = panickingResponderRegistry(t, name, &responderPanicked)
							}
							session := "at-" + deployment.name + "-" + event + "--" + stage.name
							response, req := postAuditTruthHook(t, server, name, event, session)
							row := newestHookDecision(t, store, session)
							output, _ := panicTestOutput(name, response).(map[string]interface{})
							if stage.name == "responder" && !responderPanicked {
								t.Errorf("%s: %s responder was never called", cell, name)
								return
							}

							// The audit row is the answer, and records the panic.
							if row.Structured["result"] != "panic" {
								t.Errorf("%s: audit result=%v, want panic; row=%+v", cell, row.Structured["result"], row.Structured)
								return
							}
							gotAction, _ := response["action"].(string)
							rowAction, _ := row.Structured["action"].(string)
							// A standalone tool call answered without a delivery
							// receipt is recorded unconfirmed (unreceiptedHookDecision).
							unconfirmed := deployment.name == "standalone" && rowAction == hookActionUnconfirmed && gotAction == "allow" &&
								hookexec.DeliveryReceiptEvent(name, event)
							if (rowAction != gotAction && !unconfirmed) || row.Enforced != (gotAction == "block") ||
								row.Structured["would_block"] != response["would_block"] {
								t.Errorf("%s: audit=%+v enforced=%t, want the answer %v", cell, row.Structured, row.Enforced, response)
								return
							}

							if !stage.panicVerdict {
								// A decorator panic keeps the healthy verdict.
								if gotAction != "allow" || response["would_block"] == true || panicWireDenies(output) {
									t.Errorf("%s: panic changed the healthy allow: %v", cell, response)
								}
								return
							}
							if gotAction != want || response["raw_action"] != "block" || response["would_block"] != wantWouldBlock || response["mode"] != "action" {
								t.Errorf("%s: panic answer=%v, want %s raw block would_block=%t in action mode", cell, response, want, wantWouldBlock)
								return
							}
							switch {
							case terminal:
								if output["continue"] != false || output["stopReason"] == "" || len(output) != 2 {
									t.Errorf("%s: terminal lifecycle output=%v, want continue:false with a stop reason", cell, output)
									return
								}
							case lifecycle:
								if lifecycleAnswerRepeats(output) || panicWireDenies(output) {
									t.Errorf("%s: lifecycle output=%v repeats the hook", cell, output)
									return
								}
							case want == "allow":
								if panicWireDenies(output) {
									t.Errorf("%s: advisory allow output=%v carries a native denial", cell, output)
									return
								}
							default:
								healthy := agentHookResponseForProfile(profile, req, want, "block", "WARN", "healthy comparison", nil, "action", false, profile.Capabilities)
								if got, wantShape := nativeControlShape(t, output), nativeControlShape(t, healthy.HookOutput); !reflect.DeepEqual(got, wantShape) {
									t.Errorf("%s: native output=%v, want the healthy %s control %v", cell, got, want, wantShape)
									return
								}
							}
						}()
					}
				}
			})
		}
	}
	t.Cleanup(func() {
		if got := cells.Load(); got < 500 {
			t.Errorf("cells=%d, want every registered connector and event", got)
		}
	})
}

// Review of Port-0440 loop round 1 (P2, audit truth): a panic after the
// answer was finalized, before it was written, wrote a fresh fail-mode
// verdict: the agent got a block while the audit row and the export recorded
// the allow. The late write carries the finalized answer.
func TestPanicAfterFinalizationWritesTheAuditedAnswer(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
	for _, tc := range []struct{ connector, event string }{
		{"claudecode", "PreToolUse"},
		{"codex", "PreToolUse"},
		{"cursor", "beforeShellExecution"},
		{"copilot", "preToolUse"},
		{"antigravity", "PreToolUse"},
		{"hermes", "pre_tool_call"},
	} {
		for _, deployment := range []struct{ name, mode, profile string }{
			{"per-user", "", ""},
			{"standalone", managed.DeploymentModeManagedEnterprise, managed.ProfileStandalone},
		} {
			t.Run(tc.connector+"/"+tc.event+"/"+deployment.name, func(t *testing.T) {
				injectHealthyAllowForProfile(t, tc.connector)
				injectStagePanic(t, everyCallAt("finalized"))
				store, logger := testStoreAndLogger(t)
				cfg := config.DefaultConfig()
				cfg.DataDir = t.TempDir()
				cfg.DeploymentMode, cfg.Enterprise.Profile = deployment.mode, deployment.profile
				cfg.Guardrail.Mode, cfg.Guardrail.HookFailMode, cfg.Guardrail.Connector = "action", "closed", tc.connector
				server := &APIServer{scannerCfg: cfg, store: store, logger: logger}
				response, _ := postAuditTruthHook(t, server, tc.connector, tc.event, "finalized-"+deployment.name)
				row := soleHookDecisionForTest(t, store)
				if response["action"] != "allow" || panicWireDenies(panicTestOutput(tc.connector, response)) {
					t.Fatalf("answer=%v, want the finalized allow", response)
				}
				if action := row.Structured["action"]; (action != "allow" && action != hookActionUnconfirmed) || row.Enforced {
					t.Fatalf("audit=%+v, want the allow the agent got", row.Structured)
				}
			})
		}
	}
}

// Review of Port-0440 loop round 1 (P2, audit truth): a standalone managed
// hook received and acknowledged an allow, then a panic was recovered before
// finalization: the audit row and the hook_decision export recorded the
// panic's block, which the agent never got. They record the delivered allow
// and the evaluator failure.
func TestPanicAfterDeliveryRecordsTheDeliveredAnswer(t *testing.T) {
	injectStagePanic(t, everyCallAt("delivered"))
	f := newManagedHookAuditFixture(t, nil)
	f.offer(t, "delivered-then-panic", hookexec.HookDeliveryReceiptAck)
	if got := f.audited(t, "delivered-then-panic")["delivered-then-panic"]; got != "allow" {
		t.Fatalf("audited action=%q, want the delivered allow", got)
	}
	row := soleHookDecisionForTest(t, f.store)
	if row.Structured["result"] != "panic" || row.Enforced {
		t.Fatalf("audit=%+v enforced=%t, want an unenforced allow that records the panic", row.Structured, row.Enforced)
	}
	waitForHookDecisions(t, f, "allow/panic")
}

func waitForHookDecisions(t *testing.T, f managedHookAuditFixture, want string) {
	t.Helper()
	for attempt := 0; attempt < 400; attempt++ {
		if got := strings.Join(f.decisions(t), ","); got != "" {
			if got != want {
				t.Fatalf("hook_decision records=%s, want %s", got, want)
			}
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("no hook_decision record, want %s", want)
}

// Review of Port-0440 loop round 1 (P2, responder panic): the profile
// refusal, the require-sandbox refusal of a failed gate and the sandbox's
// closed verdict kept a bare block, with no native output, when the
// connector's renderer panicked. Some agents read a bare block as an allow
// while the audit records it enforced. Each keeps the native denial a
// healthy render of the block carries.
func TestBlockRenderPanicKeepsTheNativeDenial(t *testing.T) {
	// Claude Code and Codex have no connector responder: the gateway renders
	// their answers with its own callback-free renderers.
	for _, tc := range []struct{ connector, event string }{
		{"cursor", "beforeShellExecution"},
		{"copilot", "preToolUse"},
		{"antigravity", "PreToolUse"},
		{"devin", "PreToolUse"},
		{"kiro", "PreToolUse"},
		{"opencode", "tool.execute.before"},
		{"hermes", "pre_tool_call"},
	} {
		for _, path := range []string{"profile-refusal", "require-sandbox-gate", "sandbox-closed"} {
			t.Run(tc.connector+"/"+tc.event+"/"+path, func(t *testing.T) {
				cfg := config.DefaultConfig()
				cfg.DeploymentMode, cfg.Enterprise.Profile = managed.DeploymentModeManagedEnterprise, managed.ProfileStandalone
				cfg.Guardrail.Mode, cfg.Guardrail.HookFailMode = "action", "closed"
				cfg.OpenShell.Admin.RequiredFor = []string{tc.connector}
				api := &APIServer{scannerCfg: cfg}
				healthyProfile := api.hookProfileForConnector(tc.connector)
				profile := healthyProfile
				panicked := false
				profile.Respond = func(connector.HookRespondInput) connector.HookRespondOutput {
					panicked = true
					panic("injected block render panic")
				}
				req := agentHookRequest{ConnectorName: tc.connector, HookEventName: tc.event, ToolName: "Bash"}
				ctx := withHookPanicCapture(t.Context())
				var resp agentHookResponse
				switch path {
				case "profile-refusal":
					set := &guardrailProfileSet{}
					api.guardrailProfiles.set.Store(set)
					refusedCtx := context.WithValue(ctx, resolvedGuardrailProfileKey{}, &resolvedGuardrailProfile{
						decision: profileDecision{Refused: "the user's group is unconfirmed"}, set: set,
					})
					var refused bool
					if resp, refused = api.refuseProfileHook(refusedCtx, profile, tc.connector, req, nil, nil); !refused {
						t.Fatal("the hook was not refused")
					}
				case "require-sandbox-gate":
					var gated bool
					if _, resp, gated = api.requireSandboxGateFailed(ctx, profile, tc.connector, req, nil, nil); !gated {
						t.Fatal("the failed gate did not refuse the host run")
					}
				case "sandbox-closed":
					ctx = sandboxauth.WithRequest(ctx, sandboxauth.Binding{ID: "sb-render", SandboxName: "sbx", Connector: sandboxauth.CanonicalConnector(tc.connector)}, nil)
					resp = api.failSandboxHookClosed(ctx, profile, tc.connector, req, nil, nil,
						agentHookResponse{Action: "block", RawAction: "block", Severity: "WARN", Mode: "action"})
				}
				if !panicked || resp.Action != "block" {
					t.Fatalf("render panicked=%t response=%+v, want a block after a render panic", panicked, resp)
				}
				healthy := api.renderSandboxVerdict(t.Context(), healthyProfile, req, nil, nil,
					agentHookResponse{Action: "block", RawAction: "block", Severity: "WARN", Mode: "action"}, resp.Reason)
				if len(healthy.HookOutput) == 0 {
					t.Fatalf("healthy %s/%s block has no native output", tc.connector, tc.event)
				}
				if got, want := nativeControlShape(t, resp.HookOutput), nativeControlShape(t, healthy.HookOutput); !reflect.DeepEqual(got, want) {
					t.Fatalf("render-panic block output=%v, want the healthy native denial %v", got, want)
				}
				if !hookPanicRecovered(ctx) {
					t.Fatal("the render panic was not recorded on the hook's panic capture")
				}
			})
		}
	}
}

// Every recovery reports through the hook's panic capture, and a panic the
// capture recorded marks the audit row and export of a verdict that was kept
// (GAP-0900), while an untouched hook stays result=ok.
func TestFinalizeRecordsEveryRecoveredPanic(t *testing.T) {
	for _, recovered := range []bool{false, true} {
		store, logger := testStoreAndLogger(t)
		api := &APIServer{store: store, logger: logger}
		ctx := withHookPanicCapture(t.Context())
		if recovered {
			api.handleHookPanic(ctx, "claudecode", "PreToolUse", "injected secondary panic")
		}
		req := agentHookRequest{ConnectorName: "claudecode", HookEventName: "PreToolUse", SessionID: "capture"}
		allow := agentHookResponse{Action: "allow", RawAction: "allow", Mode: "action"}
		api.finalizeAgentHook(ctx, "claudecode", req, allow, nil, []byte(`{}`), 0, false, nil)
		row := soleHookDecisionForTest(t, store)
		want := "ok"
		if recovered {
			want = "panic"
		}
		if row.Structured["result"] != want || row.Structured["action"] != "allow" {
			t.Fatalf("recovered=%t audit=%+v, want result=%s on the kept allow", recovered, row.Structured, want)
		}
	}
}

// Review of Port-0440 loop round 2 (P2, audit truth): a panic recovered in a
// finalization section after the audit row was written (the sandbox record,
// for example) left the row result=ok while the later hook_decision export
// said result=panic. The row and the export carry one result: a panic before
// the row is on both, a panic after it changes neither, and a call without a
// row is recorded by its export alone, panic included. The span follows the
// same result (hookFinalizationResult.Panicked).
func TestFinalizationPanicKeepsOneResultOnRowAndExport(t *testing.T) {
	for _, tc := range []struct {
		section    string
		auditFails bool
		want       string // row result, or "" when no row is written
		export     string
	}{
		{section: "", want: "ok", export: "allow/ok"},
		{section: "finalize_identity", want: "panic", export: "allow/panic"},
		{section: "finalize_health", want: "ok", export: "allow/ok"},
		{section: "finalize_sandbox", want: "ok", export: "allow/ok"},
		{section: "finalize_hook_join", want: "ok", export: "allow/ok"},
		{section: "finalize_sensitive_result", want: "ok", export: "allow/ok"},
		{section: "finalize_audit", export: "allow/panic"},
		{section: "finalize_sandbox", auditFails: true, export: "allow/panic"},
		{section: "finalize_health", auditFails: true, export: "allow/panic"},
	} {
		name := tc.section
		if name == "" {
			name = "no_panic"
		}
		if tc.auditFails {
			name += "/audit_write_failed"
		}
		t.Run(name, func(t *testing.T) {
			injectStagePanic(t, everyCallAt(tc.section))
			f := newManagedHookAuditFixture(t, nil)
			if tc.auditFails {
				database, err := sql.Open("sqlite", f.path)
				if err != nil {
					t.Fatal(err)
				}
				defer database.Close()
				if _, err := database.Exec(`CREATE TRIGGER zz_audit_disk_full BEFORE INSERT ON audit_events
					WHEN NEW.action = 'connector-hook' BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END`); err != nil {
					t.Fatal(err)
				}
			}
			session := "late-finalize-" + strings.ReplaceAll(name, "/", "-")
			ctx := ContextWithSessionID(withHookPanicCapture(t.Context()), session)
			req := agentHookRequest{ConnectorName: "claudecode", HookEventName: "PreToolUse", SessionID: session, ToolName: "Bash",
				Payload: map[string]interface{}{"tool_name": "Bash"}}
			allow := agentHookResponse{Action: "allow", RawAction: "allow", Severity: "NONE", Mode: "action", EvaluationID: "eval-" + session}
			// Delivered, so a failed audit write keeps the allow and the
			// export is the call's only record.
			finalization := f.api.finalizeAgentHookAnswer(ctx, "claudecode", req, allow, nil, preToolUseBody(t, session+"-tool"), time.Millisecond, false, nil, true)
			if tc.section != "" && !hookPanicRecovered(ctx) {
				t.Fatalf("the %s panic was not recovered on the hook's panic capture", tc.section)
			}
			if tc.want == "" {
				if finalization.AuditPersisted {
					t.Fatal("audit row persisted, want no row")
				}
			} else {
				row := soleHookDecisionForTest(t, f.store)
				if got := row.Structured["result"]; got != tc.want || row.Structured["action"] != "allow" {
					t.Fatalf("audit=%+v, want allow with result=%s", row.Structured, tc.want)
				}
			}
			waitForHookDecisions(t, f, tc.export)
			if wantPanic := strings.HasSuffix(tc.export, "/panic"); finalization.Panicked != wantPanic {
				t.Fatalf("finalization.Panicked=%t, want %t: the span must carry the row and export result", finalization.Panicked, wantPanic)
			}
		})
	}
}
