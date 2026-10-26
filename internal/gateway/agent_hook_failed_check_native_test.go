// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// panicNativeActionOracle is the closed answer a recovered panic may give on
// an event that is not a lifecycle event: a block only where the event's
// certified native control can carry one.
func panicNativeActionOracle(name, event string, profile connector.HookProfile) string {
	switch {
	case name == "hermes" && event == "pre_verify":
		// Hermes' documented bounded verification control.
		return "continue"
	case name == "claudecode" && event == "PostToolBatch":
		// GAP-0440: Claude Code blocks continuation on PostToolBatch.
		return "block"
	case profile.Capabilities.CanBlock && eventIn(event, profile.Capabilities.BlockEvents):
		return "block"
	}
	return "allow"
}

// Review of Port-0440 loop round 1 (P2): a closed evaluator panic on an
// advisory event answered block and was audited enforced, while the event's
// native answer carried no denial (Antigravity PostToolUse answers {}, Cursor
// afterFileEdit only observes). Every registered connector and event: the
// panic's effective action follows the event's native control, the raw intent
// stays block, and an allow never carries a denial or a "was blocked" text.
func TestHookEvaluatorPanicActionFollowsNativeControl(t *testing.T) {
	api := &APIServer{}
	profiles := panicTestProfiles(t, api)
	panicking := hookProfileRuntime{Evaluate: func(*APIServer, context.Context, agentHookRequest, []byte, map[string]interface{}) agentHookResponse {
		panic("injected evaluator error")
	}}
	advisory := 0
	for name, profile := range profiles {
		for _, event := range profile.SupportedEvents {
			if hookexec.LifecycleEvent(name, event) {
				continue
			}
			want := panicNativeActionOracle(name, event, profile)
			if want == "allow" {
				advisory++
			}
			for _, deployment := range []struct{ name, mode, profile string }{
				{"per-user", "", ""},
				{"standalone", managed.DeploymentModeManagedEnterprise, managed.ProfileStandalone},
			} {
				for _, mode := range []string{"observe", "action"} {
					t.Run(name+"/"+event+"/"+deployment.name+"/"+mode, func(t *testing.T) {
						cfg := config.DefaultConfig()
						cfg.DeploymentMode, cfg.Enterprise.Profile = deployment.mode, deployment.profile
						cfg.Guardrail.Mode, cfg.Guardrail.HookFailMode = mode, "closed"
						server := &APIServer{scannerCfg: cfg}
						req := agentHookRequest{ConnectorName: name, HookEventName: event}
						resp, panicked := server.safeEvaluateHook(t.Context(), name, req, nil, nil, panicking)
						if !panicked || resp.RawAction != "block" || resp.Mode != "action" {
							t.Fatalf("panic response=%+v panicked=%v, want raw block in action mode", resp, panicked)
						}
						if resp.Action != want {
							t.Fatalf("panic action=%q, want %q (native control of %s/%s); response=%+v", resp.Action, want, name, event, resp)
						}
						if want != "allow" {
							// A block, or Hermes' bounded verification
							// control: neither is a would-block.
							if resp.WouldBlock {
								t.Fatalf("native control %s carries would_block: %+v", want, resp)
							}
							return
						}
						if !resp.WouldBlock || panicWireDenies(resp.HookOutput) {
							t.Fatalf("advisory panic=%+v, want would_block without a native denial", resp)
						}
						for _, text := range []string{resp.Reason, resp.AdditionalContext, mustJSONForTest(t, resp.HookOutput)} {
							if strings.Contains(text, "was blocked") {
								t.Fatalf("advisory panic says it blocked: %q", text)
							}
						}
					})
				}
			}
		}
	}
	if advisory < 20 {
		t.Fatalf("advisory events covered=%d, want the registered advisory events", advisory)
	}
}

func mustJSONForTest(t *testing.T, value interface{}) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// The HTTP answer and the audit row of an advisory-event panic agree with the
// native hook: an unenforced allow with would_block. A certified block event
// keeps the enforced block with a native denial.
func TestAdvisoryEvaluatorPanicAuditMatchesNativeControl(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
	for _, tc := range []struct {
		connector, event string
		enforced         bool
	}{
		{"antigravity", "PostToolUse", false},
		{"antigravity", "PreInvocation", false},
		{"cursor", "afterFileEdit", false},
		{"cursor", "afterShellExecution", false},
		{"claudecode", "PostToolUse", false},
		{"claudecode", "Notification", false},
		{"copilot", "postToolUse", false},
		{"devin", "PostToolUse", false},
		{"antigravity", "PreToolUse", true},
		{"cursor", "beforeShellExecution", true},
		{"claudecode", "PreToolUse", true},
	} {
		for _, deployment := range []struct{ name, mode, profile string }{
			{"per-user", "", ""},
			{"standalone", managed.DeploymentModeManagedEnterprise, managed.ProfileStandalone},
		} {
			t.Run(tc.connector+"/"+tc.event+"/"+deployment.name, func(t *testing.T) {
				injectPanicForProfile(t, tc.connector)
				store, logger := testStoreAndLogger(t)
				cfg := config.DefaultConfig()
				cfg.DataDir = t.TempDir()
				cfg.DeploymentMode, cfg.Enterprise.Profile = deployment.mode, deployment.profile
				cfg.Guardrail.Mode, cfg.Guardrail.HookFailMode, cfg.Guardrail.Connector = "action", "closed", tc.connector
				server := &APIServer{scannerCfg: cfg, store: store, logger: logger}
				response, _ := postPanicTestHook(t, server, tc.connector, tc.event)
				output := panicTestOutput(tc.connector, response)
				row := soleHookDecisionForTest(t, store)
				if row.Structured["result"] != "panic" || response["raw_action"] != "block" {
					t.Fatalf("response=%v audit=%+v, want a raw-block panic row", response, row.Structured)
				}
				if tc.enforced {
					if response["action"] != "block" || !panicWireDenies(output) || row.Structured["action"] != "block" || !row.Enforced {
						t.Fatalf("response=%v audit=%+v, want an enforced native denial", response, row)
					}
					return
				}
				if response["action"] != "allow" || response["would_block"] != true || panicWireDenies(output) {
					t.Fatalf("response=%v, want the advisory allow with would_block and no native denial", response)
				}
				if row.Structured["action"] != "allow" || row.Structured["would_block"] != true || row.Enforced {
					t.Fatalf("audit=%+v, want an unenforced allow with would_block", row)
				}
			})
		}
	}
}

// Review of Port-0440 loop round 1 (P2): in an OpenShell sandbox a healthy
// Stop that allowed termination was turned into the sandbox's closed block
// when its audit write failed, and the agent ran the Stop hook again: a
// persistent audit failure looped. Every connector's lifecycle events, three
// callbacks in a row: the allow stands, and the sandbox records it.
func TestSandboxLifecycleAuditFailureNeverRepeatsTheHook(t *testing.T) {
	fixture := newAuditFailureHookFixture(t, "")
	fixture.emitter.fail = true
	covered := 0
	for _, name := range []string{"antigravity", "claudecode", "codex", "copilot", "cursor", "devin", "kiro", "opencode"} {
		for _, event := range hookexec.LifecycleEvents(name) {
			covered++
			t.Run(name+"/"+event, func(t *testing.T) {
				for callback := 1; callback <= 3; callback++ {
					sink := &sandboxRelayDecisionSink{}
					ctx := sandboxauth.WithRequest(t.Context(), sandboxauth.Binding{ID: "binding-" + name, SandboxName: "sbx", Connector: name}, nil)
					ctx = context.WithValue(ctx, sandboxRelayStateKey{}, &sandboxRelayState{sink: sink})
					req := agentHookRequest{ConnectorName: name, HookEventName: event, SessionID: "s-sbx-" + name}
					allow := agentHookResponse{Action: "allow", RawAction: "allow", Mode: "action", EvaluationID: "eval-stop"}
					result := fixture.api.finalizeAgentHook(ctx, name, req, allow, nil, []byte(`{}`), time.Millisecond, false, nil)
					if result.AuditFailedClosed || result.Response.Action != "allow" || result.Enforced {
						t.Fatalf("callback %d: %s/%s with a failed audit write: %+v, want the allow kept", callback, name, event, result)
					}
					if raw, ok := sink.trailer(); ok {
						if decision := sandboxrelay.ParseHookDecision(raw); decision != nil && decision.Action == "block" {
							t.Fatalf("callback %d: sandbox recorded %q, want the allow the agent got", callback, raw)
						}
					}
				}
			})
		}
	}
	if covered < 10 {
		t.Fatalf("lifecycle events covered=%d", covered)
	}
}

// Review of Port-0440 loop round 1 (P2): a standalone managed hook received
// and acknowledged an allow; the audit write failed afterwards and the
// gateway exported, counted and deduplicated a block the agent never got. A
// delivered answer is the recorded outcome.
func TestDeliveredManagedAllowSurvivesAFailedAuditWrite(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	database, err := sql.Open("sqlite", f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.Exec(`CREATE TRIGGER zz_audit_disk_full BEFORE INSERT ON audit_events
		WHEN NEW.action = 'connector-hook' BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END`); err != nil {
		t.Fatal(err)
	}
	f.offer(t, "delivered-audit-full", hookexec.HookDeliveryReceiptAck)
	deadline := time.Now().Add(10 * time.Second)
	for len(f.decisions(t)) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no hook_decision record for the delivered call")
		}
		time.Sleep(25 * time.Millisecond)
	}
	if got := strings.Join(f.decisions(t), ","); got != "allow/ok" {
		t.Fatalf("hook_decision records = %s, want the delivered allow/ok", got)
	}
	if blocks := f.api.health.statsFor("claudecode").toolBlocks.Load(); blocks != 0 {
		t.Fatalf("status tool blocks = %d, want 0 for a delivered allow", blocks)
	}
}

// finalizeAgentHookAnswer keeps a delivered verdict whatever the audit store
// does: the response, the enforced flag and the dedupe record it feeds stay
// the delivered allow. An undelivered allow still fails closed.
func TestFinalizeDeliveredAnswerKeepsItsVerdict(t *testing.T) {
	fixture := newAuditFailureHookFixture(t, "")
	fixture.emitter.fail = true
	req := agentHookRequest{ConnectorName: "claudecode", HookEventName: "PreToolUse", SessionID: "s-delivered", ToolName: "Bash",
		Payload: map[string]interface{}{"tool_name": "Bash"}}
	allow := agentHookResponse{Action: "allow", RawAction: "allow", Mode: "action", EvaluationID: "eval-delivered"}
	delivered := fixture.api.finalizeAgentHookAnswer(t.Context(), "claudecode", req, allow, nil, preToolUseBody(t, "toolu-delivered"), time.Millisecond, false, nil, true)
	if delivered.AuditFailedClosed || delivered.Response.Action != "allow" || delivered.Enforced || delivered.AuditPersisted {
		t.Fatalf("delivered allow with a failed audit write: %+v", delivered)
	}
	undelivered := fixture.api.finalizeAgentHookAnswer(t.Context(), "claudecode", req, allow, nil, preToolUseBody(t, "toolu-undelivered"), time.Millisecond, false, nil, false)
	if !undelivered.AuditFailedClosed || undelivered.Response.Action != "block" {
		t.Fatalf("undelivered allow with a failed audit write: %+v, want the fail-closed block", undelivered)
	}
}
