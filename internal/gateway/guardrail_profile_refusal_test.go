// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// refusalNativeActionOracle is the answer a profile refusal may give on an
// event that is not a lifecycle event, from the capability matrix: a block
// only where the event's native control carries one. Unlike a recovered
// panic (panicNativeActionOracle), a refusal follows the resolved contract on
// Claude Code's PostToolBatch.
func refusalNativeActionOracle(name, event string, profile connector.HookProfile) string {
	if name == "claudecode" && event == "PostToolBatch" {
		if profile.Capabilities.CanBlock && eventIn(event, profile.Capabilities.BlockEvents) {
			return "block"
		}
		return "allow"
	}
	return panicNativeActionOracle(name, event, profile)
}

// Review of Port-0440 loop round 3 (P2): a profile decision that needs an
// unproven identity fact answered block on every event, whatever the event's
// native control. Antigravity PostToolUse answers {} and was audited
// enforced, Cursor's stop rendered a followup_message that starts another
// turn, and Claude Code's Stop decision:block keeps the agent running. For
// every registered connector and event, with a healthy and with a panicking
// connector renderer, the refusal takes the event's native control: a block
// with the healthy native denial where the hook can deny, the advisory allow
// with would_block and no denial where it cannot, and on a stop, session-end
// or idle event the neutral allow, which neither denies nor asks for another
// turn. The audit row is enforced only for the block.
func TestProfileRefusalTakesTheEventsNativeControl(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
	const why = "the user's group membership is unconfirmed"
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.DeploymentMode, cfg.Enterprise.Profile = managed.DeploymentModeManagedEnterprise, managed.ProfileStandalone
	cfg.Guardrail.Mode, cfg.Guardrail.HookFailMode = "action", "closed"
	profiles := panicTestProfiles(t, &APIServer{scannerCfg: cfg})
	seen := map[string]bool{}
	for name, healthy := range profiles {
		store, logger := testStoreAndLogger(t)
		api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
		set := &guardrailProfileSet{}
		api.guardrailProfiles.set.Store(set)
		for _, event := range healthy.SupportedEvents {
			lifecycle := hookexec.LifecycleEvent(name, event)
			want := "allow"
			if !lifecycle {
				want = refusalNativeActionOracle(name, event, healthy)
			}
			for _, renderPanics := range []bool{false, true} {
				if renderPanics && (name == "claudecode" || name == "codex") {
					// Rendered by the gateway's callback-free renderers.
					continue
				}
				cell := name + "/" + event
				profile := healthy
				panicked := false
				if renderPanics {
					cell += "/render-panic"
					profile.Respond = func(connector.HookRespondInput) connector.HookRespondOutput {
						panicked = true
						panic("injected refusal render panic")
					}
				}
				session := "refusal-" + name + "-" + event
				if renderPanics {
					session += "-render-panic"
				}
				req := agentHookRequest{ConnectorName: name, HookEventName: event, ToolName: "Bash", SessionID: session}
				ctx := withHookPanicCapture(ContextWithSessionID(t.Context(), session))
				refusedCtx := context.WithValue(ctx, resolvedGuardrailProfileKey{}, &resolvedGuardrailProfile{
					decision: profileDecision{Refused: why}, set: set,
				})
				resp, refused := api.refuseProfileHook(refusedCtx, profile, name, req, nil, nil)
				if !refused {
					t.Fatalf("%s: the hook was not refused", cell)
				}
				seen[cell] = true
				if resp.Action != want || resp.RawAction != "block" || resp.WouldBlock != (want == "allow") ||
					resp.Mode != "action" || resp.Reason != why || hookSourceReason(resp) != why {
					t.Errorf("%s: refusal=%+v, want %s raw block would_block=%t with the refusal reason", cell, resp, want, want == "allow")
					continue
				}
				if renderPanics && !lifecycle && !panicked {
					t.Errorf("%s: the connector renderer was never called", cell)
					continue
				}
				switch {
				case lifecycle:
					if lifecycleAnswerRepeats(resp.HookOutput) {
						t.Errorf("%s: lifecycle refusal output=%v denies or asks for another turn", cell, resp.HookOutput)
						continue
					}
				case want == "allow":
					if panicWireDenies(resp.HookOutput) {
						t.Errorf("%s: advisory refusal output=%v carries a native denial", cell, resp.HookOutput)
						continue
					}
				default:
					// A healthy block of the event, rendered the same way. Some
					// blocks carry no output (Amp's tool calls, Claude Code's
					// task events): the hook runner denies from the action.
					reference := api.renderSandboxVerdict(t.Context(), healthy, req, nil, nil,
						agentHookResponse{Action: want, RawAction: "block", Severity: "HIGH", Mode: "action"}, why)
					if got, wantShape := nativeControlShape(t, resp.HookOutput), nativeControlShape(t, reference.HookOutput); !reflect.DeepEqual(got, wantShape) {
						t.Errorf("%s: refusal output=%v, want the healthy %s control %v", cell, got, want, wantShape)
						continue
					}
				}
				if renderPanics {
					continue
				}
				api.finalizeAgentHook(ctx, name, req, resp, nil, []byte(`{}`), 0, false, nil)
				row, ok := newestConnectorHookRow(t, store)
				if !ok || row.Target != event || row.Connector != name {
					t.Errorf("%s: newest hook decision row=%+v, want this call's", cell, row)
					continue
				}
				if row.Structured["action"] != want || row.Enforced != (want == "block") || row.Structured["would_block"] != (want == "allow") ||
					row.Structured["result"] != "ok" {
					t.Errorf("%s: audit=%+v enforced=%t, want the refusal's %s, enforced=%t", cell, row.Structured, row.Enforced, want, want == "block")
				}
			}
		}
	}
	// The reported cells, and a cell of each answer kind, ran.
	for _, cell := range []string{
		"antigravity/PostToolUse", "antigravity/PostToolUse/render-panic",
		"cursor/stop", "cursor/stop/render-panic",
		"claudecode/Stop", "claudecode/PreToolUse",
		"cursor/beforeShellExecution/render-panic", "hermes/pre_tool_call",
	} {
		if !seen[cell] {
			t.Errorf("cell %s did not run", cell)
		}
	}
}

// newestConnectorHookRow is store's newest connector-hook row: the row of the
// call finalized last, as the calls of a store are finalized one at a time.
func newestConnectorHookRow(t *testing.T, store *audit.Store) (audit.Event, bool) {
	t.Helper()
	events, err := store.ListEvents(8)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Action == string(audit.ActionConnectorHook) {
			return event, true
		}
	}
	return audit.Event{}, false
}
