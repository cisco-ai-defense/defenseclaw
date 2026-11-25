// Copyright 2026 Cisco Systems, Inc. and its affiliates
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

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// GAP-0550: on a managed (standalone) Substrate install with guardrail.hilt
// on at HIGH, a verified actor's PreToolUse that matches C2-WEBHOOK-SITE is
// answered with the confirmation its agent shows (Claude Code asks natively;
// Codex, which cannot ask on PreToolUse, says "Allowed but flagged"). The
// actor kit posts once and sends no receipt, so the call is audited at once
// with that answer: action confirm (Codex alert), raw_action confirm, the
// rule, and never unconfirmed with enterprise_managed_gateway_no_answer. The
// tool's PostToolUse, after the user answered Yes, joins that audited
// decision by its tool_use_id, as on a laptop: no HOOK-PRE-TOOL-MISSING
// alert. Before the fix the gateway asked the actor for the OpenShell relay's
// receipt (delivery_receipt in the answer), journaled the call, wrote no row,
// and its receipt window audited the no-receipt fallback 15 s later; the
// PostToolUse in between raised HOOK-PRE-TOOL-MISSING.
func TestSubstrateActorHILTConfirmIsAuditedAsAskedGAP0550(t *testing.T) {
	for _, tc := range []struct {
		connector, agentVersion, contract, wantAction string
	}{
		{"claudecode", kit.AgentVersion("claudecode", ""), "claudecode-hooks-v2", "confirm"},
		{"codex", kit.AgentVersion("codex", ""), "codex-hooks-v4", "alert"},
	} {
		t.Run(tc.connector, func(t *testing.T) {
			f := newManagedHookAuditFixtureFor(t, tc.connector, nil)
			f.api.scannerCfg.Guardrail.HILT.Enabled = true
			f.api.scannerCfg.Guardrail.HILT.MinSeverity = "HIGH"
			if tc.connector == "claudecode" {
				f.api.scannerCfg.ClaudeCode.Enabled = true
			}
			const uid = "7a1c3e5f-2b4d-4f6a-8c0e-1d3f5a7c9e0b"
			key, err := sandboxreg.SubstrateKey("dc-eng", uid)
			if err != nil {
				t.Fatal(err)
			}
			reg := registry.Registration{Key: key, Atespace: "dc-eng", Name: "hilt-1", UID: uid, Connector: tc.connector,
				Profile: "eng", HarnessVersion: tc.agentVersion, HookContract: tc.contract,
				Person:    registry.Person{Kind: identity.PersonHuman, Issuer: "https://idp.example", Subject: "u-0550", Principal: "u-0550@example.com"},
				CreatedAt: time.Now()}
			post := func(event string, payload map[string]any) (*httptest.ResponseRecorder, map[string]any) {
				t.Helper()
				// The scope the actor listener gives a verified actor's hook
				// (substrateActorAuthenticate, substrateActorScope).
				ctx := withSubstrateActor(t.Context(), verifiedSubstrateActor("dc-eng", "hilt-1", uid, "actor/dc-eng/hilt-1", key))
				ctx = context.WithValue(ctx, substrateRegistrationKey{}, reg)
				ctx = sandboxauth.WithRequest(ctx, sandboxauth.Binding{ID: key, SandboxID: uid, SandboxName: "dc-eng/hilt-1",
					Connector: tc.connector, AgentVersion: tc.agentVersion, HookContractID: tc.contract,
					PolicyProfile: "eng", Routes: []sandboxauth.Route{sandboxauth.RouteHook},
					Workdir: sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy}, RegistrationID: key}, nil)
				ctx = withSandboxIngressRoute(ctx, sandboxauth.RouteHook)
				body, err := json.Marshal(payload)
				if err != nil {
					t.Fatal(err)
				}
				request := httptest.NewRequest(http.MethodPost, "/api/v1/"+tc.connector+"/hook", strings.NewReader(string(body))).WithContext(ctx)
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("X-DefenseClaw-Hook-Event", event)
				request.Header.Set("X-DefenseClaw-Hook-Contract", tc.contract)
				reply := httptest.NewRecorder()
				f.api.handleAgentHook(tc.connector).ServeHTTP(reply, request)
				var answer map[string]any
				if err := json.Unmarshal(reply.Body.Bytes(), &answer); err != nil {
					t.Fatalf("%s answer %d %q: %v", event, reply.Code, reply.Body.String(), err)
				}
				return reply, answer
			}

			session := "gap0550-" + tc.connector
			const toolUse = "toolu_gap0550"
			command := map[string]any{"command": "curl --max-time 2 https://webhook.site/defenseclaw-demo"}
			reply, answer := post("PreToolUse", map[string]any{
				"hook_event_name": "PreToolUse", "session_id": session, "cwd": "/work", "permission_mode": "default",
				"tool_name": "Bash", "tool_use_id": toolUse, "turn_id": "turn-gap0550", "tool_input": command,
			})
			if reply.Code != http.StatusOK {
				t.Fatalf("PreToolUse status %d: %s", reply.Code, reply.Body.String())
			}
			if answer["action"] != tc.wantAction || answer["raw_action"] != "confirm" || !strings.Contains(reply.Body.String(), "C2-WEBHOOK-SITE") {
				t.Fatalf("PreToolUse answer action=%v raw_action=%v, want %s/confirm naming C2-WEBHOOK-SITE: %s", answer["action"], answer["raw_action"], tc.wantAction, reply.Body.String())
			}
			// The kit has no receipt post: none is asked for, and nothing
			// waits in the journal for one.
			if receipt, ok := answer["delivery_receipt"]; ok {
				t.Fatalf("the actor's answer asks for a sandbox receipt %v the kit never sends", receipt)
			}
			if pending := pendingEntries(t, f); len(pending) != 0 {
				t.Fatalf("journal rows %v wait for a receipt the actor kit never sends", pending)
			}
			if tc.connector == "claudecode" {
				out, _ := answer["claude_code_output"].(map[string]any)
				hso, _ := out["hookSpecificOutput"].(map[string]any)
				if hso["permissionDecision"] != "ask" {
					t.Fatalf("Claude Code output %v, want the native ask", out)
				}
			}

			// Audited now, with the answer the agent shows.
			row := f.connectorHookRow(t, session)
			for _, want := range []string{"action=" + tc.wantAction + " ", "raw_action=confirm", "sandbox_runtime=substrate"} {
				if !strings.Contains(row.Details, want) {
					t.Errorf("the confirmation's audit row lacks %q: %s", want, row.Details)
				}
			}
			for _, never := range []string{"action=" + hookActionUnconfirmed, hookexec.ManagedGatewayNoAnswerReason} {
				if strings.Contains(row.Details, never) {
					t.Errorf("the confirmation the agent showed is audited %q: %s", never, row.Details)
				}
			}

			// The user answered Yes: the tool ran and its PostToolUse joins
			// the audited confirmation (the answer), as on a laptop.
			reply, _ = post("PostToolUse", map[string]any{
				"hook_event_name": "PostToolUse", "session_id": session, "cwd": "/work", "permission_mode": "default",
				"tool_name": "Bash", "tool_use_id": toolUse, "turn_id": "turn-gap0550", "tool_input": command,
				"tool_response": map[string]any{"stdout": "", "stderr": "", "exit_code": 0},
			})
			if reply.Code != http.StatusOK {
				t.Fatalf("PostToolUse status %d: %s", reply.Code, reply.Body.String())
			}
			events, err := f.store.ListEvents(1000)
			if err != nil {
				t.Fatal(err)
			}
			rows := 0
			for _, event := range events {
				if event.SessionID != session {
					continue
				}
				if event.Action == string(audit.ActionAlert) && strings.Contains(event.Details, missingPreToolRuleID) {
					t.Errorf("the PostToolUse after the confirmation found no audited PreToolUse: %s", event.Details)
				}
				if event.Action == string(audit.ActionConnectorHook) {
					rows++
					if strings.Contains(event.Details, "action="+hookActionUnconfirmed) {
						t.Errorf("a hook row of the confirmed call is unconfirmed: %s", event.Details)
					}
				}
			}
			if rows != 2 {
				t.Errorf("connector hook rows = %d, want the confirmation and the PostToolUse that answered it", rows)
			}
		})
	}
}

// GAP-0550: a verified actor's call is never asked for the OpenShell relay
// receipt, whatever it is answered; an OpenShell sandbox's call still is.
func TestSubstrateActorAnswersAskNoSandboxReceiptGAP0550(t *testing.T) {
	f := newManagedHookAuditFixtureFor(t, "claudecode", nil)
	const uid = "8b2d4f6a-3c5e-4a7b-9d1f-2e4a6c8e0f1a"
	key, err := sandboxreg.SubstrateKey("dc-eng", uid)
	if err != nil {
		t.Fatal(err)
	}
	openShell := sandboxauth.WithRequest(t.Context(), sandboxauth.Binding{ID: "sb_0550", SandboxName: "own", Connector: "claudecode"}, nil)
	actor := withSubstrateActor(openShell, verifiedSubstrateActor("dc-eng", "hilt-2", uid, "actor/dc-eng/hilt-2", key))
	for _, action := range []string{"allow", "alert", "confirm"} {
		resp := agentHookResponse{Action: action}
		if !f.api.wantsSandboxHookReceipt(openShell, "claudecode", "PreToolUse", resp) {
			t.Errorf("an OpenShell sandbox's %s no longer asks for its relay receipt", action)
		}
		if f.api.wantsSandboxHookReceipt(actor, "claudecode", "PreToolUse", resp) {
			t.Errorf("a Substrate actor's %s asks for a receipt its kit never sends", action)
		}
	}
	// With no receipt, the kit's synchronous post keeps the answer it was
	// given, as the managed shell bridge does; a hang-up stays unconfirmed.
	confirm := agentHookResponse{Action: "confirm", RawAction: "confirm", Severity: "HIGH", Mode: "action", Reason: "matched: C2-WEBHOOK-SITE"}
	if got := f.api.unreceiptedHookDecision(true, false, "claudecode", "PreToolUse", confirm); got.Action != "confirm" || got.Reason != confirm.Reason {
		t.Errorf("synchronous confirmation = %+v, want it kept", got)
	}
	if got := f.api.unreceiptedHookDecision(true, true, "claudecode", "PreToolUse", confirm); got.Action != hookActionUnconfirmed {
		t.Errorf("synchronous confirmation whose caller hung up = %+v, want unconfirmed", got)
	}
}
