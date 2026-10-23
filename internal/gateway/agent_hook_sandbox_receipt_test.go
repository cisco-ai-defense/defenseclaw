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
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// GAP-0875: a buffered sandbox relay cannot send a full-duplex request-body
// receipt. Its successful Claude and Codex tool calls must get an explicit
// receipt before the gateway commits the final allow audit row.
func TestManagedSandboxToolAllowWaitsForItsRelayedReceipt(t *testing.T) {
	for _, connectorName := range []string{"claudecode", "codex"} {
		t.Run(connectorName, func(t *testing.T) {
			f := newManagedHookAuditFixtureFor(t, connectorName, nil)
			binding := sandboxauth.Binding{
				ID: "sb_0875_own", SandboxName: "own-sandbox", Connector: connectorName,
				Routes: []sandboxauth.Route{sandboxauth.RouteHook},
			}
			if connectorName == "codex" {
				binding.HookContractID = "codex-hooks-v1"
			}
			var decisionSink *sandboxRelayDecisionSink
			post := func(from sandboxauth.Binding, body string) *httptest.ResponseRecorder {
				t.Helper()
				ctx := sandboxauth.WithRequest(t.Context(), from, nil)
				ctx = withSandboxIngressRoute(ctx, sandboxauth.RouteHook)
				if _, receipt := sandboxHookReceiptID([]byte(body)); receipt {
					decisionSink = &sandboxRelayDecisionSink{}
					ctx = context.WithValue(ctx, sandboxRelayStateKey{}, &sandboxRelayState{sink: decisionSink})
				}
				request := httptest.NewRequest(http.MethodPost, "/api/v1/"+connectorName+"/hook", strings.NewReader(body)).WithContext(ctx)
				request.Header.Set("Content-Type", "application/json")
				if connectorName == "codex" {
					if _, receipt := sandboxHookReceiptID([]byte(body)); !receipt {
						request.Header.Set("X-DefenseClaw-Hook-Event", "PreToolUse")
						request.Header.Set("X-DefenseClaw-Hook-Contract", binding.HookContractID)
					}
				}
				reply := httptest.NewRecorder()
				f.api.handleAgentHook(connectorName).ServeHTTP(reply, request)
				return reply
			}
			const session = "steady-relayed-tool"
			reply := post(binding, managedHookBody(session, "PreToolUse"))
			if reply.Code != http.StatusOK {
				t.Fatalf("proposal status = %d: %s", reply.Code, reply.Body.String())
			}
			var proposal struct {
				Action          string `json:"action"`
				DeliveryReceipt string `json:"delivery_receipt"`
			}
			if err := json.Unmarshal(reply.Body.Bytes(), &proposal); err != nil {
				t.Fatal(err)
			}
			if proposal.Action != "allow" || proposal.DeliveryReceipt == "" {
				t.Fatalf("proposal = %+v, want allow and receipt id", proposal)
			}
			entry, present, err := f.store.HookDelivery(t.Context(), proposal.DeliveryReceipt)
			if err != nil || !present {
				t.Fatalf("journaled proposal = %+v: %v", entry, err)
			}
			var pending pendingHookOccurrence
			if err := json.Unmarshal(entry.Occurrence, &pending); err != nil || pending.SandboxReceipt == nil || pending.SandboxReceipt.CallRef == "" {
				t.Fatalf("pending relay reference = %+v: %v", pending, err)
			}
			callRef := pending.SandboxReceipt.CallRef
			if got := f.audited(t, session)[session]; got != "" {
				t.Fatalf("audit before receipt = %q, want no final verdict", got)
			}
			ack, _ := json.Marshal(map[string]string{"delivery_receipt": proposal.DeliveryReceipt, "result": "ack"})
			foreign := binding
			foreign.ID = "sb_0875_other"
			if got := post(foreign, string(ack)).Code; got != http.StatusForbidden {
				t.Fatalf("another sandbox's receipt status = %d, want forbidden", got)
			}
			if got := f.audited(t, session)[session]; got != "" {
				t.Fatalf("audit after foreign receipt = %q, want none", got)
			}
			if got := post(binding, string(ack)).Code; got != http.StatusOK {
				t.Fatalf("acknowledgement status = %d, want ok", got)
			}
			trailer, ok := decisionSink.trailer()
			decision := sandboxrelay.ParseHookDecision(trailer)
			if !ok || decision == nil || decision.Action != "allow" || decision.CallRef != callRef {
				t.Fatalf("relay decision trailer = %q, want allow with the original call reference", trailer)
			}
			if got := f.audited(t, session)[session]; got != "allow" {
				t.Fatalf("audited final verdict = %q, want allow", got)
			}
			rows, err := f.store.ListEvents(200)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, row := range rows {
				if row.SessionID != session || row.Action != string(audit.ActionConnectorHook) {
					continue
				}
				found = true
				for _, field := range []string{"action=allow", "raw_action=allow", "severity=NONE", "mode=action", "sandbox_binding_id"} {
					if !strings.Contains(row.Details, field) {
						t.Fatalf("receipt audit lacks %s: %s", field, row.Details)
					}
				}
			}
			if !found {
				t.Fatal("confirmed sandbox hook has no audit row")
			}
			if got := post(binding, string(ack)).Code; got != http.StatusOK {
				t.Fatalf("replayed acknowledgement status = %d, want the same accepted receipt", got)
			}

			// An older sandbox image never sends the new acknowledgement.
			// Once its bounded window ends, recovery records uncertainty
			// instead of claiming that its proposed allow was delivered.
			const missing = "relayed-without-receipt"
			unacknowledged := post(binding, managedHookBody(missing, "PreToolUse"))
			var late struct {
				DeliveryReceipt string `json:"delivery_receipt"`
			}
			if err := json.Unmarshal(unacknowledged.Body.Bytes(), &late); err != nil || late.DeliveryReceipt == "" {
				t.Fatalf("unacknowledged proposal = %q: %v", unacknowledged.Body.String(), err)
			}
			entry, present, err = f.store.HookDelivery(t.Context(), late.DeliveryReceipt)
			if err != nil || !present {
				t.Fatalf("unacknowledged journal = %+v: %v", entry, err)
			}
			if err := json.Unmarshal(entry.Occurrence, &pending); err != nil {
				t.Fatal(err)
			}
			pending.SandboxReceipt.OfferedAt = time.Now().Add(-time.Minute)
			entry.Occurrence, err = json.Marshal(&pending)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.store.UpdateHookDelivery(t.Context(), pending.ID, entry.Occurrence); err != nil {
				t.Fatal(err)
			}
			if err := f.api.recoverPendingHook(t.Context(), entry); err != nil {
				t.Fatal(err)
			}
			if got := f.audited(t, missing)[missing]; got != "unconfirmed/no_answer" {
				t.Fatalf("unacknowledged verdict = %q, want unconfirmed/no_answer", got)
			}
		})
	}
}
