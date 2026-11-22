// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// GAP-0742 N3: an expired sandbox receipt is counted as load only for a
// proposal this process offered whose receipt the store did not refuse. A
// row recovered after a gateway restart and a receipt refused for a full
// disk are a crash and a store problem, not load. The verdict recovery pins
// is the same in every case.
func TestSandboxReceiptExpiryCountsOnlyLoad(t *testing.T) {
	f := newManagedHookAuditFixtureFor(t, "claudecode", nil)
	withHookCapacity(t, time.Now())
	binding := sandboxauth.Binding{ID: "sb_0742_n3", SandboxName: "n3-sandbox", Connector: "claudecode",
		Routes: []sandboxauth.Route{sandboxauth.RouteHook}}
	post := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		ctx := sandboxauth.WithRequest(t.Context(), binding, nil)
		ctx = withSandboxIngressRoute(ctx, sandboxauth.RouteHook)
		_, receipt, _ := classifySandboxHookReceiptBody([]byte(body))
		if receipt {
			ctx = context.WithValue(ctx, sandboxRelayStateKey{}, &sandboxRelayState{sink: &sandboxRelayDecisionSink{}})
		}
		request := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", strings.NewReader(body)).WithContext(ctx)
		request.Header.Set("Content-Type", "application/json")
		if receipt {
			request.Header.Set(sandboxrelay.HookReceiptHeader, sandboxrelay.HookReceiptHeaderValue)
		}
		reply := httptest.NewRecorder()
		f.api.handleAgentHook("claudecode").ServeHTTP(reply, request)
		return reply
	}
	propose := func(session string) (audit.HookDeliveryJournalEntry, pendingHookOccurrence) {
		t.Helper()
		reply := post(managedHookBody(session, "PreToolUse"))
		var proposal struct {
			DeliveryReceipt string `json:"delivery_receipt"`
		}
		if err := json.Unmarshal(reply.Body.Bytes(), &proposal); err != nil || proposal.DeliveryReceipt == "" {
			t.Fatalf("proposal %s = %d %q: %v", session, reply.Code, reply.Body.String(), err)
		}
		entry, present, err := f.store.HookDelivery(t.Context(), proposal.DeliveryReceipt)
		var p pendingHookOccurrence
		if err != nil || !present || json.Unmarshal(entry.Occurrence, &p) != nil || p.SandboxReceipt == nil {
			t.Fatalf("journaled proposal %s = %+v: %v", session, entry, err)
		}
		return entry, p
	}
	expireAndRecover := func(session string, entry audit.HookDeliveryJournalEntry) {
		t.Helper()
		var p pendingHookOccurrence
		if err := json.Unmarshal(entry.Occurrence, &p); err != nil {
			t.Fatal(err)
		}
		p.SandboxReceipt.OfferedAt = time.Now().Add(-time.Minute)
		data, err := json.Marshal(&p)
		if err != nil {
			t.Fatal(err)
		}
		if stored, err := f.store.UpdateHookDelivery(t.Context(), p.ID, data, pendingHookJournalLimits); err != nil || !stored {
			t.Fatalf("expire %s = %t: %v", session, stored, err)
		}
		entry.Occurrence = data
		if err := f.api.recoverPendingHook(t.Context(), entry); err != nil {
			t.Fatal(err)
		}
		if got := f.audited(t, session)[session]; got != "unconfirmed/no_answer" {
			t.Fatalf("%s audited %q, want unconfirmed/no_answer", session, got)
		}
	}
	window := func(want HookCapacityCounts, after string) {
		t.Helper()
		if got := hookCapacity.snapshot().Window; got != want {
			t.Errorf("after %s: window = %+v, want %+v", after, got, want)
		}
	}

	// Control: a proposal this process offered whose receipt never came.
	entry, _ := propose("n3-load")
	expireAndRecover("n3-load", entry)
	window(HookCapacityCounts{DeadlineDenies: 1}, "an expired receipt")

	// A row an earlier gateway process journaled, recovered after a restart.
	entry, p := propose("n3-restart")
	if err := f.api.forgetPendingHook(t.Context(), p.ID); err != nil {
		t.Fatal(err)
	}
	p.ID = observability.NewTimeOrderedID()
	data, err := json.Marshal(&p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.JournalHookDelivery(t.Context(), p.ID, "an-earlier-gateway-process", data, pendingHookJournalLimits); err != nil {
		t.Fatal(err)
	}
	entry.ID, entry.Occurrence = p.ID, data
	expireAndRecover("n3-restart", entry)
	window(HookCapacityCounts{DeadlineDenies: 1}, "a row recovered after a restart")

	// The receipt came, but the store refused to record it (a full disk).
	entry, _ = propose("n3-store")
	database, err := sql.Open("sqlite", f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.Exec(`CREATE TRIGGER zz_n3_journal_full BEFORE UPDATE ON hook_delivery_journal
		BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END`); err != nil {
		t.Fatal(err)
	}
	ack, _ := json.Marshal(map[string]string{"delivery_receipt": entry.ID, "result": "ack"})
	reply := post(string(ack))
	if _, err := database.Exec(`DROP TRIGGER zz_n3_journal_full`); err != nil {
		t.Fatal(err)
	}
	if reply.Code != http.StatusServiceUnavailable || !strings.Contains(reply.Body.String(), "hook audit is unavailable") {
		t.Fatalf("receipt on a full store = %d %q, want 503 hook audit is unavailable", reply.Code, reply.Body.String())
	}
	if current, present, err := f.store.HookDelivery(t.Context(), entry.ID); err != nil || !present {
		t.Fatalf("journal row after the refused receipt = %+v: %v", current, err)
	} else {
		entry = current
	}
	expireAndRecover("n3-store", entry)
	window(HookCapacityCounts{DeadlineDenies: 1}, "a receipt the store refused")
}
