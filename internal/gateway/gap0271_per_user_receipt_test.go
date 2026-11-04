// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// A per-user tool call is recorded from the answer the hook confirmed.
func TestGAP0271PerUserReceiptRecordsDeliveredDecision(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	f.api.scannerCfg.DeploymentMode = "per_user"
	f.offer(t, "per-user-confirmed", hookexec.HookDeliveryReceiptAck)
	body := managedHookBody("per-user-released", "PreToolUse")
	request := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook",
		strings.NewReader(body+hookexec.HookDeliveryReleased))
	request.Header.Set(hookexec.HookDeliveryReceiptHeader, "1")
	request.Header.Set(hookexec.HookDeliveryPayloadBytesHeader, strconv.Itoa(len(body)))
	reply := &recordFullDuplexStatusWriter{ResponseRecorder: httptest.NewRecorder()}
	f.api.handleAgentHook("claudecode").ServeHTTP(reply, request)
	if reply.finalStatus != http.StatusOK {
		t.Fatalf("released answer status=%d", reply.finalStatus)
	}
	if got := f.audited(t, "per-user-confirmed")["per-user-confirmed"]; got != "allow" {
		t.Fatalf("confirmed per-user decision = %q, want allow", got)
	}
	if got := f.audited(t, "per-user-released")["per-user-released"]; got != "unconfirmed/no_answer" {
		t.Fatalf("unreceipted per-user decision = %q, want unconfirmed/no_answer", got)
	}
	if got := f.decisions(t); len(got) != 2 || got[0] != "allow/ok" || got[1] != "unconfirmed/ok" {
		t.Fatalf("per-user event history = %v", got)
	}
}

func TestGAP0271PerUserOnTimeBenignCallStaysAllowed(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	f.api.scannerCfg.DeploymentMode = "per_user"
	request := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook",
		strings.NewReader(managedHookBody("per-user-benign", "PreToolUse")))
	reply := httptest.NewRecorder()
	f.api.handleAgentHook("claudecode").ServeHTTP(reply, request)
	if reply.Code != http.StatusOK || !strings.Contains(reply.Body.String(), `"action":"allow"`) {
		t.Fatalf("benign answer status=%d body=%q", reply.Code, reply.Body.String())
	}
}
