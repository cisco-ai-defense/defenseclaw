// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// serveShedOnSocket runs a hook call through the hook socket's
// authentication as peer uid 1004. A call the limits admit reaches next, which
// answers 200; the response is returned.
func serveShedOnSocket(f managedHookAuditFixture, authorizer *managedHookAuthorizer, body string) *httptest.ResponseRecorder {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	r := httptest.NewRequest(http.MethodPost, goneHookPath, strings.NewReader(body))
	reply := httptest.NewRecorder()
	f.api.managedHookPeerAuth(authorizer, next).ServeHTTP(reply,
		r.WithContext(withManagedHookPeer(r.Context(), managedHookPeer{UID: 1004, Name: "shed-alice"})))
	return reply
}

func shedRows(t *testing.T, f managedHookAuditFixture, session string) []audit.Event {
	t.Helper()
	events, err := f.store.ListEvents(1000)
	if err != nil {
		t.Fatal(err)
	}
	var rows []audit.Event
	for _, event := range events {
		if event.Action == string(audit.ActionConnectorHook) && event.SessionID == session {
			rows = append(rows, event)
		}
	}
	return rows
}

// GAP-1029: a managed hook call the admission limits refuse with a 429 is
// answered by the hook itself once its retry budget ends, and the gateway
// decides nothing. The refused call still gets one audit row: unconfirmed,
// labeled shed, under its tool id, however often the hook sends it again.
func TestManagedHookCallShedWith429IsAuditedUnconfirmedUnderItsToolID(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	f.api.hookCallerLimits = hookCallerLimiter{rate: 1, burst: 1}
	if reply := serveShedOnSocket(f, machinePolicyAuthorizer(), managedHookBody("shed-first", "PreToolUse")); reply.Code != http.StatusOK {
		t.Fatalf("the first call was refused: %d", reply.Code)
	}
	for attempt := 0; attempt < 3; attempt++ {
		reply := serveShedOnSocket(f, machinePolicyAuthorizer(), managedHookBody("shed-a", "PreToolUse"))
		if reply.Code != http.StatusTooManyRequests || !strings.Contains(reply.Body.String(), "rate_limited") {
			t.Fatalf("attempt %d: status %d body %q, want the 429 refusal", attempt, reply.Code, reply.Body.String())
		}
	}
	rows := shedRows(t, f, "shed-a")
	if len(rows) != 1 {
		t.Fatalf("rows for the shed call = %d, want one for its three sends", len(rows))
	}
	if rows[0].ToolID != "shed-a-tool" || !strings.Contains(rows[0].Details, "hook_shed") {
		t.Fatalf("shed row: tool id %q, details %q", rows[0].ToolID, rows[0].Details)
	}
	if got := f.audited(t, "shed-a")["shed-a"]; got != "unconfirmed/no_answer" {
		t.Fatalf("shed call audited = %q, want unconfirmed/no_answer", got)
	}
	if got := goneRowUsers(t, f, "shed-a"); len(got) != 1 || got[0] != "1004" {
		t.Fatalf("row users = %v, want the verified peer [1004]", got)
	}
	// A second call is a second row.
	serveShedOnSocket(f, machinePolicyAuthorizer(), managedHookBody("shed-b", "PreToolUse"))
	if rows := shedRows(t, f, "shed-b"); len(rows) != 1 || rows[0].ToolID != "shed-b-tool" {
		t.Fatalf("second shed call rows = %v, want one under its own tool id", rows)
	}
}

// The control: a call the limits admit is served, not recorded as shed, and a
// shed call the socket would not have served (unenrolled account, exempt
// account) or a neutral lifecycle event gets no row.
func TestManagedHookCallShedWith429IsAuditedOnlyWhenTheSocketWouldServeIt(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	f.api.hookCallerLimits = hookCallerLimiter{rate: 1, burst: 1}
	if reply := serveShedOnSocket(f, machinePolicyAuthorizer(), managedHookBody("shed-ok", "PreToolUse")); reply.Code != http.StatusOK {
		t.Fatalf("the admitted call was refused: %d", reply.Code)
	}
	if rows := shedRows(t, f, "shed-ok"); len(rows) != 0 {
		t.Fatalf("an admitted call got %d shed rows", len(rows))
	}
	for _, tc := range []struct {
		name       string
		authorizer *managedHookAuthorizer
		body       string
	}{
		{"unenrolled", newManagedHookAuthorizer(config.EnterpriseEnrollmentConfig{}, nil, nil), managedHookBody("shed-unenrolled", "PreToolUse")},
		{"exempt", newManagedHookAuthorizer(config.EnterpriseEnrollmentConfig{ExemptUsers: []string{"1004"}}, []string{"claudecode"}, nil), managedHookBody("shed-exempt", "PreToolUse")},
		{"lifecycle", machinePolicyAuthorizer(), `{"hook_event_name":"Stop","session_id":"shed-stop","cwd":"/tmp"}`},
	} {
		session := strings.TrimPrefix(strings.Split(strings.Split(tc.body, `"session_id":"`)[1], `"`)[0], "")
		if reply := serveShedOnSocket(f, tc.authorizer, tc.body); reply.Code != http.StatusTooManyRequests {
			t.Fatalf("%s: status %d, want the 429", tc.name, reply.Code)
		}
		if rows := shedRows(t, f, session); len(rows) != 0 {
			t.Fatalf("%s: a call the socket would not have served got %d rows", tc.name, len(rows))
		}
	}
}
