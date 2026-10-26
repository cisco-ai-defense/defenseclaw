// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// GAP-0286 (missing-row variant): during a gateway stall the managed hook
// calls queue on the hook socket and their hooks answer no_answer themselves.
// The gateway admits none of them once it runs again, but each still gets
// one audit row: unconfirmed with the no-answer reason, never allow and never
// nothing. The call is still not served.
func TestManagedHookCallWhoseClientLeftBeforeAdmissionIsAuditedUnconfirmed(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	const path = "/api/v1/claude-code/hook"
	for _, tc := range []struct{ name, session, event string }{
		{"PreToolUse", "gone-pre", "PreToolUse"},
		{"UserPromptSubmit", "gone-prompt", "UserPromptSubmit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gone, hangUp := context.WithCancel(t.Context())
			hangUp()
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(managedHookBody(tc.session, tc.event))).WithContext(gone)
			if _, release := f.api.admitHookCaller(httptest.NewRecorder(), r, "1004", path); release != nil {
				t.Fatal("a request whose client had left was admitted")
			}
			if got := f.audited(t, tc.session)[tc.session]; got != "unconfirmed/no_answer" {
				t.Fatalf("audited = %q, want unconfirmed/no_answer", got)
			}
		})
	}
	events, err := f.store.ListEvents(1000)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.Action == string(audit.ActionConnectorHook) && event.SessionID == "gone-pre" {
			found = strings.Contains(event.Details, "gone-pre-tool") && strings.Contains(event.Details, "before_admission")
		}
	}
	if !found {
		t.Fatal("the audit row does not name the call's tool ID")
	}
	if got := f.decisions(t); len(got) != 0 {
		t.Fatalf("hook_decision records = %v, want none for a call that was never evaluated", got)
	}
}

// A neutral lifecycle event (Stop) whose client left gets no row: it is not
// a decision.
func TestNeutralLifecycleCallWhoseClientLeftWritesNoRow(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	const path = "/api/v1/claude-code/hook"
	gone, hangUp := context.WithCancel(t.Context())
	hangUp()
	body := `{"hook_event_name":"Stop","session_id":"gone-start","cwd":"/tmp"}`
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)).WithContext(gone)
	if _, release := f.api.admitHookCaller(httptest.NewRecorder(), r, "1004", path); release != nil {
		t.Fatal("a request whose client had left was admitted")
	}
	if got := f.audited(t, "gone-start"); len(got) != 0 {
		t.Fatalf("neutral lifecycle call audited %v", got)
	}
}
