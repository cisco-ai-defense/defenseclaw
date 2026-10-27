// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

const goneHookPath = "/api/v1/claude-code/hook"

// goneRequest is a hook call whose client has already hung up. The
// correlation identity is what the X-DefenseClaw-User-* headers claimed
// before authentication; a forging caller sets it to another account.
func goneRequest(t *testing.T, body string, claimed AgentIdentity, headers map[string]string) *http.Request {
	t.Helper()
	gone, hangUp := context.WithCancel(ContextWithAgentIdentity(t.Context(), claimed))
	hangUp()
	r := httptest.NewRequest(http.MethodPost, goneHookPath, strings.NewReader(body)).WithContext(gone)
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	return r
}

// serveGoneOnSocket runs a gone call through the hook socket's
// authentication as the kernel-verified peer uid 1004.
func serveGoneOnSocket(t *testing.T, f managedHookAuditFixture, authorizer *managedHookAuthorizer, r *http.Request) {
	t.Helper()
	peer := managedHookPeer{UID: 1004, Name: "gone-alice"}
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("a request whose client had left was served")
	})
	f.api.managedHookPeerAuth(authorizer, next).ServeHTTP(httptest.NewRecorder(), r.WithContext(withManagedHookPeer(r.Context(), peer)))
}

// goneRowUsers returns the user.id of every connector-hook row of session.
func goneRowUsers(t *testing.T, f managedHookAuditFixture, session string) []string {
	t.Helper()
	events, err := f.store.ListEvents(1000)
	if err != nil {
		t.Fatal(err)
	}
	var users []string
	for _, event := range events {
		if event.Action != string(audit.ActionConnectorHook) || event.SessionID != session {
			continue
		}
		_, quoted, ok := strings.Cut(event.Details, "details_json=")
		if !ok {
			t.Fatalf("row without details_json: %s", event.Details)
		}
		raw, err := strconv.Unquote(quoted)
		if err != nil {
			t.Fatalf("details_json: %v", err)
		}
		var details map[string]any
		if err := json.Unmarshal([]byte(raw), &details); err != nil {
			t.Fatalf("details_json: %v", err)
		}
		user, _ := details["user.id"].(string)
		users = append(users, user)
	}
	return users
}

func machinePolicyAuthorizer() *managedHookAuthorizer {
	return newManagedHookAuthorizer(config.EnterpriseEnrollmentConfig{}, []string{"claudecode"}, nil)
}

// GAP-0286 (missing-row variant): during a gateway stall the managed hook
// calls queue on the hook socket and their hooks answer no_answer themselves.
// The gateway admits none of them once it runs again, but each still gets
// one audit row: unconfirmed with the no-answer reason, never allow and never
// nothing, under the kernel-verified peer. The call is still not served.
func TestManagedHookCallWhoseClientLeftBeforeAdmissionIsAuditedUnconfirmed(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	for _, tc := range []struct{ name, session, event string }{
		{"PreToolUse", "gone-pre", "PreToolUse"},
		{"UserPromptSubmit", "gone-prompt", "UserPromptSubmit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := goneRequest(t, managedHookBody(tc.session, tc.event), AgentIdentity{UserID: "1005", UserName: "gone-bob"}, nil)
			serveGoneOnSocket(t, f, machinePolicyAuthorizer(), r)
			if got := f.audited(t, tc.session)[tc.session]; got != "unconfirmed/no_answer" {
				t.Fatalf("audited = %q, want unconfirmed/no_answer", got)
			}
			if got := goneRowUsers(t, f, tc.session); len(got) != 1 || got[0] != "1004" {
				t.Fatalf("row users = %v, want the verified peer [1004]", got)
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

// A call the socket would have refused (no enrollment ledger, an unsafe
// process context) or served as an exempt account's call is not audited as a
// connector-hook call whose answer the hook never took (review RV2-2).
func TestManagedHookCallWhoseClientLeftIsAuditedOnlyWhenTheSocketWouldServeIt(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	for _, tc := range []struct {
		name       string
		authorizer *managedHookAuthorizer
		headers    map[string]string
	}{
		{"unenrolled", newManagedHookAuthorizer(config.EnterpriseEnrollmentConfig{}, nil, nil), nil},
		{"exempt", newManagedHookAuthorizer(config.EnterpriseEnrollmentConfig{ExemptUsers: []string{"1004"}}, []string{"claudecode"}, nil), nil},
		{"process-context", machinePolicyAuthorizer(), map[string]string{hookexec.ClientRefusalHeader: hookexec.ManagedProcessContextUnknownReason}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := "gone-" + tc.name
			serveGoneOnSocket(t, f, tc.authorizer, goneRequest(t, managedHookBody(session, "PreToolUse"), AgentIdentity{}, tc.headers))
			if got := f.audited(t, session); len(got) != 0 {
				t.Fatalf("a call the socket would not have served was audited %v", got)
			}
		})
	}
}

// A call authenticated by a per-user credential (the managed Windows hook
// route) is attributed to the identity the credential is bound to, never to
// the X-DefenseClaw-User-* claim the correlation middleware read before
// authentication; one whose headers name another account would have been
// refused, so it gets no row (review RV2-1).
func TestUserScopedCallWhoseClientLeftIsAuditedUnderTheBoundIdentity(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	mark := func(ctx context.Context) context.Context { return withAuthenticatedHookConnector(ctx, "claudecode") }
	for _, tc := range []struct {
		name    string
		claimed AgentIdentity
		headers map[string]string
		want    []string
	}{
		{"no-user-headers", AgentIdentity{}, nil, []string{"1004"}},
		{"forged-claim", AgentIdentity{UserID: "1005", UserName: "gone-bob"}, nil, []string{"1004"}},
		{"forged-header", AgentIdentity{UserID: "1005", UserName: "gone-bob"}, map[string]string{llmEventUserIDHeader: "1005"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := "gone-user-" + tc.name
			r, release := f.api.admitHookCaller(httptest.NewRecorder(), goneRequest(t, managedHookBody(session, "PreToolUse"), tc.claimed, tc.headers), "1004", goneHookPath)
			if release != nil || !hookCallerLeft(r) {
				t.Fatal("a request whose client had left was admitted")
			}
			f.api.recordUserScopedCallerGone(httptest.NewRecorder(), r, "1004", mark)
			got := goneRowUsers(t, f, session)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("row users = %v, want %v", got, tc.want)
			}
		})
	}
}

// A neutral lifecycle event (Stop) whose client left gets no row: it is not
// a decision.
func TestNeutralLifecycleCallWhoseClientLeftWritesNoRow(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	body := `{"hook_event_name":"Stop","session_id":"gone-start","cwd":"/tmp"}`
	serveGoneOnSocket(t, f, machinePolicyAuthorizer(), goneRequest(t, body, AgentIdentity{}, nil))
	if got := f.audited(t, "gone-start"); len(got) != 0 {
		t.Fatalf("neutral lifecycle call audited %v", got)
	}
}
