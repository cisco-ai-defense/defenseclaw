// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"
)

// firstCallLatencyCall posts one managed Claude Code hook event and returns
// the status, the body and how long the gateway took.
func firstCallLatencyCall(t *testing.T, api *APIServer, event, session string) (int, string, time.Duration) {
	t.Helper()
	body := `{"session_id":"` + session + `","hook_event_name":"` + event + `","cwd":"/tmp","source":"startup"`
	if event == "PreToolUse" {
		body += `,"tool_name":"Read","tool_input":{"file_path":"/tmp/README.md"},"tool_use_id":"toolu_` + session + `"`
	}
	body += `}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", strings.NewReader(body))
	req.Header.Set("X-DefenseClaw-Hook-Event", event)
	req.Header.Set("X-DefenseClaw-Hook-Contract", api.hookProfileForConnector("claudecode").ContractID)
	rec := httptest.NewRecorder()
	began := time.Now()
	api.handleUnifiedConnectorHook("claudecode")(rec, req.WithContext(withAuthenticatedHookConnector(context.Background(), "claudecode")))
	return rec.Code, rec.Body.String(), time.Since(began)
}

// requireAllowedRead fails unless the call answered 200 with an allow.
func requireAllowedRead(t *testing.T, what string, code int, body string) {
	t.Helper()
	if code != http.StatusOK || !strings.Contains(body, `"action":"allow"`) {
		t.Fatalf("%s: status %d, body %s", what, code, body)
	}
}

// The first tool call of a session whose SessionStart the agent sent first
// (every real agent) takes no part in the arrival wait of the session start
// gate: with the production one-second window, the first Read of a new
// session is ALLOWED in well under 60 ms, like a later one (GAP-1005). A call
// that overtakes its start waits for it at most the window, once, and then
// runs on the verdict of the start judged in its place; that window protects
// a start that is in flight and stays.
func TestFirstToolCallOfAStartedSessionDoesNotWaitForTheStartWindow(t *testing.T) {
	saved := sessionStartArrivalWait
	sessionStartArrivalWait = time.Second
	t.Cleanup(func() { sessionStartArrivalWait = saved })
	api := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
	api.scannerCfg.DataDir = t.TempDir()

	// The median of five sessions: one slow first call on a busy machine
	// (a cold cache) is not the wait, which would show in every one.
	var firsts []time.Duration
	for _, session := range []string{"first-call-a", "first-call-b", "first-call-c", "first-call-d", "first-call-e"} {
		if code, _, _ := firstCallLatencyCall(t, api, "SessionStart", session); code != http.StatusOK {
			t.Fatalf("SessionStart of %s: status %d", session, code)
		}
		code, body, first := firstCallLatencyCall(t, api, "PreToolUse", session)
		requireAllowedRead(t, "first Read of the started session "+session, code, body)
		firsts = append(firsts, first)
	}
	sort.Slice(firsts, func(i, j int) bool { return firsts[i] < firsts[j] })
	if median := firsts[len(firsts)/2]; median >= 60*time.Millisecond {
		t.Fatalf("the median first Read of a started session took %s (all: %v): it waited for a start that had arrived", median, firsts)
	}

	// A call that overtakes its start is bounded by the window, is ALLOWED
	// on the start judged in its place, and the next call of the session
	// does not wait.
	code, body, overtaking := firstCallLatencyCall(t, api, "PreToolUse", "first-call-no-start")
	requireAllowedRead(t, "overtaking Read", code, body)
	if overtaking > sessionStartArrivalWait+sessionStartGateMaxWait/2 {
		t.Fatalf("a call without a start waited %s, past the arrival window %s", overtaking, sessionStartArrivalWait)
	}
	code, body, next := firstCallLatencyCall(t, api, "PreToolUse", "first-call-no-start")
	requireAllowedRead(t, "next Read of the overtaking session", code, body)
	if next >= 60*time.Millisecond {
		t.Fatalf("the next call of the session waited %s", next)
	}
}
