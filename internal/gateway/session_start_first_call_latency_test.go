// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// firstCallLatencyCall posts one managed Claude Code hook event and returns
// the status and how long the gateway took.
func firstCallLatencyCall(t *testing.T, api *APIServer, event, session string) (int, time.Duration) {
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
	return rec.Code, time.Since(began)
}

// The first tool call of a session whose SessionStart the agent sent first
// (every real agent) takes no part in the arrival wait of the session start
// gate: with the production one-second window, the first Read of a new
// session answers like a later one (GAP-1005). A call that overtakes its
// start waits for it at most the window, once, and then runs on the verdict
// of the start judged in its place; that window protects a start that is in
// flight and stays.
func TestFirstToolCallOfAStartedSessionDoesNotWaitForTheStartWindow(t *testing.T) {
	saved := sessionStartArrivalWait
	sessionStartArrivalWait = time.Second
	t.Cleanup(func() { sessionStartArrivalWait = saved })
	api := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
	api.scannerCfg.DataDir = t.TempDir()

	for _, session := range []string{"first-call-a", "first-call-b", "first-call-c"} {
		if code, _ := firstCallLatencyCall(t, api, "SessionStart", session); code != http.StatusOK {
			t.Fatalf("SessionStart of %s: status %d", session, code)
		}
		code, first := firstCallLatencyCall(t, api, "PreToolUse", session)
		if code != http.StatusOK {
			t.Fatalf("first Read of %s: status %d", session, code)
		}
		if first >= sessionStartArrivalWait/2 {
			t.Fatalf("first Read of the started session %s took %s: it waited for a start that had arrived", session, first)
		}
	}

	code, overtaking := firstCallLatencyCall(t, api, "PreToolUse", "first-call-no-start")
	if code != http.StatusOK {
		t.Fatalf("overtaking Read: status %d", code)
	}
	if overtaking > sessionStartArrivalWait+sessionStartGateMaxWait/2 {
		t.Fatalf("a call without a start waited %s, past the arrival window %s", overtaking, sessionStartArrivalWait)
	}
	if _, next := firstCallLatencyCall(t, api, "PreToolUse", "first-call-no-start"); next >= sessionStartArrivalWait/2 {
		t.Fatalf("the next call of the session waited %s", next)
	}
}
