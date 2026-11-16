// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// postOnAnswerFlushWriter runs the PostToolUse of the same call the moment
// the PreToolUse answer is flushed to the managed hook: the agent ran a fast
// tool before the gateway finished the PreToolUse audit.
type postOnAnswerFlushWriter struct {
	*httptest.ResponseRecorder
	post func()
	done bool
}

func (w *postOnAnswerFlushWriter) EnableFullDuplex() error         { return nil }
func (w *postOnAnswerFlushWriter) SetReadDeadline(time.Time) error { return nil }
func (w *postOnAnswerFlushWriter) Flush() {
	w.ResponseRecorder.Flush()
	if !w.done {
		w.done = true
		w.post()
	}
}

// TestPostToolBeforePreToolAuditCommitIsNotMissing is GAP-1228 (review r1
// #6): on a managed host the PreToolUse answer is offered before its audit
// commit, and a fast tool's PostToolUse can be finalized first. The
// PreToolUse key is noted once its verdict is final, before the answer is
// offered, so that PostToolUse is not reported as HOOK-PRE-TOOL-MISSING.
func TestPostToolBeforePreToolAuditCommitIsNotMissing(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	const session = "r2-1228-order"
	body := managedHookBody(session, "PreToolUse")
	request := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook",
		strings.NewReader(body+hookexec.HookDeliveryReceiptAck))
	request.Header.Set(hookexec.HookDeliveryReceiptHeader, "1")
	request.Header.Set(hookexec.HookDeliveryPayloadBytesHeader, strconv.Itoa(len(body)))
	request.Header.Set("Content-Type", "application/json")
	post := `{"hook_event_name":"PostToolUse","session_id":"` + session + `","cwd":"/tmp","tool_name":"Bash","tool_use_id":"` +
		session + `-tool","tool_input":{"command":"echo ok"},"tool_response":{"stdout":"ok"}}`
	reply := &postOnAnswerFlushWriter{ResponseRecorder: httptest.NewRecorder(), post: func() {
		postRequest := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", strings.NewReader(post))
		postRequest.Header.Set("Content-Type", "application/json")
		f.api.handleAgentHook("claudecode").ServeHTTP(httptest.NewRecorder(), postRequest)
	}}
	f.api.handleAgentHook("claudecode").ServeHTTP(reply, request)
	if !reply.done {
		t.Fatalf("the PreToolUse answer was never offered: %q", reply.Body.String())
	}
	events, err := f.store.ListEvents(1000)
	if err != nil {
		t.Fatal(err)
	}
	posts := 0
	for _, event := range events {
		if event.Action == string(audit.ActionAlert) && strings.Contains(event.Actor+event.Details, "pre-tool-missing") {
			t.Fatalf("audited PreToolUse reported missing: %+v", event)
		}
		if event.Action == string(audit.ActionConnectorHook) && strings.Contains(event.Details, "PostToolUse") {
			posts++
		}
	}
	if posts == 0 {
		t.Fatal("fixture: the PostToolUse was not audited")
	}
}
