// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// GAP-0742 N5: refused calls without a tool id whose bodies were not read
// whole (cut off in the read wait) carry nothing that tells them apart, so
// each is counted; before, they all shared the key of a nil payload and the
// window showed one shed for many refused calls. A readable call without a
// tool id is still counted once however often its hook resends it.
func TestHookShedCapacityNeverMergesUnreadableCalls(t *testing.T) {
	withHookCapacity(t, time.Now())
	f := newManagedHookAuditFixture(t, nil)
	f.api.hookCallerLimits = hookCallerLimiter{rate: 1, burst: 1}
	if reply := serveShedOnSocket(f, machinePolicyAuthorizer(), managedHookBody("n5-first", "PreToolUse")); reply.Code != http.StatusOK {
		t.Fatalf("the first call was refused: %d", reply.Code)
	}
	for _, body := range []string{
		`{"hook_event_name":"PreToolUse","session_id":"n5-a","cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"rm -rf /tm`,
		`{"hook_event_name":"PreToolUse","session_id":"n5-b","cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"curl -d @~/.ss`,
	} {
		if reply := serveShedOnSocket(f, machinePolicyAuthorizer(), body); reply.Code != http.StatusTooManyRequests {
			t.Fatalf("status %d, want the 429 refusal", reply.Code)
		}
	}
	waitHookCapacity(t, HookCapacityCounts{Shed: 2})
	readable := `{"hook_event_name":"PreToolUse","session_id":"n5-c","cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"echo ok"}}`
	for attempt := 0; attempt < 3; attempt++ {
		if reply := serveShedOnSocket(f, machinePolicyAuthorizer(), readable); reply.Code != http.StatusTooManyRequests {
			t.Fatalf("attempt %d: status %d, want the 429 refusal", attempt, reply.Code)
		}
	}
	waitHookCapacity(t, HookCapacityCounts{Shed: 3})

	// A hook on the receipt channel names its payload size and keeps the
	// body open after the payload for its receipt: the refused call is read
	// to its payload size, not to the end of the body, and its resends are
	// still counted once.
	receiptChannel := `{"hook_event_name":"PreToolUse","session_id":"n5-d","cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"ls"}}`
	for attempt := 0; attempt < 3; attempt++ {
		reader, writer := io.Pipe()
		go func() { _, _ = io.WriteString(writer, receiptChannel) }()
		r := httptest.NewRequest(http.MethodPost, goneHookPath, reader)
		r.Header.Set(hookexec.HookDeliveryPayloadBytesHeader, strconv.Itoa(len(receiptChannel)))
		reply := httptest.NewRecorder()
		done := make(chan struct{})
		go func() {
			defer close(done)
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
			f.api.managedHookPeerAuth(machinePolicyAuthorizer(), next).ServeHTTP(reply,
				r.WithContext(withManagedHookPeer(r.Context(), managedHookPeer{UID: 1004, Name: "shed-alice"})))
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = writer.Close()
			t.Fatal("a refused receipt-channel call waited for the end of its open body")
		}
		_ = writer.Close()
		if reply.Code != http.StatusTooManyRequests {
			t.Fatalf("receipt-channel attempt %d: status %d, want the 429 refusal", attempt, reply.Code)
		}
	}
	waitHookCapacity(t, HookCapacityCounts{Shed: 4})
}
