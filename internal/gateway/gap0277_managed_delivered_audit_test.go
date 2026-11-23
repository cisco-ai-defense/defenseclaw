// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// deliverAckedHookCall offers one receipt-backed PreToolUse call, reads the
// proposed allow, acknowledges it and waits for the handler to finish.
func deliverAckedHookCall(t *testing.T, f managedHookAuditFixture, session string) {
	t.Helper()
	body := managedHookBody(session, "PreToolUse")
	reader, writer := io.Pipe()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		f.server.URL+"/api/v1/claudecode/hook", reader)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(hookexec.HookDeliveryReceiptHeader, "1")
	request.Header.Set(hookexec.HookDeliveryPayloadBytesHeader, strconv.Itoa(len(body)))
	responseCh := make(chan *http.Response, 1)
	errorCh := make(chan error, 1)
	go func() {
		response, requestErr := f.server.Client().Do(request)
		if requestErr != nil {
			errorCh <- requestErr
			return
		}
		responseCh <- response
	}()
	if _, err := io.WriteString(writer, body); err != nil {
		t.Fatal(err)
	}
	var response *http.Response
	select {
	case response = <-responseCh:
	case err := <-errorCh:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("gateway did not offer the answer")
	}
	defer response.Body.Close()
	buffered := bufio.NewReader(response.Body)
	line, err := buffered.ReadString(10)
	if response.StatusCode != http.StatusOK || err != nil || !strings.Contains(line, "\"action\":\"allow\"") {
		t.Fatalf("offered answer: status=%d line=%q error=%v", response.StatusCode, line, err)
	}
	if _, err := io.WriteString(writer, hookexec.HookDeliveryReceiptAck); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	_, _ = io.Copy(io.Discard, buffered)
}

// delayDeliveredStage makes the next call that reaches the delivered stage
// wait past the ordinary persistence window, as an overloaded managed host
// does between the offer and its receipt.
func delayDeliveredStage(t *testing.T) func() {
	t.Helper()
	previous := hookStagePanicHook
	delayNext := false
	hookStagePanicHook = func(_ context.Context, stage string) {
		if stage == "delivered" && delayNext {
			delayNext = false
			time.Sleep(agentHookPersistGrace + 50*time.Millisecond)
		}
	}
	t.Cleanup(func() { hookStagePanicHook = previous })
	return func() { delayNext = true }
}

// rel-1-0-10:GAP-0277: a managed (machine) hook answer that reached its agent
// after the ordinary 10 s persistence window keeps its connector-hook audit
// row and its hook_decision record at once, instead of failing with
// context_done and leaving the call to a later journal recovery pass.
func TestGAP0277DeliveredManagedCallKeepsItsAuditRowAfterTheEarlierDeadline(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	delayNext := delayDeliveredStage(t)
	deliverAckedHookCall(t, f, "g277-benign")
	if got := f.audited(t, "g277-benign")["g277-benign"]; got != "allow" {
		t.Fatalf("ordinary managed call audit = %q, want allow", got)
	}
	delayNext()
	deliverAckedHookCall(t, f, "g277-delayed")
	if got := f.audited(t, "g277-delayed")["g277-delayed"]; got != "allow" {
		t.Fatalf("delivered managed call audit = %q, want allow (row lost to the expired window)", got)
	}
	if decisions := f.decisions(t); len(decisions) != 2 || decisions[0] != "allow/ok" || decisions[1] != "allow/ok" {
		t.Fatalf("decision records = %v, want two allows", decisions)
	}
	if entries := journalEntries(t, f); len(entries) != 0 {
		t.Fatalf("journal rows left for recovery = %d, want 0 (the delivered call settled in line)", len(entries))
	}
}
