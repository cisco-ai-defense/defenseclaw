// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// A hook waiting for the client to acknowledge its offered answer uses no
// gateway run capacity. A second hook from the same managed caller must be
// able to get its own answer before the first client's receipt arrives.
func TestManagedHookReceiptWaitDoesNotHoldCallerRunSlot(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	f.api.hookCallerLimits.running = 1
	hook := f.api.handleUnifiedConnectorHook("claudecode")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r, release := f.api.admitHookCaller(w, r, "same-uid", "claudecode-hook")
		if release == nil {
			return
		}
		defer release()
		hook.ServeHTTP(w, r)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	body := managedHookBody("waiting-for-receipt", "PreToolUse")
	reader, writer := io.Pipe()
	defer writer.Close()
	first, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/api/v1/claudecode/hook", reader)
	if err != nil {
		t.Fatal(err)
	}
	first.Header.Set(hookexec.HookDeliveryReceiptHeader, "1")
	first.Header.Set(hookexec.HookDeliveryPayloadBytesHeader, strconv.Itoa(len(body)))
	first.Header.Set("Content-Type", "application/json")
	type answer struct {
		response *http.Response
		err      error
	}
	firstAnswer := make(chan answer, 1)
	go func() {
		response, requestErr := server.Client().Do(first)
		firstAnswer <- answer{response, requestErr}
	}()
	if _, err := io.WriteString(writer, body); err != nil {
		t.Fatal(err)
	}
	var offered answer
	select {
	case offered = <-firstAnswer:
	case <-ctx.Done():
		t.Fatal("first hook was not offered an answer")
	}
	if offered.err != nil {
		t.Fatal(offered.err)
	}
	defer offered.response.Body.Close()
	line, err := bufio.NewReader(offered.response.Body).ReadString('\n')
	if err != nil || !strings.Contains(line, `"action":"allow"`) {
		t.Fatalf("first offered answer = %q, %v", line, err)
	}
	// The flushed answer puts the first handler in delivery.offer, waiting
	// for the receipt. Inspect the run slot while that wait is held instead
	// of timing how long a second full handler takes on a shared build box.
	f.api.hookCallerLimits.mu.Lock()
	run := f.api.hookCallerLimits.callers["same-uid"].running
	slotHeldBeforeReceipt := len(run) != 0
	f.api.hookCallerLimits.mu.Unlock()

	second, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/api/v1/claudecode/hook",
		strings.NewReader(managedHookBody("second-while-first-waits", "PreToolUse")))
	if err != nil {
		t.Fatal(err)
	}
	second.Header.Set("Content-Type", "application/json")
	secondAnswer := make(chan answer, 1)
	go func() {
		response, requestErr := server.Client().Do(second)
		secondAnswer <- answer{response, requestErr}
	}()
	// Release the first hook even if the assertion failed, so the test does
	// not leave a live handler behind on its red run.
	if _, err := io.WriteString(writer, hookexec.HookDeliveryReceiptAck); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	_, _ = io.Copy(io.Discard, offered.response.Body)
	if slotHeldBeforeReceipt {
		t.Fatal("first hook held its caller run slot while waiting for the delivery receipt")
	}
	var next answer
	select {
	case next = <-secondAnswer:
	case <-ctx.Done():
		t.Fatal("second hook did not answer")
	}
	if next.err != nil {
		t.Fatal(next.err)
	}
	defer next.response.Body.Close()
	result, err := io.ReadAll(next.response.Body)
	if err != nil || next.response.StatusCode != http.StatusOK || !strings.Contains(string(result), `"action":"allow"`) {
		t.Fatalf("second hook = status %d, body %q, err %v", next.response.StatusCode, result, err)
	}
}
