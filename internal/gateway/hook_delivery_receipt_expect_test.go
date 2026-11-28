// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

const (
	// hookDeliveryTestPayload is the line the hook sends before the receipt.
	hookDeliveryTestPayload = "payload\n"
	// hookDeliveryTestHang bounds a hang only; no assertion measures speed.
	hookDeliveryTestHang = 60 * time.Second
)

// The per-user hook asks for its receipt with Expect: 100-continue and keeps
// the request body open. The proposal must reach the hook without waiting for
// the receipt read: from Go 1.27 net/http locks the request body to write the
// response header of such a request, and a read already waiting on the body
// held that lock until the hook gave up at its answer budget and failed open
// (rel-1-0-10 GAP-0088).
//
// The test orders its steps by events, never by the clock (GAP-0938). The hook
// sends its payload before the gateway answers, and the handler reads it first,
// like the real one (readPayload): a handler that answered before the client
// transport had started to send the body could be overtaken by net/http, which
// drops the body of an Expect request whose final response beat its writer and
// closes the connection (Connection: close), so the receipt write failed with
// io: read/write on closed pipe in 1 of 20 runs under load. The waits below
// only bound a hang: a regression of GAP-0088 deadlocks the proposal behind the
// receipt read, and no timeout under load can tell that from a slow box, so
// they are long.
func TestHookDeliveryProposalIsNotHeldByTheReceiptRead(t *testing.T) {
	const proposal = `{"action":"allow"}`
	receipts := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := http.NewResponseController(w).EnableFullDuplex(); err != nil {
			t.Errorf("full duplex: %v", err)
			return
		}
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusEarlyHints)
		delivery := &hookDeliveryReceipt{reader: bufio.NewReader(r.Body)}
		if payload, err := delivery.reader.ReadString('\n'); err != nil || payload != hookDeliveryTestPayload {
			t.Errorf("payload = %q, %v", payload, err)
			receipts <- ""
			return
		}
		receipts <- delivery.offer(w, func() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, proposal)
		})
	}))
	defer server.Close()

	body, receipt := io.Pipe()
	defer receipt.Close()
	payloadWritten := make(chan error, 1)
	go func() {
		_, err := io.WriteString(receipt, hookDeliveryTestPayload)
		payloadWritten <- err
	}()
	request, err := http.NewRequest(http.MethodPost, server.URL, body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Expect", "100-continue")
	client := &http.Client{Transport: &http.Transport{ExpectContinueTimeout: 0}}
	type reply struct {
		answer []byte
		resp   *http.Response
		err    error
	}
	replies := make(chan reply, 1)
	go func() {
		resp, err := client.Do(request)
		if err != nil {
			replies <- reply{err: err}
			return
		}
		answer := make([]byte, len(proposal))
		_, err = io.ReadFull(resp.Body, answer)
		replies <- reply{answer: answer, resp: resp, err: err}
	}()
	var got reply
	select {
	case got = <-replies:
	case <-time.After(hookDeliveryTestHang):
		t.Fatal("the proposal waited for the receipt read (the hook would fail open at its answer budget)")
	}
	if got.err != nil || string(got.answer) != proposal {
		t.Fatalf("proposal = %q, %v", got.answer, got.err)
	}
	defer got.resp.Body.Close()
	if err := <-payloadWritten; err != nil {
		t.Fatalf("payload write: %v", err)
	}
	if _, err := io.WriteString(receipt, hookexec.HookDeliveryReceiptAck); err != nil {
		t.Fatal(err)
	}
	select {
	case line := <-receipts:
		if line != hookexec.HookDeliveryReceiptAck {
			t.Fatalf("receipt = %q", line)
		}
	case <-time.After(hookDeliveryTestHang):
		t.Fatal("the receipt was not read")
	}
	confirmed, err := io.ReadAll(got.resp.Body)
	if err != nil || string(confirmed) != hookexec.HookDeliveryConfirmed {
		t.Fatalf("confirmation = %q, %v", confirmed, err)
	}
}
