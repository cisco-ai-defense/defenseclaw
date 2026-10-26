// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"strconv"
	"sync"
	"time"
)

// The managed hook and gateway use the same HTTP request for the verdict and
// its delivery receipt. An old gateway does not send 103 Early Hints, so the
// body ends with HookDeliveryReleased after this compatibility wait. A 1.0.4
// gateway whose 103 comes later reads the same marker in place of a receipt,
// and audits the call unconfirmed, because nothing proves what the hook did.
//
// The wait covers a gateway that is still starting when the call arrives: a
// socket-activated systemd unit or a launchd job accepts the connection at
// once, and its gateway reads the request about 800 ms later. With a 250 ms
// wait the first call after every cold start ended released and was audited
// unconfirmed, though the hook enforced the gateway's allow (GAP-0683). A
// running gateway sends its 103 when it admits the request, so the wait
// costs nothing there; only a published 1.0.2 or 1.0.3 gateway, during a
// package upgrade, answers after it.
const hookDeliveryCapabilityWait = 1500 * time.Millisecond

// The agent has its answer before this wait starts. Limit a missing HTTP
// confirmation independently of the answer deadline so the hook process
// returns within the tool call's registered timeout.
const hookDeliveryReceiptTimeout = hookResponseGrace

type hookDeliveryRequest struct {
	writer *io.PipeWriter
	ready  chan struct{}
	once   sync.Once
	mu     sync.Mutex
	closed bool
	// released: the capability wait passed first and the body ended with
	// HookDeliveryReleased. The answer is ordinary, with no receipt.
	released bool
}

// DeliveryReceiptEvent reports whether a managed native hook sends a delivery
// receipt for event (1.0.4 and later): a tool call with an answer deadline.
// The managed OpenCode plugin runs the native hook, so its tool calls do.
// Amp and Omnigent call the gateway from their in-agent plugin or policy
// bridge, which sends none.
func DeliveryReceiptEvent(connector, event string) bool {
	switch connector {
	case "amp", "omnigent":
		return false
	}
	return toolGateEvent(connector, event)
}

func wantsHookDeliveryReceipt(opts Options) bool {
	return opts.ManagedEnterprise && !opts.SecureClient && opts.answerWatch != nil && !opts.answerBy.IsZero()
}

func prepareHookDeliveryRequest(req *http.Request, payload []byte, wait time.Duration) (*http.Request, *hookDeliveryRequest) {
	reader, writer := io.Pipe()
	delivery := &hookDeliveryRequest{writer: writer, ready: make(chan struct{})}
	req.Body = reader
	req.ContentLength = -1
	req.GetBody = nil
	req.Header.Set(HookDeliveryReceiptHeader, "1")
	req.Header.Set(HookDeliveryPayloadBytesHeader, strconv.Itoa(len(payload)))
	trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, _ textproto.MIMEHeader) error {
		if code == http.StatusEarlyHints {
			delivery.once.Do(func() { close(delivery.ready) })
		}
		return nil
	}}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	// The transport's write loop reads the body until it ends, and a failed
	// round trip waits for that loop: the body ends with the request, also
	// after the gateway advertised the receipt.
	context.AfterFunc(req.Context(), delivery.close)
	go func() {
		if _, err := writer.Write(payload); err != nil {
			delivery.close()
			return
		}
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-delivery.ready:
		case <-timer.C:
			delivery.release()
		case <-req.Context().Done():
		}
	}()
	return req, delivery
}

func hookDeliveryWait(opts Options) time.Duration {
	wait := hookDeliveryCapabilityWait
	if deadline := gatewayRestartDeadline(opts, opts.StartedAt); !deadline.IsZero() {
		// An older gateway keeps half the restart budget to answer.
		remaining := time.Until(deadline) / 2
		if remaining < wait {
			wait = max(remaining, 0)
		}
	}
	return wait
}

func (d *hookDeliveryRequest) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		_ = d.writer.Close()
	}
}

// release ends the body with HookDeliveryReleased unless the gateway's 103
// came first.
func (d *hookDeliveryRequest) release() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	select {
	case <-d.ready:
		return
	default:
	}
	_, _ = io.WriteString(d.writer, HookDeliveryReleased)
	d.closed = true
	d.released = true
	_ = d.writer.Close()
}

func (d *hookDeliveryRequest) wasReleased() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.released
}

func (d *hookDeliveryRequest) acknowledge(localBlock bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return errors.New("hook delivery request already closed")
	}
	ack := HookDeliveryReceiptAck
	if localBlock {
		ack = HookDeliveryReceiptBlock
	}
	_, err := io.WriteString(d.writer, ack)
	d.closed = true
	_ = d.writer.Close()
	return err
}

func (d *hookDeliveryRequest) capabilityReceived() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return false
	}
	select {
	case <-d.ready:
		return true
	default:
		return false
	}
}

type hookDeliveryResponseBody struct {
	io.ReadCloser
	delivery *hookDeliveryRequest
}

func hookDeliveryResponse(body io.ReadCloser) *hookDeliveryRequest {
	if wrapped, ok := body.(*hookDeliveryResponseBody); ok {
		return wrapped.delivery
	}
	return nil
}
