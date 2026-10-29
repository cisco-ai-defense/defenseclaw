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
// gateway whose 103 comes later reads the same marker in place of a receipt.
const hookDeliveryCapabilityWait = 250 * time.Millisecond

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

func prepareHookDeliveryRequest(req *http.Request, payload []byte, wait time.Duration, starting func(context.Context) bool) (*http.Request, *hookDeliveryRequest) {
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
		// seenStarting: the gateway was still starting when the wait
		// passed; once it runs it gets the capability wait again.
		seenStarting := false
		for {
			select {
			case <-delivery.ready:
				return
			case <-req.Context().Done():
				return
			case <-timer.C:
			}
			if starting != nil && starting(req.Context()) {
				seenStarting = true
				timer.Reset(hookDeliveryStartPoll)
				continue
			}
			if seenStarting {
				seenStarting, starting = false, nil
				timer.Reset(wait)
				continue
			}
			delivery.release()
			return
		}
	}()
	return req, delivery
}

// hookDeliveryStartPoll is how often a hook whose capability wait passed
// asks again whether its gateway is still starting.
var hookDeliveryStartPoll = 100 * time.Millisecond

// hookDeliveryGatewayStarting reports a gateway that cannot have sent its
// 103 yet because it is not serving: the Linux standalone unit (Type=notify,
// READY=1 after both listeners serve) is stopping or starting while the call
// waits in the socket systemd holds. The first call after a stop
// starts the gateway by socket activation; the gateway answered it and
// advertised the receipt only after the 250 ms capability wait, so the hook
// had already released its request and the allowed call was audited
// unconfirmed (GAP-0683). An earlier gateway that never sends a 103 (a
// package upgrade in flight) still gets its release once the unit runs. The
// probe only runs after the capability wait passed without a 103, and the
// request deadline bounds the wait. Elsewhere no probe is wired and the
// release comes at the capability wait, as before.
var hookDeliveryGatewayStarting = func(ctx context.Context, opts Options) bool {
	probe := standaloneGatewayServiceProbe
	if !opts.ManagedEnterprise || !opts.ManagedStandalone || opts.SecureClient || probe == nil {
		return false
	}
	state, err := probe(ctx)
	return err == nil && gatewayServiceNotServing(state)
}

// gatewayServiceNotServing reports a unit state in which the gateway does not
// serve its sockets yet: stopping, or starting (the socket unit queued the
// start for the waiting call). A stopped unit is not waited for: systemd
// reports a unit it does not know as inactive too, and a failed unit will not
// answer.
func gatewayServiceNotServing(state gatewayServiceState) bool {
	switch state.Active {
	case "deactivating", "activating":
		return true
	}
	return false
}

func hookDeliveryWait(opts Options) time.Duration {
	wait := hookDeliveryCapabilityWait
	if deadline := gatewayRestartDeadline(opts, opts.StartedAt); !deadline.IsZero() {
		remaining := time.Until(deadline) / 4
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
