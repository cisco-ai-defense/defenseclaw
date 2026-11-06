// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"net/url"
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
	writer      *io.PipeWriter
	cancel      context.CancelFunc
	ready       chan struct{}
	payloadDone chan struct{}
	once        sync.Once
	mu          sync.Mutex
	closed      bool
	conn        net.Conn
	// released: the capability wait passed first and the body ended with
	// HookDeliveryReleased. The answer is ordinary, with no receipt.
	released bool
	// heldForStart: the capability wait passed while the gateway unit was
	// starting, so the body was kept open for the start.
	heldForStart bool
}

// errGatewayDroppedHeldCall marks a call whose connection failed while the
// hook kept its body open for a gateway start. The gateway that accepted the
// connection exited before it read the whole call (a restart whose old
// process stopped within the capability wait), so it never evaluated the
// call: the call is sent again, to the gateway that starts, like a reset.
var errGatewayDroppedHeldCall = errors.New("gateway dropped the call while it was starting")

func (d *hookDeliveryRequest) markHeldForStart() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.heldForStart = true
}

func (d *hookDeliveryRequest) wasHeldForStart() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.heldForStart
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
	return !opts.SecureClient && opts.answerWatch != nil && !opts.answerBy.IsZero()
}

func prepareHookDeliveryRequest(req *http.Request, payload []byte, wait time.Duration, starting func(context.Context) bool, currentGateway func(context.Context, net.Conn) bool) (*http.Request, *hookDeliveryRequest) {
	reader, writer := io.Pipe()
	delivery := &hookDeliveryRequest{writer: writer, ready: make(chan struct{}), payloadDone: make(chan struct{})}
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
	// Read now: the goroutine below outlives the call by a moment (GAP-0680).
	poll := hookDeliveryStartPoll
	go func() {
		_, err := writer.Write(payload)
		if err != nil {
			delivery.close()
			close(delivery.payloadDone)
			return
		}
		close(delivery.payloadDone)
		if wait <= 0 {
			delivery.release()
			return
		}
		timer := time.NewTimer(wait)
		defer timer.Stop()
		// Verify the accepted peer during the compatibility window. The
		// probe never adds time to an older gateway's body release, while a
		// matching current gateway can keep this body for its later 103.
		var verified <-chan bool
		var cancelProbe context.CancelFunc = func() {}
		startProbe := func() {
			cancelProbe()
			verified = nil
			select {
			case <-delivery.ready:
				return
			default:
			}
			if currentGateway == nil {
				return
			}
			postConn := delivery.connection()
			if postConn == nil {
				return
			}
			// The health request must not inherit the POST's HTTP trace: a
			// health response cannot advertise receipt support for the POST.
			probeCtx, cancel := context.WithTimeout(context.Background(), wait)
			stopCancel := context.AfterFunc(req.Context(), cancel)
			cancelProbe = func() {
				stopCancel()
				cancel()
			}
			result := make(chan bool, 1)
			verified = result
			go func() { result <- currentGateway(probeCtx, postConn) }()
		}
		defer func() { cancelProbe() }()
		awaitReceipt := func() {
			select {
			case <-delivery.ready:
			case <-req.Context().Done():
			}
		}
		startProbe()
		// seenStarting: the gateway was still starting when the wait
		// passed; once it runs it gets the capability wait again.
		seenStarting := false
		for {
			select {
			case <-delivery.ready:
				return
			case <-req.Context().Done():
				return
			case same := <-verified:
				if same {
					awaitReceipt()
					return
				}
				verified = nil
				continue
			case <-timer.C:
			}
			// Prefer a completed peer check if the timer and probe become
			// ready together.
			if verified != nil {
				select {
				case same := <-verified:
					if same {
						awaitReceipt()
						return
					}
					verified = nil
				default:
				}
			}
			if starting != nil && starting(req.Context()) {
				seenStarting = true
				delivery.markHeldForStart()
				timer.Reset(poll)
				continue
			}
			if seenStarting {
				seenStarting, starting = false, nil
				timer.Reset(wait)
				startProbe()
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
// READY=1 after both listeners serve) is starting while the call
// waits in the socket systemd holds. The first call after a stop
// starts the gateway by socket activation; the gateway answered it and
// advertised the receipt only after the 250 ms capability wait, so the hook
// had already released its request and the allowed call was audited
// unconfirmed (GAP-0683). An earlier gateway that never sends a 103 (a
// package upgrade in flight) still gets its release once the unit runs. The
// probe only runs after the capability wait passed without a 103, and the
// request deadline bounds the wait. Elsewhere no probe is wired and the
// release comes at the capability wait, as before.
// It returns the look of the call opts makes (nil: none); the call reads
// the service probe when it prepares the request, because the look runs on
// the request body's goroutine, which outlives the call by a moment: a test
// that replaced the probe after it raced that read (rel-1-0-6 GAP-0680).
var hookDeliveryGatewayStarting = func(opts Options) func(context.Context) bool {
	probe := standaloneGatewayServiceProbe
	if !opts.ManagedEnterprise || !opts.ManagedStandalone || opts.SecureClient || probe == nil {
		return nil
	}
	return func(ctx context.Context) bool {
		state, err := probe(ctx)
		return err == nil && gatewayServiceNotServing(state)
	}
}

// gatewayServiceNotServing reports a unit state in which the gateway does not
// serve its sockets yet: starting (the socket unit queued the start for the
// waiting call). A stopping unit is not waited for: the process still
// draining its calls may be a 1.0.2/1.0.3 gateway (rpm upgrade, before
// %posttrans restarts it) that sends no 103 and reads the body to the end,
// so holding the body would keep its handler, and the unit, in the drain
// until the answer budget blocks the call. A stopped unit is not waited for
// either: systemd reports a unit it does not know as inactive too, and a
// failed unit will not answer.
func gatewayServiceNotServing(state gatewayServiceState) bool {
	return state.Active == "activating"
}

func hookDeliveryWait(opts Options) time.Duration {
	wait := hookDeliveryCapabilityWait
	if !opts.ManagedEnterprise && !opts.answerBy.IsZero() {
		// Preserve the short-window retry reserve. Peer verification runs
		// within this wait and never extends an older gateway's answer.
		remaining := max(time.Until(opts.answerBy), 0)
		wait = min(330*time.Millisecond, remaining/2)
		if remaining <= 2*hookDeliveryCapabilityWait {
			wait = remaining / 4
		}
	}
	if deadline := gatewayRestartDeadline(opts, opts.StartedAt); !deadline.IsZero() {
		remaining := time.Until(deadline) / 4
		if remaining < wait {
			wait = max(remaining, 0)
		}
	}
	return wait
}

// hookDeliveryCurrentGateway checks whether the process that accepted the
// POST supports receipts. A separate health response only applies when its
// connected endpoint and process match the still-open POST connection.
func hookDeliveryCurrentGateway(ctx context.Context, client *http.Client, target string, postConn net.Conn) bool {
	endpoint, err := url.Parse(target)
	if err != nil {
		return false
	}
	endpoint.Path, endpoint.RawPath, endpoint.RawQuery, endpoint.Fragment = "/health", "", "", ""
	var healthConn net.Conn
	var connMu sync.Mutex
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		connMu.Lock()
		healthConn = info.Conn
		connMu.Unlock()
	}}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	connMu.Lock()
	conn := healthConn
	connMu.Unlock()
	return resp.StatusCode == http.StatusOK && resp.Header.Get(HookDeliveryCapabilityHeader) == "1" &&
		hookDeliverySameGateway(postConn, conn)
}

func hookDeliverySameGateway(postConn, healthConn net.Conn) bool {
	if postConn == nil || healthConn == nil {
		return false
	}
	postLocal, postRemote := postConn.LocalAddr(), postConn.RemoteAddr()
	healthLocal, healthRemote := healthConn.LocalAddr(), healthConn.RemoteAddr()
	postClient, postClientOK := postLocal.(*net.TCPAddr)
	postServer, postServerOK := postRemote.(*net.TCPAddr)
	healthClient, healthClientOK := healthLocal.(*net.TCPAddr)
	healthServer, healthServerOK := healthRemote.(*net.TCPAddr)
	if !postClientOK || !postServerOK || !healthClientOK || !healthServerOK {
		return false
	}
	if postRemote.String() != healthRemote.String() {
		return false
	}
	postPID, postOK := perUserConnectedPeerPID(postClient, postServer)
	healthPID, healthOK := perUserConnectedPeerPID(healthClient, healthServer)
	return postOK && healthOK && postPID == healthPID
}

func (d *hookDeliveryRequest) setConnection(conn net.Conn) {
	d.mu.Lock()
	d.conn = conn
	d.mu.Unlock()
}

func (d *hookDeliveryRequest) connection() net.Conn {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.conn
}

func (d *hookDeliveryRequest) close() {
	// A receipt write can be waiting for the transport to read the pipe
	// while holding mu. Close the pipe first so that write can return.
	_ = d.writer.Close()
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
	}
	if d.cancel != nil {
		d.cancel()
	}
}

func (d *hookDeliveryRequest) setCancel(cancel context.CancelFunc) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		cancel()
		return
	}
	d.cancel = cancel
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

// deadline reports the watchdog's committed answer on the same request the
// gateway is evaluating. A closed or unadvertised request has no in-band
// witness; its local failure line remains available to the reporter.
func (d *hookDeliveryRequest) deadline(blocked bool) bool {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return false
	}
	d.mu.Unlock()
	readyWait := time.NewTimer(answerWatchdogLogWait)
	defer readyWait.Stop()
	select {
	case <-d.payloadDone:
	case <-readyWait.C:
		return false
	}
	select {
	case <-d.ready:
	case <-readyWait.C:
		return false
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return false
	}
	d.closed = true
	d.mu.Unlock()
	token := HookDeliveryReceiptOpen
	if blocked {
		token = HookDeliveryReceiptLate
	}
	_, err := io.WriteString(d.writer, token)
	_ = d.writer.Close()
	return err == nil
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

func (b *hookDeliveryResponseBody) Close() error {
	b.delivery.close()
	return b.ReadCloser.Close()
}

func hookDeliveryResponse(body io.ReadCloser) *hookDeliveryRequest {
	if wrapped, ok := body.(*hookDeliveryResponseBody); ok {
		return wrapped.delivery
	}
	return nil
}
