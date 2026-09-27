// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// forwardState carries one absolute-form request's decision through the
// ReverseProxy and Transport callbacks.
type forwardState struct {
	p *Proxy
	// gen is the decider that decided the request and the transport it is
	// sent on.
	gen      *generation
	tunnel   *tunnel
	scheme   string
	explicit bool // the request URL carried a port

	allowed atomic.Bool

	// upstream is the upstream connection the request got, if any.
	upstream atomic.Pointer[idleConn]

	mu      sync.Mutex
	remote  string
	dialErr *dialError
}

type forwardKey struct{}

func forwardStateOf(ctx context.Context) *forwardState {
	st, _ := ctx.Value(forwardKey{}).(*forwardState)
	return st
}

func (st *forwardState) setRemote(addr string) {
	st.mu.Lock()
	st.remote = addr
	st.mu.Unlock()
}

func (st *forwardState) remoteAddr() string {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.remote
}

func (st *forwardState) setDialErr(de *dialError) {
	st.mu.Lock()
	st.dialErr = de
	st.mu.Unlock()
}

func (st *forwardState) lastDialErr() *dialError {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.dialErr
}

func defaultPort(scheme string) int {
	switch scheme {
	case "http":
		return 80
	case "https":
		return 443
	}
	return 0
}

func (p *Proxy) serveForward(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if !r.URL.IsAbs() || r.URL.Host == "" {
		w.Header().Set("Connection", "close")
		writeJSON(w, http.StatusBadRequest, notProxyResponse())
		return
	}
	if p.isClosing() {
		w.Header().Set("Connection", "close")
		writeJSON(w, http.StatusServiceUnavailable, shuttingDownResponse())
		return
	}
	pr, presented, ok := p.authenticate(r)
	if !ok {
		p.challenged(presented, r.Method, r.URL.Host, start)
		w.Header().Set("Proxy-Authenticate", proxyAuthenticate)
		w.Header().Set("Connection", "close")
		writeJSON(w, http.StatusProxyAuthRequired, authRequiredResponse())
		return
	}

	gen := p.gen.Load()
	d := gen.decider
	scheme := strings.ToLower(r.URL.Scheme)
	port, explicit := defaultPort(scheme), r.URL.Port() != ""
	if explicit {
		if n, ok := parsePort(r.URL.Port()); ok {
			port = n
		} else {
			port = 0
		}
	}
	var dec Decision
	if scheme != "http" && scheme != "https" {
		dec = d.Decide(pr, r.URL.Hostname(), 0)
		dec = blocked(dec, CategoryInvalidDestination, SourceGuard, "")
	} else {
		dec = d.Decide(pr, r.URL.Hostname(), port)
	}
	if !dec.Allowed {
		p.refuseForward(w, pr, r.Method, dec, start)
		return
	}
	release, refusal := p.admit(r, pr, dec)
	if refusal != nil {
		p.refuseForward(w, pr, r.Method, *refusal, start)
		return
	}
	defer release()

	// The request counts toward its destination once it has an upstream
	// connection, as a CONNECT tunnel does once it is dialed: a request
	// whose dial fails or is refused is not contact.
	flow := p.counter.pending(pr, dec.Host)
	defer flow.close()
	t := &tunnel{
		id: newTunnelID(), principal: pr, method: r.Method, dec: dec, started: start,
		flow: flow, exempt: exemptFromUploadBlock(dec),
	}
	if !p.track(t) {
		w.Header().Set("Connection", "close")
		writeJSON(w, http.StatusServiceUnavailable, shuttingDownResponse())
		return
	}
	defer p.untrack(t)

	st := &forwardState{p: p, gen: gen, tunnel: t, scheme: scheme, explicit: explicit}
	// A request that began before SetDecider hands its upstream connection
	// back to the retired generation's pool once it is done; close it there.
	defer func() {
		if p.gen.Load() != gen {
			gen.transport.CloseIdleConnections()
		}
	}()
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	defer func() { _ = rc.SetWriteDeadline(time.Time{}) }()

	ctx := context.WithValue(r.Context(), forwardKey{}, st)
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			st.setRemote(info.Conn.RemoteAddr().String())
			if ic := asIdleConn(info.Conn); ic != nil {
				ic.owner.Store(t)
				st.upstream.Store(ic)
			}
			flow.open()
		},
	})
	defer func() {
		if ic := st.upstream.Load(); ic != nil {
			ic.owner.CompareAndSwap(t, nil)
		}
	}()
	out := r.WithContext(ctx)
	if r.Body != nil && r.Body != http.NoBody {
		out.Body = &countingBody{ReadCloser: r.Body, st: st, rc: rc, idle: p.idle}
	}
	cw := &countingWriter{ResponseWriter: w, st: st, rc: rc, idle: p.idle}

	// ReverseProxy aborts a response that fails mid-copy by panicking with
	// http.ErrAbortHandler; the deferred accounting still runs.
	defer func() {
		if !st.allowed.Load() {
			return
		}
		e := p.event(EventClosed, pr, r.Method, dec)
		e.TunnelID, e.RemoteAddr, e.Status = t.id, st.remoteAddr(), cw.status()
		e.BytesUp, e.BytesDown, e.Duration = flow.up.Load(), flow.down.Load(), time.Since(start)
		e.Terminated = t.cut.Load() || t.idled.Load()
		p.emit(e)
	}()
	p.forwarder.ServeHTTP(cw, out)
}

// refuseForward answers a refused request and ends its client connection,
// so the connection cannot sit idle holding a slot (and a refusal costs the
// client a new connection).
func (p *Proxy) refuseForward(w http.ResponseWriter, pr Principal, method string, dec Decision, start time.Time) {
	status := statusFor(dec)
	p.recordRefusal(pr, method, dec, status, start, "")
	w.Header().Set("Connection", "close")
	writeJSON(w, status, p.blockResponse(pr, dec))
}

// rewrite points the outgoing request at the decided destination. The
// ReverseProxy has already removed hop-by-hop headers (including
// Proxy-Authorization and Proxy-Connection) and adds no X-Forwarded-*
// headers under Rewrite, so nothing about the proxy or the sandbox leaks
// upstream.
func (p *Proxy) rewrite(pr *httputil.ProxyRequest) {
	st := forwardStateOf(pr.In.Context())
	u := *pr.In.URL
	u.Scheme = st.scheme
	u.User = nil
	host := st.tunnel.dec.Host
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is6() {
		host = "[" + host + "]"
	}
	if st.explicit {
		host = net.JoinHostPort(st.tunnel.dec.Host, strconv.Itoa(st.tunnel.dec.Port))
	}
	u.Host = host
	pr.Out.URL = &u
	pr.Out.Host = ""
}

// transportDial is the Transport's only way out: it dials the decided
// destination through the guard and refuses any other address.
func (p *Proxy) transportDial(ctx context.Context, network, addr string) (net.Conn, error) {
	st := forwardStateOf(ctx)
	if st == nil {
		return nil, errors.New("egress: upstream dial without a decided request")
	}
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, ok := parsePort(portText)
	dec := st.tunnel.dec
	if !ok || host != dec.Host || port != dec.Port {
		return nil, fmt.Errorf("egress: upstream dial to %s does not match the decided destination", sanitizeHost(addr))
	}
	conn, remote, err := p.dialer.dial(ctx, host, port, st.gen.decider.block)
	if err != nil {
		var de *dialError
		if errors.As(err, &de) {
			st.setDialErr(de)
		}
		return nil, err
	}
	st.setRemote(remote.String())
	return newIdleConn(conn, p.idle), nil
}

// idleConn is a forwarded request's upstream connection. Every read or
// write that moves bytes pushes both deadlines TunnelIdleTimeout out, so a
// pending read or write fails once nothing has moved in either direction
// for that long: an upstream that stalls after its response headers, or
// stops reading a request body, cannot hold the request, its client
// connection and its tunnel slot indefinitely.
type idleConn struct {
	net.Conn
	idle time.Duration
	// owner is the request using the connection; the idle timeout marks it.
	owner atomic.Pointer[tunnel]
}

func newIdleConn(conn net.Conn, idle time.Duration) *idleConn {
	c := &idleConn{Conn: conn, idle: idle}
	c.touch()
	return c
}

// asIdleConn finds the idleConn under a Transport connection (plain, or
// the raw connection under https:// TLS).
func asIdleConn(conn net.Conn) *idleConn {
	if tc, ok := conn.(interface{ NetConn() net.Conn }); ok {
		conn = tc.NetConn()
	}
	c, _ := conn.(*idleConn)
	return c
}

func (c *idleConn) touch() { _ = c.Conn.SetDeadline(time.Now().Add(c.idle)) }

func (c *idleConn) moved(n int, err error) {
	if n > 0 {
		c.touch()
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		if t := c.owner.Load(); t != nil {
			t.idled.Store(true)
		}
	}
}

func (c *idleConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.moved(n, err)
	return n, err
}

func (c *idleConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.moved(n, err)
	return n, err
}

func (c *idleConn) CloseWrite() error { return closeWrite(c.Conn) }

// roundTripperFunc adapts a function to http.RoundTripper.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// roundTrip sends a forwarded request on the transport of the generation
// that decided it, so it only ever reuses connections dialed under the same
// decider.
func (p *Proxy) roundTrip(r *http.Request) (*http.Response, error) {
	st := forwardStateOf(r.Context())
	if st == nil {
		return nil, errors.New("egress: upstream request without a decided destination")
	}
	return st.gen.transport.RoundTrip(r)
}

func (p *Proxy) forwardResponse(resp *http.Response) error {
	st := forwardStateOf(resp.Request.Context())
	if st == nil || !st.allowed.CompareAndSwap(false, true) {
		return nil
	}
	t := st.tunnel
	e := p.event(EventAllowed, t.principal, t.method, t.dec)
	e.TunnelID, e.RemoteAddr, e.Status, e.FirstSeen = t.id, st.remoteAddr(), resp.StatusCode, t.flow.open()
	p.emit(e)
	return nil
}

func (p *Proxy) forwardError(w http.ResponseWriter, r *http.Request, err error) {
	st := forwardStateOf(r.Context())
	if st == nil {
		writeJSON(w, http.StatusBadGateway, ErrorResponse{Error: errCodeUnreachable, Message: "The upstream request failed."})
		return
	}
	t := st.tunnel
	dec := t.dec
	if t.cut.Load() {
		refused := blocked(dec, CategoryLargeUpload, SourceLimit, "")
		refused.Reason, refused.Unblockable = p.largeUploadReason(), true
		p.refuseForward(w, t.principal, t.method, refused, t.started)
		return
	}
	var de *dialError
	if !errors.As(err, &de) {
		de = st.lastDialErr()
	}
	if de != nil && de.category != "" {
		p.refuseForward(w, t.principal, t.method, dialRefusal(dec, de), t.started)
		return
	}
	status, reason := http.StatusBadGateway, "the upstream request failed"
	var netErr net.Error
	switch {
	case de != nil:
		status, reason = de.status, de.reason
	case errors.Is(err, context.Canceled):
		reason = "the request was canceled"
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()):
		status, reason = http.StatusGatewayTimeout, "the destination did not respond in time"
	}
	p.emitFailed(t.principal, t.method, dec, status, reason, st.remoteAddr(), t.started)
	writeJSON(w, status, unreachableResponse(dec.Host, dec.Port, reason))
}

// countingBody accounts request body bytes as upload, applies the
// large-upload block, and keeps an idle deadline on the client connection
// while the body streams.
type countingBody struct {
	io.ReadCloser
	st   *forwardState
	rc   *http.ResponseController
	idle time.Duration
}

func (b *countingBody) Read(buf []byte) (int, error) {
	_ = b.rc.SetReadDeadline(time.Now().Add(b.idle))
	n, err := b.ReadCloser.Read(buf)
	if n > 0 {
		t := b.st.tunnel
		v := t.flow.addUp(int64(n), t.exempt)
		if v.signal {
			b.st.p.emitLargeUpload(t, v)
		}
		if v.cut {
			t.cut.Store(true)
			return 0, errLargeUpload
		}
	}
	if err != nil {
		// The server starts its background read once the body is done;
		// lift the idle deadline so it cannot cancel a long response.
		_ = b.rc.SetReadDeadline(time.Time{})
		if errors.Is(err, os.ErrDeadlineExceeded) {
			b.st.tunnel.idled.Store(true)
		}
	}
	return n, err
}

// countingWriter accounts response bytes as download and keeps an idle
// deadline on writes to the client. It hijacks for protocol upgrades
// (ws://) with a counting connection.
type countingWriter struct {
	http.ResponseWriter
	st   *forwardState
	rc   *http.ResponseController
	idle time.Duration
	code atomic.Int32
}

func (w *countingWriter) WriteHeader(code int) {
	if code >= 200 || code == http.StatusSwitchingProtocols {
		w.code.CompareAndSwap(0, int32(code))
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *countingWriter) Write(b []byte) (int, error) {
	w.code.CompareAndSwap(0, http.StatusOK)
	_ = w.rc.SetWriteDeadline(time.Now().Add(w.idle))
	n, err := w.ResponseWriter.Write(b)
	if n > 0 {
		w.st.tunnel.flow.addDown(int64(n))
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		w.st.tunnel.idled.Store(true)
	}
	return n, err
}

func (w *countingWriter) status() int { return int(w.code.Load()) }

// FlushError lets the ReverseProxy flush streamed responses.
func (w *countingWriter) FlushError() error { return w.rc.Flush() }

// Unwrap exposes the underlying writer to http.ResponseController.
func (w *countingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Hijack hands the ReverseProxy a counting, idle-watched connection for
// upgraded protocols.
func (w *countingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, brw, err := w.rc.Hijack()
	if err != nil {
		return nil, nil, err
	}
	// The ReverseProxy writes the 101 head straight to brw, bypassing
	// WriteHeader.
	w.code.CompareAndSwap(0, http.StatusSwitchingProtocols)
	_ = conn.SetDeadline(time.Time{})
	t := w.st.tunnel
	uc := &upgradedConn{Conn: conn, tunnel: t, p: w.st.p, done: make(chan struct{})}
	uc.touch()
	go watchIdle(w.idle, &uc.last, uc.done, t.closeIdle)
	t.setCloser(func() { _ = conn.Close() })
	return uc, brw, nil
}

// upgradedConn counts an upgraded client connection: reads are uploads,
// writes are downloads.
type upgradedConn struct {
	net.Conn
	tunnel    *tunnel
	p         *Proxy
	last      atomic.Int64
	done      chan struct{}
	closeOnce sync.Once
}

func (c *upgradedConn) touch() { c.last.Store(time.Now().UnixNano()) }

func (c *upgradedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.touch()
		t := c.tunnel
		v := t.flow.addUp(int64(n), t.exempt)
		if v.signal {
			c.p.emitLargeUpload(t, v)
		}
		if v.cut {
			t.cut.Store(true)
			return 0, errLargeUpload
		}
	}
	return n, err
}

func (c *upgradedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.touch()
		c.tunnel.flow.addDown(int64(n))
	}
	return n, err
}

func (c *upgradedConn) Close() error {
	c.closeOnce.Do(func() { close(c.done) })
	return c.Conn.Close()
}

func (c *upgradedConn) CloseWrite() error { return closeWrite(c.Conn) }

// bindingLimits enforces per-binding concurrency and new-tunnel rate limits.
type bindingLimits struct {
	max   int
	limit rate.Limit
	burst int

	mu    sync.Mutex
	state map[string]*bindingLimit
}

type bindingLimit struct {
	active  int
	limiter *rate.Limiter
}

const maxTrackedBindings = 4096

func newBindingLimits(maxActive int, perSecond float64, burst int) *bindingLimits {
	l := &bindingLimits{max: maxActive, burst: burst, state: map[string]*bindingLimit{}}
	if perSecond > 0 {
		l.limit = rate.Limit(perSecond)
	}
	return l
}

// acquire reserves a slot for binding, returning a release func, or nil and
// the reason a limit refused it.
func (l *bindingLimits) acquire(binding string) (func(), string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.state[binding]
	if st == nil {
		if len(l.state) >= maxTrackedBindings {
			l.pruneLocked()
		}
		st = &bindingLimit{}
		if l.limit > 0 {
			st.limiter = rate.NewLimiter(l.limit, l.burst)
		}
		l.state[binding] = st
	}
	if l.max > 0 && st.active >= l.max {
		return nil, fmt.Sprintf("This sandbox already has %d connections open through the egress proxy.", st.active)
	}
	if st.limiter != nil && !st.limiter.Allow() {
		return nil, "This sandbox is opening connections faster than the egress proxy allows."
	}
	st.active++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			st.active--
			l.mu.Unlock()
		})
	}, ""
}

// pruneLocked forgets idle bindings whose rate budget is full again; their
// state would be recreated identically.
func (l *bindingLimits) pruneLocked() {
	for k, st := range l.state {
		if st.active == 0 && (st.limiter == nil || st.limiter.Tokens() >= float64(l.burst)) {
			delete(l.state, k)
		}
	}
}
