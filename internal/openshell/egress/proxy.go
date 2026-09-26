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
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Defaults for Options fields left zero.
const (
	DefaultHeaderTimeout         = 10 * time.Second
	DefaultIdleTimeout           = 90 * time.Second
	DefaultTunnelIdleTimeout     = 10 * time.Minute
	DefaultDialTimeout           = 10 * time.Second
	DefaultResponseHeaderTimeout = 2 * time.Minute
	DefaultMaxHeaderBytes        = 32 << 10
	DefaultMaxConns              = 1024
	DefaultMaxTunnelsPerBinding  = 256
	DefaultTunnelsPerSecond      = 50
	DefaultTunnelBurst           = 200
)

const (
	relayBufferSize = 32 << 10
	shutdownPoll    = 20 * time.Millisecond
)

// ErrNotLoopback is returned when the proxy is asked to listen anywhere but
// loopback. Sandboxes reach it only through OpenShell's relay from
// 127.0.0.1, so a wider listener would only add exposure.
var ErrNotLoopback = errors.New("egress: the proxy listens on loopback addresses only")

var errLargeUpload = errors.New("egress: large upload to a first-seen destination blocked")

// Options configures a Proxy. Auth and Decider are required. Zero durations
// and sizes use the Default* constants.
type Options struct {
	// Auth maps proxy credentials to principals, usually a CredentialStore.
	Auth Authenticator
	// Decider makes the allow/block decisions; SetDecider swaps it live.
	Decider *Decider
	// Sink receives events; nil discards them.
	Sink EventSink
	// Counter keeps byte counts; nil creates one with default options.
	Counter *Counter
	// Resolver resolves destination names; nil uses net.DefaultResolver.
	Resolver Resolver
	// Dialer connects to validated addresses; nil uses a net.Dialer with
	// DialTimeout.
	Dialer Dialer
	// UpstreamTLS configures TLS for absolute-form https:// requests (CONNECT
	// tunnels are never terminated). Nil uses the system roots, TLS 1.2+.
	UpstreamTLS *tls.Config

	// HeaderTimeout bounds reading a request's headers (slowloris).
	HeaderTimeout time.Duration
	// IdleTimeout closes keep-alive client connections idle between
	// requests, and idle pooled upstream connections.
	IdleTimeout time.Duration
	// TunnelIdleTimeout closes a tunnel, or stalls a forwarded body, after
	// this long without bytes in either direction.
	TunnelIdleTimeout time.Duration
	// DialTimeout bounds DNS plus connect for each upstream attempt.
	DialTimeout time.Duration
	// ResponseHeaderTimeout bounds waiting for an absolute-form upstream's
	// response headers.
	ResponseHeaderTimeout time.Duration
	// MaxHeaderBytes bounds request headers; larger requests get a 431.
	MaxHeaderBytes int
	// MaxConns bounds concurrent client connections across all listeners.
	MaxConns int
	// MaxTunnelsPerBinding bounds concurrent tunnels and requests per
	// binding; negative disables the limit.
	MaxTunnelsPerBinding int
	// TunnelsPerSecond and TunnelBurst rate-limit new tunnels and requests
	// per binding; a negative rate disables the limit.
	TunnelsPerSecond float64
	TunnelBurst      int

	// UnblockHint overrides DefaultUnblockHint in 403 bodies.
	UnblockHint func(p Principal, d Decision) string
	// ErrorLog receives the HTTP server's internal errors; nil discards.
	ErrorLog *log.Logger
}

// Proxy is the sandbox egress proxy. Create it with New, run it with Serve
// on a loopback listener, and stop it with Shutdown or Close.
type Proxy struct {
	decider atomic.Pointer[Decider]
	auth    Authenticator
	sink    EventSink
	counter *Counter
	dialer  *guardDialer
	hint    func(Principal, Decision) string
	idle    time.Duration

	srv       *http.Server
	transport *http.Transport
	forwarder *httputil.ReverseProxy
	limits    *bindingLimits
	sem       chan struct{}

	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	closing bool
	tunnels map[*tunnel]struct{}
}

// New validates opts and builds a Proxy.
func New(opts Options) (*Proxy, error) {
	if opts.Auth == nil {
		return nil, errors.New("egress: Options.Auth is required")
	}
	if opts.Decider == nil {
		return nil, errors.New("egress: Options.Decider is required")
	}
	positive := func(d *time.Duration, def time.Duration) {
		if *d <= 0 {
			*d = def
		}
	}
	positive(&opts.HeaderTimeout, DefaultHeaderTimeout)
	positive(&opts.IdleTimeout, DefaultIdleTimeout)
	positive(&opts.TunnelIdleTimeout, DefaultTunnelIdleTimeout)
	positive(&opts.DialTimeout, DefaultDialTimeout)
	positive(&opts.ResponseHeaderTimeout, DefaultResponseHeaderTimeout)
	if opts.MaxHeaderBytes <= 0 {
		opts.MaxHeaderBytes = DefaultMaxHeaderBytes
	}
	if opts.MaxConns <= 0 {
		opts.MaxConns = DefaultMaxConns
	}
	if opts.MaxTunnelsPerBinding == 0 {
		opts.MaxTunnelsPerBinding = DefaultMaxTunnelsPerBinding
	}
	if opts.TunnelsPerSecond == 0 {
		opts.TunnelsPerSecond = DefaultTunnelsPerSecond
	}
	if opts.TunnelBurst <= 0 {
		opts.TunnelBurst = DefaultTunnelBurst
	}
	if opts.Counter == nil {
		opts.Counter = NewCounter(CounterOptions{})
	}
	if opts.Sink == nil {
		opts.Sink = nopSink{}
	}
	if opts.ErrorLog == nil {
		opts.ErrorLog = log.New(io.Discard, "", 0)
	}
	if opts.Resolver == nil {
		opts.Resolver = net.DefaultResolver
	}
	if opts.Dialer == nil {
		opts.Dialer = &net.Dialer{Timeout: opts.DialTimeout, KeepAlive: 30 * time.Second}
	}
	upstreamTLS := &tls.Config{MinVersion: tls.VersionTLS12}
	if opts.UpstreamTLS != nil {
		upstreamTLS = opts.UpstreamTLS.Clone()
	}

	p := &Proxy{
		auth:    opts.Auth,
		sink:    opts.Sink,
		counter: opts.Counter,
		dialer:  &guardDialer{resolver: opts.Resolver, dialer: opts.Dialer, timeout: opts.DialTimeout},
		hint:    opts.UnblockHint,
		idle:    opts.TunnelIdleTimeout,
		limits:  newBindingLimits(opts.MaxTunnelsPerBinding, opts.TunnelsPerSecond, opts.TunnelBurst),
		sem:     make(chan struct{}, opts.MaxConns),
		tunnels: map[*tunnel]struct{}{},
	}
	p.decider.Store(opts.Decider)
	p.ctx, p.cancel = context.WithCancel(context.Background())

	p.transport = &http.Transport{
		Proxy:                  nil, // never chain to the daemon's own proxy environment
		DialContext:            p.transportDial,
		TLSClientConfig:        upstreamTLS,
		TLSHandshakeTimeout:    opts.DialTimeout,
		ResponseHeaderTimeout:  opts.ResponseHeaderTimeout,
		ExpectContinueTimeout:  time.Second,
		IdleConnTimeout:        opts.IdleTimeout,
		MaxIdleConns:           64,
		MaxIdleConnsPerHost:    4,
		MaxResponseHeaderBytes: 1 << 20,
		DisableCompression:     true, // relay bytes as sent; never add or strip encodings
	}
	p.forwarder = &httputil.ReverseProxy{
		Rewrite:        p.rewrite,
		Transport:      p.transport,
		FlushInterval:  -1,
		ErrorLog:       opts.ErrorLog,
		ErrorHandler:   p.forwardError,
		ModifyResponse: p.forwardResponse,
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	p.srv = &http.Server{
		Handler:           http.HandlerFunc(p.serveHTTP),
		ReadHeaderTimeout: opts.HeaderTimeout,
		IdleTimeout:       opts.IdleTimeout,
		MaxHeaderBytes:    opts.MaxHeaderBytes,
		ErrorLog:          opts.ErrorLog,
		Protocols:         protocols,
		BaseContext:       func(net.Listener) context.Context { return p.ctx },
	}
	return p, nil
}

// Decider returns the current decider.
func (p *Proxy) Decider() *Decider { return p.decider.Load() }

// SetDecider swaps the decider used for new tunnels and requests, for
// example after a configuration reload. Open tunnels keep their decision.
func (p *Proxy) SetDecider(d *Decider) error {
	if d == nil {
		return errors.New("egress: nil decider")
	}
	p.decider.Store(d)
	return nil
}

// Counter returns the proxy's byte counter.
func (p *Proxy) Counter() *Counter { return p.counter }

// Listen opens a TCP listener on a loopback address such as
// "127.0.0.1:18972". Anything else is refused with ErrNotLoopback.
func Listen(addr string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("egress: listen address %q: %w", addr, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("%w: %q", ErrNotLoopback, addr)
	}
	return net.Listen("tcp", addr)
}

// Serve accepts connections on ln until Shutdown or Close, and returns
// http.ErrServerClosed then. ln must be a loopback TCP listener; peers that
// are not loopback are dropped on accept.
func (p *Proxy) Serve(ln net.Listener) error {
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok || !addr.IP.IsLoopback() {
		return fmt.Errorf("%w: %s", ErrNotLoopback, ln.Addr())
	}
	p.mu.Lock()
	closing := p.closing
	p.mu.Unlock()
	if closing {
		return http.ErrServerClosed
	}
	return p.srv.Serve(&limitListener{Listener: ln, sem: p.sem, done: make(chan struct{})})
}

// Shutdown stops accepting connections, closes idle ones, and waits for
// in-flight requests and tunnels to finish until ctx is done; whatever is
// still open then is closed. It returns ctx.Err() when it had to force.
func (p *Proxy) Shutdown(ctx context.Context) error {
	p.mu.Lock()
	p.closing = true
	p.mu.Unlock()
	err := p.srv.Shutdown(ctx)
	for p.activeTunnels() > 0 && ctx.Err() == nil {
		select {
		case <-ctx.Done():
		case <-time.After(shutdownPoll):
		}
	}
	if ctx.Err() != nil {
		_ = p.srv.Close()
		p.closeTunnels()
		if err == nil {
			err = ctx.Err()
		}
	}
	p.cancel()
	p.transport.CloseIdleConnections()
	return err
}

// Close stops the proxy immediately, closing every connection and tunnel.
func (p *Proxy) Close() error {
	p.mu.Lock()
	p.closing = true
	p.mu.Unlock()
	p.cancel()
	err := p.srv.Close()
	p.closeTunnels()
	p.transport.CloseIdleConnections()
	return err
}

func (p *Proxy) isClosing() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closing
}

// TunnelStats is a live snapshot of one open tunnel or forwarded request.
type TunnelStats struct {
	ID          string
	BindingID   string
	SandboxID   string
	SandboxName string
	Method      string
	Host        string
	Port        int
	Started     time.Time
	BytesUp     int64
	BytesDown   int64
}

// Tunnels returns the open tunnels and in-flight forwarded requests, oldest
// first.
func (p *Proxy) Tunnels() []TunnelStats {
	p.mu.Lock()
	out := make([]TunnelStats, 0, len(p.tunnels))
	for t := range p.tunnels {
		out = append(out, TunnelStats{
			ID: t.id, BindingID: t.principal.BindingID, SandboxID: t.principal.SandboxID,
			SandboxName: t.principal.SandboxName, Method: t.method, Host: t.dec.Host, Port: t.dec.Port,
			Started: t.started, BytesUp: t.flow.up.Load(), BytesDown: t.flow.down.Load(),
		})
	}
	p.mu.Unlock()
	slices.SortFunc(out, func(a, b TunnelStats) int {
		if c := a.Started.Compare(b.Started); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

// tunnel is one open CONNECT tunnel or forwarded request.
type tunnel struct {
	id        string
	principal Principal
	method    string
	dec       Decision
	started   time.Time
	flow      *flow
	exempt    bool
	cut       atomic.Bool

	closeMu sync.Mutex
	// closeFn force-closes the tunnel's connections. It stays nil while the
	// HTTP server owns them (plain forwarded requests) and is set once a
	// CONNECT is established or a forwarded request upgrades.
	closeFn func()
	closed  bool
}

// setCloser installs the force-close func, running it at once if the tunnel
// was already closed (a shutdown raced the upgrade).
func (t *tunnel) setCloser(fn func()) {
	t.closeMu.Lock()
	if t.closed {
		t.closeMu.Unlock()
		fn()
		return
	}
	t.closeFn = fn
	t.closeMu.Unlock()
}

// close force-closes the tunnel once; later calls are no-ops.
func (t *tunnel) close() {
	t.closeMu.Lock()
	fn := t.closeFn
	t.closeFn, t.closed = nil, true
	t.closeMu.Unlock()
	if fn != nil {
		fn()
	}
}

func (p *Proxy) track(t *tunnel) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		return false
	}
	p.tunnels[t] = struct{}{}
	return true
}

func (p *Proxy) untrack(t *tunnel) {
	p.mu.Lock()
	delete(p.tunnels, t)
	p.mu.Unlock()
}

func (p *Proxy) activeTunnels() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.tunnels)
}

func (p *Proxy) closeTunnels() {
	p.mu.Lock()
	open := make([]*tunnel, 0, len(p.tunnels))
	for t := range p.tunnels {
		open = append(open, t)
	}
	p.mu.Unlock()
	for _, t := range open {
		t.close()
	}
}

func newTunnelID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "egr-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return "egr-" + hex.EncodeToString(b[:])
}

func (p *Proxy) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.serveConnect(w, r)
		return
	}
	p.serveForward(w, r)
}

// authenticate resolves the request's proxy credential. presented reports
// whether the request carried any Proxy-Authorization at all.
func (p *Proxy) authenticate(r *http.Request) (pr Principal, presented, ok bool) {
	values := r.Header.Values("Proxy-Authorization")
	if len(values) == 0 {
		return Principal{}, false, false
	}
	user, pass, parsed := parseProxyAuthorization(values)
	if !parsed {
		return Principal{}, true, false
	}
	pr, ok = p.auth.Authenticate(user, pass)
	if !ok || strings.TrimSpace(pr.BindingID) == "" {
		return Principal{}, true, false
	}
	return pr, true, true
}

// challenged records a 407. A request without any credential is the normal
// first leg of the auth handshake (libcurl with CURLAUTH_ANY, as git uses,
// always probes that way), so only a rejected credential is an event.
func (p *Proxy) challenged(presented bool, method, target string, start time.Time) {
	if presented {
		p.emitAuthFailed(method, target, start)
	}
}

// admit applies the per-binding limits and the large-upload block to an
// allowed decision. It returns a release func, or a refusal.
func (p *Proxy) admit(pr Principal, dec Decision) (func(), *Decision) {
	release, why := p.limits.acquire(pr.BindingID)
	if release == nil {
		refused := blocked(dec, CategoryRateLimited, SourceLimit, "")
		refused.Reason = why
		return nil, &refused
	}
	if !exemptFromUploadBlock(dec) && p.counter.uploadBlocked(pr, dec.Host) {
		release()
		refused := blocked(dec, CategoryLargeUpload, SourceLimit, "")
		refused.Reason = p.largeUploadReason()
		refused.Unblockable = true
		return nil, &refused
	}
	return release, nil
}

// exemptFromUploadBlock: destinations the user unblocked or the operator
// allowed are trusted enough that a large upload only raises the signal.
func exemptFromUploadBlock(dec Decision) bool {
	return dec.Source == SourceUnblock || dec.Source == SourceOperator
}

func (p *Proxy) largeUploadReason() string {
	return fmt.Sprintf("More than %s was sent to a destination this sandbox had not contacted before.", formatBytes(p.counter.LargeUploadBytes()))
}

func formatBytes(n int64) string {
	const mib = 1 << 20
	if n >= mib && n%mib == 0 {
		return strconv.FormatInt(n/mib, 10) + " MiB"
	}
	return strconv.FormatInt(n, 10) + " bytes"
}

// ---- CONNECT ---------------------------------------------------------------

func (p *Proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, "egress proxy: cannot take over the connection", http.StatusInternalServerError)
		return
	}
	target := r.RequestURI
	if target == "" {
		target = r.Host
	}
	if p.isClosing() {
		writeRaw(conn, http.StatusServiceUnavailable, "Service Unavailable", nil, shuttingDownResponse())
		return
	}
	pr, presented, ok := p.authenticate(r)
	if !ok {
		p.challenged(presented, http.MethodConnect, target, start)
		writeRaw(conn, http.StatusProxyAuthRequired, "Proxy Authentication Required",
			http.Header{"Proxy-Authenticate": {proxyAuthenticate}}, authRequiredResponse())
		return
	}
	d := p.decider.Load()
	var dec Decision
	if host, port, err := splitAuthority(target); err != nil {
		dec = d.Decide(pr, target, 0)
	} else {
		dec = d.Decide(pr, host, port)
	}
	if !dec.Allowed {
		p.refuseRaw(conn, pr, http.MethodConnect, dec, start)
		return
	}
	release, refusal := p.admit(pr, dec)
	if refusal != nil {
		p.refuseRaw(conn, pr, http.MethodConnect, *refusal, start)
		return
	}
	defer release()

	upstream, remote, err := p.dialer.dial(p.ctx, dec.Host, dec.Port, d.block)
	if err != nil {
		p.dialFailedRaw(conn, pr, dec, err, start)
		return
	}
	flow, first := p.counter.open(pr, dec.Host)
	defer flow.close()
	t := &tunnel{
		id: newTunnelID(), principal: pr, method: http.MethodConnect, dec: dec, started: start,
		flow: flow, exempt: exemptFromUploadBlock(dec),
	}
	t.setCloser(func() {
		_ = conn.Close()
		_ = upstream.Close()
	})
	if !p.track(t) {
		_ = upstream.Close()
		writeRaw(conn, http.StatusServiceUnavailable, "Service Unavailable", nil, shuttingDownResponse())
		return
	}
	defer p.untrack(t)

	_ = conn.SetWriteDeadline(time.Now().Add(rawWriteTimeout))
	_, err = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
	_ = conn.SetWriteDeadline(time.Time{})
	if err != nil {
		t.close()
		return
	}
	allowed := p.event(EventAllowed, pr, http.MethodConnect, dec)
	allowed.TunnelID, allowed.RemoteAddr, allowed.Status, allowed.FirstSeen = t.id, remote.String(), http.StatusOK, first
	p.emit(allowed)

	idled := p.relay(t, conn, brw.Reader, upstream)

	closed := p.event(EventClosed, pr, http.MethodConnect, dec)
	closed.TunnelID, closed.RemoteAddr, closed.Status = t.id, remote.String(), http.StatusOK
	closed.BytesUp, closed.BytesDown, closed.Duration = flow.up.Load(), flow.down.Load(), time.Since(start)
	closed.Terminated = idled || t.cut.Load()
	p.emit(closed)
}

// splitAuthority parses a CONNECT authority-form target, host:port with a
// decimal port.
func splitAuthority(target string) (string, int, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, err
	}
	port, ok := parsePort(portText)
	if !ok {
		return "", 0, fmt.Errorf("egress: invalid port %q", portText)
	}
	return host, port, nil
}

// parsePort accepts 1-5 decimal digits; strconv.Atoi would also accept a
// sign.
func parsePort(s string) (int, bool) {
	if s == "" || len(s) > 5 {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(s)
	return n, err == nil && n >= 1 && n <= 65535
}

func (p *Proxy) refuseRaw(conn net.Conn, pr Principal, method string, dec Decision, start time.Time) {
	status := statusFor(dec)
	p.recordRefusal(pr, method, dec, status, start)
	writeRaw(conn, status, reasonPhrase(status, &dec), nil, p.blockResponse(pr, dec))
}

func (p *Proxy) recordRefusal(pr Principal, method string, dec Decision, status int, start time.Time) {
	if dec.Category != CategoryInvalidDestination {
		p.counter.recordBlocked(pr, dec.Host)
	}
	e := p.event(EventBlocked, pr, method, dec)
	e.Status, e.Duration = status, time.Since(start)
	p.emit(e)
}

// dialRefusal turns a policy refusal found at dial time into a decision.
func dialRefusal(dec Decision, de *dialError) Decision {
	source := SourceGuard
	if de.category == CategoryOperatorBlock {
		source = SourceOperator
	}
	refused := blocked(dec, de.category, source, de.rule)
	refused.Reason = strings.ToUpper(de.reason[:1]) + de.reason[1:] + "."
	return refused
}

func (p *Proxy) dialFailedRaw(conn net.Conn, pr Principal, dec Decision, err error, start time.Time) {
	var de *dialError
	if !errors.As(err, &de) {
		de = &dialError{status: http.StatusBadGateway, reason: "connecting to the destination failed"}
	}
	if de.category != "" {
		p.refuseRaw(conn, pr, http.MethodConnect, dialRefusal(dec, de), start)
		return
	}
	p.emitFailed(pr, http.MethodConnect, dec, de.status, de.reason, "", start)
	writeRaw(conn, de.status, reasonPhrase(de.status, nil), nil, unreachableResponse(dec.Host, dec.Port, de.reason))
}

// relay copies bytes both ways until both directions finish, one fails, or
// the tunnel is idle for TunnelIdleTimeout. It reports whether the idle
// timeout ended the tunnel.
func (p *Proxy) relay(t *tunnel, client net.Conn, clientReader io.Reader, upstream net.Conn) bool {
	var last atomic.Int64
	touch := func() { last.Store(time.Now().UnixNano()) }
	touch()
	var idled atomic.Bool
	done := make(chan struct{})
	go watchIdle(p.idle, &last, done, func() {
		idled.Store(true)
		t.close()
	})

	errc := make(chan error, 2)
	go func() {
		errc <- pipe(upstream, clientReader, touch, func(n int) bool {
			v := t.flow.addUp(int64(n), t.exempt)
			if v.signal {
				p.emitLargeUpload(t, v)
			}
			if v.cut {
				t.cut.Store(true)
				return false
			}
			return true
		})
	}()
	go func() {
		errc <- pipe(client, upstream, touch, func(n int) bool {
			t.flow.addDown(int64(n))
			return true
		})
	}()
	for range 2 {
		if err := <-errc; err != nil {
			t.close()
		}
	}
	close(done)
	t.close()
	return idled.Load()
}

var relayBuffers = sync.Pool{New: func() any {
	b := make([]byte, relayBufferSize)
	return &b
}}

// pipe copies src to dst, accounting each chunk before it is written; a
// false account result stops the copy with errLargeUpload. On a clean EOF
// it half-closes dst so the peer sees the end of the stream while the other
// direction keeps flowing.
func pipe(dst net.Conn, src io.Reader, touch func(), account func(int) bool) error {
	bp := relayBuffers.Get().(*[]byte)
	defer relayBuffers.Put(bp)
	buf := *bp
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			touch()
			if !account(n) {
				return errLargeUpload
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
			touch()
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				_ = closeWrite(dst)
				return nil
			}
			return rerr
		}
	}
}

// watchIdle calls onIdle once no activity has been recorded in last for
// idle, checking a few times per idle period, until done is closed.
func watchIdle(idle time.Duration, last *atomic.Int64, done <-chan struct{}, onIdle func()) {
	interval := min(max(idle/4, 10*time.Millisecond), 30*time.Second)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case now := <-ticker.C:
			if now.Sub(time.Unix(0, last.Load())) >= idle {
				onIdle()
				return
			}
		}
	}
}

// ---- events ----------------------------------------------------------------

func (p *Proxy) event(kind EventKind, pr Principal, method string, dec Decision) Event {
	return Event{
		Kind: kind, Time: time.Now(),
		BindingID: pr.BindingID, SandboxID: pr.SandboxID, SandboxName: pr.SandboxName,
		Method: method, Host: dec.Host, Port: dec.Port, Mode: dec.Mode,
		Category: dec.Category, Reason: dec.Reason, Rule: dec.Rule, Source: dec.Source,
		Feed: dec.Feed, FeedVersion: dec.FeedVersion, Entry: dec.Entry,
	}
}

func (p *Proxy) emit(e Event) {
	defer func() { _ = recover() }()
	p.sink.EgressEvent(e)
}

func (p *Proxy) emitAuthFailed(method, target string, start time.Time) {
	host, port := sanitizeHost(target), 0
	if h, pt, err := splitAuthority(target); err == nil {
		host, port = sanitizeHost(h), pt
	}
	p.emit(Event{
		Kind: EventAuthFailed, Time: time.Now(), Method: method, Host: host, Port: port,
		Status: http.StatusProxyAuthRequired, Reason: "invalid proxy credential",
		Duration: time.Since(start),
	})
}

func (p *Proxy) emitFailed(pr Principal, method string, dec Decision, status int, reason, remote string, start time.Time) {
	e := p.event(EventFailed, pr, method, dec)
	e.Status, e.Error, e.RemoteAddr, e.Duration = status, reason, remote, time.Since(start)
	p.emit(e)
}

func (p *Proxy) emitLargeUpload(t *tunnel, v uploadVerdict) {
	e := p.event(EventLargeUpload, t.principal, t.method, t.dec)
	e.TunnelID = t.id
	e.Category, e.Source, e.Reason = CategoryLargeUpload, SourceLimit, p.largeUploadReason()
	e.BytesUp, e.BytesDown = v.total, t.flow.dest.down.Load()
	e.FirstSeen, e.Terminated = true, v.cut
	e.Duration = time.Since(t.started)
	p.emit(e)
}

// ---- limits ----------------------------------------------------------------

// limitListener bounds concurrent connections and drops non-loopback
// peers, which can only appear if someone bypasses Listen.
type limitListener struct {
	net.Listener
	sem  chan struct{}
	done chan struct{}
	once sync.Once
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		select {
		case l.sem <- struct{}{}:
		case <-l.done:
			return nil, net.ErrClosed
		}
		c, err := l.Listener.Accept()
		if err != nil {
			<-l.sem
			return nil, err
		}
		if addr, ok := c.RemoteAddr().(*net.TCPAddr); ok && !addr.IP.IsLoopback() {
			_ = c.Close()
			<-l.sem
			continue
		}
		return &limitConn{Conn: c, release: func() { <-l.sem }}, nil
	}
}

func (l *limitListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func (c *limitConn) CloseWrite() error { return closeWrite(c.Conn) }
