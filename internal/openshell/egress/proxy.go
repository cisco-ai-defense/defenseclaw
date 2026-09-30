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
	"bytes"
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
	"net/netip"
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
	DefaultMaxConnsPerBinding    = 256
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
	// Decider makes the allow/block decisions for principals without a
	// decider of their own (Principal.Decider); SetDecider swaps it live.
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

	// HeaderTimeout bounds reading a request's headers (slowloris), and,
	// once their first byte arrived, a tunnel's first flight (a TLS
	// ClientHello or HTTP request line) and each HTTP request head in it.
	HeaderTimeout time.Duration
	// IdleTimeout closes keep-alive client connections idle between
	// requests, and idle pooled upstream connections.
	IdleTimeout time.Duration
	// TunnelIdleTimeout closes a tunnel after this long without bytes in
	// either direction, and fails a forwarded request whose client or
	// upstream connection moved no bytes for that long (a stalled request
	// or response body).
	TunnelIdleTimeout time.Duration
	// DialTimeout bounds DNS plus connect for each upstream attempt.
	DialTimeout time.Duration
	// ResponseHeaderTimeout bounds waiting for an absolute-form upstream's
	// response headers.
	ResponseHeaderTimeout time.Duration
	// MaxHeaderBytes bounds request headers; larger requests get a 431 (a
	// 400 inside a tunnel carrying HTTP).
	MaxHeaderBytes int
	// MaxConns bounds concurrent client connections across all listeners.
	// With all of them taken, a new connection displaces the oldest one no
	// request was admitted on yet (silent, slow or unauthenticated), else
	// the one idle longest between keep-alive requests; it waits only while
	// every connection carries a request or tunnel.
	MaxConns int
	// MaxConnsPerBinding bounds one binding's client connections, counted
	// once a request on them is admitted: open tunnels plus idle keep-alive
	// connections. Over it the binding's longest-idle connections are
	// closed; a request that would exceed it with none idle gets a 429.
	// Negative disables the limit. A connection no request was admitted on
	// (unauthenticated or refused) is closed after its response, so before
	// authenticating it holds a slot for at most HeaderTimeout, and only
	// until a new connection needs the slot.
	MaxConnsPerBinding int
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
	// gen is the current decider with its upstream transport.
	gen     atomic.Pointer[generation]
	auth    Authenticator
	sink    EventSink
	counter *Counter
	dialer  *guardDialer
	hint    func(Principal, Decision) string
	idle    time.Duration
	// headerTimeout bounds reading a tunnel's first flight and the head of
	// each HTTP request inside it; maxHeaderBytes bounds those heads.
	headerTimeout  time.Duration
	maxHeaderBytes int

	srv *http.Server
	// upstream is the template each generation's transport is cloned from.
	upstream  *http.Transport
	forwarder *httputil.ReverseProxy
	limits    *bindingLimits
	sem       chan struct{}
	conns     *connTracker

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
	if opts.MaxConnsPerBinding == 0 {
		opts.MaxConnsPerBinding = DefaultMaxConnsPerBinding
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
		auth:           opts.Auth,
		sink:           opts.Sink,
		counter:        opts.Counter,
		dialer:         &guardDialer{resolver: opts.Resolver, dialer: opts.Dialer, timeout: opts.DialTimeout, local: hostAddrs},
		hint:           opts.UnblockHint,
		idle:           opts.TunnelIdleTimeout,
		headerTimeout:  opts.HeaderTimeout,
		maxHeaderBytes: opts.MaxHeaderBytes,
		limits:         newBindingLimits(opts.MaxTunnelsPerBinding, opts.TunnelsPerSecond, opts.TunnelBurst),
		sem:            make(chan struct{}, opts.MaxConns),
		conns:          newConnTracker(opts.MaxConnsPerBinding),
		tunnels:        map[*tunnel]struct{}{},
	}
	p.ctx, p.cancel = context.WithCancel(context.Background())

	p.upstream = &http.Transport{
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
	p.gen.Store(p.newGeneration(opts.Decider))
	p.forwarder = &httputil.ReverseProxy{
		Rewrite:        p.rewrite,
		Transport:      roundTripperFunc(p.roundTrip),
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
		ConnContext:       withConn,
		ConnState:         p.connState,
	}
	return p, nil
}

// generation pairs a decider with the upstream transport whose pooled
// connections were dialed under it, so a connection that passed an older
// decider's dial-time checks never carries a request a newer one decided.
type generation struct {
	decider   *Decider
	transport *http.Transport
}

func (p *Proxy) newGeneration(d *Decider) *generation {
	return &generation{decider: d, transport: p.upstream.Clone()}
}

// Decider returns the current default decider.
func (p *Proxy) Decider() *Decider { return p.gen.Load().decider }

// deciderFor is the decider that decides pr's requests: its own, else the
// default of gen.
func deciderFor(pr Principal, gen *generation) *Decider {
	if pr.Decider != nil {
		return pr.Decider
	}
	return gen.decider
}

// SetDecider swaps the default decider for principals without their own,
// for example after a configuration reload, and rechecks every open tunnel
// and in-flight request (Recheck), so the new decider also reaches the
// tunnels it now refuses. Upstream connections pooled under the old
// generation are closed and never reused, so the dial-time checks (CIDR
// blocks on the resolved address) in force now apply to every later
// request. A sandbox manager that gives every principal its own decider
// calls it after re-registering them, to retire the pooled connections too.
func (p *Proxy) SetDecider(d *Decider) error {
	if d == nil {
		return errors.New("egress: nil decider")
	}
	old := p.gen.Swap(p.newGeneration(d))
	old.transport.CloseIdleConnections()
	p.Recheck("")
	return nil
}

// Recheck applies the current credentials and policy to the open tunnels
// and in-flight forwarded requests of bindingID, or of every binding when
// bindingID is empty. A tunnel is otherwise decided only when it opens, and
// traffic keeps it open well past TunnelIdleTimeout. Each one is
// authenticated again with the credential it presented and decided again
// by the decider of the principal that credential maps to now (its own,
// else the default): its destination, the address it is connected to, and
// the TLS server name it asked for. Those whose credential was revoked or
// replaced, or which that decision now refuses, are closed; a refusal is
// reported as a blocked event with the tunnel's id. It returns how many it
// closed.
//
// The sandbox manager calls it whenever it revokes or re-registers a
// binding's credential: a sandbox that fails closed or goes to the deny
// network mode, or whose policy an administrator tightened.
func (p *Proxy) Recheck(bindingID string) int {
	p.mu.Lock()
	open := make([]*tunnel, 0, len(p.tunnels))
	for t := range p.tunnels {
		// A tunnel refused for its content is ending already.
		if (bindingID == "" || t.principal.BindingID == bindingID) && !t.refused.Load() {
			open = append(open, t)
		}
	}
	p.mu.Unlock()
	ended := 0
	for _, t := range open {
		if v := p.revise(t); !v.keep() && p.endRevised(t, v) {
			ended++
		}
	}
	return ended
}

// revokedReason is the closed event's reason for a tunnel or request a
// recheck ended (Recheck).
const revokedReason = "closed: the sandbox's egress policy no longer allows it"

// revision is a recheck's verdict on an open tunnel or request.
type revision struct {
	// revoked: the credential no longer authenticates as the tunnel's
	// binding.
	revoked bool
	// refusal is the decision that now refuses it.
	refusal *Decision
}

func (v revision) keep() bool { return !v.revoked && v.refusal == nil }

// revise decides t again under the principal its credential maps to now
// and that principal's decider (its own, else the current default), and
// makes that the tunnel's policy. The address and server name are read
// after the policy is replaced, and recorded before it is read
// (connectedTo, sawServerName), so each of them is checked under the new
// policy by one side or the other.
func (p *Proxy) revise(t *tunnel) revision {
	pr, ok := p.auth.Authenticate(t.cred.Username, t.cred.Password)
	if !ok || pr.BindingID != t.principal.BindingID {
		if spr, off, found := p.suspended(t.cred.Username, t.cred.Password); found && spr.BindingID == t.principal.BindingID {
			// The policy turned the sandbox's egress off: the tunnel ends
			// with the reason, not as a revoked credential.
			dec := off
			dec.Allowed, dec.Unblockable = false, false
			dec.Host, dec.Port = t.dec.Host, t.dec.Port
			return revision{refusal: &dec}
		}
		return revision{revoked: true}
	}
	d := deciderFor(pr, p.gen.Load())
	dec := d.Decide(pr, t.dec.Host, t.dec.Port)
	if !dec.Allowed {
		return revision{refusal: &dec}
	}
	t.policyMu.Lock()
	t.pol = tunnelPolicy{pr: pr, d: d, dec: dec}
	remote, name := t.remote, t.serverName
	t.policyMu.Unlock()
	t.exempt.Store(exemptFromUploadBlock(dec))
	if remote.IsValid() {
		if de := d.dialRules(pr, dec).check(remote, p.dialer.local); de != nil {
			refused := dialRefusal(d, dec, de)
			return revision{refusal: &refused}
		}
	}
	if refused, ok := serverNameRefusal(t, pr, d, name); ok {
		return revision{refusal: &refused}
	}
	return revision{}
}

// endRevised ends t for a recheck's verdict v, reporting a refusal, unless
// something already ended it. It reports whether it did.
func (p *Proxy) endRevised(t *tunnel, v revision) bool {
	if !t.ended.CompareAndSwap(nil, &v) {
		return false
	}
	if dec := v.refusal; dec != nil {
		p.recordRefusal(t.principal, t.method, *dec, statusFor(*dec), t.started, t.id)
	}
	t.end()
	return true
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
	return p.srv.Serve(&limitListener{Listener: ln, sem: p.sem, conns: p.conns, done: make(chan struct{})})
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
	p.gen.Load().transport.CloseIdleConnections()
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
	p.gen.Load().transport.CloseIdleConnections()
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

// BindingActivity reports a binding's open tunnels and in-flight forwarded
// requests and the bytes they moved so far, both ways: what a caller that is
// about to close the binding's connections (an OpenShell policy reload) can
// watch for a quiet moment.
func (p *Proxy) BindingActivity(bindingID string) (open int, moved int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for t := range p.tunnels {
		if t.principal.BindingID == bindingID {
			open++
			moved += t.flow.up.Load() + t.flow.down.Load()
		}
	}
	return open, moved
}

// tunnel is one open CONNECT tunnel or forwarded request.
type tunnel struct {
	id string
	// principal and dec are what the tunnel opened with; host and port
	// never change, and events carry them.
	principal Principal
	method    string
	dec       Decision
	started   time.Time
	flow      *flow
	// cred is the proxy credential the tunnel authenticated with, which a
	// recheck authenticates again. Never logged (Credential redacts).
	cred Credential
	// cancel ends a forwarded request's upstream exchange; nil for CONNECT.
	cancel context.CancelFunc
	// exempt: the large-upload block only signals (exemptFromUploadBlock).
	exempt atomic.Bool
	cut    atomic.Bool
	// idled marks a tunnel or request ended by TunnelIdleTimeout.
	idled atomic.Bool
	// refused marks a CONNECT tunnel ended for its TLS server name or its
	// plaintext content.
	refused atomic.Bool
	// ended is the verdict of the recheck that ended the tunnel or request
	// (Recheck): its credential was revoked, or its policy now refuses it.
	ended atomic.Pointer[revision]

	// policyMu guards what a recheck revises and what it checks again.
	policyMu sync.Mutex
	pol      tunnelPolicy
	// remote is the upstream address the tunnel or request is connected
	// to, once known.
	remote netip.Addr
	// serverName is the TLS server name a CONNECT tunnel's ClientHello
	// asked for, once screened.
	serverName string

	closeMu sync.Mutex
	// closeFn force-closes the tunnel's connections. It stays nil while the
	// HTTP server owns them (plain forwarded requests, which a recheck ends
	// through cancel) and is set once a CONNECT is established or a
	// forwarded request upgrades.
	closeFn func()
	closed  bool
}

// tunnelPolicy is what decides an open tunnel: the principal its
// credential maps to, that principal's decider (its own, else the
// default), and the decision the decider made. A recheck replaces it.
type tunnelPolicy struct {
	pr  Principal
	d   *Decider
	dec Decision
}

func newTunnel(pr Principal, cred Credential, d *Decider, method string, dec Decision, start time.Time, flow *flow) *tunnel {
	t := &tunnel{
		id: newTunnelID(), principal: pr, method: method, dec: dec, started: start, flow: flow, cred: cred,
		pol: tunnelPolicy{pr: pr, d: d, dec: dec},
	}
	t.exempt.Store(exemptFromUploadBlock(dec))
	return t
}

// policy returns the tunnel's current policy.
func (t *tunnel) policy() tunnelPolicy {
	t.policyMu.Lock()
	defer t.policyMu.Unlock()
	return t.pol
}

// connectedTo records the upstream address and returns the policy to
// check it with.
func (t *tunnel) connectedTo(addr netip.Addr) tunnelPolicy {
	t.policyMu.Lock()
	defer t.policyMu.Unlock()
	t.remote = addr.Unmap()
	return t.pol
}

// sawServerName records the TLS server name and returns the policy to
// decide it with.
func (t *tunnel) sawServerName(name string) tunnelPolicy {
	t.policyMu.Lock()
	defer t.policyMu.Unlock()
	t.serverName = name
	return t.pol
}

// terminated reports a tunnel or request the proxy cut short: the
// large-upload block, the idle timeout, a refusal inside the tunnel, or a
// recheck.
func (t *tunnel) terminated() bool {
	return t.cut.Load() || t.idled.Load() || t.refused.Load() || t.ended.Load() != nil
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

// end force-closes the tunnel's connections and cancels a forwarded
// request's upstream exchange, which ends it whether or not its response
// began.
func (t *tunnel) end() {
	if t.cancel != nil {
		t.cancel()
	}
	t.close()
}

// closeIdle ends the tunnel for TunnelIdleTimeout.
func (t *tunnel) closeIdle() {
	t.idled.Store(true)
	t.close()
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
// whether the request carried any Proxy-Authorization at all. A credential
// the authenticator suspended (SuspendingAuthenticator) is not ok, but
// comes with its principal and the refusal to answer it with (off).
func (p *Proxy) authenticate(r *http.Request) (pr Principal, cred Credential, presented, ok bool, off *Decision) {
	values := r.Header.Values("Proxy-Authorization")
	if len(values) == 0 {
		return Principal{}, Credential{}, false, false, nil
	}
	user, pass, parsed := parseProxyAuthorization(values)
	if !parsed {
		return Principal{}, Credential{}, true, false, nil
	}
	pr, ok = p.auth.Authenticate(user, pass)
	if !ok || strings.TrimSpace(pr.BindingID) == "" {
		if spr, dec, found := p.suspended(user, pass); found {
			return spr, Credential{}, true, false, &dec
		}
		return Principal{}, Credential{}, true, false, nil
	}
	return pr, Credential{Username: user, Password: pass}, true, true, nil
}

// suspended looks up a suspended credential (SuspendingAuthenticator).
func (p *Proxy) suspended(user, pass string) (Principal, Decision, bool) {
	sa, ok := p.auth.(SuspendingAuthenticator)
	if !ok {
		return Principal{}, Decision{}, false
	}
	pr, dec, found := sa.Suspended(user, pass)
	if !found || strings.TrimSpace(pr.BindingID) == "" {
		return Principal{}, Decision{}, false
	}
	return pr, dec, true
}

// suspendedRefusal is the refusal of a request to target from a suspended
// credential: off, for that destination.
func suspendedRefusal(off Decision, target string) Decision {
	dec := off
	dec.Allowed, dec.Unblockable = false, false
	if host, port, err := splitAuthority(target); err == nil {
		dec.Host, dec.Port = sanitizeHost(host), port
	} else {
		dec.Host = sanitizeHost(target)
	}
	return dec
}

// confirmTracked rechecks a tunnel or request once it is tracked, since a
// recheck that ran after it authenticated but before it was tracked did not
// see it. It returns nil to go on, else the verdict that ended it; mine
// reports that this check ended it, so the refusal is the caller's to
// report (a concurrent Recheck reports its own).
func (p *Proxy) confirmTracked(t *tunnel) (v *revision, mine bool) {
	if rv := p.revise(t); !rv.keep() && t.ended.CompareAndSwap(nil, &rv) {
		return &rv, true
	}
	return t.ended.Load(), false
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
// allowed decision d made, and attributes r's client connection to the
// binding. It returns a release func, or a refusal.
func (p *Proxy) admit(r *http.Request, pr Principal, d *Decider, dec Decision) (func(), *Decision) {
	release, why := p.limits.acquire(pr.BindingID)
	if release == nil {
		refused := blocked(dec, CategoryRateLimited, SourceLimit, "")
		refused.Reason = why
		return nil, &refused
	}
	if why, ok := p.claimConn(r, pr); !ok {
		release()
		refused := blocked(dec, CategoryRateLimited, SourceLimit, "")
		refused.Reason = why
		return nil, &refused
	}
	if !exemptFromUploadBlock(dec) && p.counter.uploadBlocked(pr, dec.Host) {
		release()
		refused := p.largeUploadRefusal(pr, d, dec, "")
		return nil, &refused
	}
	return release, nil
}

// largeUploadRefusal is dec, made by d for pr, refused by the large-upload
// block; scope names the domain or address total that crossed, empty for
// the destination's own. An unblock of the destination lifts the block.
func (p *Proxy) largeUploadRefusal(pr Principal, d *Decider, dec Decision, scope string) Decision {
	refused := blocked(dec, CategoryLargeUpload, SourceLimit, "")
	refused.Reason, refused.Unblockable = p.largeUploadReason(pr), d.UnblocksAllowed()
	if scope != "" {
		refused.Reason = p.largeUploadScopeReason(pr, scope)
	}
	return refused
}

// exemptFromUploadBlock: destinations the user unblocked, or the operator
// or administrator allowed, are trusted enough that a large upload only
// raises the signal.
func exemptFromUploadBlock(dec Decision) bool {
	return dec.Source == SourceUnblock || dec.Source == SourceOperator || dec.Source == SourceAdmin
}

func (p *Proxy) largeUploadReason(pr Principal) string {
	return fmt.Sprintf("More than %s was sent to a destination this sandbox had not contacted before.", FormatThreshold(p.counter.thresholdFor(pr)))
}

func (p *Proxy) largeUploadScopeReason(pr Principal, scope string) string {
	return fmt.Sprintf("More than %s was sent to %s this sandbox had not contacted before.",
		FormatThreshold(p.counter.thresholdFor(pr)), scope)
}

// FormatThreshold is a large-upload threshold as refusals and events name
// it: "25 MiB", or "1500 bytes" when it is not a whole number of MiB.
func FormatThreshold(n int64) string {
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
	pr, cred, presented, ok, off := p.authenticate(r)
	if off != nil {
		p.refuseRaw(conn, pr, http.MethodConnect, suspendedRefusal(*off, target), start)
		return
	}
	if !ok {
		p.challenged(presented, http.MethodConnect, target, start)
		writeAuthRequired(conn)
		return
	}
	d := deciderFor(pr, p.gen.Load())
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
	release, refusal := p.admit(r, pr, d, dec)
	if refusal != nil {
		p.refuseRaw(conn, pr, http.MethodConnect, *refusal, start)
		return
	}
	defer release()

	upstream, remote, err := p.dialer.dial(p.ctx, dec.Host, dec.Port, d.dialRules(pr, dec))
	if err != nil {
		p.dialFailedRaw(conn, pr, d, dec, err, start)
		return
	}
	flow, first := p.counter.open(pr, dec.Host, remote.Addr())
	defer flow.close()
	exempt := exemptFromUploadBlock(dec)
	if scope, refused := flow.uploadRefused(exempt); refused {
		// A total the tunnel counts toward (its address's, say) already
		// crossed the threshold, so its first upload chunk would be cut:
		// refuse it now, with a body and an event, instead of cutting it
		// silently after the 200.
		_ = upstream.Close()
		p.refuseRaw(conn, pr, http.MethodConnect, p.largeUploadRefusal(pr, d, dec, scope), start)
		return
	}
	t := newTunnel(pr, cred, d, http.MethodConnect, dec, start, flow)
	t.connectedTo(remote.Addr())
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
	if v, mine := p.confirmTracked(t); v != nil {
		// The credential was revoked or the policy changed while the
		// tunnel was being dialed. A concurrent Recheck that ended it
		// closed the connection already, so these writes fail quietly.
		_ = upstream.Close()
		switch {
		case v.refusal == nil:
			if mine {
				p.emitAuthFailed(http.MethodConnect, target, start)
			}
			writeAuthRequired(conn)
		case mine:
			p.refuseRaw(conn, pr, http.MethodConnect, *v.refusal, start)
		default:
			status := statusFor(*v.refusal)
			writeRaw(conn, status, reasonPhrase(status, v.refusal), nil, p.blockResponse(pr, *v.refusal))
		}
		return
	}

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

	p.relay(t, conn, brw.Reader, upstream)

	closed := p.event(EventClosed, pr, http.MethodConnect, dec)
	closed.TunnelID, closed.RemoteAddr, closed.Status = t.id, remote.String(), http.StatusOK
	closed.BytesUp, closed.BytesDown, closed.Duration = flow.up.Load(), flow.down.Load(), time.Since(start)
	closed.Terminated = t.terminated()
	if t.ended.Load() != nil {
		closed.Reason = revokedReason
	}
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
	p.recordRefusal(pr, method, dec, status, start, "")
	writeRaw(conn, status, reasonPhrase(status, &dec), nil, p.blockResponse(pr, dec))
}

// recordRefusal counts and reports a refusal; tunnelID is set when an
// established tunnel was refused. An invalid destination counts like any
// other refusal, under the host the event names: the feed shows it as a
// blocked destination, and the counts must agree with the feed. The
// refusal-only records are capped (CounterOptions.MaxDestinations), so a
// flood of made-up names costs nothing else.
func (p *Proxy) recordRefusal(pr Principal, method string, dec Decision, status int, start time.Time, tunnelID string) {
	if dec.Host != "" {
		p.counter.recordBlocked(pr, dec.Host)
	}
	e := p.event(EventBlocked, pr, method, dec)
	e.TunnelID, e.Status, e.Duration = tunnelID, status, time.Since(start)
	p.emit(e)
}

// dialRefusal turns a policy refusal found at dial time for a destination
// d decided as dec into a decision.
func dialRefusal(d *Decider, dec Decision, de *dialError) Decision {
	source := SourceGuard
	switch {
	case de.category == CategoryAdminBlock:
		source = SourceAdmin
	case de.category == CategoryOperatorBlock:
		source = SourceOperator
	case de.feed != nil:
		source = SourceFeed
	}
	refused := blocked(dec, de.category, source, de.rule)
	refused.Reason = strings.ToUpper(de.reason[:1]) + de.reason[1:] + "."
	if m := de.feed; m != nil {
		// As for a feed match in Decide: an unblock of the name lifts it.
		refused.Reason += " " + m.Entry.Reason
		refused.Feed, refused.FeedVersion, refused.Entry = m.Feed.Name, m.Feed.Version, m.Entry.Name
		refused.Unblockable = d.UnblocksAllowed()
	}
	return refused
}

func (p *Proxy) dialFailedRaw(conn net.Conn, pr Principal, d *Decider, dec Decision, err error, start time.Time) {
	var de *dialError
	if !errors.As(err, &de) {
		de = &dialError{status: http.StatusBadGateway, reason: "connecting to the destination failed"}
	}
	if de.category != "" {
		p.refuseRaw(conn, pr, http.MethodConnect, dialRefusal(d, dec, de), start)
		return
	}
	p.emitFailed(pr, http.MethodConnect, dec, de.status, de.reason, "", start)
	writeRaw(conn, de.status, reasonPhrase(de.status, nil), nil, unreachableResponse(dec.Host, dec.Port, de.reason))
}

// relay copies bytes both ways until both directions finish, one fails, or
// the tunnel is idle for TunnelIdleTimeout. The client's first flight is
// screened before anything reaches the upstream (screenFirstFlight); a
// tunnel carrying HTTP/1.x has its requests inspected one by one.
func (p *Proxy) relay(t *tunnel, client net.Conn, clientReader io.Reader, upstream net.Conn) {
	var last atomic.Int64
	touch := func() { last.Store(time.Now().UnixNano()) }
	touch()
	done := make(chan struct{})
	go watchIdle(p.idle, &last, done, t.closeIdle)

	up := func(n int) bool {
		v := t.flow.addUp(int64(n), t.exempt.Load())
		if v.signal {
			p.emitLargeUpload(t, v)
		}
		if v.cut {
			t.cut.Store(true)
			return false
		}
		return true
	}
	hs := newHTTPSession()
	errc := make(chan error, 2)
	go func() {
		first, kind, err := p.screenFirstFlight(t, client, clientReader)
		if err != nil {
			errc <- err
			return
		}
		src := clientReader
		if len(first) > 0 {
			src = io.MultiReader(bytes.NewReader(first), clientReader)
		}
		if kind == flightHTTP {
			hs.start(upstream)
			errc <- p.relayRequests(t, client, src, upstream, touch, up, hs)
			return
		}
		errc <- pipe(upstream, src, touch, up)
	}()
	go func() {
		errc <- p.relayDown(t, client, upstream, touch, hs)
	}()
	for range 2 {
		if err := <-errc; err != nil {
			t.close()
		}
	}
	close(done)
	t.close()
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
		Unblockable: kind == EventBlocked && dec.Unblockable,
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
	e.Category, e.Source, e.Reason = CategoryLargeUpload, SourceLimit, p.largeUploadReason(t.principal)
	if v.scope != "" {
		e.Reason = p.largeUploadScopeReason(t.principal, v.scope)
	}
	e.BytesUp, e.Threshold = v.total, p.counter.thresholdFor(t.principal)
	if d := t.flow.dest.Load(); d != nil {
		e.BytesDown = d.down.Load()
	}
	e.FirstSeen, e.Terminated = true, v.cut
	if v.cut {
		// As for the refusals that follow (largeUploadRefusal): an unblock
		// of the destination lifts the block.
		e.Unblockable = t.policy().d.UnblocksAllowed()
	}
	e.Duration = time.Since(t.started)
	p.emit(e)
}
