// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

const (
	testRouterHost = "router.example.test"
	testRouterAddr = testRouterHost + ":8444"
	testToken      = "tok-SECRET-0123456789"
)

var testTarget = Target{Atespace: "a6-test", Name: "cc-1"}

// pki is a throwaway CA.
type pki struct {
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	pem   []byte
	nextN int64
}

func newPKI(t *testing.T, cn string) *pki {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &pki{cert: c, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nextN: 2}
}

// issue returns a certificate and key (PEM) signed by the CA.
func (p *pki) issue(t *testing.T, cn string, server bool) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p.nextN++
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(p.nextN), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	if server {
		tmpl.DNSNames = []string{cn}
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.cert, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})
}

// chanListener hands tunneled connections to an http.Server.
type chanListener struct {
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *chanListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *chanListener) Addr() net.Addr { return fakeAddr{} }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "tcp" }
func (fakeAddr) String() string  { return "actor.invalid:8080" }

// fakeRouter is the router's CONNECT-TLS port: TLS 1.3 with a required
// client certificate from its CA, a CONNECT with ate-target-actor, then the
// tunnel to an http.Handler (the relay).
type fakeRouter struct {
	t     *testing.T
	ln    net.Listener
	inner *chanListener
	srv   *http.Server

	mu        sync.Mutex
	connects  int
	targets   []string
	hosts     []string
	tunnels   []net.Conn
	statusFor func(n int) (int, http.Header)
}

func newFakeRouter(t *testing.T, ca *pki, h http.Handler) *fakeRouter {
	t.Helper()
	certPEM, keyPEM := ca.issue(t, testRouterHost, true)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	conf := &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS13}
	ln, err := tls.Listen("tcp", "localhost:0", conf)
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeRouter{t: t, ln: ln, inner: &chanListener{ch: make(chan net.Conn), done: make(chan struct{})}, srv: &http.Server{Handler: h}}
	go r.srv.Serve(r.inner)
	go r.accept()
	t.Cleanup(func() {
		ln.Close()
		r.srv.Close()
		r.dropTunnels()
	})
	return r
}

func (r *fakeRouter) accept() {
	for {
		c, err := r.ln.Accept()
		if err != nil {
			return
		}
		go r.handle(c)
	}
}

func (r *fakeRouter) handle(c net.Conn) {
	tc := c.(*tls.Conn)
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.Handshake(); err != nil {
		tc.Close()
		return
	}
	br := bufio.NewReader(tc)
	req, err := http.ReadRequest(br)
	if err != nil {
		tc.Close()
		return
	}
	r.mu.Lock()
	r.connects++
	n := r.connects
	r.targets = append(r.targets, req.Header.Get("ate-target-actor"))
	r.hosts = append(r.hosts, req.Host)
	sf := r.statusFor
	r.mu.Unlock()
	if req.Method != http.MethodConnect || req.Host != "actor.invalid:8080" || req.Header.Get("ate-target-actor") == "" {
		io.WriteString(tc, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		tc.Close()
		return
	}
	status, hdr := http.StatusOK, http.Header(nil)
	if sf != nil {
		status, hdr = sf(n)
	}
	if status != http.StatusOK {
		fmt.Fprintf(tc, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
		if hdr != nil {
			hdr.Write(tc)
		}
		io.WriteString(tc, "Content-Length: 0\r\n\r\n")
		tc.Close()
		return
	}
	io.WriteString(tc, "HTTP/1.1 200 Connection established\r\n\r\n")
	_ = tc.SetDeadline(time.Time{})
	r.mu.Lock()
	r.tunnels = append(r.tunnels, tc)
	r.mu.Unlock()
	select {
	case r.inner.ch <- &bufConn{Conn: tc, r: br}:
	case <-r.inner.done:
		tc.Close()
	}
}

func (r *fakeRouter) dropTunnels() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.tunnels {
		c.Close()
	}
	r.tunnels = nil
}

func (r *fakeRouter) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.connects
}

// router returns the client side settings that reach this router.
func (r *fakeRouter) router(caFile string) Router {
	addr := r.ln.Addr().String()
	return Router{URL: "https://" + testRouterAddr, CAFile: caFile,
		dial: func(ctx context.Context, network, a string) (net.Conn, error) {
			if a != testRouterAddr {
				return nil, fmt.Errorf("test dial to unexpected %s", a)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
		proxy: func(*http.Request) (*url.URL, error) { return nil, nil },
	}
}

// fakeRelay speaks dcrelay/1 (WebSocket and long-poll) without tmux:
// "DROP" in the input drops the connection, "EXIT" makes the agent exit 7,
// anything else is echoed.
type fakeRelay struct {
	mu        sync.Mutex
	tokens    map[string]bool
	blockWS   int
	wsConns   int
	pollOpens int
	resizes   []relay.Resize
	detaches  int
	inputs    bytes.Buffer
	polls     map[string]*fakePoll
	nextPoll  int
}

func newFakeRelay(tokens ...string) *fakeRelay {
	f := &fakeRelay{tokens: map[string]bool{}, polls: map[string]*fakePoll{}}
	for _, t := range tokens {
		f.tokens[t] = true
	}
	return f
}

func (f *fakeRelay) snapshot() (ws, polls, detaches int, resizes []relay.Resize) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.wsConns, f.pollOpens, f.detaches, append([]relay.Resize(nil), f.resizes...)
}

func (f *fakeRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	ok := f.tokens[relay.TokenFrom(r)]
	block := f.blockWS
	f.mu.Unlock()
	if !ok {
		http.Error(w, "relay: no launcher session token", http.StatusUnauthorized)
		return
	}
	p := r.URL.Path
	switch {
	case p == "/dcrelay/1/ws":
		if block != 0 {
			http.Error(w, "upgrade blocked", block)
			return
		}
		f.serveWS(w, r)
	case p == "/dcrelay/1/status":
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"version": relay.Version, "session": "sess-1", "agent_running": true})
	case p == "/dcrelay/1/poll" && r.Method == http.MethodPost:
		f.pollOpen(w)
	case strings.HasPrefix(p, "/dcrelay/1/poll/"):
		f.pollRoute(w, r, strings.TrimPrefix(p, "/dcrelay/1/poll/"))
	default:
		http.NotFound(w, r)
	}
}

// react applies one client frame.
func (f *fakeRelay) react(frame []byte, send func([]byte)) (end, drop bool) {
	t, p, err := relay.Decode(frame)
	if err != nil {
		return false, false
	}
	switch t {
	case relay.FrameData:
		f.mu.Lock()
		f.inputs.Write(p)
		f.mu.Unlock()
		s := string(p)
		switch {
		case strings.Contains(s, "DROP"):
			return false, true
		case strings.Contains(s, "EXIT"):
			code := 7
			send(relay.EncodeControl(relay.Control{Type: relay.CtlExit, Code: &code}))
			return true, false
		default:
			send(relay.Encode(relay.FrameData, []byte("echo:"+s)))
		}
	case relay.FrameResize:
		if rs, err := relay.DecodeResize(p); err == nil {
			f.mu.Lock()
			f.resizes = append(f.resizes, rs)
			f.mu.Unlock()
		}
	case relay.FrameControl:
		if c, _ := relay.DecodeControl(p); c.Type == relay.CtlDetach {
			f.mu.Lock()
			f.detaches++
			f.mu.Unlock()
			return true, false
		}
	}
	return false, false
}

func (f *fakeRelay) serveWS(w http.ResponseWriter, r *http.Request) {
	up := websocket.Upgrader{Subprotocols: []string{relay.Subprotocol}, CheckOrigin: func(*http.Request) bool { return true }}
	conn, err := up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	f.mu.Lock()
	f.wsConns++
	n := f.wsConns
	if rs, err := relay.DecodeResize([]byte(`{"cols":` + r.URL.Query().Get("cols") + `,"rows":` + r.URL.Query().Get("rows") + `}`)); err == nil {
		f.resizes = append(f.resizes, rs)
	}
	f.mu.Unlock()
	var wmu sync.Mutex
	send := func(b []byte) {
		wmu.Lock()
		defer wmu.Unlock()
		_ = conn.WriteMessage(websocket.BinaryMessage, b)
	}
	send(relay.EncodeControl(relay.Control{Type: relay.CtlHello, Version: relay.Version, Session: "sess-1", Mode: "interact"}))
	send(relay.Encode(relay.FrameData, []byte("screen:"+strconv.Itoa(n)+"\r\n")))
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		end, drop := f.react(msg, send)
		if drop {
			conn.UnderlyingConn().Close()
			return
		}
		if end {
			return
		}
	}
}

type fakePoll struct {
	mu     sync.Mutex
	frames [][]byte
	closed bool
	cursor int
	notify chan struct{}
}

func (p *fakePoll) push(b []byte) {
	p.mu.Lock()
	p.frames = append(p.frames, b)
	p.mu.Unlock()
	select {
	case p.notify <- struct{}{}:
	default:
	}
}

func (p *fakePoll) close() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	select {
	case p.notify <- struct{}{}:
	default:
	}
}

func (f *fakeRelay) pollOpen(w http.ResponseWriter) {
	p := &fakePoll{notify: make(chan struct{}, 1)}
	f.mu.Lock()
	f.pollOpens++
	f.nextPoll++
	id := "p" + strconv.Itoa(f.nextPoll)
	f.polls[id] = p
	f.mu.Unlock()
	p.push(relay.EncodeControl(relay.Control{Type: relay.CtlHello, Version: relay.Version, Session: "sess-1", Mode: "interact"}))
	p.push(relay.Encode(relay.FrameData, []byte("screen:lp\r\n")))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"id": id, "cursor": 0})
}

func (f *fakeRelay) pollRoute(w http.ResponseWriter, r *http.Request, id string) {
	f.mu.Lock()
	p := f.polls[id]
	f.mu.Unlock()
	if p == nil {
		http.Error(w, "relay: no such attachment", http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		deadline := time.After(500 * time.Millisecond)
		for {
			p.mu.Lock()
			if len(p.frames) > 0 || p.closed {
				break
			}
			p.mu.Unlock()
			select {
			case <-p.notify:
			case <-deadline:
				p.mu.Lock()
				goto write
			case <-r.Context().Done():
				return
			}
		}
	write:
		frames := p.frames
		p.frames = nil
		closed := p.closed
		p.cursor += len(frames)
		cur := p.cursor
		p.mu.Unlock()
		w.Header().Set("X-Dcrelay-Cursor", strconv.Itoa(cur))
		if len(frames) == 0 && closed {
			w.WriteHeader(http.StatusGone)
			return
		}
		var body []byte
		for _, fr := range frames {
			body = relay.AppendStream(body, fr)
		}
		w.Write(body)
	case http.MethodPost:
		raw, _ := io.ReadAll(r.Body)
		frames, err := relay.SplitStream(raw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for _, fr := range frames {
			if end, _ := f.react(fr, p.push); end {
				p.close()
				break
			}
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		f.mu.Lock()
		f.detaches++
		f.mu.Unlock()
		p.close()
		w.WriteHeader(http.StatusNoContent)
	}
}

// fakeSessions issues grants.
type fakeSessions struct {
	mu      sync.Mutex
	calls   int
	now     func() time.Time
	life    time.Duration
	cert    []byte
	key     []byte
	err     error
	targets []Target
}

func (s *fakeSessions) Session(ctx context.Context, t Target) (SessionGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.targets = append(s.targets, t)
	if s.err != nil {
		return SessionGrant{}, s.err
	}
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	life := s.life
	if life == 0 {
		life = 5 * time.Minute
	}
	return SessionGrant{Token: testToken, Expires: now().Add(life), ClientCertPEM: s.cert, ClientKeyPEM: s.key}, nil
}

func (s *fakeSessions) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// syncBuf is a goroutine-safe buffer.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// fakeClock is a clock that the injected Sleep advances.
type fakeClock struct {
	mu     sync.Mutex
	t      time.Time
	sleeps []time.Duration
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) sleep(ctx context.Context, d time.Duration) error {
	c.mu.Lock()
	c.sleeps = append(c.sleeps, d)
	c.t = c.t.Add(d)
	c.mu.Unlock()
	return ctx.Err()
}

func (c *fakeClock) slept() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.sleeps...)
}

// rig is one launcher against a fake router and relay.
type rig struct {
	t      *testing.T
	ca     *pki
	caFile string
	router *fakeRouter
	relay  *fakeRelay
	sess   *fakeSessions
	out    *syncBuf
	errb   *syncBuf
	inR    *os.File
	inW    *os.File
	clock  *fakeClock
	sizes  chan relay.Resize
}

func newRig(t *testing.T, h http.Handler) *rig {
	t.Helper()
	ca := newPKI(t, "router-ca")
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, ca.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	fr := newFakeRelay(testToken)
	if h == nil {
		h = fr
	}
	cert, key := ca.issue(t, "launcher", false)
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inR.Close(); inW.Close() })
	return &rig{t: t, ca: ca, caFile: caFile, router: newFakeRouter(t, ca, h), relay: fr,
		sess: &fakeSessions{cert: cert, key: key}, out: &syncBuf{}, errb: &syncBuf{}, inR: inR, inW: inW,
		clock: newFakeClock(), sizes: make(chan relay.Resize, 4)}
}

func (r *rig) options() Options {
	return Options{Target: testTarget, Router: r.router.router(r.caFile), Sessions: r.sess,
		Banner: Banner{Connector: "claudecode", Profile: "default"},
		In:     r.inR, Out: r.out, Err: r.errb,
		Backoff: Backoff{Initial: time.Millisecond, Max: 2 * time.Millisecond, Jitter: -1, MaxAttempts: 4},
		Sleep:   r.clock.sleep, SizeEvents: r.sizes}
}

type attachRun struct {
	res Result
	err error
}

func (r *rig) start(o Options) <-chan attachRun {
	ch := make(chan attachRun, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	r.t.Cleanup(cancel)
	go func() {
		res, err := Attach(ctx, o)
		ch <- attachRun{res, err}
	}()
	return ch
}

func (r *rig) wait(ch <-chan attachRun) attachRun {
	r.t.Helper()
	select {
	case a := <-ch:
		return a
	case <-time.After(20 * time.Second):
		r.t.Fatal("Attach did not return")
	}
	return attachRun{}
}

func (r *rig) typ(s string) {
	r.t.Helper()
	if _, err := r.inW.Write([]byte(s)); err != nil {
		r.t.Fatal(err)
	}
}

// noSecrets fails when s carries the session token or PEM material.
func noSecrets(t *testing.T, what, s string) {
	t.Helper()
	for _, bad := range []string{testToken, "PRIVATE KEY", "BEGIN CERTIFICATE", "Bearer"} {
		if strings.Contains(s, bad) {
			t.Fatalf("%s leaks %q: %q", what, bad, s)
		}
	}
}
