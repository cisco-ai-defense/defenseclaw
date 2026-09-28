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
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// must fails the test on an unexpected error.
func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// fakeResolver answers from a table. A host with several answer sets
// returns them in turn (the last one repeats), which models rebinding.
// Names are looked up without their trailing dot; asked records the names
// exactly as the proxy passed them.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][][]string
	errs    map[string]error
	calls   map[string]int
	asked   []string
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{answers: map[string][][]string{}, errs: map[string]error{}, calls: map[string]int{}}
}

func (r *fakeResolver) set(host string, answers ...[]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.answers[host] = answers
}

func (r *fakeResolver) fail(host string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errs[host] = err
}

func (r *fakeResolver) callCount(host string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[host]
}

// names returns the names the resolver was asked for, as asked.
func (r *fakeResolver) names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.asked)
}

func (r *fakeResolver) LookupIPAddr(ctx context.Context, name string) ([]net.IPAddr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.asked = append(r.asked, name)
	host := strings.TrimSuffix(name, ".")
	n := r.calls[host]
	r.calls[host] = n + 1
	if err := r.errs[host]; err != nil {
		return nil, err
	}
	sets, ok := r.answers[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	set := sets[min(n, len(sets)-1)]
	out := make([]net.IPAddr, 0, len(set))
	for _, s := range set {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

// mapDialer records every address it is asked to dial and connects to the
// local listener registered for the destination port instead.
type mapDialer struct {
	mu      sync.Mutex
	targets map[int]string
	fail    map[string]error
	hang    map[string]bool
	dialed  []string
	// onDial, when set, runs before each dial (to hold one while a test
	// changes the proxy's policy).
	onDial func(address string)
}

func newMapDialer() *mapDialer {
	return &mapDialer{targets: map[int]string{}, fail: map[string]error{}, hang: map[string]bool{}}
}

func (d *mapDialer) route(port int, target string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.targets[port] = target
}

func (d *mapDialer) setOnDial(fn func(address string)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.onDial = fn
}

func (d *mapDialer) addresses() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.dialed)
}

func (d *mapDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(portText)
	d.mu.Lock()
	d.dialed = append(d.dialed, address)
	failErr, hang, target, onDial := d.fail[host], d.hang[host], d.targets[port], d.onDial
	d.mu.Unlock()
	if onDial != nil {
		onDial(address)
	}
	if net.ParseIP(host) == nil {
		return nil, fmt.Errorf("mapDialer: asked to dial non-literal %q", address)
	}
	if failErr != nil {
		return nil, failErr
	}
	if hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if target == "" {
		return nil, errors.New("mapDialer: connection refused")
	}
	var nd net.Dialer
	return nd.DialContext(ctx, "tcp", target)
}

// recordingSink collects events.
type recordingSink struct {
	mu     sync.Mutex
	events []Event
}

func (s *recordingSink) EgressEvent(e Event) {
	s.mu.Lock()
	s.events = append(s.events, e)
	s.mu.Unlock()
}

func (s *recordingSink) ofKind(kind EventKind) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Event
	for _, e := range s.events {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// wait polls until n events of kind arrived and returns them.
func (s *recordingSink) wait(t *testing.T, kind EventKind, n int) []Event {
	t.Helper()
	var got []Event
	eventually(t, fmt.Sprintf("%d %q events", n, kind), func() bool { got = s.ofKind(kind); return len(got) >= n })
	return got
}

// harness runs a Proxy on a loopback listener with fake DNS and dialing.
type harness struct {
	t        *testing.T
	proxy    *Proxy
	addr     string
	creds    *CredentialStore
	cred     Credential
	pr       Principal
	sink     *recordingSink
	resolver *fakeResolver
	dialer   *mapDialer
	unblocks *MemoryUnblocks
	// local is the fake interface list (ownV4, ownV6) the decider and the
	// dialer see instead of the test machine's.
	local  *localAddrs
	served chan error
}

type harnessConfig struct {
	opts    Options
	decider DeciderOptions
	counter *CounterOptions
	// sink replaces the recording sink when set.
	sink EventSink
}

// uploadBlock configures a harness to block large uploads past n bytes.
func uploadBlock(n int64) func(*harnessConfig) {
	return func(c *harnessConfig) { c.counter = &CounterOptions{LargeUploadBytes: n, BlockLargeUploads: true} }
}

func newHarness(t *testing.T, configure func(*harnessConfig)) *harness {
	t.Helper()
	h := &harness{
		t:        t,
		creds:    NewCredentialStore(),
		sink:     &recordingSink{},
		resolver: newFakeResolver(),
		dialer:   newMapDialer(),
		local:    fixedLocalAddrs(ownV4, ownV6),
		served:   make(chan error, 1),
	}
	var err error
	h.unblocks, err = NewMemoryUnblocks()
	must(t, err)
	h.resolver.set("example.com", []string{publicV4})
	h.resolver.set("webhook.site", []string{publicV4Alt})

	cfg := &harnessConfig{decider: DeciderOptions{Unblocks: h.unblocks}}
	if configure != nil {
		configure(cfg)
	}
	decider := h.newDecider(cfg.decider)
	opts := cfg.opts
	opts.Auth, opts.Decider, opts.Sink = h.creds, decider, h.sink
	if cfg.sink != nil {
		opts.Sink = cfg.sink
	}
	opts.Resolver, opts.Dialer = h.resolver, h.dialer
	if cfg.counter != nil {
		opts.Counter = NewCounter(*cfg.counter)
	}
	if h.proxy, err = New(opts); err != nil {
		t.Fatalf("New: %v", err)
	}
	h.proxy.dialer.local = h.local

	h.pr = Principal{BindingID: "binding-one", SandboxID: "sb-1", SandboxName: "sb-one"}
	h.cred = h.addPrincipal(h.pr)

	ln, err := Listen("127.0.0.1:0")
	must(t, err)
	h.addr = ln.Addr().String()
	go func() { h.served <- h.proxy.Serve(ln) }()
	t.Cleanup(func() { _ = h.proxy.Close() })
	return h
}

// newDecider builds a decider that sees the harness's fake interfaces.
func (h *harness) newDecider(opts DeciderOptions) *Decider {
	h.t.Helper()
	d := mustDecider(h.t, opts)
	d.local = h.local
	return d
}

// addPrincipal registers another sandbox and returns its credential.
func (h *harness) addPrincipal(pr Principal) Credential {
	h.t.Helper()
	cred, err := NewCredential()
	must(h.t, err)
	must(h.t, h.creds.Register(cred, pr))
	return cred
}

// serve runs an HTTP upstream the dialer reaches on port.
func (h *harness) serve(port int, handler http.HandlerFunc) *httptest.Server {
	s := httptest.NewServer(handler)
	h.t.Cleanup(s.Close)
	h.dialer.route(port, s.Listener.Addr().String())
	return s
}

// answerOK is an upstream handler that answers "ok".
func answerOK(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "ok") }

// clientFor returns an http.Client that sends everything through the proxy
// with cred, trusting the httptest TLS upstream.
func (h *harness) clientFor(cred Credential, upstream *httptest.Server) *http.Client {
	proxyURL, err := url.Parse(cred.ProxyURL("127.0.0.1", h.port()))
	must(h.t, err)
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), ForceAttemptHTTP2: true}
	if upstream != nil && upstream.TLS != nil {
		pool := x509.NewCertPool()
		pool.AddCert(upstream.Certificate())
		tr.TLSClientConfig = &tls.Config{RootCAs: pool}
	}
	h.t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func (h *harness) port() int {
	_, p, _ := net.SplitHostPort(h.addr)
	n, _ := strconv.Atoi(p)
	return n
}

func basicAuth(c Credential) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password))
}

func decodeBlock(t *testing.T, body []byte) BlockResponse {
	t.Helper()
	var b BlockResponse
	if err := json.Unmarshal(body, &b); err != nil {
		t.Fatalf("block body %q: %v", body, err)
	}
	return b
}

// fetch GETs u with client and returns the response and its body.
func fetch(t *testing.T, client *http.Client, u string) (*http.Response, []byte) {
	t.Helper()
	resp, err := client.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, body
}

// readResponse reads one response and its body off br.
func readResponse(t *testing.T, br *bufio.Reader) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, body
}

// sendGet writes an absolute-form GET of u with cred and the extra header
// lines on conn.
func sendGet(conn net.Conn, cred Credential, u, extra string) {
	host := u
	if parsed, err := url.Parse(u); err == nil {
		host = parsed.Host
	}
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\n%sProxy-Authorization: %s\r\n\r\n", u, host, extra, basicAuth(cred))
}

// get sends an absolute-form GET of u on a new client connection and reads
// the response, leaving the connection open for more requests.
func (h *harness) get(cred Credential, u, extra string) (net.Conn, *bufio.Reader, *http.Response, []byte) {
	h.t.Helper()
	conn, br := h.dialProxy()
	sendGet(conn, cred, u, extra)
	resp, body := readResponse(h.t, br)
	return conn, br, resp, body
}

// rawResponse is a proxy response read off a raw connection.
type rawResponse struct {
	status int
	reason string
	header textproto.MIMEHeader
	body   []byte
}

// dialProxy opens a raw client connection to the proxy.
func (h *harness) dialProxy() (net.Conn, *bufio.Reader) {
	h.t.Helper()
	conn, err := net.DialTimeout("tcp", h.addr, 5*time.Second)
	must(h.t, err)
	h.t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return conn, bufio.NewReader(conn)
}

// connect sends a CONNECT with the given Proxy-Authorization value (empty
// for none) plus any extra bytes, and reads the proxy's response head (and
// body for refusals).
func (h *harness) connect(target, auth string, extra []byte) (net.Conn, *bufio.Reader, rawResponse) {
	h.t.Helper()
	conn, br := h.dialProxy()
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if auth != "" {
		fmt.Fprintf(&b, "Proxy-Authorization: %s\r\n", auth)
	}
	b.WriteString("\r\n")
	_, err := conn.Write(append([]byte(b.String()), extra...))
	must(h.t, err)
	return conn, br, readRawResponse(h.t, br)
}

// refused sends a CONNECT to target with cred and returns the refusal.
func (h *harness) refused(cred Credential, target string) (rawResponse, BlockResponse) {
	h.t.Helper()
	conn, _, resp := h.connect(target, basicAuth(cred), nil)
	_ = conn.Close()
	if resp.status == http.StatusOK {
		h.t.Fatalf("CONNECT %s was allowed", target)
	}
	return resp, decodeBlock(h.t, resp.body)
}

// tunnel opens a CONNECT tunnel to target, sending extra with the CONNECT
// head, and fails the test unless it is established.
func (h *harness) tunnel(target string, extra []byte) (net.Conn, *bufio.Reader) {
	h.t.Helper()
	conn, br, resp := h.connect(target, basicAuth(h.cred), extra)
	if resp.status != http.StatusOK {
		h.t.Fatalf("CONNECT %s = %d %s", target, resp.status, resp.body)
	}
	return conn, br
}

// openTunnel opens a CONNECT tunnel to target with cred and sends a TLS
// ClientHello for serverName (target's host when empty), waiting for the
// echo upstream to return it: the tunnel is established and screened.
func (h *harness) openTunnel(cred Credential, target, serverName string) (net.Conn, *bufio.Reader) {
	h.t.Helper()
	if serverName == "" {
		serverName, _, _ = net.SplitHostPort(target)
	}
	hello := helloFor(serverName)
	conn, br, resp := h.connect(target, basicAuth(cred), hello)
	if resp.status != http.StatusOK {
		h.t.Fatalf("CONNECT %s = %d %s", target, resp.status, resp.body)
	}
	if _, err := io.ReadFull(br, make([]byte, len(hello))); err != nil {
		h.t.Fatalf("tunnel to %s: %v", target, err)
	}
	return conn, br
}

// relays reports whether a tunnel still carries bytes to its echo upstream.
func relays(conn net.Conn, br *bufio.Reader) bool {
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("probe")); err != nil {
		return false
	}
	got := make([]byte, 5)
	_, err := io.ReadFull(br, got)
	return err == nil && string(got) == "probe"
}

// closedByProxy reports whether the proxy closed a client connection within
// wait.
func closedByProxy(conn net.Conn, br *bufio.Reader, wait time.Duration) bool {
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	_, err := br.ReadByte()
	var ne net.Error
	return err != nil && !(errors.As(err, &ne) && ne.Timeout())
}

// waitClosed fails unless the proxy closes the client connection.
func waitClosed(t *testing.T, what string, conn net.Conn, br *bufio.Reader) {
	t.Helper()
	if !closedByProxy(conn, br, 5*time.Second) {
		t.Fatalf("%s: the connection is still open", what)
	}
}

func readRawResponse(t *testing.T, br *bufio.Reader) rawResponse {
	t.Helper()
	tp := textproto.NewReader(br)
	line, err := tp.ReadLine()
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	proto, rest, ok := strings.Cut(line, " ")
	code, reason, _ := strings.Cut(rest, " ")
	status, err := strconv.Atoi(code)
	if !ok || !strings.HasPrefix(proto, "HTTP/1.") || err != nil {
		t.Fatalf("bad status line %q", line)
	}
	header, err := tp.ReadMIMEHeader()
	if err != nil {
		t.Fatalf("read header: %v", err)
	}
	resp := rawResponse{status: status, reason: reason, header: header}
	if status != http.StatusOK || header.Get("Content-Length") != "" {
		n, _ := strconv.Atoi(header.Get("Content-Length"))
		resp.body = make([]byte, n)
		if _, err := io.ReadFull(br, resp.body); err != nil {
			t.Fatalf("read body: %v", err)
		}
	}
	return resp
}

// startTCP runs a TCP server that hands every connection to serve.
func startTCP(t *testing.T, serve func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				serve(c)
			}()
		}
	}()
	return ln.Addr().String()
}

// startEcho runs a TCP echo server and returns its address.
func startEcho(t *testing.T) string {
	return startTCP(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
}

// startSink runs a TCP server that counts and discards what it receives.
func startSink(t *testing.T) (string, func() int64) {
	var mu sync.Mutex
	var total int64
	addr := startTCP(t, func(c net.Conn) {
		n, _ := io.Copy(io.Discard, c)
		mu.Lock()
		total += n
		mu.Unlock()
	})
	return addr, func() int64 {
		mu.Lock()
		defer mu.Unlock()
		return total
	}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
