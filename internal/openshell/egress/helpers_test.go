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
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

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
}

func newMapDialer() *mapDialer {
	return &mapDialer{targets: map[int]string{}, fail: map[string]error{}, hang: map[string]bool{}}
}

func (d *mapDialer) route(port int, target string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.targets[port] = target
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
	failErr, hang, target := d.fail[host], d.hang[host], d.targets[port]
	d.mu.Unlock()
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

func (s *recordingSink) all() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.events)
}

func (s *recordingSink) ofKind(kind EventKind) []Event {
	var out []Event
	for _, e := range s.all() {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// wait polls until n events of kind arrived and returns them.
func (s *recordingSink) wait(t *testing.T, kind EventKind, n int) []Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := s.ofKind(kind)
		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d %q events; have %+v", n, kind, s.all())
		}
		time.Sleep(5 * time.Millisecond)
	}
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

	clientsMu sync.Mutex
	clients   []*http.Transport
}

type harnessConfig struct {
	opts    Options
	decider DeciderOptions
	counter *CounterOptions
	// sink replaces the recording sink when set.
	sink EventSink
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
	if h.unblocks, err = NewMemoryUnblocks(); err != nil {
		t.Fatal(err)
	}
	h.resolver.set("example.com", []string{publicV4})
	h.resolver.set("webhook.site", []string{publicV4Alt})

	cfg := &harnessConfig{decider: DeciderOptions{Unblocks: h.unblocks}}
	if configure != nil {
		configure(cfg)
	}
	decider, err := NewDecider(cfg.decider)
	if err != nil {
		t.Fatalf("NewDecider: %v", err)
	}
	decider.local = h.local
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

	if h.cred, err = NewCredential(); err != nil {
		t.Fatal(err)
	}
	h.pr = Principal{BindingID: "binding-one", SandboxID: "sb-1", SandboxName: "sb-one"}
	if err := h.creds.Register(h.cred, h.pr); err != nil {
		t.Fatal(err)
	}

	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.addr = ln.Addr().String()
	go func() { h.served <- h.proxy.Serve(ln) }()
	t.Cleanup(func() { _ = h.proxy.Close() })
	return h
}

// addPrincipal registers another sandbox and returns its credential.
func (h *harness) addPrincipal(pr Principal) Credential {
	h.t.Helper()
	cred, err := NewCredential()
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.creds.Register(cred, pr); err != nil {
		h.t.Fatal(err)
	}
	return cred
}

func basicAuth(c Credential) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password))
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
	if err != nil {
		h.t.Fatal(err)
	}
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
	if _, err := conn.Write(append([]byte(b.String()), extra...)); err != nil {
		h.t.Fatal(err)
	}
	return conn, br, readRawResponse(h.t, br)
}

func readRawResponse(t *testing.T, br *bufio.Reader) rawResponse {
	t.Helper()
	tp := textproto.NewReader(br)
	line, err := tp.ReadLine()
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	proto, rest, ok := strings.Cut(line, " ")
	if !ok || !strings.HasPrefix(proto, "HTTP/1.") {
		t.Fatalf("bad status line %q", line)
	}
	code, reason, _ := strings.Cut(rest, " ")
	status, err := strconv.Atoi(code)
	if err != nil {
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

// startEcho runs a TCP echo server and returns its address.
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

// startSink runs a TCP server that counts and discards what it receives.
func startSink(t *testing.T) (string, func() int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var mu sync.Mutex
	var total int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				n, _ := io.Copy(io.Discard, c)
				mu.Lock()
				total += n
				mu.Unlock()
			}()
		}
	}()
	return ln.Addr().String(), func() int64 {
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
