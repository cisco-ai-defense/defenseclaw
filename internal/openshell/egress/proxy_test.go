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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// clientFor returns an http.Client that sends everything through the proxy
// with cred, trusting the httptest TLS upstream.
func (h *harness) clientFor(cred Credential, upstream *httptest.Server) *http.Client {
	proxyURL, err := url.Parse(cred.ProxyURL("127.0.0.1", h.port()))
	if err != nil {
		h.t.Fatal(err)
	}
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), ForceAttemptHTTP2: true}
	if upstream != nil && upstream.TLS != nil {
		pool := x509.NewCertPool()
		pool.AddCert(upstream.Certificate())
		tr.TLSClientConfig = &tls.Config{RootCAs: pool}
	}
	h.clientsMu.Lock()
	h.clients = append(h.clients, tr)
	h.clientsMu.Unlock()
	h.t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func (h *harness) port() int {
	_, p, _ := net.SplitHostPort(h.addr)
	n, _ := strconv.Atoi(p)
	return n
}

func decodeBlock(t *testing.T, body []byte) BlockResponse {
	t.Helper()
	var b BlockResponse
	if err := json.Unmarshal(body, &b); err != nil {
		t.Fatalf("block body %q: %v", body, err)
	}
	return b
}

// TestProxyConnectTLSEndToEnd drives a real HTTPS request through CONNECT
// to an httptest TLS upstream and checks attribution, events and counters.
func TestProxyConnectTLSEndToEnd(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "hello %s %d", r.URL.Path, len(body))
	}))
	defer upstream.Close()
	h := newHarness(t, nil)
	h.dialer.route(443, upstream.Listener.Addr().String())

	client := h.clientFor(h.cred, upstream)
	resp, err := client.Post("https://example.com/upload", "text/plain", strings.NewReader(strings.Repeat("x", 5000)))
	if err != nil {
		t.Fatalf("POST through proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "hello /upload 5000" {
		t.Fatalf("response %d %q", resp.StatusCode, body)
	}

	allowed := h.sink.wait(t, EventAllowed, 1)[0]
	if allowed.Method != http.MethodConnect || allowed.Host != "example.com" || allowed.Port != 443 ||
		allowed.BindingID != "binding-one" || allowed.SandboxName != "sb-one" || allowed.RemoteAddr != publicV4+":443" ||
		!allowed.FirstSeen || allowed.Status != http.StatusOK || allowed.Source != SourceDefault || allowed.TunnelID == "" {
		t.Errorf("allowed event = %+v", allowed)
	}
	if n := len(h.proxy.Tunnels()); n != 1 {
		t.Errorf("Tunnels() = %d open, want 1 while the client keeps the connection", n)
	}

	closeIdle(t, h)
	closed := h.sink.wait(t, EventClosed, 1)[0]
	if closed.TunnelID != allowed.TunnelID || closed.BytesUp < 5000 || closed.BytesDown == 0 || closed.Duration <= 0 || closed.Terminated {
		t.Errorf("closed event = %+v", closed)
	}
	stats := h.proxy.Counter().DestinationsFor("binding-one")
	if len(stats) != 1 || stats[0].BytesUp != closed.BytesUp || stats[0].BytesDown != closed.BytesDown || stats[0].Tunnels != 1 || stats[0].Active != 0 {
		t.Errorf("destination stats = %+v, closed event %+v", stats, closed)
	}
	if n := len(h.proxy.Tunnels()); n != 0 {
		t.Errorf("Tunnels() = %d after close", n)
	}
}

// closeIdle closes every client transport the test created so tunnels end.
func closeIdle(t *testing.T, h *harness) {
	t.Helper()
	h.clientsMu.Lock()
	defer h.clientsMu.Unlock()
	for _, tr := range h.clients {
		tr.CloseIdleConnections()
	}
}

// TestProxyConnectHTTP2 checks that h2 negotiated inside the tunnel works;
// the proxy relays TLS opaquely.
func TestProxyConnectHTTP2(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.Proto)
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()
	h := newHarness(t, nil)
	h.dialer.route(443, upstream.Listener.Addr().String())

	resp, err := h.clientFor(h.cred, upstream).Get("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.ProtoMajor != 2 || string(body) != "HTTP/2.0" {
		t.Errorf("proto = %s, body %q", resp.Proto, body)
	}
}

// TestProxyConnectEarlyData: bytes a client pipelines right after the
// CONNECT head (before the 200) must reach the upstream.
func TestProxyConnectEarlyData(t *testing.T) {
	h := newHarness(t, nil)
	h.dialer.route(443, startEcho(t))
	conn, br, resp := h.connect("example.com:443", basicAuth(h.cred), []byte("early-bytes"))
	if resp.status != http.StatusOK {
		t.Fatalf("CONNECT = %d %s", resp.status, resp.body)
	}
	got := make([]byte, len("early-bytes"))
	if _, err := io.ReadFull(br, got); err != nil || string(got) != "early-bytes" {
		t.Fatalf("echo = %q, %v", got, err)
	}
	if _, err := conn.Write([]byte("more")); err != nil {
		t.Fatal(err)
	}
	got = make([]byte, 4)
	if _, err := io.ReadFull(br, got); err != nil || string(got) != "more" {
		t.Fatalf("echo = %q, %v", got, err)
	}
}

// TestProxyAbsoluteForm forwards plain-HTTP proxy requests and checks what
// reaches the upstream.
func TestProxyAbsoluteForm(t *testing.T) {
	var seen atomic.Pointer[http.Request]
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen.Store(r.Clone(context.Background()))
		w.Header().Set("X-Upstream", "yes")
		fmt.Fprintf(w, "%s %s %d", r.Method, r.URL.RequestURI(), len(body))
	}))
	defer upstream.Close()
	h := newHarness(t, nil)
	h.dialer.route(80, upstream.Listener.Addr().String())
	client := h.clientFor(h.cred, nil)

	req, _ := http.NewRequest(http.MethodPost, "http://example.com/v1/items?q=1&r=two", strings.NewReader(strings.Repeat("y", 1234)))
	req.Header.Set("Connection", "keep-alive, X-Hop")
	req.Header.Set("X-Hop", "drop-me")
	req.Header.Set("X-Keep", "keep-me")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "POST /v1/items?q=1&r=two 1234" || resp.Header.Get("X-Upstream") != "yes" {
		t.Fatalf("response %d %q %v", resp.StatusCode, body, resp.Header)
	}
	r := seen.Load()
	if r.Host != "example.com" || r.Header.Get("X-Keep") != "keep-me" {
		t.Errorf("upstream saw Host %q headers %v", r.Host, r.Header)
	}
	for _, hdr := range []string{"Proxy-Authorization", "Proxy-Connection", "X-Hop", "X-Forwarded-For", "X-Forwarded-Host", "Forwarded", "Via"} {
		if v := r.Header.Get(hdr); v != "" {
			t.Errorf("upstream received %s: %q", hdr, v)
		}
	}

	allowed := h.sink.wait(t, EventAllowed, 1)[0]
	closed := h.sink.wait(t, EventClosed, 1)[0]
	if allowed.Method != http.MethodPost || allowed.Host != "example.com" || allowed.Port != 80 || allowed.Status != http.StatusOK ||
		allowed.RemoteAddr != publicV4+":80" || !allowed.FirstSeen {
		t.Errorf("allowed event = %+v", allowed)
	}
	if closed.TunnelID != allowed.TunnelID || closed.BytesUp != 1234 || closed.BytesDown != int64(len(body)) || closed.Status != http.StatusOK {
		t.Errorf("closed event = %+v", closed)
	}
}

// TestProxyKeepAlive sends two absolute-form requests on one client
// connection.
func TestProxyKeepAlive(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.URL.Path)
	}))
	defer upstream.Close()
	h := newHarness(t, nil)
	h.dialer.route(80, upstream.Listener.Addr().String())
	conn, br := h.dialProxy()
	for _, path := range []string{"/one", "/two"} {
		fmt.Fprintf(conn, "GET http://example.com%s HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: %s\r\n\r\n", path, basicAuth(h.cred))
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != path || resp.Close {
			t.Fatalf("%s: %d %q close=%v", path, resp.StatusCode, body, resp.Close)
		}
	}
	if n := len(h.sink.wait(t, EventClosed, 2)); n != 2 {
		t.Errorf("closed events = %d", n)
	}
}

func TestProxyAbsoluteFormHTTPSUpstream(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "tls-ok")
	}))
	defer upstream.Close()
	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())
	h := newHarness(t, func(c *harnessConfig) { c.opts.UpstreamTLS = &tls.Config{RootCAs: pool} })
	h.dialer.route(443, upstream.Listener.Addr().String())
	conn, br := h.dialProxy()
	fmt.Fprintf(conn, "GET https://example.com/x HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: %s\r\n\r\n", basicAuth(h.cred))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "tls-ok" {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
}

func TestProxyAuthFailures(t *testing.T) {
	h := newHarness(t, nil)
	h.dialer.route(443, startEcho(t))
	revoked := h.addPrincipal(Principal{BindingID: "binding-two"})
	h.creds.Revoke("binding-two")
	wrong := h.cred
	wrong.Password = strings.Repeat("0", 64)
	cases := map[string]string{
		"missing":        "",
		"wrong password": basicAuth(wrong),
		"unknown user":   basicAuth(Credential{Username: "dcx-nobody", Password: h.cred.Password}),
		"bearer":         "Bearer " + h.cred.Password,
		"revoked":        basicAuth(revoked),
	}
	for name, auth := range cases {
		conn, br, resp := h.connect("example.com:443", auth, nil)
		if resp.status != http.StatusProxyAuthRequired || resp.header.Get("Proxy-Authenticate") == "" {
			t.Errorf("%s: CONNECT = %d %v", name, resp.status, resp.header)
		}
		var body ErrorResponse
		if err := json.Unmarshal(resp.body, &body); err != nil || body.Error != errCodeAuth {
			t.Errorf("%s: body %q", name, resp.body)
		}
		if _, err := br.ReadByte(); !errors.Is(err, io.EOF) {
			t.Errorf("%s: connection left open after 407 (%v)", name, err)
		}
		_ = conn.Close()
	}
	// Every rejected credential is an event; the credential-less probe is
	// just a challenge.
	h.sink.wait(t, EventAuthFailed, len(cases)-1)
	time.Sleep(50 * time.Millisecond)
	if got := len(h.sink.ofKind(EventAuthFailed)); got != len(cases)-1 {
		t.Errorf("auth_failed events = %d, want %d", got, len(cases)-1)
	}
	for _, e := range h.sink.ofKind(EventAuthFailed) {
		if e.BindingID != "" || e.Host != "example.com" || e.Port != 443 || e.Status != http.StatusProxyAuthRequired {
			t.Errorf("auth_failed event = %+v", e)
		}
	}
	if n := len(h.dialer.addresses()); n != 0 {
		t.Errorf("unauthenticated requests dialed upstream %d times", n)
	}

	// Absolute form gets the same treatment.
	conn, br := h.dialProxy()
	fmt.Fprint(conn, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusProxyAuthRequired || resp.Header.Get("Proxy-Authenticate") == "" || !resp.Close {
		t.Errorf("absolute-form 407 = %d %v close=%v", resp.StatusCode, resp.Header, resp.Close)
	}
}

func TestProxyBlockedConnect(t *testing.T) {
	h := newHarness(t, nil)
	_, br, resp := h.connect("webhook.site:443", basicAuth(h.cred), []byte("\x16\x03\x01 client hello bytes"))
	if resp.status != http.StatusForbidden || resp.reason != "Blocked by DefenseClaw (webhook_catcher)" {
		t.Fatalf("CONNECT = %d %q", resp.status, resp.reason)
	}
	if ct := resp.header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q", ct)
	}
	b := decodeBlock(t, resp.body)
	if b.Error != "egress_blocked" || b.Host != "webhook.site" || b.Port != 443 || b.Category != CategoryWebhookCatcher ||
		b.Source != SourceFeed || b.Feed != "defenseclaw-blocklist" || b.FeedVersion == "" || !b.Unblockable ||
		b.Sandbox != "sb-one" || b.Mode != ModeOpen {
		t.Errorf("block body = %+v", b)
	}
	if !strings.Contains(b.HowToUnblock, "defenseclaw sandbox unblock webhook.site --sandbox sb-one") ||
		!strings.Contains(b.HowToUnblock, "--always") || !strings.Contains(b.Message, "webhook.site:443") {
		t.Errorf("guidance = %q / %q", b.Message, b.HowToUnblock)
	}
	if _, err := br.ReadByte(); !errors.Is(err, io.EOF) {
		t.Errorf("connection left open after 403 (%v)", err)
	}
	e := h.sink.wait(t, EventBlocked, 1)[0]
	if e.Host != "webhook.site" || e.Category != CategoryWebhookCatcher || e.Status != http.StatusForbidden || e.BindingID != "binding-one" || e.Rule != "webhook.site" {
		t.Errorf("blocked event = %+v", e)
	}
	if n := len(h.dialer.addresses()); n != 0 {
		t.Errorf("blocked destination dialed %d times", n)
	}
	if s := h.proxy.Counter().DestinationsFor("binding-one"); len(s) != 1 || s[0].Blocked != 1 {
		t.Errorf("counter = %+v", s)
	}
}

func TestProxyBlockedAbsoluteForm(t *testing.T) {
	h := newHarness(t, nil)
	resp, err := h.clientFor(h.cred, nil).Get("http://pastebin.com/raw/abc")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if b := decodeBlock(t, body); b.Category != CategoryPasteSite || b.Port != 80 || !b.Unblockable {
		t.Errorf("block body = %+v", b)
	}
}

func TestProxyGuardRefusals(t *testing.T) {
	h := newHarness(t, nil)
	h.dialer.route(443, startEcho(t))
	h.dialer.route(80, startEcho(t))
	h.resolver.set("internal.example.com", []string{"10.1.2.3"})
	h.resolver.set("split.example.com", []string{publicV4, "192.168.0.7"})
	h.resolver.set("rebind.example.com", []string{publicV4}, []string{"169.254.169.254"})
	h.resolver.set("own.example.com", []string{ownV6})

	targets := []string{
		"127.0.0.1:443", "[::1]:443", "169.254.169.254:80", "10.0.0.1:443", "[fd00::1]:443",
		"[::ffff:127.0.0.1]:443", "100.64.0.1:443", "0.0.0.0:443",
		"localhost:443", "host.openshell.internal:443", "metadata.google.internal:80",
		"internal.example.com:443", "split.example.com:443",
		// This machine's own public addresses (fake interface list).
		ownV4 + ":443", ownV4 + ":80", "[" + ownV6 + "]:443", "own.example.com:443",
	}
	for _, target := range targets {
		_, _, resp := h.connect(target, basicAuth(h.cred), nil)
		if resp.status != http.StatusForbidden {
			t.Errorf("CONNECT %s = %d, want 403", target, resp.status)
			continue
		}
		b := decodeBlock(t, resp.body)
		if b.Category != CategoryPrivateNetwork || b.Unblockable || b.Source != SourceGuard || !strings.Contains(b.HowToUnblock, "--host-port") {
			t.Errorf("CONNECT %s body = %+v", target, b)
		}
	}

	// Rebinding between two tunnels: the first connects to the public
	// answer, the second sees the metadata answer and is refused.
	conn, _, resp := h.connect("rebind.example.com:443", basicAuth(h.cred), nil)
	if resp.status != http.StatusOK {
		t.Fatalf("first rebind CONNECT = %d", resp.status)
	}
	_ = conn.Close()
	if _, _, resp := h.connect("rebind.example.com:443", basicAuth(h.cred), nil); resp.status != http.StatusForbidden {
		t.Errorf("second rebind CONNECT = %d", resp.status)
	}

	// Absolute form goes through the same guard.
	for _, u := range []string{"http://internal.example.com/", "http://own.example.com/", "http://" + ownV4 + "/"} {
		resp2, err := h.clientFor(h.cred, nil).Get(u)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp2.Body)
		resp2.Body.Close()
		if resp2.StatusCode != http.StatusForbidden || decodeBlock(t, body).Category != CategoryPrivateNetwork {
			t.Errorf("absolute-form %s = %d %s", u, resp2.StatusCode, body)
		}
	}

	for _, addr := range h.dialer.addresses() {
		if isPrivateTarget(addr) {
			t.Errorf("dialer was handed prohibited address %s", addr)
		}
	}
}

func TestProxyRefusalMatrix(t *testing.T) {
	h := newHarness(t, nil)
	tests := []struct {
		target   string
		status   int
		category Category // empty: Go's HTTP server rejects the request line itself
		hint     string
	}{
		{"example.com:22", http.StatusForbidden, CategoryPortNotAllowed, "openshell.egress.ports"},
		{"example.com:8080", http.StatusForbidden, CategoryPortNotAllowed, "openshell.egress.ports"},
		{"example.com", http.StatusBadRequest, CategoryInvalidDestination, "CONNECT host:port"},
		{"exa$mple.com:443", http.StatusBadRequest, CategoryInvalidDestination, ""},
		{"127.1:443", http.StatusBadRequest, CategoryInvalidDestination, ""},
		{"0x7f000001:443", http.StatusBadRequest, CategoryInvalidDestination, ""},
		{"example.com:99999", http.StatusBadRequest, CategoryInvalidDestination, ""},
		{"example.com:+443", http.StatusBadRequest, "", ""},
	}
	for _, tt := range tests {
		_, _, resp := h.connect(tt.target, basicAuth(h.cred), nil)
		if resp.status != tt.status {
			t.Errorf("CONNECT %s = %d, want %d", tt.target, resp.status, tt.status)
			continue
		}
		if tt.category == "" {
			continue
		}
		b := decodeBlock(t, resp.body)
		if b.Category != tt.category || b.Unblockable || !strings.Contains(b.HowToUnblock, tt.hint) {
			t.Errorf("CONNECT %s body = %+v", tt.target, b)
		}
	}

	// An origin-form request is not a proxy request.
	conn, br := h.dialProxy()
	fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	var e ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&e)
	if resp.StatusCode != http.StatusBadRequest || e.Error != errCodeNotProxy {
		t.Errorf("origin-form = %d %+v", resp.StatusCode, e)
	}

	// Unsupported absolute-form schemes are invalid destinations.
	conn, br = h.dialProxy()
	fmt.Fprintf(conn, "GET ftp://example.com/file HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: %s\r\n\r\n", basicAuth(h.cred))
	resp, err = http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("ftp:// = %d", resp.StatusCode)
	}
}

func TestProxyUpstreamFailures(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) { c.opts.DialTimeout = 100 * time.Millisecond })
	h.resolver.set("refused.example.com", []string{publicV4Alt})
	h.resolver.set("slow.example.com", []string{"8.8.8.9"})
	h.dialer.hang["8.8.8.9"] = true
	// No route for 443: every dial is refused.
	tests := []struct {
		target string
		status int
		reason string
	}{
		{"nxdomain.example.com:443", http.StatusBadGateway, "DNS resolution failed"},
		{"refused.example.com:443", http.StatusBadGateway, "connecting to the destination failed"},
		{"slow.example.com:443", http.StatusGatewayTimeout, "timed out"},
	}
	for _, tt := range tests {
		_, _, resp := h.connect(tt.target, basicAuth(h.cred), nil)
		var e ErrorResponse
		_ = json.Unmarshal(resp.body, &e)
		if resp.status != tt.status || e.Error != errCodeUnreachable || !strings.Contains(e.Reason, tt.reason) {
			t.Errorf("CONNECT %s = %d %+v", tt.target, resp.status, e)
		}
	}
	failed := h.sink.wait(t, EventFailed, len(tests))
	for _, e := range failed {
		if e.Error == "" || e.BindingID != "binding-one" || (e.Status != http.StatusBadGateway && e.Status != http.StatusGatewayTimeout) {
			t.Errorf("failed event = %+v", e)
		}
	}
	if n := len(h.sink.ofKind(EventAllowed)); n != 0 {
		t.Errorf("%d allowed events for failed dials", n)
	}

	// Absolute form maps the same failures.
	resp, err := h.clientFor(h.cred, nil).Get("http://nxdomain.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("absolute-form DNS failure = %d", resp.StatusCode)
	}
}

func TestProxyHeaderLimit(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) { c.opts.MaxHeaderBytes = 1024 })
	conn, br := h.dialProxy()
	fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nX-Big: %s\r\n\r\n", strings.Repeat("a", 16<<10))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("oversized header = %d", resp.StatusCode)
	}
}

// TestProxySlowloris: a client that never finishes its request head is
// disconnected after HeaderTimeout.
func TestProxySlowloris(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) { c.opts.HeaderTimeout = 150 * time.Millisecond })
	conn, br := h.dialProxy()
	start := time.Now()
	fmt.Fprint(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: exam")
	_, _ = io.Copy(io.Discard, br) // returns when the proxy closes the connection
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("slow client held the connection for %v", elapsed)
	}
}

// TestProxyMaxConns: connections beyond MaxConns wait in the backlog
// instead of being served, and are served once a slot frees.
func TestProxyMaxConns(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) { c.opts.MaxConns = 2 })
	first, _ := h.dialProxy()
	second, _ := h.dialProxy()
	third, br := h.dialProxy()
	fmt.Fprintf(third, "CONNECT example.com:22 HTTP/1.1\r\nHost: example.com:22\r\nProxy-Authorization: %s\r\n\r\n", basicAuth(h.cred))
	_ = third.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("a connection over MaxConns was served")
	}
	_ = first.Close()
	_ = third.SetReadDeadline(time.Now().Add(5 * time.Second))
	if resp := readRawResponse(t, br); resp.status != http.StatusForbidden {
		t.Errorf("queued connection = %d once a slot freed", resp.status)
	}
	_ = second.Close()
}

func TestProxyTunnelIdleTimeout(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) { c.opts.TunnelIdleTimeout = 200 * time.Millisecond })
	h.dialer.route(443, startEcho(t))
	_, br, resp := h.connect("example.com:443", basicAuth(h.cred), nil)
	if resp.status != http.StatusOK {
		t.Fatal(resp.status)
	}
	start := time.Now()
	_, err := br.ReadByte()
	if err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("idle tunnel read = %v after %v", err, time.Since(start))
	}
	closed := h.sink.wait(t, EventClosed, 1)[0]
	if !closed.Terminated {
		t.Errorf("closed event = %+v, want Terminated", closed)
	}
}

// TestProxyTunnelHalfDuplex: a tunnel with traffic in only one direction is
// not idle.
func TestProxyTunnelHalfDuplex(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		for i := 0; i < 12; i++ {
			if _, err := c.Write([]byte{'t'}); err != nil {
				return
			}
			time.Sleep(60 * time.Millisecond)
		}
	}()
	h := newHarness(t, func(c *harnessConfig) { c.opts.TunnelIdleTimeout = 250 * time.Millisecond })
	h.dialer.route(443, ln.Addr().String())
	_, br, resp := h.connect("example.com:443", basicAuth(h.cred), nil)
	if resp.status != http.StatusOK {
		t.Fatal(resp.status)
	}
	got, _ := io.ReadAll(br)
	if len(got) != 12 {
		t.Errorf("received %d of 12 bytes: the download-only tunnel was treated as idle", len(got))
	}
}

func TestProxyPerBindingLimits(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) { c.opts.MaxTunnelsPerBinding = 1 })
	h.dialer.route(443, startEcho(t))
	first, _, resp := h.connect("example.com:443", basicAuth(h.cred), nil)
	if resp.status != http.StatusOK {
		t.Fatal(resp.status)
	}
	_, _, resp = h.connect("example.com:443", basicAuth(h.cred), nil)
	if resp.status != http.StatusTooManyRequests || decodeBlock(t, resp.body).Category != CategoryRateLimited {
		t.Fatalf("second tunnel = %d %s", resp.status, resp.body)
	}
	other := h.addPrincipal(Principal{BindingID: "binding-two"})
	if _, _, resp := h.connect("example.com:443", basicAuth(other), nil); resp.status != http.StatusOK {
		t.Errorf("another binding was limited: %d", resp.status)
	}
	_ = first.Close()
	eventually(t, "the first tunnel to close", func() bool { return len(h.sink.ofKind(EventClosed)) >= 1 })
	if _, _, resp := h.connect("example.com:443", basicAuth(h.cred), nil); resp.status != http.StatusOK {
		t.Errorf("tunnel after release = %d", resp.status)
	}
	e := h.sink.ofKind(EventBlocked)
	if len(e) != 1 || e[0].Category != CategoryRateLimited || e[0].Source != SourceLimit || e[0].Status != http.StatusTooManyRequests {
		t.Errorf("blocked events = %+v", e)
	}
}

func TestProxyRateLimit(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) {
		c.opts.TunnelsPerSecond = 0.001
		c.opts.TunnelBurst = 2
	})
	h.dialer.route(443, startEcho(t))
	var statuses []int
	for i := 0; i < 3; i++ {
		conn, _, resp := h.connect("example.com:443", basicAuth(h.cred), nil)
		statuses = append(statuses, resp.status)
		_ = conn.Close()
	}
	if statuses[0] != http.StatusOK || statuses[1] != http.StatusOK || statuses[2] != http.StatusTooManyRequests {
		t.Errorf("statuses = %v", statuses)
	}
}

func TestProxyLargeUploadAlert(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) { c.counter = &CounterOptions{LargeUploadBytes: 1024} })
	h.dialer.route(443, startEcho(t))
	conn, br, resp := h.connect("example.com:443", basicAuth(h.cred), nil)
	if resp.status != http.StatusOK {
		t.Fatal(resp.status)
	}
	payload := bytes.Repeat([]byte("z"), 4096)
	go func() { _, _ = conn.Write(payload) }()
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(br, echo); err != nil {
		t.Fatalf("alert-only mode interrupted the tunnel: %v", err)
	}
	e := h.sink.wait(t, EventLargeUpload, 1)
	if len(e) != 1 || e[0].Host != "example.com" || e[0].BytesUp <= 1024 || !e[0].FirstSeen || e[0].Terminated ||
		e[0].Category != CategoryLargeUpload || e[0].BindingID != "binding-one" || e[0].TunnelID == "" {
		t.Errorf("large_upload events = %+v", e)
	}
	_ = conn.Close()
}

func TestProxyLargeUploadBlock(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) {
		c.counter = &CounterOptions{LargeUploadBytes: 1024, BlockLargeUploads: true}
	})
	sinkAddr, received := startSink(t)
	h.dialer.route(443, sinkAddr)
	conn, br, resp := h.connect("example.com:443", basicAuth(h.cred), nil)
	if resp.status != http.StatusOK {
		t.Fatal(resp.status)
	}
	for i := 0; i < 8; i++ {
		if _, err := conn.Write(bytes.Repeat([]byte("u"), 512)); err != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, _ = io.Copy(io.Discard, br) // the proxy cuts the tunnel
	e := h.sink.wait(t, EventLargeUpload, 1)[0]
	if !e.Terminated {
		t.Errorf("large_upload event = %+v", e)
	}
	if closed := h.sink.wait(t, EventClosed, 1)[0]; !closed.Terminated || closed.BytesUp > 1024 {
		t.Errorf("closed event = %+v", closed)
	}
	eventually(t, "the upstream to see the cut", func() bool { return received() > 0 })
	if got := received(); got > 1024 {
		t.Errorf("upstream received %d bytes past the 1024-byte block", got)
	}

	// Further tunnels to the flagged destination are refused ...
	_, _, resp = h.connect("example.com:443", basicAuth(h.cred), nil)
	if resp.status != http.StatusForbidden || decodeBlock(t, resp.body).Category != CategoryLargeUpload {
		t.Fatalf("tunnel after the block = %d %s", resp.status, resp.body)
	}
	// ... until the user unblocks it.
	if err := h.unblocks.Add(Unblock{Pattern: "example.com", SandboxID: "sb-1"}); err != nil {
		t.Fatal(err)
	}
	if _, _, resp := h.connect("example.com:443", basicAuth(h.cred), nil); resp.status != http.StatusOK {
		t.Errorf("tunnel after unblock = %d", resp.status)
	}
}

func TestProxyLargeUploadBlockAbsoluteForm(t *testing.T) {
	var got atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		got.Add(n)
	}))
	defer upstream.Close()
	h := newHarness(t, func(c *harnessConfig) {
		c.counter = &CounterOptions{LargeUploadBytes: 1024, BlockLargeUploads: true}
	})
	h.dialer.route(80, upstream.Listener.Addr().String())
	resp, err := h.clientFor(h.cred, nil).Post("http://example.com/upload", "application/octet-stream", bytes.NewReader(bytes.Repeat([]byte("p"), 64<<10)))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || decodeBlock(t, body).Category != CategoryLargeUpload {
		t.Fatalf("large POST = %d %s", resp.StatusCode, body)
	}
	if got.Load() > 1024 {
		t.Errorf("upstream received %d bytes", got.Load())
	}
}

func TestProxyUnblockAndSetDecider(t *testing.T) {
	h := newHarness(t, nil)
	h.dialer.route(443, startEcho(t))
	if _, _, resp := h.connect("webhook.site:443", basicAuth(h.cred), nil); resp.status != http.StatusForbidden {
		t.Fatalf("before unblock = %d", resp.status)
	}
	if err := h.unblocks.Add(Unblock{Pattern: "webhook.site", SandboxID: "sb-1"}); err != nil {
		t.Fatal(err)
	}
	conn, _, resp := h.connect("webhook.site:443", basicAuth(h.cred), nil)
	if resp.status != http.StatusOK {
		t.Fatalf("after unblock = %d", resp.status)
	}
	_ = conn.Close()
	// The refusal before the unblock was not contact: the first allowed
	// tunnel is still the first contact.
	if e := h.sink.wait(t, EventAllowed, 1)[0]; e.Source != SourceUnblock || e.Rule != "webhook.site" || !e.FirstSeen {
		t.Errorf("allowed event = %+v", e)
	}

	d, err := NewDecider(DeciderOptions{Block: []string{"example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.proxy.SetDecider(d); err != nil || h.proxy.Decider() != d {
		t.Fatal("SetDecider did not take")
	}
	if h.proxy.SetDecider(nil) == nil {
		t.Error("SetDecider(nil) accepted")
	}
	_, _, resp = h.connect("example.com:443", basicAuth(h.cred), nil)
	if resp.status != http.StatusForbidden || decodeBlock(t, resp.body).Category != CategoryOperatorBlock {
		t.Errorf("after SetDecider = %d %s", resp.status, resp.body)
	}
	if b := decodeBlock(t, resp.body); b.Unblockable || !strings.Contains(b.HowToUnblock, "openshell.egress.block") {
		t.Errorf("operator block body = %+v", b)
	}
}

func TestProxyWebSocketUpgrade(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "want upgrade", http.StatusBadRequest)
			return
		}
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprint(brw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = brw.Flush()
		_, _ = io.Copy(conn, brw)
	}))
	defer upstream.Close()
	h := newHarness(t, nil)
	h.dialer.route(80, upstream.Listener.Addr().String())

	conn, br := h.dialProxy()
	fmt.Fprintf(conn, "GET http://example.com/ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nProxy-Authorization: %s\r\n\r\n", basicAuth(h.cred))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade = %d", resp.StatusCode)
	}
	fmt.Fprint(conn, "frame-data")
	got := make([]byte, len("frame-data"))
	if _, err := io.ReadFull(br, got); err != nil || string(got) != "frame-data" {
		t.Fatalf("echo = %q, %v", got, err)
	}
	if n := len(h.proxy.Tunnels()); n != 1 {
		t.Errorf("Tunnels() = %d during the upgrade", n)
	}
	_ = conn.Close()
	closed := h.sink.wait(t, EventClosed, 1)[0]
	if closed.BytesUp < int64(len("frame-data")) || closed.BytesDown < int64(len("frame-data")) || closed.Status != http.StatusSwitchingProtocols {
		t.Errorf("closed event = %+v", closed)
	}
}

func TestProxySinkPanicIsContained(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) { c.sink = EventSinkFunc(func(Event) { panic("sink bug") }) })
	h.dialer.route(443, startEcho(t))
	conn, br, resp := h.connect("example.com:443", basicAuth(h.cred), nil)
	if resp.status != http.StatusOK {
		t.Fatal(resp.status)
	}
	fmt.Fprint(conn, "ok")
	got := make([]byte, 2)
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("tunnel broken by a panicking sink: %v", err)
	}
}

func TestProxyShutdown(t *testing.T) {
	h := newHarness(t, nil)
	h.dialer.route(443, startEcho(t))
	conn, br, resp := h.connect("example.com:443", basicAuth(h.cred), nil)
	if resp.status != http.StatusOK {
		t.Fatal(resp.status)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.proxy.Shutdown(ctx) }()

	// The open tunnel keeps working while Shutdown waits ...
	eventually(t, "the listener to close", func() bool {
		c, err := net.DialTimeout("tcp", h.addr, 100*time.Millisecond)
		if err == nil {
			c.Close()
		}
		return err != nil
	})
	fmt.Fprint(conn, "still")
	got := make([]byte, 5)
	if _, err := io.ReadFull(br, got); err != nil || string(got) != "still" {
		t.Fatalf("tunnel during shutdown = %q, %v", got, err)
	}
	// ... and is closed when the grace period ends.
	if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Shutdown = %v, want DeadlineExceeded", err)
	}
	if _, err := br.ReadByte(); err == nil {
		t.Error("tunnel survived the end of the grace period")
	}
	if err := <-h.served; !errors.Is(err, http.ErrServerClosed) {
		t.Errorf("Serve returned %v", err)
	}
	if err := h.proxy.Serve(mustListen(t)); !errors.Is(err, http.ErrServerClosed) {
		t.Errorf("Serve after Shutdown = %v", err)
	}
}

func TestProxyShutdownIdle(t *testing.T) {
	h := newHarness(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if err := h.proxy.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
	if time.Since(start) > time.Second {
		t.Errorf("idle Shutdown took %v", time.Since(start))
	}
}

// A keep-alive connection that sends a request after Shutdown began gets a
// 503 instead of a new upstream connection.
func TestProxyRefusesWhileClosing(t *testing.T) {
	h := newHarness(t, nil)
	h.proxy.mu.Lock()
	h.proxy.closing = true
	h.proxy.mu.Unlock()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Proxy-Authorization", basicAuth(h.cred))
	rec := httptest.NewRecorder()
	h.proxy.serveHTTP(rec, req)
	var e ErrorResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &e)
	if rec.Code != http.StatusServiceUnavailable || e.Error != errCodeShuttingDown || rec.Header().Get("Connection") != "close" {
		t.Errorf("request during shutdown = %d %+v", rec.Code, e)
	}
	if n := len(h.dialer.addresses()); n != 0 {
		t.Errorf("dialed %d times during shutdown", n)
	}
}

func TestBindingLimitsPrune(t *testing.T) {
	l := newBindingLimits(1, 1000, 5)
	for i := 0; i < maxTrackedBindings; i++ {
		release, why := l.acquire(fmt.Sprintf("b-%d", i))
		if release == nil {
			t.Fatalf("acquire %d refused: %s", i, why)
		}
		if i%2 == 0 {
			release()
			release() // idempotent
		}
	}
	// Refill the idle bindings' token buckets, then add one more binding.
	time.Sleep(20 * time.Millisecond)
	if release, _ := l.acquire("fresh"); release == nil {
		t.Fatal("acquire after prune refused")
	}
	l.mu.Lock()
	n := len(l.state)
	l.mu.Unlock()
	if n > maxTrackedBindings/2+2 {
		t.Errorf("%d bindings tracked after prune; idle ones were not dropped", n)
	}
	if release, why := l.acquire("b-1"); release != nil || why == "" {
		t.Error("an active binding lost its concurrency count in the prune")
	}
}

func mustListen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

type fakeAddrListener struct {
	net.Listener
	addr net.Addr
}

func (l fakeAddrListener) Addr() net.Addr { return l.addr }

func TestProxyLoopbackOnly(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", "[::]:0", "192.0.2.1:0", "localhost:0", "nonsense"} {
		if ln, err := Listen(addr); err == nil {
			ln.Close()
			t.Errorf("Listen(%q) succeeded", addr)
		}
	}
	d, _ := NewDecider(DeciderOptions{})
	p, err := New(Options{Auth: NewCredentialStore(), Decider: d})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	wide := fakeAddrListener{Listener: mustListen(t), addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1}}
	if err := p.Serve(wide); !errors.Is(err, ErrNotLoopback) {
		t.Errorf("Serve(non-loopback) = %v", err)
	}
	if ln, err := Listen("[::1]:0"); err == nil {
		ln.Close()
	}
}

func TestNewValidation(t *testing.T) {
	d, _ := NewDecider(DeciderOptions{})
	if _, err := New(Options{Decider: d}); err == nil {
		t.Error("New without Auth succeeded")
	}
	if _, err := New(Options{Auth: NewCredentialStore()}); err == nil {
		t.Error("New without Decider succeeded")
	}
}

func TestProxyConcurrentTunnels(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.URL.Path)
	}))
	defer upstream.Close()
	h := newHarness(t, nil)
	h.dialer.route(443, upstream.Listener.Addr().String())
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			client := h.clientFor(h.cred, upstream)
			client.Transport.(*http.Transport).DisableKeepAlives = true
			resp, err := client.Get(fmt.Sprintf("https://example.com/%d", i))
			if err != nil {
				errs <- err
				return
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(body) != fmt.Sprintf("/%d", i) {
				errs <- fmt.Errorf("body %q for %d", body, i)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	eventually(t, "all tunnels to close", func() bool { return len(h.sink.ofKind(EventClosed)) == 32 })
	if s := h.proxy.Counter().DestinationsFor("binding-one"); len(s) != 1 || s[0].Tunnels != 32 || s[0].Active != 0 {
		t.Errorf("stats = %+v", s)
	}
}

// getStatus sends a GET through client and returns the status.
func getStatus(client *http.Client, u string) (int, error) {
	resp, err := client.Get(u)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, nil
}

// A forwarded request counts toward its destination only once it has an
// upstream connection, like a CONNECT tunnel: a request whose dial fails or
// is refused is neither a tunnel nor the first contact.
func TestProxyForwardCountsConnectedRequestsOnly(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer upstream.Close()
	h := newHarness(t, nil)
	h.resolver.set("internal.example.com", []string{"10.1.2.3"})
	client := h.clientFor(h.cred, nil)

	// Nothing listens for port 80 yet, so the dial fails; the second name
	// resolves to a private address and is refused at dial time.
	for u, want := range map[string]int{"http://example.com/": http.StatusBadGateway, "http://internal.example.com/": http.StatusForbidden} {
		if status, err := getStatus(client, u); err != nil || status != want {
			t.Fatalf("GET %s = %d, %v; want %d", u, status, err, want)
		}
	}
	stats := map[string]DestinationStats{}
	for _, s := range h.proxy.Counter().DestinationsFor("binding-one") {
		stats[s.Host] = s
	}
	if s, ok := stats["example.com"]; ok && (s.Tunnels != 0 || s.Active != 0) {
		t.Errorf("failed request counted as a tunnel: %+v", s)
	}
	if s := stats["internal.example.com"]; s.Tunnels != 0 || s.Blocked != 1 {
		t.Errorf("dial-time refusal stats = %+v", s)
	}

	h.dialer.route(80, upstream.Listener.Addr().String())
	if status, err := getStatus(client, "http://example.com/"); err != nil || status != http.StatusOK {
		t.Fatalf("GET after the route = %d, %v", status, err)
	}
	if e := h.sink.wait(t, EventAllowed, 1)[0]; !e.FirstSeen {
		t.Errorf("the first connected request is not the first contact: %+v", e)
	}
	eventually(t, "the request to be counted and closed", func() bool {
		s := h.proxy.Counter().DestinationsFor("binding-one")
		return len(s) == 2 && s[0].Host == "example.com" && s[0].Tunnels == 1 && s[0].Active == 0
	})
}

// SetDecider must not let upstream connections pooled under the old decider
// carry requests the new one refuses at dial time (here a CIDR block on the
// resolved address), including connections that in-flight requests hand
// back to the pool after the swap.
func TestProxySetDeciderRetiresPooledUpstreams(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			entered <- struct{}{}
			<-release
		}
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	h := newHarness(t, nil)
	h.dialer.route(80, upstream.Listener.Addr().String())
	a, b := h.clientFor(h.cred, nil), h.clientFor(h.cred, nil)

	if status, err := getStatus(a, "http://example.com/"); err != nil || status != http.StatusOK {
		t.Fatalf("warm-up = %d, %v", status, err)
	}
	slow := make(chan error, 1)
	go func() {
		status, err := getStatus(b, "http://example.com/slow")
		if err == nil && status != http.StatusOK {
			err = fmt.Errorf("status %d", status)
		}
		slow <- err
	}()
	<-entered // the in-flight request holds the pooled connection
	if status, err := getStatus(a, "http://example.com/"); err != nil || status != http.StatusOK {
		t.Fatalf("second connection = %d, %v", status, err)
	}

	d := mustDecider(t, DeciderOptions{Block: []string{publicV4 + "/32"}})
	d.local = h.local
	if err := h.proxy.SetDecider(d); err != nil {
		t.Fatal(err)
	}
	unblock()
	if err := <-slow; err != nil {
		t.Fatalf("in-flight request across SetDecider: %v", err)
	}
	for i := 0; i < 3; i++ {
		if status, err := getStatus(a, "http://example.com/"); err != nil || status != http.StatusForbidden {
			t.Fatalf("request %d after SetDecider = %d, %v; want 403 (a pooled connection skipped the new CIDR block)", i, status, err)
		}
	}
	if e := h.sink.wait(t, EventBlocked, 1)[0]; e.Category != CategoryOperatorBlock || e.Rule != publicV4+"/32" {
		t.Errorf("blocked event = %+v", e)
	}
}
