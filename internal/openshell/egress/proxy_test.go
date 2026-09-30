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

//go:build !windows

package egress

import (
	"bufio"
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
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestProxyConnectTLSEndToEnd drives a real HTTPS request through CONNECT
// to an httptest TLS upstream, with HTTP/2 negotiated inside the tunnel (the
// proxy relays TLS opaquely), and checks attribution, events and counters.
func TestProxyConnectTLSEndToEnd(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "%s %s %d", r.Proto, r.URL.Path, len(body))
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()
	h := newHarness(t, nil)
	h.dialer.route(443, upstream.Listener.Addr().String())

	client := h.clientFor(h.cred, upstream)
	resp, err := client.Post("https://example.com/upload", "text/plain", strings.NewReader(strings.Repeat("x", 5000)))
	must(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "HTTP/2.0 /upload 5000" {
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
	if open, moved := h.proxy.BindingActivity("binding-one"); open != 1 || moved < 5000 {
		t.Errorf("BindingActivity = %d open, %d bytes moved; want the tunnel and its upload", open, moved)
	}
	if open, moved := h.proxy.BindingActivity("binding-two"); open != 0 || moved != 0 {
		t.Errorf("another binding's activity = %d, %d", open, moved)
	}

	client.CloseIdleConnections()
	closed := h.sink.wait(t, EventClosed, 1)[0]
	if closed.TunnelID != allowed.TunnelID || closed.BytesUp < 5000 || closed.BytesDown == 0 || closed.Duration <= 0 || closed.Terminated {
		t.Errorf("closed event = %+v", closed)
	}
	stats := h.proxy.Counter().DestinationsFor("binding-one")
	if len(stats) != 1 || stats[0].BytesUp != closed.BytesUp || stats[0].BytesDown != closed.BytesDown || stats[0].Tunnels != 1 || stats[0].Active != 0 {
		t.Errorf("destination stats = %+v, closed event %+v", stats, closed)
	}
	if open, _ := h.proxy.BindingActivity("binding-one"); open != 0 || len(h.proxy.Tunnels()) != 0 {
		t.Errorf("after close: BindingActivity = %d open, Tunnels() = %+v", open, h.proxy.Tunnels())
	}
}

// TestProxyConnectEarlyData: bytes a client pipelines right after the
// CONNECT head (before the 200), a ClientHello and whatever follows it, must
// reach the upstream.
func TestProxyConnectEarlyData(t *testing.T) {
	h := newHarness(t, nil)
	h.dialer.route(443, startEcho(t))
	early := append(helloFor("example.com"), "early-bytes"...)
	conn, br := h.tunnel("example.com:443", early)
	got := make([]byte, len(early))
	if _, err := io.ReadFull(br, got); err != nil || !bytes.Equal(got, early) {
		t.Fatalf("echo = %q, %v", got, err)
	}
	if !relays(conn, br) {
		t.Fatal("the tunnel stopped relaying after the early data")
	}
}

// TestProxyAbsoluteForm forwards plain-HTTP proxy requests and checks what
// reaches the upstream.
func TestProxyAbsoluteForm(t *testing.T) {
	var seen atomic.Pointer[http.Request]
	h := newHarness(t, nil)
	h.serve(80, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen.Store(r.Clone(context.Background()))
		w.Header().Set("X-Upstream", "yes")
		fmt.Fprintf(w, "%s %s %d", r.Method, r.URL.RequestURI(), len(body))
	})
	req, _ := http.NewRequest(http.MethodPost, "http://example.com/v1/items?q=1&r=two", strings.NewReader(strings.Repeat("y", 1234)))
	req.Header.Set("Connection", "keep-alive, X-Hop")
	req.Header.Set("X-Hop", "drop-me")
	req.Header.Set("X-Keep", "keep-me")
	resp, err := h.clientFor(h.cred, nil).Do(req)
	must(t, err)
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
	// Upload is the request as sent upstream: its head and the 1234-byte
	// body.
	if closed.TunnelID != allowed.TunnelID || closed.BytesUp <= 1234+int64(len("POST /v1/items?q=1&r=two HTTP/1.1\r\n")) ||
		closed.BytesUp > 1234+512 || closed.BytesDown != int64(len(body)) || closed.Status != http.StatusOK {
		t.Errorf("closed event = %+v", closed)
	}
}

func TestProxyAbsoluteFormHTTPSUpstream(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(answerOK))
	defer upstream.Close()
	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())
	h := newHarness(t, func(c *harnessConfig) { c.opts.UpstreamTLS = &tls.Config{RootCAs: pool} })
	h.dialer.route(443, upstream.Listener.Addr().String())
	if _, _, resp, body := h.get(h.cred, "https://example.com/x", ""); resp.StatusCode != http.StatusOK || string(body) != "ok" {
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
		_, br, resp := h.connect("example.com:443", auth, nil)
		var body ErrorResponse
		if err := json.Unmarshal(resp.body, &body); err != nil || body.Error != errCodeAuth ||
			resp.status != http.StatusProxyAuthRequired || resp.header.Get("Proxy-Authenticate") == "" {
			t.Errorf("%s: CONNECT = %d %v %q", name, resp.status, resp.header, resp.body)
		}
		if _, err := br.ReadByte(); !errors.Is(err, io.EOF) {
			t.Errorf("%s: connection left open after 407 (%v)", name, err)
		}
	}
	// Every rejected credential is an event; the credential-less probe is
	// just a challenge.
	h.sink.wait(t, EventAuthFailed, len(cases)-1)
	time.Sleep(50 * time.Millisecond)
	failed := h.sink.ofKind(EventAuthFailed)
	if len(failed) != len(cases)-1 {
		t.Errorf("auth_failed events = %d, want %d", len(failed), len(cases)-1)
	}
	for _, e := range failed {
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
	if resp, _ := readResponse(t, br); resp.StatusCode != http.StatusProxyAuthRequired || resp.Header.Get("Proxy-Authenticate") == "" || !resp.Close {
		t.Errorf("absolute-form 407 = %d %v close=%v", resp.StatusCode, resp.Header, resp.Close)
	}
}

// A blocklisted destination is refused before anything is dialed, with a
// 403 that says why and how to unblock it, for CONNECT and absolute-form
// requests alike. A refusal also ends the connection, so it cannot sit idle
// holding a connection slot.
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
	if s := h.proxy.Counter().DestinationsFor("binding-one"); len(s) != 1 || s[0].Blocked != 1 {
		t.Errorf("counter = %+v", s)
	}

	resp2, body := fetch(t, h.clientFor(h.cred, nil), "http://pastebin.com/raw/abc")
	if b := decodeBlock(t, body); resp2.StatusCode != http.StatusForbidden || !resp2.Close || b.Category != CategoryPasteSite || b.Port != 80 || !b.Unblockable {
		t.Errorf("absolute-form refusal = %d close=%v %+v", resp2.StatusCode, resp2.Close, b)
	}
	if n := len(h.dialer.addresses()); n != 0 {
		t.Errorf("blocked destinations dialed %d times", n)
	}
}

// TestProxyPerPrincipalDeciders pins that every principal is decided by its
// own decider (its sandbox's policy): one sandbox's block list, ports and
// mode never reach another's requests, a principal without one gets the
// default, and re-registering a credential with a new decider applies it to
// the next request.
func TestProxyPerPrincipalDeciders(t *testing.T) {
	h := newHarness(t, nil)
	echo := startEcho(t)
	h.dialer.route(443, echo)
	h.dialer.route(8443, echo)
	h.resolver.set("other.example", []string{publicV4})
	balanced := h.newDecider(DeciderOptions{Mode: ModeAllowlist, Allowlists: []*Feed{}, Allow: []string{"example.com"}})
	a := h.addPrincipal(Principal{BindingID: "b-a", SandboxID: "sb-a", SandboxName: "sb-a", Decider: balanced})
	bPrincipal := Principal{BindingID: "b-b", SandboxID: "sb-b", SandboxName: "sb-b", Decider: h.newDecider(DeciderOptions{Ports: []int{443, 8443}, Block: []string{"example.com"}})}
	b := h.addPrincipal(bPrincipal)
	check := func(who string, c Credential, target string, want int, category Category) {
		t.Helper()
		conn, _, resp := h.connect(target, basicAuth(c), nil)
		_ = conn.Close()
		if resp.status != want || (want == http.StatusForbidden && decodeBlock(t, resp.body).Category != category) {
			t.Fatalf("%s CONNECT %s = %d %s, want %d %s", who, target, resp.status, resp.body, want, category)
		}
	}
	check("a", a, "example.com:443", http.StatusOK, "")
	check("a", a, "other.example:443", http.StatusForbidden, CategoryNotAllowlisted)
	check("a", a, "other.example:8443", http.StatusForbidden, CategoryPortNotAllowed)
	check("b", b, "example.com:443", http.StatusForbidden, CategoryOperatorBlock)
	if _, blk := h.refused(b, "example.com:443"); blk.Unblockable || !strings.Contains(blk.HowToUnblock, "openshell.egress.block") {
		t.Errorf("operator block body = %+v", blk)
	}
	check("b", b, "other.example:8443", http.StatusOK, "")
	check("default", h.cred, "example.com:443", http.StatusOK, "")
	check("default", h.cred, "other.example:8443", http.StatusForbidden, CategoryPortNotAllowed)
	// Absolute-form requests are decided by the principal's decider too.
	if _, _, resp, body := h.get(b, "http://example.com:8443/", ""); resp.StatusCode != http.StatusForbidden || decodeBlock(t, body).Category != CategoryOperatorBlock {
		t.Fatalf("absolute-form request of b = %d %s", resp.StatusCode, body)
	}

	bPrincipal.Decider = h.newDecider(DeciderOptions{Ports: []int{443, 8443}, Block: []string{"other.example"}})
	must(t, h.creds.Register(b, bPrincipal))
	check("b after re-registering", b, "other.example:8443", http.StatusForbidden, CategoryOperatorBlock)
	check("b after re-registering", b, "example.com:443", http.StatusOK, "")
	for _, e := range h.sink.ofKind(EventBlocked) {
		if e.BindingID == "b-b" && e.Category == CategoryOperatorBlock && e.Unblockable {
			t.Fatalf("an operator block was reported unblockable: %+v", e)
		}
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
	h.resolver.set("lan-device.example.net", []string{"2620:fe::1"})

	hints := map[Category]string{CategoryHostInternal: "--host-port", CategoryPrivateNetwork: "openshell.egress.allow"}
	targets := map[string]Category{
		"127.0.0.1:443": CategoryHostInternal, "[::1]:443": CategoryHostInternal, "169.254.169.254:80": CategoryHostInternal,
		"[::ffff:127.0.0.1]:443": CategoryHostInternal, "0.0.0.0:443": CategoryHostInternal,
		"localhost:443": CategoryHostInternal, "host.openshell.internal:443": CategoryHostInternal,
		"metadata.google.internal:80": CategoryHostInternal,
		"10.0.0.1:443":                CategoryPrivateNetwork, "[fd00::1]:443": CategoryPrivateNetwork, "100.64.0.1:443": CategoryPrivateNetwork,
		"internal.example.com:443": CategoryPrivateNetwork, "split.example.com:443": CategoryPrivateNetwork,
		"nas.lan:443": CategoryPrivateNetwork,
		// This machine's own public addresses (fake interface list).
		ownV4 + ":443": CategoryHostInternal, ownV4 + ":80": CategoryHostInternal, "[" + ownV6 + "]:443": CategoryHostInternal,
		"own.example.com:443": CategoryHostInternal,
		// Other hosts on its public subnets: the router, a NAS, other
		// instances in the VPC.
		"lan-device.example.net:443": CategoryPrivateNetwork, "lan-device.example.net:80": CategoryPrivateNetwork,
		"[2620:fe::1]:443": CategoryPrivateNetwork, "9.9.40.2:443": CategoryPrivateNetwork,
	}
	for target, category := range targets {
		resp, b := h.refused(h.cred, target)
		if resp.status != http.StatusForbidden || b.Category != category || b.Unblockable || b.Source != SourceGuard || !strings.Contains(b.HowToUnblock, hints[category]) {
			t.Errorf("CONNECT %s = %d %+v", target, resp.status, b)
		}
	}

	// Rebinding between two tunnels: the first connects to the public
	// answer, the second sees the metadata answer and is refused.
	conn, _ := h.tunnel("rebind.example.com:443", nil)
	_ = conn.Close()
	if resp, _ := h.refused(h.cred, "rebind.example.com:443"); resp.status != http.StatusForbidden {
		t.Errorf("second rebind CONNECT = %d", resp.status)
	}

	// Absolute form goes through the same guard.
	client := h.clientFor(h.cred, nil)
	for u, category := range map[string]Category{"http://internal.example.com/": CategoryPrivateNetwork, "http://own.example.com/": CategoryHostInternal, "http://" + ownV4 + "/": CategoryHostInternal} {
		if resp, body := fetch(t, client, u); resp.StatusCode != http.StatusForbidden || decodeBlock(t, body).Category != category {
			t.Errorf("absolute-form %s = %d %s", u, resp.StatusCode, body)
		}
	}
	for _, addr := range h.dialer.addresses() {
		if isPrivateTarget(addr) {
			t.Errorf("dialer was handed prohibited address %s", addr)
		}
	}
}

// An operator allow rule opens a private-network destination end to end,
// such as an npm mirror on the corporate network: CONNECT and absolute-form
// requests reach it, while private destinations no rule names stay closed
// with a hint that points at the allow list. A wildcard under a public
// domain opens its public answers only. A sandbox whose policy does not let
// the user unblock (its allow entries are ignored) is pointed at the
// administrator instead, for an address and a name refused at dial time
// alike.
func TestProxyOperatorAllowOpensPrivateNetworks(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) {
		c.decider.Allow = []string{"artifactory.corp.example", "10.20.0.0/16", "git.corp", "*.cloud.example"}
	})
	h.dialer.route(443, startEcho(t))
	h.serve(80, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "mirror") })
	for host, addr := range map[string]string{
		"artifactory.corp.example": "10.1.2.3", "db.example.com": "10.20.1.1", "git.corp": "192.168.4.4",
		"wiki.example.com": "10.9.9.9", "api.cloud.example": publicV4, "internal-lb.cloud.example": "10.30.0.1",
	} {
		h.resolver.set(host, []string{addr})
	}

	for _, target := range []string{"artifactory.corp.example:443", "db.example.com:443", "git.corp:443", "10.20.3.3:443", "api.cloud.example:443"} {
		conn, _ := h.tunnel(target, nil)
		_ = conn.Close()
	}
	if resp, body := fetch(t, h.clientFor(h.cred, nil), "http://artifactory.corp.example/api/npm/"); resp.StatusCode != http.StatusOK || string(body) != "mirror" {
		t.Errorf("absolute-form to the allowed mirror = %d %q", resp.StatusCode, body)
	}
	for _, target := range []string{"wiki.example.com:443", "10.9.9.9:443", "nas.lan:443", "internal-lb.cloud.example:443"} {
		resp, b := h.refused(h.cred, target)
		if resp.status != http.StatusForbidden || b.Category != CategoryPrivateNetwork || b.Unblockable ||
			!strings.Contains(b.HowToUnblock, "openshell.egress.allow") || strings.Contains(b.HowToUnblock, "--host-port") {
			t.Errorf("CONNECT %s = %d %+v", target, resp.status, b)
		}
	}

	locked := h.addPrincipal(Principal{BindingID: "b-locked", SandboxID: "sb-locked", Decider: h.newDecider(DeciderOptions{NoUnblock: true})})
	for _, target := range []string{"10.9.9.9:443", "wiki.example.com:443", "nas.lan:443"} {
		resp, b := h.refused(locked, target)
		if resp.status != http.StatusForbidden || b.Category != CategoryPrivateNetwork || b.Unblockable ||
			strings.Contains(b.HowToUnblock, "openshell.egress.allow") || !strings.Contains(b.HowToUnblock, "administrator") {
			t.Errorf("CONNECT %s without unblocking = %d %+v", target, resp.status, b)
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
		if b := decodeBlock(t, resp.body); b.Category != tt.category || b.Unblockable || !strings.Contains(b.HowToUnblock, tt.hint) {
			t.Errorf("CONNECT %s body = %+v", tt.target, b)
		}
	}
	// An invalid destination is a refused destination like any other: the
	// feed names it as blocked, so the counts include it (cert copilot:F8).
	stats := map[string]DestinationStats{}
	for _, s := range h.proxy.Counter().DestinationsFor("binding-one") {
		stats[s.Host] = s
	}
	if s := stats["exa$mple.com"]; s.Blocked != 1 || s.Contacted {
		t.Errorf("invalid destination counted as %+v; want one refusal and no contact", s)
	}
	if s := stats["example.com"]; s.Blocked < 3 || s.Contacted {
		t.Errorf("example.com counted as %+v (all %+v); want its refusals, the one without a port among them", s, stats)
	}

	// An origin-form request is not a proxy request.
	conn, br := h.dialProxy()
	fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
	resp, body := readResponse(t, br)
	var e ErrorResponse
	_ = json.Unmarshal(body, &e)
	if resp.StatusCode != http.StatusBadRequest || e.Error != errCodeNotProxy {
		t.Errorf("origin-form = %d %+v", resp.StatusCode, e)
	}
	// Unsupported absolute-form schemes are invalid destinations.
	if _, _, resp, _ := h.get(h.cred, "ftp://example.com/file", ""); resp.StatusCode != http.StatusBadRequest {
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
	for _, e := range h.sink.wait(t, EventFailed, len(tests)) {
		if e.Error == "" || e.BindingID != "binding-one" || (e.Status != http.StatusBadGateway && e.Status != http.StatusGatewayTimeout) {
			t.Errorf("failed event = %+v", e)
		}
	}
	if n := len(h.sink.ofKind(EventAllowed)); n != 0 {
		t.Errorf("%d allowed events for failed dials", n)
	}
	// Absolute form maps the same failures.
	if resp, _ := fetch(t, h.clientFor(h.cred, nil), "http://nxdomain.example.com/"); resp.StatusCode != http.StatusBadGateway {
		t.Errorf("absolute-form DNS failure = %d", resp.StatusCode)
	}
}

// Request heads are bounded: an oversized one is refused, and a client that
// never finishes its head (slowloris) is disconnected after HeaderTimeout.
func TestProxyRequestHeadLimits(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) {
		c.opts.MaxHeaderBytes = 1024
		c.opts.HeaderTimeout = 150 * time.Millisecond
	})
	conn, br := h.dialProxy()
	fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nX-Big: %s\r\n\r\n", strings.Repeat("a", 16<<10))
	if resp, _ := readResponse(t, br); resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("oversized header = %d", resp.StatusCode)
	}
	conn, br = h.dialProxy()
	start := time.Now()
	fmt.Fprint(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: exam")
	_, _ = io.Copy(io.Discard, br) // returns when the proxy closes the connection
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("slow client held the connection for %v", elapsed)
	}
}

// TestProxyMaxConns: connections beyond MaxConns wait in the backlog
// instead of being served, and are served once a slot frees.
// With every slot carrying a tunnel, a new connection waits until one
// closes.
func TestProxyMaxConns(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) { c.opts.MaxConns = 2 })
	h.dialer.route(443, startEcho(t))
	first, _ := h.tunnel("example.com:443", nil)
	second, _ := h.tunnel("example.com:443", nil)
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

// Nothing can be attributed before a request authenticates (every sandbox
// arrives from loopback), so connections that send nothing, or never finish
// their first request, give way to new ones: they cannot hold every slot,
// stall the accept loop while another sandbox waits, or make the proxy
// close other sandboxes' idle keep-alive connections.
func TestProxyPreAuthConnectionsCannotStarve(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) { c.opts.MaxConns = 4 })
	h.serve(80, answerOK)
	h.dialer.route(443, startEcho(t))
	other := h.addPrincipal(Principal{BindingID: "binding-two", SandboxID: "sb-2"})
	keep, keepBR := h.keepAliveGet(other)
	h.waitIdle("binding-two", 1)

	type silent struct {
		conn net.Conn
		br   *bufio.Reader
	}
	pendingConns := func() int {
		h.proxy.conns.mu.Lock()
		defer h.proxy.conns.mu.Unlock()
		return len(h.proxy.conns.pending)
	}
	var quiet []silent
	for i := 0; i < 3; i++ {
		conn, br := h.dialProxy()
		if i == 2 {
			fmt.Fprint(conn, "CONNECT example.com:443 HTTP/1.1\r\n") // a head that never ends
		}
		quiet = append(quiet, silent{conn, br})
		eventually(t, "the connection to be accepted", func() bool { return pendingConns() == i+1 })
	}

	// Every slot is taken. A sandbox's CONNECT is served at once, in place
	// of the oldest silent connection.
	start := time.Now()
	conn, _ := h.tunnel("example.com:443", nil)
	if time.Since(start) > 2*time.Second {
		t.Fatalf("CONNECT with every slot held by silent connections took %v", time.Since(start))
	}
	_ = conn.Close()
	if !closedByProxy(quiet[0].conn, quiet[0].br, 5*time.Second) {
		t.Error("the oldest silent connection was not closed to make room")
	}
	if closedByProxy(quiet[1].conn, quiet[1].br, 100*time.Millisecond) {
		t.Error("more silent connections were closed than needed")
	}

	// A flood of new silent connections displaces older silent ones, never
	// the other sandbox's idle keep-alive connection: the free slot takes
	// the first, the next five replace the two silent connections left and
	// the first three of the flood.
	var flood []silent
	for i := 0; i < 6; i++ {
		conn, br := h.dialProxy()
		flood = append(flood, silent{conn, br})
	}
	if !closedByProxy(flood[2].conn, flood[2].br, 5*time.Second) {
		t.Fatal("the flood did not displace older silent connections")
	}
	if closedByProxy(keep, keepBR, 100*time.Millisecond) {
		t.Fatal("an authenticated idle keep-alive connection was closed for unauthenticated ones")
	}
	sendGet(keep, other, "http://example.com/", "")
	_ = keep.SetReadDeadline(time.Now().Add(5 * time.Second))
	if resp, _ := readResponse(t, keepBR); resp.StatusCode != http.StatusOK {
		t.Fatalf("keep-alive request after the flood = %d", resp.StatusCode)
	}
}

// A tunnel or forwarded request idle in both directions for
// TunnelIdleTimeout is cut and reported terminated, rather than holding the
// client, the tunnel slot and the upstream connection indefinitely; traffic
// in one direction alone, however slow, keeps it open.
func TestProxyIdleTimeouts(t *testing.T) {
	idle := func(c *harnessConfig) { c.opts.TunnelIdleTimeout = 250 * time.Millisecond }
	trickle := func(write func() error) {
		for i := 0; i < 8 && write() == nil; i++ {
			time.Sleep(60 * time.Millisecond)
		}
	}
	t.Run("tunnel", func(t *testing.T) {
		h := newHarness(t, idle)
		h.dialer.route(443, startEcho(t))
		_, br := h.tunnel("example.com:443", nil)
		start := time.Now()
		if _, err := br.ReadByte(); err == nil || time.Since(start) > 3*time.Second {
			t.Fatalf("idle tunnel read = %v after %v", err, time.Since(start))
		}
		if closed := h.sink.wait(t, EventClosed, 1)[0]; !closed.Terminated {
			t.Errorf("closed event = %+v, want Terminated", closed)
		}
	})
	t.Run("download-only tunnel", func(t *testing.T) {
		h := newHarness(t, idle)
		h.dialer.route(443, startTCP(t, func(c net.Conn) {
			trickle(func() error { _, err := c.Write([]byte{'t'}); return err })
		}))
		_, br := h.tunnel("example.com:443", nil)
		if got, _ := io.ReadAll(br); len(got) != 8 {
			t.Errorf("received %d of 8 bytes: the download-only tunnel was treated as idle", len(got))
		}
	})
	t.Run("stalled forwarded response", func(t *testing.T) {
		stall := make(chan struct{})
		defer close(stall)
		h := newHarness(t, idle)
		h.serve(80, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "1000")
			_, _ = io.WriteString(w, "partial")
			_ = http.NewResponseController(w).Flush()
			select {
			case <-stall:
			case <-r.Context().Done():
			}
		})
		conn, br := h.dialProxy()
		sendGet(conn, h.cred, "http://example.com/", "")
		resp, err := http.ReadResponse(br, nil)
		must(t, err)
		start := time.Now()
		if body, err := io.ReadAll(resp.Body); err == nil || string(body) != "partial" || time.Since(start) > 3*time.Second {
			t.Fatalf("stalled body = %q, %v after %v", body, err, time.Since(start))
		}
		if closed := h.sink.wait(t, EventClosed, 1)[0]; !closed.Terminated || closed.BytesDown != int64(len("partial")) || closed.Status != http.StatusOK {
			t.Errorf("closed event = %+v", closed)
		}
		eventually(t, "the request to be untracked", func() bool { return len(h.proxy.Tunnels()) == 0 })
	})
	t.Run("slow forwarded response", func(t *testing.T) {
		h := newHarness(t, idle)
		h.serve(80, func(w http.ResponseWriter, r *http.Request) {
			rc := http.NewResponseController(w)
			trickle(func() error { _, _ = io.WriteString(w, "t"); return rc.Flush() })
		})
		if resp, body := fetch(t, h.clientFor(h.cred, nil), "http://example.com/"); resp.StatusCode != http.StatusOK || string(body) != "tttttttt" {
			t.Errorf("slow response = %d %q", resp.StatusCode, body)
		}
		if closed := h.sink.wait(t, EventClosed, 1)[0]; closed.Terminated {
			t.Errorf("closed event = %+v", closed)
		}
	})
}

func TestProxyPerBindingLimits(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) { c.opts.MaxTunnelsPerBinding = 1 })
	h.dialer.route(443, startEcho(t))
	first, _ := h.tunnel("example.com:443", nil)
	if resp, b := h.refused(h.cred, "example.com:443"); resp.status != http.StatusTooManyRequests || b.Category != CategoryRateLimited {
		t.Fatalf("second tunnel = %d %+v", resp.status, b)
	}
	other := h.addPrincipal(Principal{BindingID: "binding-two"})
	if _, _, resp := h.connect("example.com:443", basicAuth(other), nil); resp.status != http.StatusOK {
		t.Errorf("another binding was limited: %d", resp.status)
	}
	_ = first.Close()
	eventually(t, "the first tunnel to close", func() bool { return len(h.sink.ofKind(EventClosed)) >= 1 })
	h.tunnel("example.com:443", nil) // the slot was released
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
	if !slices.Equal(statuses, []int{http.StatusOK, http.StatusOK, http.StatusTooManyRequests}) {
		t.Errorf("statuses = %v", statuses)
	}
}

func TestProxyLargeUploadAlert(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) { c.counter = &CounterOptions{LargeUploadBytes: 1024} })
	h.dialer.route(443, startEcho(t))
	conn, br := h.tunnel("example.com:443", nil)
	payload := append(helloFor("example.com"), bytes.Repeat([]byte("z"), 4096)...)
	go func() { _, _ = conn.Write(payload) }()
	if _, err := io.ReadFull(br, make([]byte, len(payload))); err != nil {
		t.Fatalf("alert-only mode interrupted the tunnel: %v", err)
	}
	e := h.sink.wait(t, EventLargeUpload, 1)
	if len(e) != 1 || e[0].Host != "example.com" || e[0].BytesUp <= 1024 || !e[0].FirstSeen || e[0].Terminated ||
		e[0].Category != CategoryLargeUpload || e[0].BindingID != "binding-one" || e[0].TunnelID == "" ||
		!strings.Contains(e[0].Reason, "More than 1024 bytes was sent") {
		t.Errorf("large_upload events = %+v", e)
	}
}

// Under the block a tunnel is cut at the threshold, a TLS one or an
// inspected plain-HTTP one alike, and later tunnels to the flagged
// destination are refused until the user unblocks it. The refusal quotes
// the threshold of the sandbox it refused.
func TestProxyLargeUploadBlock(t *testing.T) {
	for _, tc := range []struct {
		port  int
		first []byte
	}{
		{443, helloFor("example.com")},
		{80, fmt.Appendf(nil, "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: %d\r\n\r\n", 8<<10)},
	} {
		t.Run(strconv.Itoa(tc.port), func(t *testing.T) {
			h := newHarness(t, uploadBlock(1024))
			sinkAddr, received := startSink(t)
			h.dialer.route(tc.port, sinkAddr)
			target := fmt.Sprintf("example.com:%d", tc.port)
			conn, br := h.tunnel(target, tc.first)
			for i := 0; i < 16; i++ {
				if _, err := conn.Write(bytes.Repeat([]byte("u"), 512)); err != nil {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			_, _ = io.Copy(io.Discard, br) // the proxy cuts the tunnel
			if e := h.sink.wait(t, EventLargeUpload, 1)[0]; !e.Terminated {
				t.Errorf("large_upload event = %+v", e)
			}
			if closed := h.sink.wait(t, EventClosed, 1)[0]; !closed.Terminated || closed.BytesUp > 1024 {
				t.Errorf("closed event = %+v", closed)
			}
			eventually(t, "the upstream to see the cut", func() bool { return received() > 0 })
			if got := received(); got > 1024 {
				t.Errorf("upstream received %d bytes past the 1024-byte block", got)
			}

			if resp, b := h.refused(h.cred, target); resp.status != http.StatusForbidden || b.Category != CategoryLargeUpload {
				t.Fatalf("tunnel after the block = %d %+v", resp.status, b)
			}
			must(t, h.unblocks.Add(Unblock{Pattern: "example.com", SandboxID: "sb-1"}))
			h.tunnel(target, nil)
		})
	}
	h := newHarness(t, uploadBlock(0))
	if got := h.proxy.largeUploadReason(Principal{LargeUploadBytes: 3 << 20}, false); !strings.Contains(got, "More than 3 MiB was sent") {
		t.Errorf("reason for a 3 MiB threshold = %q", got)
	}
	// The block stops the upload before it crosses: it says what was tried.
	if got := h.proxy.largeUploadReason(Principal{LargeUploadBytes: 3 << 20}, true); got !=
		"This sandbox tried to send more than 3 MiB to a destination it had not contacted before." {
		t.Errorf("reason of the block for a 3 MiB threshold = %q", got)
	}
}

// A sandbox whose policy blocks large uploads (Principal.BlockLargeUploads)
// has its upload cut at its own threshold while another sandbox on the same
// proxy, whose policy only reports them, keeps uploading. The cut's event
// carries the threshold it crossed and says an unblock lifts the block.
func TestProxyLargeUploadBlockPerSandbox(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) { c.counter = &CounterOptions{LargeUploadBytes: 1 << 20} })
	sinkAddr, received := startSink(t)
	h.dialer.route(443, sinkAddr)
	blocking := h.addPrincipal(Principal{BindingID: "binding-two", SandboxID: "sb-2", SandboxName: "sb-two",
		LargeUploadBytes: 1024, BlockLargeUploads: true})

	conn, br := h.openTunnelTo(blocking, "example.com:443")
	upload(conn, br, 4096)
	e := h.sink.wait(t, EventLargeUpload, 1)[0]
	// At most the threshold left: the reason says what the sandbox tried,
	// not that more was sent.
	if e.SandboxName != "sb-two" || !e.Terminated || !e.Unblockable || e.Threshold != 1024 || e.BytesUp > 1024 ||
		!strings.Contains(e.Reason, "tried to send more than 1024 bytes") || strings.Contains(e.Reason, "was sent") {
		t.Errorf("large_upload event of the blocking sandbox = %+v", e)
	}
	if resp, b := h.refused(blocking, "example.com:443"); resp.status != http.StatusForbidden || b.Category != CategoryLargeUpload ||
		!strings.Contains(b.Reason, "tried to send more than 1024 bytes") {
		t.Fatalf("tunnel after the block = %d %+v", resp.status, b)
	}

	before := received()
	conn, br = h.openTunnelTo(h.cred, "example.com:443")
	upload(conn, br, 4096)
	eventually(t, "the reporting sandbox's upload to arrive", func() bool { return received()-before >= 4096 })
	if got := h.sink.ofKind(EventLargeUpload); len(got) != 1 {
		t.Errorf("large_upload events = %+v, want only the blocking sandbox's", got)
	}
}

// openTunnelTo opens a CONNECT tunnel to target with cred and sends a TLS
// ClientHello for its host, as a client's first flight, without waiting
// for an answer (the upstream may only read).
func (h *harness) openTunnelTo(cred Credential, target string) (net.Conn, *bufio.Reader) {
	h.t.Helper()
	host, _, _ := net.SplitHostPort(target)
	conn, br, resp := h.connect(target, basicAuth(cred), helloFor(host))
	if resp.status != http.StatusOK {
		h.t.Fatalf("CONNECT %s = %d %s", target, resp.status, resp.body)
	}
	return conn, br
}

// upload sends n bytes up an established tunnel, half-closes it and waits
// for the proxy to end it.
func upload(conn net.Conn, br *bufio.Reader, n int) {
	_, _ = conn.Write(bytes.Repeat([]byte("u"), n))
	_ = conn.(interface{ CloseWrite() error }).CloseWrite()
	_, _ = io.Copy(io.Discard, br)
	_ = conn.Close()
}

// Names of different domains that all point at one server share one
// large-upload budget: each fresh name is first-seen, but the address is
// not, so the upload that takes the address total over the threshold is
// cut. Then a CONNECT to another first-seen name at that address, one
// contacted before or a new one, is refused before the tunnel is
// established, with a large_upload body and a blocked event, rather than
// cut silently after the 200.
func TestProxyLargeUploadBlockAtFlaggedAddress(t *testing.T) {
	h := newHarness(t, uploadBlock(1024))
	sinkAddr, received := startSink(t)
	h.dialer.route(443, sinkAddr)
	for _, host := range []string{"known.example", "big.example", "fresh.example"} {
		h.resolver.set(host, []string{publicV4})
	}
	conn, br := h.tunnel("known.example:443", helloFor("known.example"))
	upload(conn, br, 600)
	conn, br = h.tunnel("big.example:443", helloFor("big.example"))
	upload(conn, br, 600) // flags the address, not big.example's own total
	if e := h.sink.wait(t, EventLargeUpload, 1)[0]; e.Host != "big.example" || !e.Terminated || !strings.Contains(e.Reason, "destinations at "+publicV4) {
		t.Fatalf("large_upload event = %+v", e)
	}
	if got := received(); got > 1024 {
		t.Errorf("the sink received %d bytes across two names past the 1024-byte block", got)
	}
	eventually(t, "every tunnel to close", func() bool { return len(h.proxy.Tunnels()) == 0 })

	for _, host := range []string{"known.example", "fresh.example"} {
		resp, b := h.refused(h.cred, host+":443")
		if resp.status != http.StatusForbidden || b.Category != CategoryLargeUpload || !b.Unblockable ||
			!strings.Contains(b.Reason, "destinations at "+publicV4) || !strings.Contains(b.HowToUnblock, "sandbox unblock "+host) {
			t.Errorf("CONNECT %s after the address total crossed = %d %+v", host, resp.status, b)
		}
	}
	var refused []string
	for _, e := range h.sink.ofKind(EventBlocked) {
		if e.Category == CategoryLargeUpload {
			refused = append(refused, e.Host)
		}
	}
	if !slices.Equal(refused, []string{"known.example", "fresh.example"}) {
		t.Errorf("large_upload refusals = %q", refused)
	}
	// An unblock of the name exempts it from the block.
	must(t, h.unblocks.Add(Unblock{Pattern: "fresh.example", SandboxID: "sb-1"}))
	h.tunnel("fresh.example:443", nil)
}

func TestProxyLargeUploadBlockAbsoluteForm(t *testing.T) {
	var got atomic.Int64
	h := newHarness(t, uploadBlock(1024))
	h.serve(80, func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		got.Add(n)
	})
	resp, err := h.clientFor(h.cred, nil).Post("http://example.com/upload", "application/octet-stream", bytes.NewReader(bytes.Repeat([]byte("p"), 64<<10)))
	must(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || decodeBlock(t, body).Category != CategoryLargeUpload {
		t.Fatalf("large POST = %d %s", resp.StatusCode, body)
	}
	if got.Load() > 1024 {
		t.Errorf("upstream received %d bytes", got.Load())
	}
}

// startHTTPCounter runs an HTTP/1.1 upstream that answers every request
// with "ok" and counts the bytes it receives, request heads included.
func startHTTPCounter(t *testing.T) (string, func() int64) {
	var total atomic.Int64
	return startTCP(t, func(c net.Conn) {
		br := bufio.NewReader(&countingReader{r: c, n: &total})
		for {
			req, err := http.ReadRequest(br)
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, req.Body)
			if _, err := io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); err != nil {
				return
			}
		}
	}), total.Load
}

type countingReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c *countingReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	c.n.Add(int64(n))
	return n, err
}

// An absolute-form request's head (request line, URL and headers) is upload
// like its body: a header or query string cannot carry data past the byte
// counts, the large-upload signal or its block. The counts are exactly what
// the upstream received.
func TestProxyAbsoluteFormCountsRequestHeads(t *testing.T) {
	for _, block := range []bool{false, true} {
		t.Run(fmt.Sprintf("block=%v", block), func(t *testing.T) {
			addr, received := startHTTPCounter(t)
			h := newHarness(t, func(c *harnessConfig) {
				c.counter = &CounterOptions{LargeUploadBytes: 4096, BlockLargeUploads: block}
			})
			h.dialer.route(80, addr)
			conn, br := h.dialProxy()
			pad := strings.Repeat("A", 2<<10)
			refused := false
			for i := 0; i < 4 && !refused; i++ {
				sendGet(conn, h.cred, fmt.Sprintf("http://example.com/c%d?d=%s", i, pad[:64]), "X-Pad: "+pad+"\r\n")
				resp, body := readResponse(t, br)
				switch {
				case resp.StatusCode == http.StatusOK:
				case block && resp.StatusCode == http.StatusForbidden && decodeBlock(t, body).Category == CategoryLargeUpload:
					refused = true
				default:
					t.Fatalf("request %d = %d %s", i, resp.StatusCode, body)
				}
			}
			if e := h.sink.wait(t, EventLargeUpload, 1)[0]; e.Terminated != block || e.Host != "example.com" || block != refused {
				t.Errorf("large_upload event = %+v, refused = %v with block = %v", e, refused, block)
			}
			var up int64
			eventually(t, "every request to close", func() bool {
				up = 0
				for _, s := range h.proxy.Counter().DestinationsFor("binding-one") {
					up += s.BytesUp
				}
				return len(h.proxy.Tunnels()) == 0
			})
			if got := received(); up != got || up == 0 || (block && got > 4096) {
				t.Errorf("counted %d bytes up; the upstream received %d (block %v at 4096)", up, got, block)
			}
		})
	}
}

// A custom feed's CIDR entry blocks names that resolve into it, with the
// feed's provenance and the usual unblock path. The refusal before the
// unblock was not contact: the first allowed tunnel is still the first
// contact.
func TestProxyFeedCIDRBlocksNames(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) { c.decider.Blocklists = []*Feed{testFeedCIDR(t)} })
	h.dialer.route(443, startEcho(t))
	h.resolver.set("drop.example.org", []string{publicV4Alt})
	resp, b := h.refused(h.cred, "drop.example.org:443")
	if resp.status != http.StatusForbidden || b.Category != CategoryFileDrop || b.Source != SourceFeed || b.Feed != "team" ||
		b.Rule != "8.8.4.0/24" || !b.Unblockable || !strings.Contains(b.HowToUnblock, "sandbox unblock drop.example.org") {
		t.Fatalf("CONNECT into a feed CIDR = %d %+v", resp.status, b)
	}
	if e := h.sink.wait(t, EventBlocked, 1)[0]; e.Category != CategoryFileDrop || e.Feed != "team" || e.Entry != "Drop net" {
		t.Errorf("blocked event = %+v", e)
	}
	must(t, h.unblocks.Add(Unblock{Pattern: "drop.example.org", SandboxID: "sb-1"}))
	h.tunnel("drop.example.org:443", nil)
	if e := h.sink.wait(t, EventAllowed, 1)[0]; e.Source != SourceUnblock || e.Rule != "drop.example.org" || !e.FirstSeen {
		t.Errorf("allowed event = %+v", e)
	}
}

// wsHandler switches a /ws request that offers a WebSocket upgrade to an
// echo of the raw connection and answers 400 to anything else.
func wsHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/ws" || r.Header.Get("Upgrade") != "websocket" {
		http.Error(w, "no upgrade here", http.StatusBadRequest)
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
}

func TestProxyWebSocketUpgrade(t *testing.T) {
	h := newHarness(t, nil)
	h.serve(80, wsHandler)
	conn, br := h.dialProxy()
	sendGet(conn, h.cred, "http://example.com/ws", "Upgrade: websocket\r\nConnection: Upgrade\r\n")
	if resp, err := http.ReadResponse(br, nil); err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade = %v, %v", resp, err)
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

// Absolute-form requests honor only WebSocket upgrades too: an h2c offer is
// stripped, and an upstream that switches anyway gets a 502 instead of an
// uninspected relay.
func TestProxyAbsoluteFormOnlyWebSocketUpgrades(t *testing.T) {
	var seen atomic.Value
	sw := &switchingUpstream{}
	h := newHarness(t, func(c *harnessConfig) { c.decider.Ports = []int{80, 443, 8080} })
	h.serve(80, func(w http.ResponseWriter, r *http.Request) {
		seen.Store(r.Header.Get("Upgrade") + "|" + r.Header.Get("Http2-Settings"))
		fmt.Fprint(w, "plain")
	})
	h.dialer.route(8080, sw.start(t))
	offer := "Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAoAAAAAIAAAAA\r\n"
	for u, want := range map[string]int{"http://example.com/": http.StatusOK, "http://example.com:8080/": http.StatusBadGateway} {
		if _, _, resp, _ := h.get(h.cred, u, offer); resp.StatusCode != want {
			t.Errorf("%s with an h2c offer = %d, want %d", u, resp.StatusCode, want)
		}
	}
	if got, _ := seen.Load().(string); got != "|" {
		t.Errorf("the upstream saw Upgrade|HTTP2-Settings %q", got)
	}
	if upgrades, _ := sw.seen(); len(upgrades) != 1 || upgrades[0] != "|" {
		t.Errorf("the switching upstream saw %q", upgrades)
	}
}

func TestProxySinkPanicIsContained(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) { c.sink = EventSinkFunc(func(Event) { panic("sink bug") }) })
	h.dialer.route(443, startEcho(t))
	h.openTunnel(h.cred, "example.com:443", "") // fails if the panicking sink broke the tunnel
}

func TestProxyShutdown(t *testing.T) {
	h := newHarness(t, nil)
	h.dialer.route(443, startEcho(t))
	conn, br := h.openTunnel(h.cred, "example.com:443", "")

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
	if !relays(conn, br) {
		t.Fatal("the tunnel stopped during shutdown")
	}
	// ... and is closed when the grace period ends.
	if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Shutdown = %v, want DeadlineExceeded", err)
	}
	if !closedByProxy(conn, br, 5*time.Second) {
		t.Error("tunnel survived the end of the grace period")
	}
	if err := <-h.served; !errors.Is(err, http.ErrServerClosed) {
		t.Errorf("Serve returned %v", err)
	}
	if err := h.proxy.Serve(mustListen(t)); !errors.Is(err, http.ErrServerClosed) {
		t.Errorf("Serve after Shutdown = %v", err)
	}

	idle := newHarness(t, nil)
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if err := idle.proxy.Shutdown(ctx); err != nil || time.Since(start) > time.Second {
		t.Errorf("idle Shutdown = %v after %v", err, time.Since(start))
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
	must(t, err)
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
	d := mustDecider(t, DeciderOptions{})
	if _, err := New(Options{Decider: d}); err == nil {
		t.Error("New without Auth succeeded")
	}
	if _, err := New(Options{Auth: NewCredentialStore()}); err == nil {
		t.Error("New without Decider succeeded")
	}
	p, err := New(Options{Auth: NewCredentialStore(), Decider: d})
	must(t, err)
	defer p.Close()
	wide := fakeAddrListener{Listener: mustListen(t), addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1}}
	if err := p.Serve(wide); !errors.Is(err, ErrNotLoopback) {
		t.Errorf("Serve(non-loopback) = %v", err)
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
	h := newHarness(t, nil)
	h.resolver.set("internal.example.com", []string{"10.1.2.3"})
	client := h.clientFor(h.cred, nil)

	// Nothing listens for port 80 yet, so the dial fails; the second name
	// resolves to a private address and is refused at dial time.
	for u, want := range map[string]int{"http://example.com/": http.StatusBadGateway, "http://internal.example.com/": http.StatusForbidden} {
		if resp, _ := fetch(t, client, u); resp.StatusCode != want {
			t.Fatalf("GET %s = %d; want %d", u, resp.StatusCode, want)
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

	h.serve(80, answerOK)
	if resp, _ := fetch(t, client, "http://example.com/"); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET after the route = %d", resp.StatusCode)
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
// back to the pool after the swap. The in-flight request itself is
// rechecked and refused: it is connected to the blocked address.
func TestProxySetDeciderRetiresPooledUpstreams(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	h := newHarness(t, nil)
	h.serve(80, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			entered <- struct{}{}
			<-release
		}
		fmt.Fprint(w, "ok")
	})
	a, b := h.clientFor(h.cred, nil), h.clientFor(h.cred, nil)

	if status, err := getStatus(a, "http://example.com/"); err != nil || status != http.StatusOK {
		t.Fatalf("warm-up = %d, %v", status, err)
	}
	slow := make(chan error, 1)
	go func() {
		status, err := getStatus(b, "http://example.com/slow")
		if err == nil && status != http.StatusForbidden {
			err = fmt.Errorf("status %d, want 403", status)
		}
		slow <- err
	}()
	<-entered // the in-flight request holds the pooled connection
	if status, err := getStatus(a, "http://example.com/"); err != nil || status != http.StatusOK {
		t.Fatalf("second connection = %d, %v", status, err)
	}

	must(t, h.proxy.SetDecider(h.newDecider(DeciderOptions{Block: []string{publicV4 + "/32"}})))
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

// The upstream Transport pools connections by destination alone, so a
// pooled connection must not carry a request its own dial-time rules would
// refuse: here a feed CIDR that one sandbox's unblock of the address lifts,
// reused by another sandbox and after the unblock is revoked.
func TestProxyPooledUpstreamsKeepPerSandboxDialRules(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) { c.decider.Blocklists = []*Feed{testFeedCIDR(t)} })
	h.serve(80, answerOK)
	h.resolver.set("cdn.example.org", []string{publicV4Alt})
	must(t, h.unblocks.Add(Unblock{Pattern: publicV4Alt, SandboxID: "sb-1"}))
	a := h.clientFor(h.cred, nil)
	b := h.clientFor(h.addPrincipal(Principal{BindingID: "binding-two", SandboxID: "sb-2", SandboxName: "sb-two"}), nil)
	get := func(client *http.Client, who string, want, dials int) {
		t.Helper()
		resp, body := fetch(t, client, "http://cdn.example.org/")
		if resp.StatusCode != want {
			t.Fatalf("%s = %d %q; want %d (a pooled connection skipped its dial-time rules)", who, resp.StatusCode, body, want)
		}
		if want == http.StatusForbidden {
			if blk := decodeBlock(t, body); blk.Category != CategoryFileDrop || blk.Feed != "team" || blk.Rule != "8.8.4.0/24" {
				t.Errorf("%s block = %+v", who, blk)
			}
		}
		if n := len(h.dialer.addresses()); n != dials {
			t.Fatalf("%s: upstream dialed %d times, want %d", who, n, dials)
		}
	}
	get(a, "unblocked sandbox", http.StatusOK, 1)
	get(a, "unblocked sandbox on the pooled connection", http.StatusOK, 1)
	get(b, "another sandbox on the pooled connection", http.StatusForbidden, 1)
	// The refusal closed the pooled connection; the unblocked sandbox warms
	// a new one, which must not outlive the unblock. Refused requests never
	// reach the dialer.
	get(a, "unblocked sandbox after the refusal", http.StatusOK, 2)
	if !h.unblocks.Remove("sb-1", publicV4Alt) {
		t.Fatal("unblock not removed")
	}
	get(a, "the same sandbox after its unblock was revoked", http.StatusForbidden, 2)
}

// keepAliveGet sends an absolute-form GET on a new client connection and
// reads the response, leaving the connection open for more requests.
func (h *harness) keepAliveGet(cred Credential) (net.Conn, *bufio.Reader) {
	h.t.Helper()
	conn, br, resp, _ := h.get(cred, "http://example.com/", "")
	if resp.StatusCode != http.StatusOK || resp.Close {
		h.t.Fatalf("keep-alive GET = %d close=%v", resp.StatusCode, resp.Close)
	}
	return conn, br
}

// waitIdle waits until binding has n idle keep-alive connections.
func (h *harness) waitIdle(binding string, n int) {
	h.t.Helper()
	eventually(h.t, fmt.Sprintf("%d idle connections of %s", n, binding), func() bool {
		tr := h.proxy.conns
		tr.mu.Lock()
		defer tr.mu.Unlock()
		idle := 0
		for c := range tr.byBinding[binding] {
			if !c.idleSince.IsZero() {
				idle++
			}
		}
		return idle == n
	})
}

// When every connection slot is taken, the connection idle longest is
// closed to admit a new one, so one sandbox's idle keep-alive connections
// cannot keep another sandbox out.
func TestProxyReclaimsIdleConnectionsWhenFull(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) { c.opts.MaxConns = 2 })
	h.serve(80, answerOK)
	c1, b1 := h.keepAliveGet(h.cred)
	h.waitIdle("binding-one", 1)
	c2, b2 := h.keepAliveGet(h.cred)
	h.waitIdle("binding-one", 2)
	h.keepAliveGet(h.addPrincipal(Principal{BindingID: "binding-two"}))
	if !closedByProxy(c1, b1, 5*time.Second) {
		t.Error("the longest-idle connection was not closed to make room")
	}
	if closedByProxy(c2, b2, 100*time.Millisecond) {
		t.Error("more connections were closed than needed")
	}
}

// One binding's connections are capped: over MaxConnsPerBinding its
// longest-idle keep-alive connections are closed, and with none idle a new
// request is refused, so a sandbox cannot hoard the proxy's connection
// slots. Other bindings are unaffected.
func TestProxyPerBindingConnectionCap(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) { c.opts.MaxConnsPerBinding = 2 })
	h.serve(80, answerOK)
	h.dialer.route(443, startEcho(t))

	// The server marks a connection idle only after writing its response,
	// so wait for that before the next one to keep the idle order fixed.
	c1, b1 := h.keepAliveGet(h.cred)
	h.waitIdle("binding-one", 1)
	c2, b2 := h.keepAliveGet(h.cred)
	h.waitIdle("binding-one", 2)
	h.keepAliveGet(h.cred) // over the cap: c1, idle longest, is closed
	if !closedByProxy(c1, b1, 5*time.Second) {
		t.Fatal("the longest-idle connection was left open over the cap")
	}
	if closedByProxy(c2, b2, 100*time.Millisecond) {
		t.Fatal("a connection within the cap was closed")
	}
	h.waitIdle("binding-one", 2)

	// Open tunnels count too and are never closed for the cap: two of them
	// displace both idle connections, and a third finds nothing idle.
	h.tunnel("example.com:443", nil)
	h.tunnel("example.com:443", nil)
	if !closedByProxy(c2, b2, 5*time.Second) {
		t.Error("an idle connection survived tunnels taking its place")
	}
	if resp, b := h.refused(h.cred, "example.com:443"); resp.status != http.StatusTooManyRequests || b.Category != CategoryRateLimited ||
		!strings.Contains(b.Reason, "2 connections") {
		t.Errorf("tunnel over the cap = %d %+v", resp.status, b)
	}
	h.keepAliveGet(h.addPrincipal(Principal{BindingID: "binding-two"}))
}

// pipeConn is a tracked connection over one end of a pipe.
func pipeConn(t *testing.T, tr *connTracker, accepted time.Time) *limitConn {
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return &limitConn{Conn: a, tracker: tr, accepted: accepted, release: func() {}}
}

// A connection no request was admitted on is closed as soon as it goes
// idle, and claims move a connection between bindings.
func TestConnTracker(t *testing.T) {
	tr := newConnTracker(1)
	if anon := pipeConn(t, tr, time.Time{}); !tr.setIdle(anon, true) {
		t.Error("an unattributed idle connection is kept")
	}
	c := pipeConn(t, tr, time.Time{})
	if n, ok := tr.claim(c, "b-1"); !ok || n != 1 || tr.setIdle(c, true) {
		t.Fatalf("claim = %d, %v", n, ok)
	}
	if n, ok := tr.claim(c, "b-2"); !ok || n != 1 || len(tr.byBinding["b-1"]) != 0 || !c.idleSince.IsZero() {
		t.Errorf("moving a connection: %d, %v, %v", n, ok, tr.byBinding)
	}
	busy := pipeConn(t, tr, time.Time{})
	if _, ok := tr.claim(busy, "b-2"); ok || busy.binding != "" || len(tr.byBinding["b-2"]) != 1 {
		t.Errorf("claim over the cap with nothing idle = %v, state %+v", ok, tr.byBinding)
	}
	_ = c.Close()
	if len(tr.byBinding) != 0 || len(tr.idle) != 0 || tr.reclaim() || tr.setIdle(c, true) {
		t.Errorf("closed connection still tracked: %v %v", tr.byBinding, tr.idle)
	}
}

// reclaim closes connections no request was admitted on first, oldest
// first, then the longest-idle one, and never one carrying a request.
func TestConnTrackerReclaimOrder(t *testing.T) {
	tr := newConnTracker(0)
	base := time.Unix(1_700_000_000, 0)
	var closed []string
	newConn := func(name string, accepted time.Time) *limitConn {
		c := pipeConn(t, tr, accepted)
		c.release = func() { closed = append(closed, name) }
		tr.addPending(c)
		return c
	}
	idleOld := newConn("idle-old", base)
	idleNew := newConn("idle-new", base.Add(time.Second))
	busy := newConn("busy", base.Add(2*time.Second))
	for _, c := range []*limitConn{idleOld, idleNew, busy} {
		if _, ok := tr.claim(c, "b-1"); !ok {
			t.Fatal("claim failed")
		}
	}
	tr.setIdle(idleOld, true)
	time.Sleep(time.Millisecond)
	tr.setIdle(idleNew, true)
	newConn("pending-new", base.Add(4*time.Second))
	newConn("pending-old", base.Add(3*time.Second))

	for tr.reclaim() {
	}
	if want := []string{"pending-old", "pending-new", "idle-old", "idle-new"}; !slices.Equal(closed, want) {
		t.Errorf("reclaim order = %v, want %v", closed, want)
	}
	if busy.closed {
		t.Error("a connection carrying a request was reclaimed")
	}
}
