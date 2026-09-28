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
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// realClientHello returns the first flight crypto/tls sends for serverName.
func realClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		defer client.Close()
		_ = tls.Client(client, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}).Handshake()
	}()
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, tlsRecordHeaderLen)
	_, err := io.ReadFull(server, hdr)
	must(t, err)
	body := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
	_, err = io.ReadFull(server, body)
	must(t, err)
	return append(hdr, body...)
}

type helloExt struct {
	typ  uint16
	data []byte
}

// sniExt builds a server_name extension listing names as host_names.
func sniExt(names ...string) helloExt {
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, n := range names {
			b.AddUint8(tlsSNIHostName)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(n)) })
		}
	})
	return helloExt{typ: tlsExtServerName, data: b.BytesOrPanic()}
}

// helloMsg builds a minimal ClientHello handshake message; nil exts omits
// the extensions block.
func helloMsg(exts []helloExt) []byte {
	var b cryptobyte.Builder
	b.AddUint8(tlsHandshakeClientHello)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(0x0303)
		b.AddBytes(make([]byte, 32))
		b.AddUint8LengthPrefixed(func(*cryptobyte.Builder) {})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(0x1301) })
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(0) })
		if exts == nil {
			return
		}
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, e := range exts {
				b.AddUint16(e.typ)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(e.data) })
			}
		})
	})
	return b.BytesOrPanic()
}

// records frames a handshake message into handshake records carrying at
// most size bytes each.
func records(msg []byte, size int) []byte {
	var out []byte
	for len(msg) > 0 {
		n := min(size, len(msg))
		out = append(out, tlsRecordHandshake, 3, 1, byte(n>>8), byte(n))
		out = append(out, msg[:n]...)
		msg = msg[n:]
	}
	return out
}

func helloFor(names ...string) []byte {
	return records(helloMsg([]helloExt{{typ: 0x000a, data: []byte{0, 2, 0, 0x1d}}, sniExt(names...)}), tlsMaxPlaintext)
}

// readHello runs readClientHello the way screenFirstFlight does: the first
// read's bytes in hand, the rest from the reader. It returns the bytes read
// followed by what the reader still holds, which the relay forwards next.
func readHello(flight []byte, firstRead int) ([]byte, string, error) {
	firstRead = min(firstRead, len(flight))
	rest := bytes.NewReader(flight[firstRead:])
	got, sni, err := readClientHello(bytes.Clone(flight[:firstRead]), rest)
	unread, _ := io.ReadAll(rest)
	return append(got, unread...), sni, err
}

func TestReadClientHelloRealClients(t *testing.T) {
	for _, name := range []string{"example.com", "pastebin.com", "a.b.c.example.org"} {
		flight := realClientHello(t, name)
		for _, first := range []int{1, 5, 6, len(flight)} {
			got, sni, err := readHello(flight, first)
			if err != nil || sni != name || !bytes.Equal(got, flight) {
				t.Errorf("%s (first read %d): sni %q err %v, %d of %d bytes", name, first, sni, err, len(got), len(flight))
			}
		}
	}
	// crypto/tls sends no SNI for an IP address.
	if _, sni, err := readHello(realClientHello(t, publicV4), 1); err != nil || sni != "" {
		t.Errorf("IP ServerName: sni %q err %v", sni, err)
	}
}

func TestReadClientHelloFraming(t *testing.T) {
	early := []byte("0-rtt application data")
	tests := []struct {
		name   string
		flight []byte
		sni    string
		err    error
	}{
		{"one record", helloFor("webhook.site"), "webhook.site", nil},
		// Record fragmentation is a known SNI-filter evasion; servers
		// reassemble, so must the proxy.
		{"one-byte records", records(helloMsg([]helloExt{sniExt("webhook.site")}), 1), "webhook.site", nil},
		{"seven-byte records", records(helloMsg([]helloExt{sniExt("webhook.site")}), 7), "webhook.site", nil},
		{"trailing dot kept", helloFor("webhook.site."), "webhook.site.", nil},
		{"no extensions", records(helloMsg(nil), tlsMaxPlaintext), "", nil},
		{"no server_name", records(helloMsg([]helloExt{{typ: 0x000a, data: []byte{0, 2, 0, 0x1d}}}), tlsMaxPlaintext), "", nil},
		{"unknown name type skipped", records(helloMsg([]helloExt{{typ: tlsExtServerName, data: []byte{0, 4, 7, 0, 1, 'x'}}}), 64), "", nil},
		{"pipelined bytes kept", append(helloFor("example.com"), early...), "example.com", nil},

		{"duplicate server_name", records(helloMsg([]helloExt{sniExt("example.com"), sniExt("pastebin.com")}), tlsMaxPlaintext), "", errMalformedClientHello},
		{"two host_names", helloFor("example.com", "pastebin.com"), "", errMalformedClientHello},
		{"empty host_name", helloFor(""), "", errMalformedClientHello},
		{"empty server_name list", records(helloMsg([]helloExt{{typ: tlsExtServerName, data: []byte{0, 0}}}), 64), "", errMalformedClientHello},
		{"truncated extension", records(helloMsg([]helloExt{{typ: tlsExtServerName, data: []byte{0, 9, 0}}}), 64), "", errMalformedClientHello},
		{"not a ClientHello", records([]byte{2, 0, 0, 1, 0}, 64), "", errMalformedClientHello},
		{"alert record", []byte{tlsRecordHandshake, 3, 1, 0, 2, 1, 0, tlsRecordAlert, 3, 3, 0, 2, 2, 40}, "", errMalformedClientHello},
		{"zero-length record", []byte{tlsRecordHandshake, 3, 1, 0, 0}, "", errMalformedClientHello},
		{"oversized record", []byte{tlsRecordHandshake, 3, 1, 0x40, 0x01}, "", errMalformedClientHello},
		{"not TLS 1.x", []byte{tlsRecordHandshake, 2, 0, 0, 4, 1, 0, 0, 0}, "", errMalformedClientHello},
		{"oversized ClientHello", []byte{tlsRecordHandshake, 3, 1, 0, 4, 1, 0x01, 0x00, 0x01}, "", errMalformedClientHello},
		{"truncated", helloFor("example.com")[:40], "", io.ErrUnexpectedEOF},
	}
	for _, tt := range tests {
		got, sni, err := readHello(tt.flight, 1)
		if !errors.Is(err, tt.err) || sni != tt.sni {
			t.Errorf("%s: sni %q err %v, want %q %v", tt.name, sni, err, tt.sni, tt.err)
			continue
		}
		if tt.err == nil && !bytes.Equal(got, tt.flight) {
			t.Errorf("%s: returned %d of %d bytes", tt.name, len(got), len(tt.flight))
		}
	}
}

// A hello split into tiny records costs more than maxFirstFlight to buffer
// and is refused instead of read without bound.
func TestReadClientHelloBounded(t *testing.T) {
	var pad cryptobyte.Builder
	pad.AddBytes(make([]byte, 30_000))
	msg := helloMsg([]helloExt{{typ: 0x0015, data: pad.BytesOrPanic()}, sniExt("example.com")})
	if _, sni, err := readHello(records(msg, tlsMaxPlaintext), 1); err != nil || sni != "example.com" {
		t.Fatalf("large hello: sni %q err %v", sni, err)
	}
	if _, _, err := readHello(records(msg, 1), 1); !errors.Is(err, errMalformedClientHello) {
		t.Fatalf("hello in one-byte records = %v, want malformed", err)
	}
	// One byte at a time from the reader still assembles the hello.
	flight := helloFor("example.com")
	got, sni, err := readClientHello(flight[:1:1], iotest.OneByteReader(bytes.NewReader(flight[1:])))
	if err != nil || sni != "example.com" || !bytes.Equal(got, flight) {
		t.Fatalf("one-byte reads: sni %q err %v", sni, err)
	}
}

// tunnelConn reads an established tunnel through the reader that consumed
// the proxy's response head.
type tunnelConn struct {
	net.Conn
	r io.Reader
}

func (c tunnelConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// tlsThrough opens a CONNECT tunnel to target and runs a TLS handshake for
// serverName inside it; a nil pool skips certificate verification.
func (h *harness) tlsThrough(target, serverName string, pool *x509.CertPool) (*tls.Conn, error) {
	h.t.Helper()
	conn, br := h.tunnel(target, nil)
	tc := tls.Client(tunnelConn{Conn: conn, r: br}, &tls.Config{ServerName: serverName, RootCAs: pool, InsecureSkipVerify: pool == nil})
	return tc, tc.Handshake()
}

// TestProxyIPLiteralCONNECT is the open-mode bypass: CONNECT to a CDN
// address, then TLS with a blocklisted server name.
func TestProxyIPLiteralCONNECT(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	upstream.Config.ErrorLog = log.New(io.Discard, "", 0) // refused tunnels drop the dialed upstream mid-handshake
	upstream.StartTLS()
	defer upstream.Close()
	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())
	h := newHarness(t, nil)
	h.dialer.route(443, upstream.Listener.Addr().String())

	_, _, resp := h.connect(publicV4+":443", basicAuth(h.cred), helloFor("pastebin.com"))
	if resp.status != http.StatusForbidden || resp.reason != "Blocked by DefenseClaw (ip_literal)" {
		t.Fatalf("CONNECT literal = %d %q", resp.status, resp.reason)
	}
	if b := decodeBlock(t, resp.body); b.Category != CategoryIPLiteral || b.Source != SourceDefault || !b.Unblockable || b.Host != publicV4 ||
		!strings.Contains(b.HowToUnblock, "host name") ||
		!strings.Contains(b.HowToUnblock, "defenseclaw sandbox unblock "+publicV4+" --sandbox sb-one") {
		t.Errorf("block body = %+v", b)
	}
	if resp, body := fetch(t, h.clientFor(h.cred, nil), "http://["+publicV6+"]/"); resp.StatusCode != http.StatusForbidden || decodeBlock(t, body).Category != CategoryIPLiteral {
		t.Errorf("absolute-form literal = %d %s", resp.StatusCode, body)
	}
	if n := len(h.dialer.addresses()); n != 0 {
		t.Errorf("refused literals dialed %d times", n)
	}

	// Unblocked, the literal works, but its tunnel still cannot carry a
	// blocklisted server name.
	must(t, h.unblocks.Add(Unblock{Pattern: publicV4, SandboxID: "sb-1"}))
	tc, err := h.tlsThrough(publicV4+":443", "example.com", pool)
	if err != nil {
		t.Fatalf("unblocked literal with an allowed server name: %v", err)
	}
	_ = tc.Close()
	if _, err := h.tlsThrough(publicV4+":443", "pastebin.com", nil); err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("unblocked literal with SNI pastebin.com: handshake error %v, want an access_denied alert", err)
	}
	e := h.sink.wait(t, EventBlocked, 3)[2]
	if e.Host != "pastebin.com" || e.Category != CategoryPasteSite || e.Source != SourceFeed || e.TunnelID == "" ||
		!strings.Contains(e.Reason, publicV4) {
		t.Errorf("SNI blocked event = %+v", e)
	}
}

func TestProxyServerNameScreening(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) { c.opts.HeaderTimeout = 300 * time.Millisecond })
	h.dialer.route(443, startEcho(t))

	tests := []struct {
		name     string
		hello    []byte
		pipeline bool     // send the hello with the CONNECT head
		category Category // empty: the hello must reach the upstream
		alert    byte
	}{
		{name: "same name", hello: helloFor("example.com")},
		{name: "same name, case and trailing dot", hello: helloFor("EXAMPLE.com.")},
		{name: "other allowed name", hello: helloFor("api.github.com")},
		{name: "IP literal SNI", hello: helloFor(publicV4)},
		{name: "no SNI", hello: records(helloMsg(nil), tlsMaxPlaintext)},
		{name: "blocklisted", hello: helloFor("pastebin.com"), category: CategoryPasteSite, alert: tlsAlertAccessDenied},
		{name: "blocklisted, pipelined", hello: helloFor("webhook.site"), pipeline: true, category: CategoryWebhookCatcher, alert: tlsAlertAccessDenied},
		{name: "blocklisted, fragmented", hello: records(helloMsg([]helloExt{sniExt("Abc.NGROK-free.app.")}), 3), category: CategoryTunnel, alert: tlsAlertAccessDenied},
		{name: "host-internal", hello: helloFor("host.openshell.internal"), category: CategoryHostInternal, alert: tlsAlertAccessDenied},
		{name: "invalid name", hello: helloFor("exa mple.com"), category: CategoryInvalidDestination, alert: tlsAlertAccessDenied},
		{name: "duplicate server_name", hello: records(helloMsg([]helloExt{sniExt("example.com"), sniExt("pastebin.com")}), tlsMaxPlaintext),
			category: CategoryInvalidDestination, alert: tlsAlertDecodeError},
	}
	for _, tt := range tests {
		var extra []byte
		if tt.pipeline {
			extra = tt.hello
		}
		before := len(h.sink.ofKind(EventBlocked))
		conn, br := h.tunnel("example.com:443", extra)
		if !tt.pipeline {
			_, err := conn.Write(tt.hello)
			must(t, err)
		}
		if tt.category == "" {
			echo := make([]byte, len(tt.hello))
			if _, err := io.ReadFull(br, echo); err != nil || !bytes.Equal(echo, tt.hello) {
				t.Errorf("%s: hello did not reach the upstream intact (%v)", tt.name, err)
			}
			_ = conn.Close()
			continue
		}
		got, err := io.ReadAll(br)
		if alert := []byte{tlsRecordAlert, 3, 3, 0, 2, tlsAlertFatal, tt.alert}; !bytes.Equal(got, alert) {
			t.Errorf("%s: client got %x (%v), want alert %x and EOF", tt.name, got, err, alert)
		}
		e := h.sink.wait(t, EventBlocked, before+1)[before]
		if e.Category != tt.category || e.TunnelID == "" || e.Method != http.MethodConnect || e.BindingID != "binding-one" {
			t.Errorf("%s: blocked event = %+v", tt.name, e)
		}
		_ = conn.Close()
	}
	eventually(t, "every tunnel to close", func() bool { return len(h.sink.ofKind(EventClosed)) == len(tests) })
	var terminated int
	for _, e := range h.sink.ofKind(EventClosed) {
		if e.Terminated {
			terminated++
			if e.BytesUp != 0 {
				t.Errorf("refused tunnel counted %d bytes up", e.BytesUp)
			}
		}
	}
	if terminated != 6 {
		t.Errorf("%d tunnels closed as terminated, want the 6 refused ones", terminated)
	}
	stats := map[string]DestinationStats{}
	for _, s := range h.proxy.Counter().DestinationsFor("binding-one") {
		stats[s.Host] = s
	}
	if stats["pastebin.com"].Blocked != 1 || stats["abc.ngrok-free.app"].Blocked != 1 {
		t.Errorf("destination stats = %+v", stats)
	}

	// A ClientHello that stalls halfway ends the tunnel after HeaderTimeout.
	_, br := h.tunnel("example.com:443", []byte{tlsRecordHandshake, 3, 1})
	start := time.Now()
	if got, _ := io.ReadAll(br); len(got) != 0 || time.Since(start) > 3*time.Second {
		t.Errorf("stalled hello: got %x after %v", got, time.Since(start))
	}
}

// In allowlist mode the server name must be allowed too, or a CONNECT to an
// allowlisted CDN-hosted registry could carry any site's name.
func TestProxyServerNameAllowlistMode(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) { c.decider.Mode = ModeAllowlist })
	h.dialer.route(443, startEcho(t))
	h.resolver.set("registry.npmjs.org", []string{publicV4})
	try := func(serverName string, want byte) {
		t.Helper()
		conn, br := h.tunnel("registry.npmjs.org:443", helloFor(serverName))
		defer conn.Close()
		if got, err := br.ReadByte(); err != nil || got != want {
			t.Errorf("server name %s: got record type %x (%v), want %x", serverName, got, err, want)
		}
	}
	try("registry.npmjs.org", tlsRecordHandshake)
	try("example.com", tlsRecordAlert)
	if e := h.sink.wait(t, EventBlocked, 1)[0]; e.Category != CategoryNotAllowlisted || e.Host != "example.com" || e.Mode != ModeAllowlist {
		t.Errorf("blocked event = %+v", e)
	}
	must(t, h.unblocks.Add(Unblock{Pattern: "example.com", SandboxID: "sb-1"}))
	try("example.com", tlsRecordHandshake)
}
