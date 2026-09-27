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
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

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

// readTunnelRefusal reads the JSON refusal written into a tunnel and checks
// that the tunnel closes after it.
func readTunnelRefusal(t *testing.T, br *bufio.Reader) BlockResponse {
	t.Helper()
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("reading the refusal: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	b := decodeBlock(t, body)
	if resp.StatusCode != http.StatusBadRequest || !resp.Close || b.Category != CategoryInvalidDestination || b.Source != SourceGuard ||
		b.Unblockable || b.Host != "example.com" {
		t.Errorf("refusal %d close=%v body %+v", resp.StatusCode, resp.Close, b)
	}
	if _, err := br.ReadByte(); !errors.Is(err, io.EOF) {
		t.Errorf("tunnel left open after the refusal (%v)", err)
	}
	return b
}

// hostRecorder is an upstream that records the Host of every request it
// serves and describes each request in its response.
type hostRecorder struct {
	mu    sync.Mutex
	hosts []string
}

func (rec *hostRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	rec.mu.Lock()
	rec.hosts = append(rec.hosts, r.Host)
	rec.mu.Unlock()
	fmt.Fprintf(w, "%s %s %s body=%q te=%v ua=%q", r.Method, r.Host, r.URL.RequestURI(), body, r.TransferEncoding, r.UserAgent())
}

func (rec *hostRecorder) seen() []string {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return append([]string(nil), rec.hosts...)
}

// Plain HTTP through CONNECT, as undici sends http:// URLs, works when every
// request is for the tunnel's host: pipelined requests, chunked bodies and
// absolute-form request targets are forwarded and answered in order.
func TestTunnelHTTPForwardsRequestsForItsHost(t *testing.T) {
	rec := &hostRecorder{}
	upstream := httptest.NewServer(rec)
	defer upstream.Close()
	h := newHarness(t, nil)
	h.dialer.route(80, upstream.Listener.Addr().String())

	requests := "GET /one HTTP/1.1\r\nHost: EXAMPLE.com:80\r\n\r\n" +
		"POST /two HTTP/1.1\r\nHost: example.com.\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n" +
		"GET http://example.com/three?q=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: agent/1\r\n\r\n"
	conn, br := h.tunnel("example.com:80", []byte(requests))
	want := []string{
		`GET EXAMPLE.com:80 /one body="" te=[] ua=""`,
		`POST example.com. /two body="hello" te=[chunked] ua=""`,
		`GET example.com /three?q=1 body="" te=[] ua="agent/1"`,
	}
	for _, w := range want {
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("reading the response for %q: %v", w, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != w {
			t.Errorf("response = %d %q, want %q", resp.StatusCode, body, w)
		}
	}
	_ = conn.Close()
	closed := h.sink.wait(t, EventClosed, 1)[0]
	if closed.Terminated || closed.BytesUp < int64(len("GET /one HTTP/1.1\r\n")) || closed.BytesDown == 0 {
		t.Errorf("closed event = %+v", closed)
	}
	if n := len(h.sink.ofKind(EventBlocked)); n != 0 {
		t.Errorf("%d blocked events", n)
	}
}

// A request in a tunnel for any other host, or another port, is refused
// before it reaches the upstream: its Host header could otherwise select any
// site served from the tunnel's address.
func TestTunnelHTTPRefusesOtherHosts(t *testing.T) {
	rec := &hostRecorder{}
	upstream := httptest.NewServer(rec)
	defer upstream.Close()
	h := newHarness(t, func(c *harnessConfig) { c.opts.MaxHeaderBytes = 2048 })
	h.dialer.route(80, upstream.Listener.Addr().String())

	tests := []struct {
		name, request, reason string
	}{
		{"Host header", "GET /raw HTTP/1.1\r\nHost: pastebin.com\r\n\r\n", "asked for pastebin.com"},
		{"absolute-form target", "GET http://pastebin.com/raw HTTP/1.1\r\nHost: example.com\r\n\r\n", "asked for pastebin.com"},
		{"other port", "GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n", "asked for example.com:8080"},
		{"leading empty lines", "\r\n\r\nPOST /hook HTTP/1.1\r\nHost: webhook.site\r\nContent-Length: 2\r\n\r\nhi", "asked for webhook.site"},
		{"lower-case version", "GET / http/1.1\r\nHost: example.com\r\n\r\n", "malformed"},
		{"HTTP/2 request line", "GET / HTTP/2.0\r\nHost: example.com\r\n\r\n", "not HTTP/1.x"},
		{"header too large", "GET / HTTP/1.1\r\nHost: example.com\r\nX-Big: " + strings.Repeat("a", 8<<10) + "\r\n\r\n", "too large"},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, br := h.tunnel("example.com:80", []byte(tt.request))
			if b := readTunnelRefusal(t, br); !strings.Contains(b.Reason, tt.reason) {
				t.Errorf("reason %q does not mention %q", b.Reason, tt.reason)
			}
			e := h.sink.wait(t, EventBlocked, i+1)[i]
			if e.TunnelID == "" || e.Category != CategoryInvalidDestination || e.Method != http.MethodConnect || e.Status != http.StatusBadRequest {
				t.Errorf("blocked event = %+v", e)
			}
		})
	}

	// A refused request after an accepted one ends the tunnel too.
	conn, br := h.tunnel("example.com:80", []byte("GET /ok HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("first request = %v, %v", resp, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	fmt.Fprint(conn, "GET /raw HTTP/1.1\r\nHost: pastebin.com\r\n\r\n")
	readTunnelRefusal(t, br)

	if got := rec.seen(); len(got) != 1 || got[0] != "example.com" {
		t.Errorf("the upstream served hosts %q; only the one allowed request may reach it", got)
	}
	eventually(t, "every tunnel to close", func() bool { return len(h.sink.ofKind(EventClosed)) == len(tests)+1 })
	for _, e := range h.sink.ofKind(EventClosed) {
		if !e.Terminated {
			t.Errorf("closed event of a refused tunnel = %+v", e)
		}
	}
}

// Protocols other than TLS and HTTP/1.x are relayed only on a port the
// operator added: the CONNECT target decided the destination, and nothing
// inside them can name another host. The web ports refuse them, HTTP/2
// prior knowledge included.
func TestTunnelOpaqueProtocols(t *testing.T) {
	h := newHarness(t, func(c *harnessConfig) { c.decider.Ports = []int{80, 443, 5432} })
	sinkAddr, received := startSink(t)
	h.dialer.route(80, sinkAddr)
	h.dialer.route(443, sinkAddr)
	h.dialer.route(5432, startEcho(t))

	h2Preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	for _, data := range [][]byte{[]byte("SSH-2.0-OpenSSH_9.6\r\n"), {0, 0, 0, 8, 4, 0xd2, 0x16, 0x2f}, h2Preface} {
		conn, br := h.tunnel("example.com:5432", nil)
		if _, err := conn.Write(data); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(data))
		if _, err := io.ReadFull(br, got); err != nil || !bytes.Equal(got, data) {
			t.Errorf("extra port relay of %q = %q, %v", data, got, err)
		}
		_ = conn.Close()
	}

	for _, tt := range []struct {
		target string
		data   []byte
	}{
		{"example.com:443", []byte("SSH-2.0-OpenSSH_9.6\r\n")},
		{"example.com:80", []byte{0, 0, 0, 8, 4, 0xd2, 0x16, 0x2f}},
		{"example.com:80", h2Preface},
		{"example.com:443", h2Preface},
		{"example.com:80", []byte("get foo\r\n")},
	} {
		_, br := h.tunnel(tt.target, tt.data)
		if b := readTunnelRefusal(t, br); !strings.Contains(b.Reason, "neither TLS nor an HTTP/1.x request") {
			t.Errorf("%s %q: reason %q", tt.target, tt.data, b.Reason)
		}
	}
	eventually(t, "the refused tunnels to close", func() bool { return len(h.sink.ofKind(EventClosed)) == 8 })
	if n := received(); n != 0 {
		t.Errorf("the web-port upstream received %d bytes", n)
	}
}

// A first flight split across small writes is buffered until it can be
// classified; one that never completes its first line is refused after
// HeaderTimeout rather than guessed at.
func TestTunnelFirstFlightSplit(t *testing.T) {
	rec := &hostRecorder{}
	upstream := httptest.NewServer(rec)
	defer upstream.Close()
	h := newHarness(t, func(c *harnessConfig) {
		c.opts.HeaderTimeout = 300 * time.Millisecond
		c.decider.Ports = []int{80, 443, 2222}
	})
	h.dialer.route(80, upstream.Listener.Addr().String())
	h.dialer.route(2222, startEcho(t))

	writeSlowly := func(conn net.Conn, parts ...string) {
		t.Helper()
		for _, part := range parts {
			if _, err := io.WriteString(conn, part); err != nil {
				t.Fatal(err)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	conn, br := h.tunnel("example.com:80", nil)
	writeSlowly(conn, "\r\n", "GE", "T /split HT", "TP/1.1\r\nHo", "st: example.com\r\n\r\n")
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.HasPrefix(string(body), "GET example.com /split") {
		t.Errorf("split request = %q", body)
	}
	// A stray empty line before an idle pause is not the start of a slow
	// request head.
	writeSlowly(conn, "\r\n")
	time.Sleep(450 * time.Millisecond)
	fmt.Fprint(conn, "GET /later HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if resp, err := http.ReadResponse(br, nil); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("request after a pause = %v, %v", resp, err)
	}
	_ = conn.Close()

	conn, br = h.tunnel("example.com:2222", nil)
	writeSlowly(conn, "SSH-2.0", "-client\r\n")
	got := make([]byte, len("SSH-2.0-client\r\n"))
	if _, err := io.ReadFull(br, got); err != nil || string(got) != "SSH-2.0-client\r\n" {
		t.Errorf("split opaque flight = %q, %v", got, err)
	}
	_ = conn.Close()

	// An unfinished request line would otherwise let the rest of a request
	// through unread, on any port.
	for _, target := range []string{"example.com:80", "example.com:2222"} {
		start := time.Now()
		_, br = h.tunnel(target, []byte("GET / HTTP/1.1"))
		if b := readTunnelRefusal(t, br); !strings.Contains(b.Reason, "did not arrive in full") || time.Since(start) > 3*time.Second {
			t.Errorf("%s: stalled request line refused after %v: %q", target, time.Since(start), b.Reason)
		}
	}
}

// After 101 Switching Protocols to an Upgrade request the tunnel relays the
// new protocol as is. An Upgrade the upstream declines leaves the tunnel
// inspected.
func TestTunnelHTTPUpgrade(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ws" {
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
	}))
	defer upstream.Close()
	h := newHarness(t, nil)
	h.dialer.route(80, upstream.Listener.Addr().String())
	upgrade := func(path string) string {
		return "GET " + path + " HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n\r\n"
	}

	conn, br := h.tunnel("example.com:80", []byte(upgrade("/ws")))
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade = %v, %v", resp, err)
	}
	frames := "frame-data GET / HTTP/1.1\r\nHost: pastebin.com\r\n\r\n"
	fmt.Fprint(conn, frames)
	got := make([]byte, len(frames))
	if _, err := io.ReadFull(br, got); err != nil || string(got) != frames {
		t.Fatalf("frames after the upgrade = %q, %v", got, err)
	}
	_ = conn.Close()

	conn, br = h.tunnel("example.com:80", []byte(upgrade("/plain")))
	resp, err = http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("declined upgrade = %v, %v", resp, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	fmt.Fprint(conn, "GET /raw HTTP/1.1\r\nHost: pastebin.com\r\n\r\n")
	readTunnelRefusal(t, br)
}

// Upload bytes in an inspected tunnel count toward the large-upload block
// as in any other tunnel.
func TestTunnelHTTPLargeUpload(t *testing.T) {
	sinkAddr, received := startSink(t)
	h := newHarness(t, func(c *harnessConfig) {
		c.counter = &CounterOptions{LargeUploadBytes: 1024, BlockLargeUploads: true}
	})
	h.dialer.route(80, sinkAddr)
	conn, br := h.tunnel("example.com:80", nil)
	fmt.Fprintf(conn, "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: %d\r\n\r\n", 8<<10)
	for i := 0; i < 16; i++ {
		if _, err := conn.Write(bytes.Repeat([]byte("u"), 512)); err != nil {
			break
		}
	}
	_, _ = io.Copy(io.Discard, br)
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
}

func TestClassifyFlight(t *testing.T) {
	tests := map[string]flightKind{
		"":                                   flightUnknown,
		"\r\n":                               flightUnknown,
		"GET / HT":                           flightUnknown,
		"SSH-2.0-OpenSSH":                    flightUnknown,
		"GET / HTTP/1.1\r\n":                 flightHTTP,
		"\r\nget /x HTTP/1.0\n":              flightHTTP,
		"GET\t/\thttp/1.1\r\n":               flightHTTP,
		"GET / HTTP/1.1 junk\r\n":            flightHTTP,
		"GET / HTTP/2.0\r\n":                 flightHTTP,
		"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n":   flightOpaque,
		"SSH-2.0-OpenSSH_9.6\r\n":            flightOpaque,
		"get foo\r\n":                        flightOpaque,
		"\x00\x00\x00\x08":                   flightOpaque,
		"{\"jsonrpc\":\"2.0\"}":              flightOpaque,
		"GET /\x01 HTTP/1.1\r\n":             flightOpaque,
		"GET /caf\xc3\xa9 HTTP/1.1\r\n":      flightHTTP,
		"GET / HTTP/1.1\rHost: example.com":  flightUnknown,
		"G\x80T / HTTP/1.1\r\n":              flightOpaque,
		"*1\r\n$4\r\nPING\r\n":               flightOpaque,
		"CONNECT host:443 HTTP/1.1\r\n\r\n":  flightHTTP,
		"OPTIONS * HTTP/1.1\r\nHost: x\r\n":  flightHTTP,
		"PRI * HTTP/2.0\r\n":                 flightOpaque,
		" GET / HTTP/1.1\r\n":                flightHTTP,
		"GET":                                flightUnknown,
		"GET / HTTP/1.1\r":                   flightUnknown,
		"M-SEARCH * HTTP/1.1\r\n":            flightHTTP,
		"QUIT\r\n":                           flightOpaque,
		"\r\n\r\n\r\nPOST / HTTP/1.1\r\n":    flightHTTP,
		"GET / HTTP/1.1\x7f\r\n":             flightOpaque,
		"hello world HTTP/1.1 there\r\n":     flightHTTP,
		"STARTTLS\r\n":                       flightOpaque,
		"EHLO client.example.com\r\n":        flightOpaque,
		"GET /x HTTP/\r\n":                   flightHTTP,
		"GET /x HTTPS/1.1\r\n":               flightOpaque,
		"A B C D E F\r\n":                    flightOpaque,
		"GET /\tHTTP/1.1\r\n":                flightHTTP,
		"\n":                                 flightUnknown,
		"GET / HTTP/1.1\r\nHost: example.co": flightHTTP,
	}
	for in, want := range tests {
		if got := classifyFlight([]byte(in)); got != want {
			t.Errorf("classifyFlight(%q) = %d, want %d", in, got, want)
		}
	}
}
