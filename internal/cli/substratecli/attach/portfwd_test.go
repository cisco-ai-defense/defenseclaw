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

package attach

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// T-PF6 (B3.2): the laptop end of a forward listens on 127.0.0.1 only. A
// forwarded page is a localhost page in the browser; nothing on the LAN
// reaches it, and an address part is refused rather than honoured.
func TestPortListenerLoopbackOnly(t *testing.T) {
	for _, bad := range []string{"0.0.0.0:3000", "localhost:3000", "[::]:3000", "192.168.1.5:3000", "3000:0.0.0.0", "3000:", "80", "0", "70000", ""} {
		if _, err := ParsePortSpec(bad); err == nil {
			t.Errorf("ParsePortSpec(%q) accepted", bad)
		}
	}
	spec, err := ParsePortSpec("3000:0")
	if err == nil {
		t.Fatalf("LOCAL 0 accepted: %+v", spec)
	}
	for in, want := range map[string]PortSpec{"3000": {Remote: 3000}, "3000:8000": {Remote: 3000, Local: 8000}, "5173": {Remote: 5173}} {
		got, err := ParsePortSpec(in)
		if err != nil || got != want {
			t.Errorf("ParsePortSpec(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	// Take a port, then ask for it: the next free one is used, on loopback.
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	p := busy.Addr().(*net.TCPAddr).Port
	if p+portFreeTries > 65535 {
		t.Skip("ephemeral port too high for the next-free walk")
	}
	l, err := ListenPort(PortSpec{Remote: p})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	a := l.Addr().(*net.TCPAddr)
	if !a.IP.Equal(net.IPv4(127, 0, 0, 1)) || a.Port == p {
		t.Fatalf("listener on %s; want 127.0.0.1 and not the busy port %d", a, p)
	}
	if _, err := ListenPort(PortSpec{Remote: 3000, Local: p}); err == nil || !strings.Contains(err.Error(), ":LOCAL") {
		t.Fatalf("explicit busy LOCAL: %v", err)
	}
}

// portRelay is a relay that serves port streams from a local echo server.
type portRelay struct {
	mu     sync.Mutex
	paths  []string
	refuse string // reason of a 403 refusal, "" to serve
	echo   string // address of the echo server, "" for nothing listening
}

func (p *portRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.paths = append(p.paths, r.URL.Path)
	refuse, echo := p.refuse, p.echo
	p.mu.Unlock()
	if refuse != "" {
		routeRefusal(w, http.StatusForbidden, refuse)
		return
	}
	up := websocket.Upgrader{Subprotocols: []string{relay.Subprotocol}}
	conn, err := up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	if echo == "" {
		b, _ := json.Marshal(relay.PortError{Type: "error", Code: relay.PortErrNothingListening})
		_ = conn.WriteMessage(websocket.TextMessage, b)
		_ = conn.Close()
		return
	}
	tcp, err := net.Dial("tcp", echo)
	if err != nil {
		_ = conn.Close()
		return
	}
	_ = relay.PipePort(conn, tcp)
}

func echoServer(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l.Addr().String()
}

func TestPortForwardCarriesBytes(t *testing.T) {
	pr := &portRelay{echo: echoServer(t)}
	r := newRig(t, pr)
	tun, err := NewTunnel(context.Background(), r.admin.gateway(r.caFile), r.bearer.token, testTarget)
	if err != nil {
		t.Fatal(err)
	}
	l, err := ListenPort(PortSpec{Remote: 3000, Local: freeLocalPort(t)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &PortForward{Tunnel: tun, Spec: PortSpec{Remote: 3000}, Listener: l}
	done := make(chan error, 1)
	go func() { done <- f.Serve(ctx) }()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte("hello forward")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("hello forward"))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hello forward" {
		t.Fatalf("echo through the forward: %q, %v", buf, err)
	}
	c.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve after cancel: %v", err)
	}
	pr.mu.Lock()
	defer pr.mu.Unlock()
	if len(pr.paths) == 0 || pr.paths[0] != relay.Path(relay.RoutePort+"/3000") {
		t.Fatalf("relay paths %v", pr.paths)
	}
	for _, s := range r.admin.seen() {
		if !s.ws || !strings.HasPrefix(s.bearer, bearerPrefix) {
			t.Fatalf("stream request %+v: want a WebSocket with the person's bearer", s)
		}
	}
}

func TestPortForwardRefusals(t *testing.T) {
	for _, tc := range []struct {
		reason string
		final  bool
		text   string
	}{
		{"port_forward_off", true, "turned off on this cluster"},
		{"port_not_allowed", true, "can't be forwarded"},
		{"relay_too_old", true, "Rebuild its template"},
		{"too_many_streams", false, "too many open forwards"},
	} {
		pr := &portRelay{refuse: tc.reason}
		r := newRig(t, pr)
		tun, err := NewTunnel(context.Background(), r.admin.gateway(r.caFile), r.bearer.token, testTarget)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tun.DialPort(context.Background(), 3000)
		var ref *PortRefusal
		if !errors.As(err, &ref) || ref.Reason != tc.reason || ref.Final() != tc.final || !strings.Contains(err.Error(), tc.text) {
			t.Fatalf("%s: %v (%+v)", tc.reason, err, ref)
		}
	}
	// A signed-out bearer is the sign-in error, so the exit code says so.
	r := newRig(t, &portRelay{})
	tun, err := NewTunnel(context.Background(), r.admin.gateway(r.caFile), func(context.Context) (string, error) { return "expired", nil }, testTarget)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tun.DialPort(context.Background(), 3000); !errors.Is(err, ErrNotSignedIn) {
		t.Fatalf("signed out: %v", err)
	}
}

func TestPortForwardNothingListeningIsANote(t *testing.T) {
	r := newRig(t, &portRelay{})
	tun, err := NewTunnel(context.Background(), r.admin.gateway(r.caFile), r.bearer.token, testTarget)
	if err != nil {
		t.Fatal(err)
	}
	l, err := ListenPort(PortSpec{Remote: 3000, Local: freeLocalPort(t)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	noted := make(chan string, 4)
	f := &PortForward{Tunnel: tun, Spec: PortSpec{Remote: 3000}, Listener: l, Note: func(s string) { noted <- s }}
	done := make(chan error, 1)
	go func() { done <- f.Serve(ctx) }()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case s := <-noted:
		if !strings.Contains(s, "Nothing in the agent listens on port 3000") {
			t.Fatalf("note %q", s)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no note for nothing_listening")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("nothing_listening stopped the forward: %v", err)
	}
}

func freeLocalPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}
