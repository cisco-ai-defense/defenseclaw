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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// newDecider builds a decider that sees the harness's fake interfaces.
func (h *harness) newDecider(opts DeciderOptions) *Decider {
	h.t.Helper()
	d := mustDecider(h.t, opts)
	d.local = h.local
	return d
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
	conn, br, resp := h.connect(target, basicAuth(cred), nil)
	if resp.status != http.StatusOK {
		h.t.Fatalf("CONNECT %s = %d %s", target, resp.status, resp.body)
	}
	if _, err := conn.Write(hello); err != nil {
		h.t.Fatal(err)
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

// waitClosed fails unless the proxy closes the tunnel's client connection.
func waitClosed(t *testing.T, what string, conn net.Conn, br *bufio.Reader) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := br.ReadByte()
	if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("%s: the tunnel is still open (read: %v)", what, err)
	}
}

func closedEvent(t *testing.T, h *harness, tunnelID string) Event {
	t.Helper()
	var found Event
	eventually(t, "the closed event of "+tunnelID, func() bool {
		for _, e := range h.sink.ofKind(EventClosed) {
			if e.TunnelID == tunnelID {
				found = e
				return true
			}
		}
		return false
	})
	return found
}

func allowedTunnel(t *testing.T, h *harness, binding, host string) string {
	t.Helper()
	for _, e := range h.sink.ofKind(EventAllowed) {
		if e.BindingID == binding && e.Host == host {
			return e.TunnelID
		}
	}
	t.Fatalf("no allowed event for %s to %s", binding, host)
	return ""
}

// A revoked credential ends its binding's open tunnels once the proxy
// rechecks them, and only that binding's; the store alone cannot reach
// them.
func TestRecheckEndsTunnelsOfARevokedCredential(t *testing.T) {
	h := newHarness(t, nil)
	h.dialer.route(443, startEcho(t))
	other := h.addPrincipal(Principal{BindingID: "binding-two", SandboxID: "sb-2", SandboxName: "sb-two"})
	conn, br := h.openTunnel(h.cred, "example.com:443", "")
	otherConn, otherBr := h.openTunnel(other, "example.com:443", "")

	if !h.creds.Revoke("binding-one") {
		t.Fatal("no credential to revoke")
	}
	if !relays(conn, br) {
		t.Fatal("the tunnel closed before any recheck")
	}
	if n := h.proxy.Recheck("binding-one"); n != 1 {
		t.Fatalf("Recheck ended %d tunnels, want 1", n)
	}
	waitClosed(t, "revoked binding", conn, br)
	if !relays(otherConn, otherBr) {
		t.Fatal("another binding's tunnel was ended")
	}
	if e := closedEvent(t, h, allowedTunnel(t, h, "binding-one", "example.com")); !e.Terminated {
		t.Errorf("closed event = %+v, want terminated", e)
	}
	if blocked := h.sink.ofKind(EventBlocked); len(blocked) != 0 {
		t.Errorf("a revocation is not a destination refusal: %+v", blocked)
	}
	if _, _, resp := h.connect("example.com:443", basicAuth(h.cred), nil); resp.status != http.StatusProxyAuthRequired {
		t.Errorf("CONNECT with the revoked credential = %d", resp.status)
	}
	if n := h.proxy.Recheck(""); n != 0 {
		t.Errorf("a second Recheck ended %d more", n)
	}
}

// A rotated credential ends the tunnels the old one opened.
func TestRecheckEndsTunnelsOfARotatedCredential(t *testing.T) {
	h := newHarness(t, nil)
	h.dialer.route(443, startEcho(t))
	conn, br := h.openTunnel(h.cred, "example.com:443", "")
	rotated, err := NewCredential()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.creds.Register(rotated, h.pr); err != nil {
		t.Fatal(err)
	}
	if n := h.proxy.Recheck("binding-one"); n != 1 {
		t.Fatalf("Recheck ended %d tunnels, want 1", n)
	}
	waitClosed(t, "rotated credential", conn, br)
	newConn, newBr := h.openTunnel(rotated, "example.com:443", "")
	if n := h.proxy.Recheck("binding-one"); n != 0 || !relays(newConn, newBr) {
		t.Fatalf("Recheck ended %d tunnels of the current credential", n)
	}
}

// Re-registering a credential with a tighter decider (an administrator's
// block list, say) ends the open tunnels it now refuses, reported as
// blocked events of those tunnels, and keeps the others.
func TestRecheckAppliesAReregisteredDecider(t *testing.T) {
	h := newHarness(t, nil)
	h.dialer.route(443, startEcho(t))
	h.resolver.set("api.example.net", []string{publicV4Alt})
	pr := h.pr
	pr.Decider = h.newDecider(DeciderOptions{Unblocks: h.unblocks})
	if err := h.creds.Register(h.cred, pr); err != nil {
		t.Fatal(err)
	}
	refusedConn, refusedBr := h.openTunnel(h.cred, "example.com:443", "")
	keptConn, keptBr := h.openTunnel(h.cred, "api.example.net:443", "")

	pr.Decider = h.newDecider(DeciderOptions{AdminBlock: []string{"example.com"}, Unblocks: h.unblocks})
	if err := h.creds.Register(h.cred, pr); err != nil {
		t.Fatal(err)
	}
	if n := h.proxy.Recheck("binding-one"); n != 1 {
		t.Fatalf("Recheck ended %d tunnels, want 1", n)
	}
	waitClosed(t, "admin-blocked destination", refusedConn, refusedBr)
	if !relays(keptConn, keptBr) {
		t.Fatal("a tunnel the new decider allows was ended")
	}
	id := allowedTunnel(t, h, "binding-one", "example.com")
	e := h.sink.wait(t, EventBlocked, 1)[0]
	if e.TunnelID != id || e.Category != CategoryAdminBlock || e.Source != SourceAdmin || e.Host != "example.com" ||
		e.Method != http.MethodConnect || e.Unblockable {
		t.Errorf("blocked event = %+v, want the admin block of tunnel %s", e, id)
	}
	if e := closedEvent(t, h, id); !e.Terminated {
		t.Errorf("closed event = %+v, want terminated", e)
	}
	if n := h.proxy.Recheck("binding-one"); n != 0 {
		t.Errorf("a second Recheck ended %d more", n)
	}
}

// SetDecider rechecks the tunnels of principals without their own decider:
// the address a tunnel is connected to and the TLS server name it asked for
// are decided again too, not only its CONNECT target.
func TestSetDeciderRechecksAddressAndServerName(t *testing.T) {
	h := newHarness(t, nil)
	h.dialer.route(443, startEcho(t))
	h.resolver.set("cdn.example.net", []string{publicV4Alt})
	byAddr, byAddrBr := h.openTunnel(h.cred, "example.com:443", "") // resolves to publicV4
	byName, byNameBr := h.openTunnel(h.cred, "cdn.example.net:443", "files.example.org")
	kept, keptBr := h.openTunnel(h.cred, "cdn.example.net:443", "")

	if err := h.proxy.SetDecider(h.newDecider(DeciderOptions{Block: []string{publicV4 + "/32", "files.example.org"}})); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, "blocked address", byAddr, byAddrBr)
	waitClosed(t, "blocked server name", byName, byNameBr)
	if !relays(kept, keptBr) {
		t.Fatal("a tunnel the new decider allows was ended")
	}
	var addr, name bool
	for _, e := range h.sink.wait(t, EventBlocked, 2) {
		switch {
		case e.Host == "example.com" && e.Rule == publicV4+"/32" && e.Category == CategoryOperatorBlock && e.TunnelID != "":
			addr = true
		case e.Host == "files.example.org" && e.Category == CategoryOperatorBlock && e.TunnelID != "" &&
			strings.Contains(e.Reason, "TLS server name"):
			name = true
		default:
			t.Errorf("unexpected blocked event %+v", e)
		}
	}
	if !addr || !name {
		t.Errorf("blocked events = %+v, want the address and the server name", h.sink.ofKind(EventBlocked))
	}
}

// An in-flight forwarded request ends too: before its response began it is
// answered with the refusal or the 407, after that its response is cut.
func TestRecheckEndsInFlightForwardedRequests(t *testing.T) {
	entered := make(chan string, 2)
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stream" {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "first chunk")
			w.(http.Flusher).Flush()
		}
		entered <- r.URL.Path
		<-release
		_, _ = io.WriteString(w, "rest")
	}))
	defer upstream.Close()
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()

	for _, tc := range []struct {
		name   string
		change func(h *harness)
		status int
	}{
		{"revoked credential", func(h *harness) { h.creds.Revoke("binding-one") }, http.StatusProxyAuthRequired},
		{"tighter policy", func(h *harness) {
			pr := h.pr
			pr.Decider = h.newDecider(DeciderOptions{Block: []string{"example.com"}})
			if err := h.creds.Register(h.cred, pr); err != nil {
				h.t.Fatal(err)
			}
		}, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)
			h.dialer.route(80, upstream.Listener.Addr().String())
			waiting, streaming := h.clientFor(h.cred, nil), h.clientFor(h.cred, nil)
			type result struct {
				status int
				body   string
				err    error
			}
			// get sends a request and reports its outcome; with first set it
			// also signals once the response's first chunk arrived.
			get := func(client *http.Client, u string, first chan<- struct{}, out chan<- result) {
				resp, err := client.Get(u)
				if err != nil {
					out <- result{err: err}
					return
				}
				defer resp.Body.Close()
				var head []byte
				if first != nil {
					head = make([]byte, len("first chunk"))
					if _, err := io.ReadFull(resp.Body, head); err != nil {
						out <- result{status: resp.StatusCode, err: err}
						return
					}
					close(first)
				}
				body, err := io.ReadAll(resp.Body)
				out <- result{status: resp.StatusCode, body: string(head) + string(body), err: err}
			}
			waited, streamed, first := make(chan result, 1), make(chan result, 1), make(chan struct{})
			go get(waiting, "http://example.com/wait", nil, waited)
			go get(streaming, "http://example.com/stream", first, streamed)
			for range 2 {
				<-entered
			}
			<-first

			tc.change(h)
			if n := h.proxy.Recheck("binding-one"); n != 2 {
				t.Fatalf("Recheck ended %d requests, want 2", n)
			}
			if r := <-waited; r.err != nil || r.status != tc.status {
				t.Errorf("request waiting for its response = %d %q, %v; want %d", r.status, r.body, r.err, tc.status)
			} else if tc.status == http.StatusForbidden && decodeBlock(t, []byte(r.body)).Category != CategoryOperatorBlock {
				t.Errorf("refusal body = %s", r.body)
			}
			if r := <-streamed; r.err == nil || r.body != "first chunk" {
				t.Errorf("streamed response = %d %q, %v; want it cut after the first chunk", r.status, r.body, r.err)
			}
			eventually(t, "both requests to finish", func() bool { return len(h.proxy.Tunnels()) == 0 })
			if e := h.sink.wait(t, EventClosed, 1)[0]; !e.Terminated {
				t.Errorf("closed event of the streamed response = %+v, want terminated", e)
			}
		})
	}
}

// A credential revoked, or a policy tightened, while a tunnel is being
// dialed reaches it too: the Recheck that ran then could not see it yet, so
// the tunnel is checked again once it is tracked, before its 200.
func TestRecheckReachesTunnelsBeingDialed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		change   func(h *harness)
		status   int
		category Category
	}{
		{"revoked credential", func(h *harness) { h.creds.Revoke("binding-one") }, http.StatusProxyAuthRequired, ""},
		{"tighter policy", func(h *harness) {
			pr := h.pr
			pr.Decider = h.newDecider(DeciderOptions{AdminBlock: []string{"example.com"}})
			if err := h.creds.Register(h.cred, pr); err != nil {
				h.t.Fatal(err)
			}
		}, http.StatusForbidden, CategoryAdminBlock},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)
			h.dialer.route(443, startEcho(t))
			dialing, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			h.dialer.setOnDial(func(string) {
				once.Do(func() {
					close(dialing)
					<-release
				})
			})
			conn, br := h.dialProxy()
			if _, err := fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: %s\r\n\r\n",
				basicAuth(h.cred)); err != nil {
				t.Fatal(err)
			}
			<-dialing
			tc.change(h)
			if n := h.proxy.Recheck("binding-one"); n != 0 {
				t.Fatalf("Recheck ended %d tunnels while none was tracked", n)
			}
			close(release)
			resp := readRawResponse(t, br)
			if resp.status != tc.status {
				t.Fatalf("CONNECT = %d %s, want %d", resp.status, resp.body, tc.status)
			}
			if tc.category != "" {
				if b := decodeBlock(t, resp.body); b.Category != tc.category {
					t.Errorf("refusal = %+v", b)
				}
				if e := h.sink.wait(t, EventBlocked, 1)[0]; e.Category != tc.category || e.TunnelID != "" {
					t.Errorf("blocked event = %+v", e)
				}
			} else if e := h.sink.wait(t, EventAuthFailed, 1)[0]; e.Host != "example.com" {
				t.Errorf("auth_failed event = %+v", e)
			}
			if got := h.sink.ofKind(EventAllowed); len(got) != 0 {
				t.Errorf("allowed events = %+v, want none", got)
			}
		})
	}
}

// TestProxyRecheckClosesRefusedTunnels pins that one Recheck of every
// binding makes the open tunnels follow their sandboxes' current policy: a
// tunnel its re-registered decider now refuses, or whose credential was
// revoked, is closed and its closed event says why; the others stay.
func TestProxyRecheckClosesRefusedTunnels(t *testing.T) {
	h := newHarness(t, nil)
	h.dialer.route(443, startEcho(t))
	h.resolver.set("keep.example", []string{publicV4})
	build := func(opts DeciderOptions) *Decider {
		d := mustDecider(t, opts)
		d.local = h.local
		return d
	}
	pr := Principal{BindingID: "b-a", SandboxID: "sb-a", SandboxName: "sb-a", Decider: build(DeciderOptions{})}
	cred := h.addPrincipal(pr)
	other := h.addPrincipal(Principal{BindingID: "b-b", SandboxID: "sb-b", SandboxName: "sb-b", Decider: build(DeciderOptions{})})
	open := func(c Credential, target string) *bufio.Reader {
		t.Helper()
		_, br, resp := h.connect(target, basicAuth(c), nil)
		if resp.status != http.StatusOK {
			t.Fatalf("CONNECT %s = %d", target, resp.status)
		}
		return br
	}
	openTunnels := func() []string {
		var out []string
		for _, tn := range h.proxy.Tunnels() {
			out = append(out, tn.BindingID+" "+tn.Host)
		}
		slices.Sort(out)
		return out
	}
	blocked := open(cred, "example.com:443")
	open(cred, "keep.example:443")
	revoked := open(other, "example.com:443")
	eventually(t, "three open tunnels", func() bool { return len(openTunnels()) == 3 })
	if n := h.proxy.Recheck(""); n != 0 {
		t.Fatalf("an unchanged policy closed %d tunnel(s)", n)
	}

	// The sandbox's policy now blocks one destination; the other sandbox's
	// credential is revoked.
	pr.Decider = build(DeciderOptions{Block: []string{"example.com"}})
	if err := h.creds.Register(cred, pr); err != nil {
		t.Fatal(err)
	}
	h.creds.Revoke("b-b")
	if n := h.proxy.Recheck(""); n != 2 {
		t.Fatalf("Recheck closed %d tunnel(s), want 2", n)
	}
	for name, br := range map[string]*bufio.Reader{"blocked": blocked, "revoked": revoked} {
		start := time.Now()
		if _, err := br.ReadByte(); err == nil || time.Since(start) > 3*time.Second {
			t.Fatalf("the %s tunnel is still open", name)
		}
	}
	eventually(t, "only the allowed tunnel left", func() bool {
		return slices.Equal(openTunnels(), []string{"b-a keep.example"})
	})
	var terminated int
	for _, e := range h.sink.wait(t, EventClosed, 2) {
		if e.Terminated && e.Reason == revokedReason {
			terminated++
		}
	}
	if terminated != 2 {
		t.Fatalf("closed events for the rechecked tunnels: %d, want 2", terminated)
	}
}
