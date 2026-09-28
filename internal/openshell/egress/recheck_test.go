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
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
)

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

// Recheck makes the open tunnels follow their sandboxes' current policy,
// which the credential store alone cannot reach: a tunnel whose credential
// was revoked or rotated, or whose re-registered decider (an
// administrator's block list, say) now refuses it, is closed and its closed
// event says why; a refusal is also a blocked event of that tunnel. Recheck
// of one binding touches only that binding, of "" every binding, and the
// tunnels the current policy allows stay.
func TestRecheckEndsTunnelsThePolicyNoLongerAllows(t *testing.T) {
	h := newHarness(t, nil)
	h.dialer.route(443, startEcho(t))
	h.resolver.set("api.example.net", []string{publicV4Alt})
	pa := Principal{BindingID: "b-a", SandboxID: "sb-a", SandboxName: "sb-a", Decider: h.newDecider(DeciderOptions{Unblocks: h.unblocks})}
	a := h.addPrincipal(pa)
	b := h.addPrincipal(Principal{BindingID: "b-b", SandboxID: "sb-b", SandboxName: "sb-b"})
	c := h.addPrincipal(Principal{BindingID: "b-c", SandboxID: "sb-c", SandboxName: "sb-c"})
	aConn, aBr := h.openTunnel(a, "example.com:443", "")
	keptConn, keptBr := h.openTunnel(a, "api.example.net:443", "")
	bConn, bBr := h.openTunnel(b, "example.com:443", "")
	cConn, cBr := h.openTunnel(c, "example.com:443", "")
	rotConn, rotBr := h.openTunnel(h.cred, "example.com:443", "")
	if n := h.proxy.Recheck(""); n != 0 {
		t.Fatalf("an unchanged policy closed %d tunnel(s)", n)
	}

	// A revoked credential.
	if !h.creds.Revoke("b-b") {
		t.Fatal("no credential to revoke")
	}
	if !relays(bConn, bBr) {
		t.Fatal("the tunnel closed before any recheck")
	}
	if n := h.proxy.Recheck("b-b"); n != 1 {
		t.Fatalf("Recheck ended %d tunnels of the revoked binding, want 1", n)
	}
	waitClosed(t, "revoked binding", bConn, bBr)
	if !relays(cConn, cBr) {
		t.Fatal("another binding's tunnel was ended")
	}
	if e := closedEvent(t, h, allowedTunnel(t, h, "b-b", "example.com")); !e.Terminated || e.Reason != revokedReason {
		t.Errorf("closed event = %+v, want terminated with the recheck's reason", e)
	}
	if blocked := h.sink.ofKind(EventBlocked); len(blocked) != 0 {
		t.Errorf("a revocation is not a destination refusal: %+v", blocked)
	}
	if _, _, resp := h.connect("example.com:443", basicAuth(b), nil); resp.status != http.StatusProxyAuthRequired {
		t.Errorf("CONNECT with the revoked credential = %d", resp.status)
	}

	// A rotated credential ends the tunnels the old one opened.
	rotated, err := NewCredential()
	must(t, err)
	must(t, h.creds.Register(rotated, h.pr))
	if n := h.proxy.Recheck("binding-one"); n != 1 {
		t.Fatalf("Recheck ended %d tunnels of the rotated credential, want 1", n)
	}
	waitClosed(t, "rotated credential", rotConn, rotBr)
	newConn, newBr := h.openTunnel(rotated, "example.com:443", "")
	if n := h.proxy.Recheck("binding-one"); n != 0 || !relays(newConn, newBr) {
		t.Fatalf("Recheck ended %d tunnels of the current credential", n)
	}

	// A tighter re-registered decider and another revocation, in one
	// Recheck of every binding.
	pa.Decider = h.newDecider(DeciderOptions{AdminBlock: []string{"example.com"}, Unblocks: h.unblocks})
	must(t, h.creds.Register(a, pa))
	h.creds.Revoke("b-c")
	if n := h.proxy.Recheck(""); n != 2 {
		t.Fatalf("Recheck ended %d tunnels, want 2", n)
	}
	waitClosed(t, "admin-blocked destination", aConn, aBr)
	waitClosed(t, "revoked binding", cConn, cBr)
	if !relays(keptConn, keptBr) || !relays(newConn, newBr) {
		t.Fatal("a tunnel the current policy allows was ended")
	}
	id := allowedTunnel(t, h, "b-a", "example.com")
	if e := h.sink.wait(t, EventBlocked, 1)[0]; e.TunnelID != id || e.Category != CategoryAdminBlock || e.Source != SourceAdmin ||
		e.Host != "example.com" || e.Method != http.MethodConnect || e.Unblockable {
		t.Errorf("blocked event = %+v, want the admin block of tunnel %s", e, id)
	}
	for _, id := range []string{id, allowedTunnel(t, h, "b-c", "example.com")} {
		if e := closedEvent(t, h, id); !e.Terminated || e.Reason != revokedReason {
			t.Errorf("closed event = %+v, want terminated with the recheck's reason", e)
		}
	}
	var open []string
	for _, tn := range h.proxy.Tunnels() {
		open = append(open, tn.BindingID+" "+tn.Host)
	}
	slices.Sort(open)
	if !slices.Equal(open, []string{"b-a api.example.net", "binding-one example.com"}) || h.proxy.Recheck("") != 0 {
		t.Errorf("open tunnels after the recheck = %q", open)
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

	d := h.newDecider(DeciderOptions{Block: []string{publicV4 + "/32", "files.example.org"}})
	if err := h.proxy.SetDecider(d); err != nil || h.proxy.Decider() != d || h.proxy.SetDecider(nil) == nil {
		t.Fatalf("SetDecider = %v, or SetDecider(nil) accepted", err)
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

// recheckChanges are the policy changes a recheck applies: a revoked
// credential is answered with a 407, a tighter policy with its refusal.
var recheckChanges = []struct {
	name     string
	change   func(h *harness)
	status   int
	category Category
}{
	{"revoked credential", func(h *harness) { h.creds.Revoke("binding-one") }, http.StatusProxyAuthRequired, ""},
	{"tighter policy", func(h *harness) {
		pr := h.pr
		pr.Decider = h.newDecider(DeciderOptions{AdminBlock: []string{"example.com"}})
		must(h.t, h.creds.Register(h.cred, pr))
	}, http.StatusForbidden, CategoryAdminBlock},
}

// An in-flight forwarded request ends too: before its response began it is
// answered with the refusal or the 407, after that its response is cut.
func TestRecheckEndsInFlightForwardedRequests(t *testing.T) {
	for _, tc := range recheckChanges {
		t.Run(tc.name, func(t *testing.T) {
			entered := make(chan string, 2)
			release := make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			h := newHarness(t, nil)
			h.serve(80, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/stream" {
					w.WriteHeader(http.StatusOK)
					_, _ = io.WriteString(w, "first chunk")
					w.(http.Flusher).Flush()
				}
				entered <- r.URL.Path
				<-release
				_, _ = io.WriteString(w, "rest")
			})
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
			go get(h.clientFor(h.cred, nil), "http://example.com/wait", nil, waited)
			go get(h.clientFor(h.cred, nil), "http://example.com/stream", first, streamed)
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
			} else if tc.category != "" && decodeBlock(t, []byte(r.body)).Category != tc.category {
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
	for _, tc := range recheckChanges {
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
			fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: %s\r\n\r\n", basicAuth(h.cred))
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
