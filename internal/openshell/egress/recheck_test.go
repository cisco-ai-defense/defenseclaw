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
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

// TestProxyRecheckClosesRefusedTunnels pins that open tunnels follow their
// sandbox's current policy: a tunnel its re-registered decider now refuses,
// or whose credential was revoked, is closed by Recheck; the others stay.
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
	if n := h.proxy.Recheck(h.creds.Lookup); n != 0 {
		t.Fatalf("an unchanged policy closed %d tunnel(s)", n)
	}

	// The sandbox's policy now blocks one destination; the other sandbox's
	// credential is revoked.
	pr.Decider = build(DeciderOptions{Block: []string{"example.com"}})
	if err := h.creds.Register(cred, pr); err != nil {
		t.Fatal(err)
	}
	h.creds.Revoke("b-b")
	if n := h.proxy.Recheck(h.creds.Lookup); n != 2 {
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

// TestProxyRecheckEndsForwardedRequests pins that an absolute-form request
// in flight when its sandbox's credential is revoked is ended too.
func TestProxyRecheckEndsForwardedRequests(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer upstream.Close()
	defer close(release)
	h := newHarness(t, nil)
	h.dialer.route(80, upstream.Listener.Addr().String())
	status := make(chan int, 1)
	go func() {
		resp, err := h.clientFor(h.cred, nil).Get("http://example.com/")
		if err != nil {
			status <- 0
			return
		}
		resp.Body.Close()
		status <- resp.StatusCode
	}()
	eventually(t, "the request in flight", func() bool { return len(h.proxy.Tunnels()) == 1 })
	h.creds.Revoke(h.pr.BindingID)
	if n := h.proxy.Recheck(h.creds.Lookup); n != 1 {
		t.Fatalf("Recheck ended %d request(s), want 1", n)
	}
	select {
	case got := <-status:
		if got != http.StatusForbidden {
			t.Fatalf("the ended request got %d, want 403", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the request outlived the revoked credential")
	}
}
