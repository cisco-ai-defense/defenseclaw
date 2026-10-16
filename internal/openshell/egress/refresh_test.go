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
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// GAP-0172: Options.Refresh runs before a new tunnel or forwarded request is
// decided. The decider the credential maps to once the refresh returned
// decides the request, a refusal it returns answers like a suspended
// credential's, and a request without a known credential never reaches it.
func TestProxyRefreshDecidesWithTheCurrentPolicy(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	var next func() *Decision
	h := newHarness(t, func(c *harnessConfig) {
		c.opts.Refresh = func(ctx context.Context, pr Principal) *Decision {
			if ctx == nil {
				t.Error("Refresh without the request's context")
			}
			mu.Lock()
			seen = append(seen, pr.BindingID)
			fn := next
			mu.Unlock()
			if fn == nil {
				return nil
			}
			return fn()
		}
	})
	set := func(fn func() *Decision) {
		mu.Lock()
		next = fn
		mu.Unlock()
	}
	h.dialer.route(443, startEcho(t))
	h.serve(80, answerOK)

	if conn, br := h.openTunnel(h.cred, "example.com:443", ""); !relays(conn, br) {
		t.Fatal("no tunnel under the unchanged policy")
	}

	// Tightened while the sandbox runs: the refresh registers the credential
	// again with a decider that blocks example.com.
	set(func() *Decision {
		pr := h.pr
		pr.Decider = h.newDecider(DeciderOptions{Unblocks: h.unblocks, Block: []string{"example.com"}})
		must(t, h.creds.Register(h.cred, pr))
		return nil
	})
	if resp, body := h.refused(h.cred, "example.com:443"); resp.status != http.StatusForbidden || body.Host != "example.com" ||
		body.Category == CategoryEgressOff {
		t.Fatalf("tightened CONNECT = %d %+v", resp.status, body)
	}
	if res, data := fetch(t, h.clientFor(h.cred, nil), "http://example.com/"); res.StatusCode != http.StatusForbidden {
		t.Fatalf("tightened forwarded GET = %d %s", res.StatusCode, data)
	}

	// Changed and not confirmed: refused as a suspended credential is.
	set(func() *Decision { off := testEgressOff; return &off })
	if resp, body := h.refused(h.cred, "example.com:443"); resp.status != http.StatusForbidden || body.Category != CategoryEgressOff ||
		body.Host != "example.com" || body.Port != 443 {
		t.Fatalf("unconfirmed CONNECT = %d %+v", resp.status, body)
	}
	if res, data := fetch(t, h.clientFor(h.cred, nil), "http://example.com/"); res.StatusCode != http.StatusForbidden ||
		!strings.Contains(string(data), "egress_off") {
		t.Fatalf("unconfirmed forwarded GET = %d %s", res.StatusCode, data)
	}

	// Loosened again.
	set(func() *Decision {
		must(t, h.creds.Register(h.cred, h.pr))
		return nil
	})
	if conn, br := h.openTunnel(h.cred, "example.com:443", ""); !relays(conn, br) {
		t.Fatal("no tunnel after the policy was loosened")
	}

	mu.Lock()
	before := len(seen)
	mu.Unlock()
	conn, _, resp := h.connect("example.com:443", "", nil)
	_ = conn.Close()
	mu.Lock()
	defer mu.Unlock()
	if resp.status != http.StatusProxyAuthRequired || len(seen) != before {
		t.Fatalf("unauthenticated CONNECT = %d, refreshes %d -> %d", resp.status, before, len(seen))
	}
	for _, id := range seen {
		if id != h.pr.BindingID {
			t.Fatalf("refreshed principals %v", seen)
		}
	}
}

// GAP-0172 (DELTA-15 verify r1): a request whose own refresh changed nothing
// is still decided by the decider the credential maps to once the refresh
// returned. A connection that waited for another one's confirmation, or
// found the lease that confirmation renewed, kept the decider it had read
// before the other connection's change was registered, and reached a
// destination the new policy blocks, or was refused one a lifted block
// allows. An allowed tunnel or request is checked again once it is tracked
// (confirmTracked), a refused one is not, so the lifted block is what shows
// the read after Refresh.
func TestProxyRefreshReadsTheCredentialAgainAfterAnotherRequestsChange(t *testing.T) {
	var mu sync.Mutex
	var h *harness
	var next *Principal
	h = newHarness(t, func(c *harnessConfig) {
		c.opts.Refresh = func(context.Context, Principal) *Decision {
			// Another connection's confirmation registers the changed
			// policy while this one waits; this one's own refresh has
			// nothing to report.
			mu.Lock()
			defer mu.Unlock()
			if next != nil {
				must(t, h.creds.Register(h.cred, *next))
				next = nil
			}
			return nil
		}
	})
	h.dialer.route(443, startEcho(t))
	h.serve(80, answerOK)
	blocking := h.pr
	blocking.Decider = h.newDecider(DeciderOptions{Unblocks: h.unblocks, Block: []string{"example.com"}})
	change := func(from, to Principal) {
		must(t, h.creds.Register(h.cred, from))
		mu.Lock()
		next = &to
		mu.Unlock()
	}

	// Tightened by the other connection's confirmation.
	change(h.pr, blocking)
	if res, data := fetch(t, h.clientFor(h.cred, nil), "http://example.com/"); res.StatusCode != http.StatusForbidden ||
		!strings.Contains(string(data), "operator_block") {
		t.Fatalf("forwarded GET after another request's tightening = %d %s", res.StatusCode, data)
	}
	change(h.pr, blocking)
	if resp, body := h.refused(h.cred, "example.com:443"); resp.status != http.StatusForbidden || body.Host != "example.com" ||
		body.Category == CategoryEgressOff {
		t.Fatalf("CONNECT after another request's tightening = %d %+v", resp.status, body)
	}

	// Loosened by it: the block is lifted before this request is decided.
	change(blocking, h.pr)
	if res, data := fetch(t, h.clientFor(h.cred, nil), "http://example.com/"); res.StatusCode != http.StatusOK {
		t.Fatalf("forwarded GET after another request's loosening = %d %s", res.StatusCode, data)
	}
	change(blocking, h.pr)
	if conn, br := h.openTunnel(h.cred, "example.com:443", ""); !relays(conn, br) {
		t.Fatal("no tunnel after another request's loosening")
	}
}
