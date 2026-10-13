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
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct{ n atomic.Int64 }

func (c *fakeClock) now() time.Time {
	return time.Unix(1_700_000_000, 0).Add(time.Duration(c.n.Add(1)) * time.Second)
}

// verdict fails unless an upload verdict signalled and cut as wanted.
func verdict(t *testing.T, what string, v uploadVerdict, signal, cut bool) {
	t.Helper()
	if v.signal != signal || v.cut != cut {
		t.Errorf("%s: verdict %+v, want signal %v cut %v", what, v, signal, cut)
	}
}

func TestCounterAccumulates(t *testing.T) {
	c := NewCounter(CounterOptions{LargeUploadBytes: -1})
	f1, first := c.open(testPrincipal, "example.com", netip.Addr{})
	f2, again := c.open(testPrincipal, "example.com", netip.Addr{})
	if !first || again {
		t.Errorf("first contact reported %v, then %v", first, again)
	}
	f3, _ := c.open(Principal{BindingID: "b-2"}, "example.com", netip.Addr{})
	f1.addUp(100, false)
	f1.addDown(1000)
	f2.addUp(10, false)
	f3.addDown(7)
	f2.close()
	f2.close() // idempotent

	if f1.up.Load() != 100 || f1.down.Load() != 1000 || f2.up.Load() != 10 {
		t.Errorf("per-flow counts = %d/%d, %d", f1.up.Load(), f1.down.Load(), f2.up.Load())
	}
	if got := c.DestinationsFor(testPrincipal.BindingID); len(got) != 1 || got[0].BytesUp != 110 || got[0].BytesDown != 1000 ||
		got[0].Tunnels != 2 || got[0].Active != 1 || got[0].LargeUpload {
		t.Errorf("DestinationsFor = %+v", got)
	}
	c.recordBlocked(testPrincipal, "webhook.site")
	all := c.Destinations()
	if len(all) != 3 || all[0].BindingID != "b-1" || all[0].Host != "example.com" || all[1].Host != "webhook.site" || all[1].Blocked != 1 || all[2].BindingID != "b-2" {
		t.Errorf("Destinations ordering/contents = %+v", all)
	}
	if n := c.Forget("b-1"); n != 2 || len(c.DestinationsFor("b-1")) != 0 || len(c.Destinations()) != 1 {
		t.Errorf("Forget = %d, left %+v", n, c.Destinations())
	}
	f1.addUp(1, false) // a detached flow keeps counting without panicking
}

func TestCounterLargeUploadSignal(t *testing.T) {
	c := NewCounter(CounterOptions{LargeUploadBytes: 100})
	if c.LargeUploadBytes() != 100 || NewCounter(CounterOptions{}).LargeUploadBytes() != DefaultLargeUploadBytes {
		t.Fatal("threshold not applied, or zero does not use the default")
	}
	a, _ := c.open(testPrincipal, "drop.example", netip.Addr{})
	b, _ := c.open(testPrincipal, "drop.example", netip.Addr{})
	verdict(t, "below", a.addUp(60, false), false, false)
	if v := b.addUp(60, false); !v.signal || v.cut || v.total != 120 {
		t.Fatalf("crossing verdict = %+v", v)
	}
	verdict(t, "after the signal", a.addUp(500, false), false, false)
	if s := c.DestinationsFor("b-1")[0]; !s.LargeUpload || s.BytesUp != 620 || c.uploadBlocked(testPrincipal, "drop.example") {
		t.Errorf("stats = %+v; an alert-only counter must not block", s)
	}
	// Downloads never count toward the signal, and other bindings are separate.
	other, _ := c.open(Principal{BindingID: "b-2"}, "drop.example", netip.Addr{})
	other.addDown(1 << 20)
	verdict(t, "another binding", other.addUp(99, false), false, false)
}

func TestCounterBlockLargeUploads(t *testing.T) {
	c := NewCounter(CounterOptions{LargeUploadBytes: 100, BlockLargeUploads: true})
	f, _ := c.open(testPrincipal, "drop.example", netip.Addr{})
	verdict(t, "below the threshold", f.addUp(90, false), false, false)
	if v := f.addUp(20, false); !v.signal || !v.cut || v.total != 90 {
		t.Fatalf("crossing verdict = %+v (the crossing chunk must not be counted)", v)
	}
	verdict(t, "after the block", f.addUp(1, false), false, true)
	if !c.uploadBlocked(testPrincipal, "drop.example") || c.uploadBlocked(Principal{BindingID: "b-2"}, "drop.example") {
		t.Error("uploadBlocked scope is wrong")
	}
	// Exempt flows (unblocked destinations) keep flowing.
	e, _ := c.open(testPrincipal, "drop.example", netip.Addr{})
	verdict(t, "exempt flow", e.addUp(1000, true), false, false)

	off := NewCounter(CounterOptions{LargeUploadBytes: -1, BlockLargeUploads: true})
	g, _ := off.open(testPrincipal, "drop.example", netip.Addr{})
	verdict(t, "disabled threshold", g.addUp(1<<40, false), false, false)
	if off.uploadBlocked(testPrincipal, "drop.example") {
		t.Error("disabled threshold still blocks")
	}
}

// TestCounterPerPrincipalThreshold pins that each sandbox's large-upload
// threshold is its own: a principal's LargeUploadBytes overrides the
// counter's, negative turns the signal (and the block) off for it alone,
// and zero keeps the counter's.
func TestCounterPerPrincipalThreshold(t *testing.T) {
	c := NewCounter(CounterOptions{LargeUploadBytes: 1000, BlockLargeUploads: true})
	strict := Principal{BindingID: "b-strict", LargeUploadBytes: 100}
	off := Principal{BindingID: "b-off", LargeUploadBytes: -1}
	s, _ := c.open(strict, "drop.example", netip.Addr{})
	verdict(t, "the sandbox's own 100-byte threshold", s.addUp(101, false), true, true)
	if !c.uploadBlocked(strict, "drop.example") {
		t.Fatal("the strict sandbox's block did not apply")
	}
	d, _ := c.open(Principal{BindingID: "b-default"}, "drop.example", netip.Addr{})
	verdict(t, "another sandbox", d.addUp(101, false), false, false)
	verdict(t, "the counter's threshold", d.addUp(1000, false), true, true)
	o, _ := c.open(off, "drop.example", netip.Addr{})
	verdict(t, "signal off", o.addUp(1<<30, false), false, false)
	if c.uploadBlocked(off, "drop.example") {
		t.Fatal("a sandbox with the signal off was blocked")
	}
}

// TestCounterPerPrincipalBlock pins that the block is each sandbox's own
// too: a principal's BlockLargeUploads blocks its uploads on a counter that
// only reports, other principals' uploads are only reported, and with its
// signal off the flag blocks nothing.
func TestCounterPerPrincipalBlock(t *testing.T) {
	c := NewCounter(CounterOptions{LargeUploadBytes: 100})
	blocking := Principal{BindingID: "b-block", BlockLargeUploads: true}
	b, _ := c.open(blocking, "drop.example", netip.Addr{})
	if v := b.addUp(101, false); !v.signal || !v.cut || v.total != 0 {
		t.Fatalf("the blocking sandbox's crossing verdict = %+v", v)
	}
	if !c.uploadBlocked(blocking, "drop.example") {
		t.Fatal("the blocking sandbox's later uploads are not refused")
	}
	r, _ := c.open(Principal{BindingID: "b-report"}, "drop.example", netip.Addr{})
	verdict(t, "a reporting sandbox", r.addUp(101, false), true, false)
	if c.uploadBlocked(Principal{BindingID: "b-report"}, "drop.example") {
		t.Fatal("a reporting sandbox was blocked")
	}
	off := Principal{BindingID: "b-off", LargeUploadBytes: -1, BlockLargeUploads: true}
	o, _ := c.open(off, "drop.example", netip.Addr{})
	verdict(t, "block without a threshold", o.addUp(1<<30, false), false, false)
}

// Eviction past MaxDestinations keeps live state: open flows, destinations
// flagged for a large upload, the latest one, and upload totals toward the
// threshold, which a flood of other destinations, or of refusals (which no
// limit throttles), must not reset.
func TestCounterEvictionKeepsLiveState(t *testing.T) {
	for name, tc := range map[string]struct {
		flood func(c *Counter)
		max   int
	}{
		"contacts": {func(c *Counter) {
			for i := 0; i < 40; i++ {
				g, _ := c.open(testPrincipal, fmt.Sprintf("h%d.example", i), netip.Addr{})
				g.addDown(1 << 20)
				g.close()
			}
		}, 8},
		// Refusal-only records are capped on their own.
		"refusals": {func(c *Counter) {
			for i := 0; i < 1000; i++ {
				c.recordBlocked(testPrincipal, fmt.Sprintf("h%d.pastebin.com", i))
			}
		}, 16},
	} {
		t.Run(name, func(t *testing.T) {
			clock := &fakeClock{}
			c := NewCounter(CounterOptions{MaxDestinations: 8, LargeUploadBytes: 100, BlockLargeUploads: true, Now: clock.now})
			active, _ := c.open(testPrincipal, "active.example", netip.Addr{})
			defer active.close()
			flagged, _ := c.open(testPrincipal, "flagged.example", netip.Addr{})
			flagged.addUp(101, false)
			flagged.close()
			f, _ := c.open(testPrincipal, "drop.example", netip.Addr{})
			verdict(t, "below the threshold", f.addUp(90, false), false, false)
			f.close()
			tc.flood(c)
			kept := map[string]bool{}
			for _, s := range c.Destinations() {
				kept[s.Host] = true
			}
			if len(kept) > tc.max || !kept["active.example"] || !kept["flagged.example"] || (name == "contacts" && !kept["h39.example"]) {
				t.Errorf("%d destinations tracked (cap %d); kept %v", len(kept), tc.max, kept)
			}
			g, first := c.open(testPrincipal, "drop.example", netip.Addr{})
			defer g.close()
			if v := g.addUp(20, false); first || !v.cut || v.total != 90 {
				t.Errorf("drop.example after the flood: first %v, upload %+v; want a cut at 90", first, v)
			}
		})
	}
}

func TestCounterConcurrent(t *testing.T) {
	c := NewCounter(CounterOptions{LargeUploadBytes: 1000})
	var signals atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f, _ := c.open(testPrincipal, "shared.example", netip.Addr{})
			defer f.close()
			for j := 0; j < 100; j++ {
				if f.addUp(1, false).signal {
					signals.Add(1)
				}
				f.addDown(2)
				_ = c.Destinations()
			}
		}()
	}
	wg.Wait()
	if s := c.DestinationsFor("b-1")[0]; s.BytesUp != 1600 || s.BytesDown != 3200 || s.Tunnels != 16 || s.Active != 0 || signals.Load() != 1 {
		t.Errorf("stats = %+v, signal fired %d times (want 1)", s, signals.Load())
	}
}

// A pending flow (a forwarded request still waiting for its upstream
// connection) counts nothing until it opens, opens once, and never opens
// after it closed.
func TestCounterPendingFlow(t *testing.T) {
	c := NewCounter(CounterOptions{LargeUploadBytes: 100, BlockLargeUploads: true})
	f := c.pending(testPrincipal, "example.com")
	f.addDown(50) // the proxy's own error body, with no upstream
	if s := c.Destinations(); len(s) != 0 || f.down.Load() != 0 {
		t.Fatalf("pending flow counted: %+v, down %d", s, f.down.Load())
	}
	if !f.open() || !f.open() {
		t.Error("the first open is not reported as first contact")
	}
	f.addDown(7)
	if v := f.addUp(10, false); v.cut || v.total != 10 {
		t.Errorf("upload = %+v", v)
	}
	f.close()
	f.close()
	if s := c.DestinationsFor("b-1"); len(s) != 1 || s[0].Tunnels != 1 || s[0].Active != 0 || s[0].BytesUp != 10 || s[0].BytesDown != 7 {
		t.Errorf("stats = %+v", s)
	}

	// Closed before it opened: nothing is counted, and uploads stop.
	g := c.pending(testPrincipal, "other.example")
	g.close()
	if g.open() || len(c.DestinationsFor("b-1")) != 1 {
		t.Error("a closed flow opened")
	}
	verdict(t, "upload on a closed, never-opened flow", g.addUp(1, false), false, true)

	// An upload opens a pending flow, so the threshold always applies.
	u := c.pending(testPrincipal, "drop.example")
	defer u.close()
	verdict(t, "upload on a pending flow", u.addUp(101, false), true, true)
}

// Refusals are not contact: they must not use up the first contact or
// count as tunnels, and their count carries over once the destination is
// contacted.
func TestCounterRefusalIsNotContact(t *testing.T) {
	c := NewCounter(CounterOptions{})
	c.recordBlocked(testPrincipal, "example.com")
	c.recordBlocked(testPrincipal, "example.com")
	s := c.DestinationsFor("b-1")
	if len(s) != 1 || s[0].Blocked != 2 || s[0].Tunnels != 0 || s[0].Contacted || s[0].FirstSeen.IsZero() {
		t.Fatalf("refusal-only stats = %+v", s)
	}
	f, first := c.open(testPrincipal, "example.com", netip.Addr{})
	defer f.close()
	if !first {
		t.Error("the refusals used up the first contact")
	}
	c.recordBlocked(testPrincipal, "example.com")
	if s = c.DestinationsFor("b-1"); len(s) != 1 || s[0].Blocked != 3 || s[0].Tunnels != 1 || !s[0].Contacted {
		t.Errorf("stats after contact = %+v", s)
	}
	c.recordBlocked(testPrincipal, "webhook.site")
	if n := c.Forget("b-1"); n != 2 || len(c.Destinations()) != 0 {
		t.Errorf("Forget = %d, left %+v", n, c.Destinations())
	}
}

// Parallel flows to one destination must not together send more than the
// threshold: the check and the add are one reservation.
func TestCounterUploadReservationIsAtomic(t *testing.T) {
	const threshold, chunk = 10_000, 100
	for round := 0; round < 300; round++ {
		c := NewCounter(CounterOptions{LargeUploadBytes: threshold, BlockLargeUploads: true})
		var sent atomic.Int64
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				f, _ := c.open(testPrincipal, "drop.example", netip.Addr{})
				defer f.close()
				<-start
				for !f.addUp(chunk, false).cut {
					sent.Add(chunk)
				}
			}()
		}
		close(start)
		wg.Wait()
		if s := c.DestinationsFor("b-1")[0]; sent.Load() > threshold || s.BytesUp != sent.Load() || !s.LargeUpload {
			t.Fatalf("round %d: %d bytes let through (counted %d) past a %d-byte block", round, sent.Load(), s.BytesUp, threshold)
		}
	}
}

func TestRegistrableDomain(t *testing.T) {
	for host, want := range map[string]string{
		"example.com": "example.com", "c7.attacker.example.com": "example.com", "a.b.example.co.uk": "example.co.uk",
		"co.uk": "co.uk", "x1.workers.dev": "workers.dev", "a.b.x1.workers.dev": "workers.dev", "someone.github.io": "github.io",
		"bucket.s3.amazonaws.com": "amazonaws.com", "host.attacker.example": "attacker.example",
		"deep.host.corp.internal": "corp.internal", "registry.npmjs.org": "npmjs.org",
		"objects.githubusercontent.com": "githubusercontent.com",
	} {
		if got := registrableDomain(host); got != want {
			t.Errorf("registrableDomain(%q) = %q, want %q", host, got, want)
		}
	}
}

// Uploads to first-seen hosts are totalled per registrable domain and per
// address as well as per host, so rotating subdomains, pointing many names
// at one server, or a provider's free subdomains does not reset the
// threshold. Exempt (unblocked or operator-allowed) flows count only toward
// their own host.
func TestCounterAggregatesUploads(t *testing.T) {
	c := NewCounter(CounterOptions{LargeUploadBytes: 1000})
	send := func(host, remote string, n int64, exempt bool) uploadVerdict {
		addr, _ := netip.ParseAddr(remote)
		f, _ := c.open(testPrincipal, host, addr)
		defer f.close()
		return f.addUp(n, exempt)
	}
	// Subdomain rotation: each host stays far below the threshold.
	verdict(t, "chunk 0", send("c0.attacker.example", "198.51.100.10", 400, false), false, false)
	verdict(t, "chunk 1", send("c1.attacker.example", "198.51.100.11", 400, false), false, false)
	verdict(t, "an exempt flow", send("c9.attacker.example", "198.51.100.12", 1000, true), false, false)
	if v := send("c2.attacker.example", "198.51.100.13", 400, false); !v.signal || v.cut || v.total != 1200 || !strings.Contains(v.scope, "under attacker.example") {
		t.Fatalf("crossing the domain total = %+v", v)
	}
	verdict(t, "the domain again", send("c3.attacker.example", "198.51.100.14", 400, false), false, false)

	for _, tc := range []struct{ a, b, remoteA, remoteB, scope string }{
		// A provider's customer zones count as the provider's domain.
		{"x1.workers.dev", "x2.workers.dev", "198.51.100.20", "198.51.100.21", "under workers.dev"},
		// Different domains at one address count together.
		{"one.example", "two.example", "203.0.113.9", "203.0.113.9", "at 203.0.113.9"},
		// An IPv6 server can answer on every address of its /64.
		{"six-a.example", "six-b.example", "2001:470:1:2::a", "2001:470:1:2::b", "at 2001:470:1:2::/64"},
	} {
		send(tc.a, tc.remoteA, 600, false)
		if v := send(tc.b, tc.remoteB, 600, false); !v.signal || !strings.Contains(v.scope, tc.scope) {
			t.Errorf("%s then %s = %+v, want the total %s", tc.a, tc.b, v, tc.scope)
		}
	}
	if n := c.Forget("b-1"); n == 0 || len(c.aggs) != 0 {
		t.Errorf("Forget left %d aggregates", len(c.aggs))
	}
}

// Under the block, a domain or address total over the threshold cuts every
// first-seen host behind it and refuses those already contacted, while
// exempt flows keep going.
func TestCounterBlocksAggregates(t *testing.T) {
	c := NewCounter(CounterOptions{LargeUploadBytes: 1000, BlockLargeUploads: true})
	var sent int64
	for i := 0; i < 8; i++ {
		f, _ := c.open(testPrincipal, fmt.Sprintf("c%d.attacker.example", i), netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}))
		for !f.addUp(300, false).cut {
			sent += 300
		}
		f.close()
	}
	if sent > 1000 {
		t.Errorf("%d bytes reached rotating subdomains past a 1000-byte block", sent)
	}
	if !c.uploadBlocked(testPrincipal, "c1.attacker.example") || c.uploadBlocked(testPrincipal, "c1.other.example") ||
		c.uploadBlocked(Principal{BindingID: "b-2"}, "c1.attacker.example") {
		t.Error("uploadBlocked does not follow the domain total")
	}
	f, _ := c.open(testPrincipal, "new.attacker.example", netip.Addr{})
	verdict(t, "a first-seen host under a blocked domain", f.addUp(1, false), false, true)
	if v := f.addUp(5000, true); v.cut {
		t.Errorf("an exempt flow was cut: %+v", v)
	}
}

// uploadRefused tells an open flow whose first upload chunk the block would
// cut: its destination, domain or address total already crossed. Exempt
// flows and the alert-only mode are never refused.
func TestCounterUploadRefused(t *testing.T) {
	addr := netip.MustParseAddr("198.51.100.7")
	for _, block := range []bool{true, false} {
		c := NewCounter(CounterOptions{LargeUploadBytes: 1000, BlockLargeUploads: block})
		f, _ := c.open(testPrincipal, "big.example", addr)
		if scope, refused := f.uploadRefused(false); refused {
			t.Fatalf("a fresh flow is refused (%q)", scope)
		}
		verdict(t, "2000 bytes over a 1000-byte threshold", f.addUp(2000, false), true, block)
		f.close()
		if scope, refused := f.uploadRefused(false); refused != block || scope != "" {
			t.Errorf("the flagged destination (block %v) = %q, %v", block, scope, refused)
		}
		if !block {
			continue // the alert-only mode refuses nothing
		}
		for _, tt := range []struct {
			host    string
			addr    netip.Addr
			exempt  bool
			scope   string
			refused bool
		}{
			{host: "other.example", addr: addr, scope: "destinations at 198.51.100.7", refused: true},
			{host: "cdn.big.example", scope: "destinations under big.example", refused: true},
			{host: "other.example", addr: addr, exempt: true},
			{host: "elsewhere.example", addr: netip.MustParseAddr("198.51.100.8")},
		} {
			f, _ := c.open(testPrincipal, tt.host, tt.addr)
			scope, refused := f.uploadRefused(tt.exempt)
			if refused != tt.refused || scope != tt.scope {
				t.Errorf("%s at %s (exempt %v) = %q, %v; want %q, %v", tt.host, tt.addr, tt.exempt, scope, refused, tt.scope, tt.refused)
			}
			// addUp agrees: a refused flow's first chunk is cut.
			if v := f.addUp(1, tt.exempt); v.cut != tt.refused {
				t.Errorf("%s: addUp = %+v, uploadRefused %v", tt.host, v, refused)
			}
			f.close()
		}
	}
}
