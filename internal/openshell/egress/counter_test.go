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

func TestCounterAccumulates(t *testing.T) {
	c := NewCounter(CounterOptions{LargeUploadBytes: -1})
	p2 := Principal{BindingID: "b-2"}

	f1, first := c.open(testPrincipal, "example.com", netip.Addr{})
	if !first {
		t.Error("first contact not reported")
	}
	f2, first := c.open(testPrincipal, "example.com", netip.Addr{})
	if first {
		t.Error("second contact reported as first")
	}
	f3, _ := c.open(p2, "example.com", netip.Addr{})
	f1.addUp(100, false)
	f1.addDown(1000)
	f2.addUp(10, false)
	f3.addDown(7)
	f2.close()
	f2.close() // idempotent

	if f1.up.Load() != 100 || f1.down.Load() != 1000 || f2.up.Load() != 10 {
		t.Errorf("per-flow counts = %d/%d, %d", f1.up.Load(), f1.down.Load(), f2.up.Load())
	}
	got := c.DestinationsFor(testPrincipal.BindingID)
	if len(got) != 1 {
		t.Fatalf("DestinationsFor = %+v", got)
	}
	s := got[0]
	if s.BytesUp != 110 || s.BytesDown != 1000 || s.Tunnels != 2 || s.Active != 1 || !s.Novel || s.LargeUpload {
		t.Errorf("destination stats = %+v", s)
	}
	c.recordBlocked(testPrincipal, "webhook.site")
	all := c.Destinations()
	if len(all) != 3 || all[0].BindingID != "b-1" || all[0].Host != "example.com" || all[1].Host != "webhook.site" || all[1].Blocked != 1 || all[2].BindingID != "b-2" {
		t.Errorf("Destinations ordering/contents = %+v", all)
	}
	if n := c.Forget("b-1"); n != 2 {
		t.Errorf("Forget = %d, want 2", n)
	}
	if len(c.DestinationsFor("b-1")) != 0 || len(c.Destinations()) != 1 {
		t.Error("Forget left destinations behind")
	}
	f1.addUp(1, false) // a detached flow keeps counting without panicking
}

func TestCounterLargeUploadSignal(t *testing.T) {
	c := NewCounter(CounterOptions{LargeUploadBytes: 100})
	if c.LargeUploadBytes() != 100 {
		t.Fatal("threshold not applied")
	}
	a, _ := c.open(testPrincipal, "drop.example", netip.Addr{})
	b, _ := c.open(testPrincipal, "drop.example", netip.Addr{})
	if v := a.addUp(60, false); v.signal || v.cut {
		t.Fatalf("signalled early: %+v", v)
	}
	v := b.addUp(60, false)
	if !v.signal || v.cut || v.total != 120 {
		t.Fatalf("crossing verdict = %+v", v)
	}
	if v := a.addUp(500, false); v.signal || v.cut {
		t.Errorf("signalled twice: %+v", v)
	}
	if s := c.DestinationsFor("b-1")[0]; !s.LargeUpload || s.BytesUp != 620 {
		t.Errorf("stats = %+v", s)
	}
	if c.uploadBlocked(testPrincipal, "drop.example") {
		t.Error("alert-only counter blocks uploads")
	}
	// Downloads never count toward the signal, and other bindings are separate.
	other, _ := c.open(Principal{BindingID: "b-2"}, "drop.example", netip.Addr{})
	other.addDown(1 << 20)
	if v := other.addUp(99, false); v.signal {
		t.Error("another binding inherited the upload total")
	}
}

func TestCounterKnownHost(t *testing.T) {
	var calls atomic.Int32
	c := NewCounter(CounterOptions{
		LargeUploadBytes: 10,
		KnownHost: func(p Principal, host string) bool {
			calls.Add(1)
			return host == "github.com"
		},
	})
	f, _ := c.open(testPrincipal, "github.com", netip.Addr{})
	if v := f.addUp(1000, false); v.signal {
		t.Error("known host raised the large-upload signal")
	}
	c.open(testPrincipal, "github.com", netip.Addr{})
	g, _ := c.open(testPrincipal, "new.example", netip.Addr{})
	if v := g.addUp(11, false); !v.signal {
		t.Error("first-seen host did not raise the signal")
	}
	if calls.Load() != 2 {
		t.Errorf("KnownHost called %d times, want once per destination", calls.Load())
	}
	if s := c.DestinationsFor("b-1"); s[0].Novel || !s[1].Novel {
		t.Errorf("novelty = %+v", s)
	}
}

func TestCounterBlockLargeUploads(t *testing.T) {
	c := NewCounter(CounterOptions{LargeUploadBytes: 100, BlockLargeUploads: true})
	f, _ := c.open(testPrincipal, "drop.example", netip.Addr{})
	if v := f.addUp(90, false); v.cut {
		t.Fatal("cut below the threshold")
	}
	v := f.addUp(20, false)
	if !v.signal || !v.cut || v.total != 90 {
		t.Fatalf("crossing verdict = %+v (the crossing chunk must not be counted)", v)
	}
	if v := f.addUp(1, false); !v.cut || v.signal {
		t.Errorf("after the block: %+v", v)
	}
	if !c.uploadBlocked(testPrincipal, "drop.example") || c.uploadBlocked(Principal{BindingID: "b-2"}, "drop.example") {
		t.Error("uploadBlocked scope is wrong")
	}
	// Exempt flows (unblocked destinations) keep flowing.
	e, _ := c.open(testPrincipal, "drop.example", netip.Addr{})
	if v := e.addUp(1000, true); v.cut {
		t.Error("exempt flow cut")
	}

	off := NewCounter(CounterOptions{LargeUploadBytes: -1, BlockLargeUploads: true})
	g, _ := off.open(testPrincipal, "drop.example", netip.Addr{})
	if v := g.addUp(1<<40, false); v.signal || v.cut || off.uploadBlocked(testPrincipal, "drop.example") {
		t.Error("disabled threshold still signals or blocks")
	}
	if NewCounter(CounterOptions{}).LargeUploadBytes() != DefaultLargeUploadBytes {
		t.Error("zero threshold does not use the default")
	}
}

func TestCounterEviction(t *testing.T) {
	clock := &fakeClock{}
	c := NewCounter(CounterOptions{MaxDestinations: 8, LargeUploadBytes: 1, Now: clock.now})
	active, _ := c.open(testPrincipal, "active.example", netip.Addr{})
	flagged, _ := c.open(testPrincipal, "flagged.example", netip.Addr{})
	flagged.addUp(5, false)
	flagged.close()
	for i := 0; i < 40; i++ {
		f, _ := c.open(testPrincipal, fmt.Sprintf("h%d.example", i), netip.Addr{})
		f.close()
	}
	got := c.Destinations()
	if len(got) > 8 {
		t.Fatalf("%d destinations tracked, cap is 8", len(got))
	}
	kept := map[string]bool{}
	for _, s := range got {
		kept[s.Host] = true
	}
	if !kept["active.example"] || !kept["flagged.example"] || !kept["h39.example"] {
		t.Errorf("eviction dropped live state: %v", kept)
	}
	active.close()
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
	s := c.DestinationsFor("b-1")[0]
	if s.BytesUp != 1600 || s.BytesDown != 3200 || s.Tunnels != 16 || s.Active != 0 {
		t.Errorf("stats = %+v", s)
	}
	if signals.Load() != 1 {
		t.Errorf("signal fired %d times, want 1", signals.Load())
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
	if v := g.addUp(1, false); !v.cut {
		t.Errorf("upload on a closed, never-opened flow = %+v", v)
	}

	// An upload opens a pending flow, so the threshold always applies.
	u := c.pending(testPrincipal, "drop.example")
	defer u.close()
	if v := u.addUp(101, false); !v.cut || !v.signal {
		t.Errorf("upload on a pending flow = %+v", v)
	}
}

// Refusals are not contact: they must not call KnownHost, use up the first
// contact or count as tunnels, and their count carries over once the
// destination is contacted.
func TestCounterRefusalIsNotContact(t *testing.T) {
	var calls atomic.Int32
	c := NewCounter(CounterOptions{KnownHost: func(Principal, string) bool {
		calls.Add(1)
		return false
	}})
	c.recordBlocked(testPrincipal, "example.com")
	c.recordBlocked(testPrincipal, "example.com")
	if n := calls.Load(); n != 0 {
		t.Errorf("KnownHost ran %d times for refusals", n)
	}
	s := c.DestinationsFor("b-1")
	if len(s) != 1 || s[0].Blocked != 2 || s[0].Tunnels != 0 || s[0].Novel || s[0].FirstSeen.IsZero() {
		t.Fatalf("refusal-only stats = %+v", s)
	}
	f, first := c.open(testPrincipal, "example.com", netip.Addr{})
	defer f.close()
	if !first {
		t.Error("a refusal used up the first contact")
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("KnownHost ran %d times, want once at first contact", n)
	}
	c.recordBlocked(testPrincipal, "example.com")
	s = c.DestinationsFor("b-1")
	if len(s) != 1 || s[0].Blocked != 3 || s[0].Tunnels != 1 || !s[0].Novel {
		t.Errorf("stats after contact = %+v", s)
	}
	c.recordBlocked(testPrincipal, "webhook.site")
	if n := c.Forget("b-1"); n != 2 || len(c.Destinations()) != 0 {
		t.Errorf("Forget = %d, left %+v", n, c.Destinations())
	}
}

// A flood of refusals, which no limit throttles, must not evict a
// destination's upload total: that would reset its large-upload threshold.
func TestCounterRefusalsKeepUploadState(t *testing.T) {
	clock := &fakeClock{}
	c := NewCounter(CounterOptions{MaxDestinations: 8, LargeUploadBytes: 100, BlockLargeUploads: true, Now: clock.now})
	f, _ := c.open(testPrincipal, "drop.example", netip.Addr{})
	if v := f.addUp(90, false); v.cut {
		t.Fatal("cut below the threshold")
	}
	f.close()
	for i := 0; i < 1000; i++ {
		c.recordBlocked(testPrincipal, fmt.Sprintf("h%d.pastebin.com", i))
	}
	if n := len(c.Destinations()); n > 16 {
		t.Errorf("%d destinations tracked; refusal-only ones are not capped", n)
	}
	g, first := c.open(testPrincipal, "drop.example", netip.Addr{})
	defer g.close()
	if first {
		t.Error("refusals evicted drop.example")
	}
	if v := g.addUp(20, false); !v.cut || v.total != 90 {
		t.Errorf("upload after the refusal flood = %+v, want a cut at 90", v)
	}
}

// Contacting many other destinations evicts those with nothing counted
// toward the large-upload signal before one close to the threshold.
func TestCounterEvictionKeepsUploadTotals(t *testing.T) {
	clock := &fakeClock{}
	c := NewCounter(CounterOptions{MaxDestinations: 8, LargeUploadBytes: 100, BlockLargeUploads: true, Now: clock.now})
	f, _ := c.open(testPrincipal, "drop.example", netip.Addr{})
	f.addUp(90, false)
	f.close()
	for i := 0; i < 40; i++ {
		g, _ := c.open(testPrincipal, fmt.Sprintf("h%d.example", i), netip.Addr{})
		g.addDown(1 << 20)
		g.close()
	}
	if n := len(c.Destinations()); n > 8 {
		t.Errorf("%d destinations tracked, cap is 8", n)
	}
	g, first := c.open(testPrincipal, "drop.example", netip.Addr{})
	defer g.close()
	if first || !g.addUp(20, false).cut {
		t.Error("eviction reset drop.example's upload total")
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
		s := c.DestinationsFor("b-1")[0]
		if sent.Load() > threshold || s.BytesUp != sent.Load() || !s.LargeUpload {
			t.Fatalf("round %d: %d bytes let through (counted %d) past a %d-byte block", round, sent.Load(), s.BytesUp, threshold)
		}
	}
}

func TestRegistrableDomain(t *testing.T) {
	for host, want := range map[string]string{
		"example.com":                   "example.com",
		"c7.attacker.example.com":       "example.com",
		"a.b.example.co.uk":             "example.co.uk",
		"co.uk":                         "co.uk",
		"x1.workers.dev":                "workers.dev",
		"a.b.x1.workers.dev":            "workers.dev",
		"someone.github.io":             "github.io",
		"bucket.s3.amazonaws.com":       "amazonaws.com",
		"host.attacker.example":         "attacker.example",
		"deep.host.corp.internal":       "corp.internal",
		"registry.npmjs.org":            "npmjs.org",
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
// threshold. Known hosts and exempt (unblocked or operator-allowed) flows
// count only toward their own host.
func TestCounterAggregatesUploads(t *testing.T) {
	sink := netip.MustParseAddr("203.0.113.9")
	c := NewCounter(CounterOptions{
		LargeUploadBytes: 1000,
		KnownHost:        func(_ Principal, host string) bool { return host == "known.attacker.example" },
	})
	send := func(host string, remote netip.Addr, n int64, exempt bool) uploadVerdict {
		f, _ := c.open(testPrincipal, host, remote)
		defer f.close()
		return f.addUp(n, exempt)
	}
	addr := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}) }

	// Subdomain rotation: each host stays far below the threshold.
	if v := send("known.attacker.example", addr(1), 5000, false); v.signal {
		t.Errorf("a known host counted toward the domain: %+v", v)
	}
	for i := 0; i < 2; i++ {
		if v := send(fmt.Sprintf("c%d.attacker.example", i), addr(10+i), 400, false); v.signal {
			t.Fatalf("chunk %d signalled early: %+v", i, v)
		}
	}
	if v := send("c9.attacker.example", addr(12), 1000, true); v.signal {
		t.Errorf("an exempt flow counted toward the domain: %+v", v)
	}
	v := send("c2.attacker.example", addr(13), 400, false)
	if !v.signal || v.cut || v.total != 1200 || !strings.Contains(v.scope, "under attacker.example") {
		t.Fatalf("crossing the domain total = %+v", v)
	}
	if v := send("c3.attacker.example", addr(14), 400, false); v.signal {
		t.Errorf("the domain signalled twice: %+v", v)
	}

	// A provider's customer zones count as the provider's domain.
	send("x1.workers.dev", addr(20), 600, false)
	if v := send("x2.workers.dev", addr(21), 600, false); !v.signal || !strings.Contains(v.scope, "under workers.dev") {
		t.Errorf("workers.dev rotation = %+v", v)
	}

	// Different domains at one address count together.
	send("one.example", sink, 600, false)
	if v := send("two.example", sink, 600, false); !v.signal || !strings.Contains(v.scope, "at 203.0.113.9") {
		t.Errorf("one address behind two domains = %+v", v)
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
	if v := f.addUp(1, false); !v.cut {
		t.Errorf("a first-seen host under a blocked domain = %+v", v)
	}
	if v := f.addUp(5000, true); v.cut {
		t.Errorf("an exempt flow was cut: %+v", v)
	}
}
