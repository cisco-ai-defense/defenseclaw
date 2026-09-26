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

	f1, first := c.open(testPrincipal, "example.com")
	if !first {
		t.Error("first contact not reported")
	}
	f2, first := c.open(testPrincipal, "example.com")
	if first {
		t.Error("second contact reported as first")
	}
	f3, _ := c.open(p2, "example.com")
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
	a, _ := c.open(testPrincipal, "drop.example")
	b, _ := c.open(testPrincipal, "drop.example")
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
	other, _ := c.open(Principal{BindingID: "b-2"}, "drop.example")
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
	f, _ := c.open(testPrincipal, "github.com")
	if v := f.addUp(1000, false); v.signal {
		t.Error("known host raised the large-upload signal")
	}
	c.open(testPrincipal, "github.com")
	g, _ := c.open(testPrincipal, "new.example")
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
	f, _ := c.open(testPrincipal, "drop.example")
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
	e, _ := c.open(testPrincipal, "drop.example")
	if v := e.addUp(1000, true); v.cut {
		t.Error("exempt flow cut")
	}

	off := NewCounter(CounterOptions{LargeUploadBytes: -1, BlockLargeUploads: true})
	g, _ := off.open(testPrincipal, "drop.example")
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
	active, _ := c.open(testPrincipal, "active.example")
	flagged, _ := c.open(testPrincipal, "flagged.example")
	flagged.addUp(5, false)
	flagged.close()
	for i := 0; i < 40; i++ {
		f, _ := c.open(testPrincipal, fmt.Sprintf("h%d.example", i))
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
			f, _ := c.open(testPrincipal, "shared.example")
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
