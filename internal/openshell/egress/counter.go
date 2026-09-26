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
	"cmp"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultLargeUploadBytes is the default large-upload threshold (the
// openshell.egress.large_upload_mb default of 25).
const DefaultLargeUploadBytes int64 = 25 << 20

const defaultMaxDestinations = 8192

// CounterOptions configures a Counter.
type CounterOptions struct {
	// LargeUploadBytes is the volume sent to a first-seen destination that
	// raises the large-upload signal. Zero uses DefaultLargeUploadBytes; a
	// negative value disables the signal.
	LargeUploadBytes int64
	// BlockLargeUploads also cuts the tunnel or request that crosses the
	// threshold and refuses further uploads to that destination for the
	// binding, unless the decision came from an unblock or operator allow.
	BlockLargeUploads bool
	// KnownHost reports destinations that are not first-seen for a
	// principal, for example hosts contacted in earlier sessions or trusted
	// by the operator. It is called once per binding and destination. Nil
	// treats every destination as first-seen at its first contact.
	KnownHost func(p Principal, host string) bool
	// MaxDestinations caps tracked (binding, destination) pairs; the least
	// recently used idle ones are evicted. Zero uses 8192.
	MaxDestinations int
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Counter keeps byte and tunnel counts per binding and destination and
// raises the large-upload signal. It is safe for concurrent use.
type Counter struct {
	threshold int64
	block     bool
	known     func(Principal, string) bool
	max       int
	now       func() time.Time

	mu    sync.Mutex
	dests map[destKey]*destination
}

type destKey struct {
	binding string
	host    string
}

type destination struct {
	key       destKey
	firstSeen time.Time
	novel     bool

	lastSeen atomic.Int64
	up       atomic.Int64
	down     atomic.Int64
	tunnels  atomic.Int64
	active   atomic.Int64
	blocked  atomic.Int64
	flagged  atomic.Bool
}

// DestinationStats is a snapshot of one binding's traffic to one host.
type DestinationStats struct {
	BindingID string
	Host      string
	// BytesUp and BytesDown are payload bytes sent and received across all
	// tunnels and requests (bodies only for absolute-form requests).
	BytesUp   int64
	BytesDown int64
	// Tunnels counts allowed tunnels and requests; Active those still open.
	Tunnels int64
	Active  int64
	// Blocked counts refused attempts.
	Blocked   int64
	FirstSeen time.Time
	LastSeen  time.Time
	// Novel reports that the destination was not a known host at first
	// contact, so uploads to it count toward the large-upload signal.
	Novel bool
	// LargeUpload reports that the large-upload signal fired.
	LargeUpload bool
}

// NewCounter returns a Counter.
func NewCounter(opts CounterOptions) *Counter {
	c := &Counter{
		threshold: opts.LargeUploadBytes,
		block:     opts.BlockLargeUploads,
		known:     opts.KnownHost,
		max:       opts.MaxDestinations,
		now:       opts.Now,
		dests:     map[destKey]*destination{},
	}
	if c.threshold == 0 {
		c.threshold = DefaultLargeUploadBytes
	}
	if c.max <= 0 {
		c.max = defaultMaxDestinations
	}
	if c.now == nil {
		c.now = time.Now
	}
	return c
}

// LargeUploadBytes returns the effective threshold (<= 0 when disabled).
func (c *Counter) LargeUploadBytes() int64 { return c.threshold }

func (c *Counter) lookup(p Principal, host string) (*destination, bool) {
	key := destKey{binding: p.BindingID, host: host}
	now := c.now()
	c.mu.Lock()
	if d := c.dests[key]; d != nil {
		c.mu.Unlock()
		d.lastSeen.Store(now.UnixNano())
		return d, false
	}
	c.mu.Unlock()

	// KnownHost is caller code; never run it under the lock.
	novel := c.known == nil || !c.known(p, host)

	c.mu.Lock()
	defer c.mu.Unlock()
	if d := c.dests[key]; d != nil {
		d.lastSeen.Store(now.UnixNano())
		return d, false
	}
	if len(c.dests) >= c.max {
		c.evictLocked()
	}
	d := &destination{key: key, firstSeen: now, novel: novel}
	d.lastSeen.Store(now.UnixNano())
	c.dests[key] = d
	return d, true
}

// evictLocked drops the least recently used idle, unflagged destinations
// down to 7/8 of the cap. Active and flagged ones are kept so live counters
// and the large-upload state survive.
func (c *Counter) evictLocked() {
	target := c.max - c.max/8
	idle := make([]*destination, 0, len(c.dests))
	for _, d := range c.dests {
		if d.active.Load() == 0 && !d.flagged.Load() {
			idle = append(idle, d)
		}
	}
	slices.SortFunc(idle, func(a, b *destination) int { return cmp.Compare(a.lastSeen.Load(), b.lastSeen.Load()) })
	for _, d := range idle {
		if len(c.dests) <= target {
			return
		}
		delete(c.dests, d.key)
	}
}

// recordBlocked counts a refused attempt.
func (c *Counter) recordBlocked(p Principal, host string) {
	d, _ := c.lookup(p, host)
	d.blocked.Add(1)
}

// uploadBlocked reports that the large-upload block already applies to
// p's traffic to host.
func (c *Counter) uploadBlocked(p Principal, host string) bool {
	if !c.block || c.threshold <= 0 {
		return false
	}
	c.mu.Lock()
	d := c.dests[destKey{binding: p.BindingID, host: host}]
	c.mu.Unlock()
	return d != nil && d.novel && d.flagged.Load()
}

// open starts counting one tunnel or request and reports whether this is
// the binding's first contact with host.
func (c *Counter) open(p Principal, host string) (*flow, bool) {
	d, created := c.lookup(p, host)
	d.tunnels.Add(1)
	d.active.Add(1)
	return &flow{counter: c, dest: d}, created
}

// flow counts one tunnel or forwarded request.
type flow struct {
	counter *Counter
	dest    *destination
	up      atomic.Int64
	down    atomic.Int64
	closed  atomic.Bool
}

// uploadVerdict is the large-upload outcome of one upload chunk.
type uploadVerdict struct {
	// signal is set exactly once per destination: on the chunk that pushed
	// the total over the threshold.
	signal bool
	// cut means the chunk was not counted and the flow must stop.
	cut bool
	// total is the destination's upload total.
	total int64
}

// addUp accounts n bytes about to be sent upstream. exempt flows (unblocked
// or operator-allowed destinations) are signalled but never cut.
func (f *flow) addUp(n int64, exempt bool) uploadVerdict {
	c, d := f.counter, f.dest
	armed := c.threshold > 0 && d.novel
	if armed && c.block && !exempt && (d.flagged.Load() || d.up.Load()+n > c.threshold) {
		return uploadVerdict{signal: d.flagged.CompareAndSwap(false, true), cut: true, total: d.up.Load()}
	}
	f.up.Add(n)
	total := d.up.Add(n)
	d.lastSeen.Store(c.now().UnixNano())
	v := uploadVerdict{total: total}
	if armed && total > c.threshold {
		v.signal = d.flagged.CompareAndSwap(false, true)
	}
	return v
}

// addDown accounts n bytes received from upstream.
func (f *flow) addDown(n int64) {
	f.down.Add(n)
	f.dest.down.Add(n)
	f.dest.lastSeen.Store(f.counter.now().UnixNano())
}

func (f *flow) close() {
	if f.closed.CompareAndSwap(false, true) {
		f.dest.active.Add(-1)
		f.dest.lastSeen.Store(f.counter.now().UnixNano())
	}
}

func (d *destination) stats() DestinationStats {
	return DestinationStats{
		BindingID:   d.key.binding,
		Host:        d.key.host,
		BytesUp:     d.up.Load(),
		BytesDown:   d.down.Load(),
		Tunnels:     d.tunnels.Load(),
		Active:      d.active.Load(),
		Blocked:     d.blocked.Load(),
		FirstSeen:   d.firstSeen,
		LastSeen:    time.Unix(0, d.lastSeen.Load()),
		Novel:       d.novel,
		LargeUpload: d.flagged.Load(),
	}
}

// Destinations returns a snapshot of every tracked destination, ordered by
// binding and host.
func (c *Counter) Destinations() []DestinationStats {
	return c.snapshot(func(destKey) bool { return true })
}

// DestinationsFor returns the destinations of one binding, ordered by host.
func (c *Counter) DestinationsFor(bindingID string) []DestinationStats {
	return c.snapshot(func(k destKey) bool { return k.binding == bindingID })
}

func (c *Counter) snapshot(keep func(destKey) bool) []DestinationStats {
	c.mu.Lock()
	out := make([]DestinationStats, 0, len(c.dests))
	for k, d := range c.dests {
		if keep(k) {
			out = append(out, d.stats())
		}
	}
	c.mu.Unlock()
	slices.SortFunc(out, func(a, b DestinationStats) int {
		return cmp.Or(cmp.Compare(a.BindingID, b.BindingID), cmp.Compare(a.Host, b.Host))
	})
	return out
}

// Forget drops every destination of bindingID (for example when its sandbox
// is deleted) and returns how many were dropped. Open flows keep counting
// into their detached records.
func (c *Counter) Forget(bindingID string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for k := range c.dests {
		if k.binding == bindingID {
			delete(c.dests, k)
			n++
		}
	}
	return n
}
