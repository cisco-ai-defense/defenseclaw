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
	// by the operator. It is called once per binding and destination, at
	// the first contact; refused attempts are not contact. Nil treats every
	// destination as first-seen at its first contact.
	KnownHost func(p Principal, host string) bool
	// MaxDestinations caps tracked (binding, destination) pairs. Over the
	// cap, idle contacted destinations are evicted, those with the least
	// upload counted toward the large-upload signal first, then the least
	// recently used. Destinations that were only ever refused are capped
	// separately at the same number, so refusals never evict a contacted
	// destination. Zero uses 8192.
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
	// refused holds destinations that were only ever refused. Refusals pass
	// no rate limit, so they are kept apart: they never call KnownHost,
	// never use up a destination's first contact, and can only evict each
	// other.
	refused map[destKey]*refusal
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

// refusal counts the refused attempts to a destination that was never
// contacted. Counter.mu guards it.
type refusal struct {
	count     int64
	firstSeen time.Time
	lastSeen  int64
}

// DestinationStats is a snapshot of one binding's traffic to one host.
type DestinationStats struct {
	BindingID string
	Host      string
	// BytesUp and BytesDown are payload bytes sent and received across all
	// tunnels and requests. For absolute-form requests BytesUp is the
	// request as sent upstream (head and body, TLS records for https://)
	// and BytesDown the response body.
	BytesUp   int64
	BytesDown int64
	// Tunnels counts tunnels and forwarded requests that reached the
	// destination; Active those still open.
	Tunnels int64
	Active  int64
	// Blocked counts refused attempts.
	Blocked int64
	// FirstSeen is when the destination was first tracked: its first
	// refusal or its first contact, whichever came first.
	FirstSeen time.Time
	LastSeen  time.Time
	// Novel reports that the destination was not a known host at first
	// contact, so uploads to it count toward the large-upload signal. It is
	// false for destinations that were only ever refused.
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
		refused:   map[destKey]*refusal{},
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

// contact returns p's record for host, creating it at the first contact,
// and reports whether it was created.
func (c *Counter) contact(p Principal, host string) (*destination, bool) {
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
	if r := c.refused[key]; r != nil {
		d.firstSeen = r.firstSeen
		d.blocked.Store(r.count)
		delete(c.refused, key)
	}
	d.lastSeen.Store(now.UnixNano())
	c.dests[key] = d
	return d, true
}

// armedUp is the upload counted toward the large-upload signal.
func (c *Counter) armedUp(d *destination) int64 {
	if c.threshold <= 0 || !d.novel {
		return 0
	}
	return d.up.Load()
}

// evictLocked drops idle, unflagged destinations down to 7/8 of the cap:
// first those with the least upload counted toward the large-upload signal,
// so contacting many other hosts cannot reset a destination's progress
// toward the threshold, then the least recently used. Active and flagged
// ones are kept so live counters and the large-upload state survive.
func (c *Counter) evictLocked() {
	type candidate struct {
		d               *destination
		armed, lastSeen int64
	}
	target := c.max - c.max/8
	idle := make([]candidate, 0, len(c.dests))
	for _, d := range c.dests {
		if d.active.Load() == 0 && !d.flagged.Load() {
			idle = append(idle, candidate{d: d, armed: c.armedUp(d), lastSeen: d.lastSeen.Load()})
		}
	}
	slices.SortFunc(idle, func(a, b candidate) int {
		return cmp.Or(cmp.Compare(a.armed, b.armed), cmp.Compare(a.lastSeen, b.lastSeen))
	})
	for _, cand := range idle {
		if len(c.dests) <= target {
			return
		}
		delete(c.dests, cand.d.key)
	}
}

// recordBlocked counts a refused attempt. A refusal is not contact: a
// destination that was never contacted gets a refusal-only record, which
// costs no KnownHost call and no eviction sort.
func (c *Counter) recordBlocked(p Principal, host string) {
	key := destKey{binding: p.BindingID, host: host}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if d := c.dests[key]; d != nil {
		d.blocked.Add(1)
		d.lastSeen.Store(now.UnixNano())
		return
	}
	r := c.refused[key]
	if r == nil {
		if len(c.refused) >= c.max {
			c.evictRefusedLocked()
		}
		r = &refusal{firstSeen: now}
		c.refused[key] = r
	}
	r.count++
	r.lastSeen = now.UnixNano()
}

// evictRefusedLocked drops an arbitrary eighth of the refusal-only records.
// They only feed statistics, and skipping the sort keeps a refusal flood
// cheap.
func (c *Counter) evictRefusedLocked() {
	n := max(c.max/8, 1)
	for k := range c.refused {
		if n == 0 {
			return
		}
		delete(c.refused, k)
		n--
	}
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
	f := c.pending(p, host)
	return f, f.open()
}

// pending returns a flow that counts toward host only once it opens: a
// forwarded request becomes contact when it gets an upstream connection.
func (c *Counter) pending(p Principal, host string) *flow {
	return &flow{counter: c, principal: p, host: host}
}

// flow counts one tunnel or forwarded request.
type flow struct {
	counter   *Counter
	principal Principal
	host      string

	opening sync.Once
	dest    atomic.Pointer[destination]
	first   atomic.Bool
	closed  atomic.Bool
	up      atomic.Int64
	down    atomic.Int64
}

// open counts the flow toward its destination, once, and reports whether
// that was the binding's first contact. A closed flow no longer opens.
func (f *flow) open() bool {
	f.opening.Do(func() {
		if f.closed.Load() {
			return
		}
		d, created := f.counter.contact(f.principal, f.host)
		d.tunnels.Add(1)
		d.active.Add(1)
		f.first.Store(created)
		f.dest.Store(d)
	})
	return f.first.Load()
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

// addUp accounts n bytes about to be sent upstream, opening the flow if it
// is not open yet. exempt flows (unblocked or operator-allowed
// destinations) are signalled but never cut. Under the block the chunk is
// reserved against the threshold atomically, so parallel flows cannot
// together send more than it.
func (f *flow) addUp(n int64, exempt bool) uploadVerdict {
	f.open()
	c, d := f.counter, f.dest.Load()
	if d == nil {
		return uploadVerdict{cut: true} // closed before it opened: nothing more is relayed
	}
	armed := c.threshold > 0 && d.novel
	if armed && c.block && !exempt {
		for {
			cur := d.up.Load()
			if d.flagged.Load() || cur+n > c.threshold {
				return uploadVerdict{signal: d.flagged.CompareAndSwap(false, true), cut: true, total: cur}
			}
			if d.up.CompareAndSwap(cur, cur+n) {
				f.up.Add(n)
				d.lastSeen.Store(c.now().UnixNano())
				return uploadVerdict{total: cur + n}
			}
		}
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

// addDown accounts n bytes received from upstream. A flow that never
// opened has had no upstream, so it counts nothing.
func (f *flow) addDown(n int64) {
	d := f.dest.Load()
	if d == nil {
		return
	}
	f.down.Add(n)
	d.down.Add(n)
	d.lastSeen.Store(f.counter.now().UnixNano())
}

func (f *flow) close() {
	if !f.closed.CompareAndSwap(false, true) {
		return
	}
	f.opening.Do(func() {}) // wait out an open in progress; later ones are no-ops
	if d := f.dest.Load(); d != nil {
		d.active.Add(-1)
		d.lastSeen.Store(f.counter.now().UnixNano())
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
	out := make([]DestinationStats, 0, len(c.dests)+len(c.refused))
	for k, d := range c.dests {
		if keep(k) {
			out = append(out, d.stats())
		}
	}
	for k, r := range c.refused {
		if keep(k) {
			out = append(out, DestinationStats{
				BindingID: k.binding, Host: k.host, Blocked: r.count,
				FirstSeen: r.firstSeen, LastSeen: time.Unix(0, r.lastSeen),
			})
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
	for k := range c.refused {
		if k.binding == bindingID {
			delete(c.refused, k)
			n++
		}
	}
	return n
}
