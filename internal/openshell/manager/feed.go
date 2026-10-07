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

package manager

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// Feed defaults.
const (
	DefaultFeedSize      = 1024
	defaultSubscriberBuf = 256
	maxSubscribers       = 64
)

// Feed is the activity ring buffer behind GET /api/v1/sandbox/activity. Late
// subscribers replay what is still buffered; slow subscribers skip events
// and are told how many with an ActivityDropped event, so a stuck client can
// never block a producer. It lives in memory: a daemon that restarts starts
// a new feed, numbered from one again under another epoch, which every
// event carries so that a client can tell.
type Feed struct {
	now   func() time.Time
	epoch string

	mu   sync.Mutex
	buf  []sandboxapi.ActivityEvent
	next int
	full bool
	seq  uint64
	subs map[*subscriber]struct{}
}

type subscriber struct {
	ch      chan sandboxapi.ActivityEvent
	sandbox string
	missed  uint64
}

// NewFeed returns a feed that keeps the last size events.
func NewFeed(size int, now func() time.Time) *Feed {
	if size <= 0 {
		size = DefaultFeedSize
	}
	if now == nil {
		now = time.Now
	}
	return &Feed{now: now, epoch: newFeedEpoch(), buf: make([]sandboxapi.ActivityEvent, size), subs: map[*subscriber]struct{}{}}
}

// newFeedEpoch names a feed: 16 random hex digits, or the time in
// nanoseconds should the system's randomness fail.
func newFeedEpoch() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
}

// Epoch names this feed (sandboxapi.ActivityEvent.Epoch).
func (f *Feed) Epoch() string { return f.epoch }

// Publish stamps ev with the next sequence number (and the time, when
// unset), buffers it and hands it to every matching subscriber. Its text
// is made safe to print first (sandboxapi.DisplayText): events carry what a
// sandbox controls (tool names, directory names, hosts), and the CLI and
// the TUI print them on the user's terminal.
func (f *Feed) Publish(ev sandboxapi.ActivityEvent) sandboxapi.ActivityEvent {
	for _, s := range []*string{&ev.Sandbox, &ev.Host, &ev.Method, &ev.Source, &ev.Category, &ev.Rule, &ev.ApprovalID,
		&ev.Tool, &ev.Event, &ev.Phase, &ev.Severity, &ev.Reason, &ev.Message} {
		*s = sandboxapi.DisplayText(*s)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	ev.Seq, ev.Epoch = f.seq, f.epoch
	if ev.Time.IsZero() {
		ev.Time = f.now().UTC()
	}
	f.buf[f.next] = ev
	f.next = (f.next + 1) % len(f.buf)
	if f.next == 0 {
		f.full = true
	}
	for s := range f.subs {
		if s.sandbox != "" && ev.Sandbox != s.sandbox {
			continue
		}
		f.deliverLocked(s, ev)
	}
	return ev
}

func (f *Feed) deliverLocked(s *subscriber, ev sandboxapi.ActivityEvent) {
	if s.missed > 0 {
		marker := sandboxapi.ActivityEvent{Seq: ev.Seq, Epoch: ev.Epoch, Time: ev.Time, Kind: sandboxapi.ActivityDropped,
			Sandbox: s.sandbox, BytesUp: int64(s.missed), Message: "the activity stream skipped events; reconnect with ?since to replay"}
		select {
		case s.ch <- marker:
			s.missed = 0
		default:
			s.missed++
			return
		}
	}
	select {
	case s.ch <- ev:
	default:
		s.missed++
	}
}

// Since returns the buffered events after seq, oldest first, for one
// sandbox or (with an empty name) all of them.
func (f *Feed) Since(seq uint64, sandbox string) []sandboxapi.ActivityEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sinceLocked(seq, sandbox)
}

func (f *Feed) sinceLocked(seq uint64, sandbox string) []sandboxapi.ActivityEvent {
	var out []sandboxapi.ActivityEvent
	n := f.next
	if f.full {
		n = len(f.buf)
	}
	start := 0
	if f.full {
		start = f.next
	}
	for i := 0; i < n; i++ {
		ev := f.buf[(start+i)%len(f.buf)]
		if ev.Seq <= seq || (sandbox != "" && ev.Sandbox != sandbox) {
			continue
		}
		out = append(out, ev)
	}
	return out
}

// Subscribe returns the buffered events after since and a channel of later
// ones. cancel releases the subscription and closes the channel. It fails
// (ok false) when too many subscribers are connected.
func (f *Feed) Subscribe(since uint64, sandbox string) (backlog []sandboxapi.ActivityEvent, events <-chan sandboxapi.ActivityEvent, cancel func(), ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.subs) >= maxSubscribers {
		return nil, nil, func() {}, false
	}
	s := &subscriber{ch: make(chan sandboxapi.ActivityEvent, defaultSubscriberBuf), sandbox: sandbox}
	f.subs[s] = struct{}{}
	backlog = f.sinceLocked(since, sandbox)
	cancel = func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		if _, ok := f.subs[s]; ok {
			delete(f.subs, s)
			close(s.ch)
		}
	}
	return backlog, s.ch, cancel, true
}

// closeSubscribers ends every subscription, whose streams then end: a
// manager that stops (the daemon lets go of its sandboxes, or another
// takes over) publishes nothing more, and a client that kept following it
// would wait for ever instead of reconnecting to the feed that replaces it.
func (f *Feed) closeSubscribers() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for s := range f.subs {
		delete(f.subs, s)
		close(s.ch)
	}
}

// Seq returns the last sequence number published.
func (f *Feed) Seq() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seq
}

// SubscribeActivity subscribes to the activity feed (see Feed.Subscribe).
func (m *Manager) SubscribeActivity(since uint64, sandbox string) ([]sandboxapi.ActivityEvent, <-chan sandboxapi.ActivityEvent, func(), bool) {
	return m.feed.Subscribe(since, sandbox)
}

// ActivitySince returns the buffered activity after since.
func (m *Manager) ActivitySince(since uint64, sandbox string) []sandboxapi.ActivityEvent {
	return m.feed.Since(since, sandbox)
}
