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

package feed

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/sandboxfeed"
)

// ownerAll addresses a frame to every subscriber (status frames).
const ownerAll = -1

// Item is one frame and the uid it belongs to: the io.defenseclaw.uid label
// of the sandbox it names, or ownerAll.
type Item struct {
	Frame sandboxfeed.Frame
	Owner int
}

// subscriptionBuffer is how many frames a slow reader may fall behind before
// frames are dropped (and counted) for it alone.
const subscriptionBuffer = 4096

// Hub fans the mapped stream out to the connected gateways, each receiving
// only its own uid's frames.
type Hub struct {
	now func() time.Time

	mu       sync.Mutex
	subs     map[*Subscription]struct{}
	tetragon string
	reason   string
}

// NewHub returns a hub with no subscriber; Tetragon is unavailable until the
// source says otherwise.
func NewHub(now func() time.Time) *Hub {
	if now == nil {
		now = time.Now
	}
	return &Hub{now: now, subs: map[*Subscription]struct{}{}, tetragon: sandboxfeed.TetragonUnavailable, reason: "starting"}
}

// Subscription is one connected reader of one uid.
type Subscription struct {
	hub     *Hub
	uid     int
	frames  chan sandboxfeed.Frame
	dropped atomic.Int64
}

// Subscribe adds a reader for uid's frames.
func (h *Hub) Subscribe(uid int) *Subscription {
	s := &Subscription{hub: h, uid: uid, frames: make(chan sandboxfeed.Frame, subscriptionBuffer)}
	h.mu.Lock()
	h.subs[s] = struct{}{}
	h.mu.Unlock()
	return s
}

// Frames is the reader's stream.
func (s *Subscription) Frames() <-chan sandboxfeed.Frame { return s.frames }

// TakeDropped returns, and resets, how many frames were dropped for this
// reader because it fell behind.
func (s *Subscription) TakeDropped() int64 { return s.dropped.Swap(0) }

// Close removes the reader.
func (s *Subscription) Close() {
	s.hub.mu.Lock()
	delete(s.hub.subs, s)
	s.hub.mu.Unlock()
}

// Subscribers is how many readers are connected.
func (h *Hub) Subscribers() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

// Publish hands item to the readers it belongs to. It never blocks: a reader
// whose buffer is full loses the frame and is told how many it lost.
func (h *Hub) Publish(item Item) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs {
		if item.Owner != ownerAll && item.Owner != s.uid {
			continue
		}
		select {
		case s.frames <- item.Frame:
		default:
			s.dropped.Add(1)
		}
	}
}

// SetTetragon records whether the Tetragon stream is up, telling every reader
// when that changes.
func (h *Hub) SetTetragon(state, reason string) {
	h.mu.Lock()
	changed := h.tetragon != state || h.reason != reason
	h.tetragon, h.reason = state, reason
	h.mu.Unlock()
	if changed {
		h.Publish(Item{Owner: ownerAll, Frame: h.status(0)})
	}
}

// Lost tells every reader the feed lost n records (Tetragon's rate limit or
// throttle): their trees have gaps.
func (h *Hub) Lost(n int64) {
	if n > 0 {
		h.Publish(Item{Owner: ownerAll, Frame: h.status(n)})
	}
}

// Tetragon is the stream's state and why.
func (h *Hub) Tetragon() (state, reason string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.tetragon, h.reason
}

func (h *Hub) status(dropped int64) sandboxfeed.Frame {
	state, reason := h.Tetragon()
	return sandboxfeed.Frame{Kind: sandboxfeed.FrameStatus, At: h.now(), Tetragon: state, Reason: reason, Dropped: dropped}
}
