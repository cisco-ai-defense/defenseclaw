// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"context"
	"sync"
)

// ring is the long-poll output buffer: a window of the stream of
// length-prefixed frames, addressed by absolute byte offset (the cursor).
type ring struct {
	mu     sync.Mutex
	cond   chan struct{}
	base   uint64 // offset of buf[0]
	buf    []byte
	limit  int
	closed bool
}

func newRing(limit int) *ring {
	if limit <= 0 {
		limit = 1 << 20
	}
	return &ring{limit: limit, cond: make(chan struct{})}
}

func (r *ring) wake() {
	close(r.cond)
	r.cond = make(chan struct{})
}

// Append adds a frame.
func (r *ring) Append(frame []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = AppendStream(r.buf, frame)
	// Drop whole frames from the front while over the limit.
	for len(r.buf) > r.limit {
		n := 4 + int(uint32(r.buf[0])<<24|uint32(r.buf[1])<<16|uint32(r.buf[2])<<8|uint32(r.buf[3]))
		if n > len(r.buf) {
			break
		}
		r.buf = r.buf[n:]
		r.base += uint64(n)
	}
	r.wake()
}

// Close ends the stream.
func (r *ring) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		r.wake()
	}
}

// Read returns the frames after cursor and the next cursor, waiting until
// there are some, the stream ends or ctx ends. reset is set when output
// before the window was dropped (the client's cursor fell behind).
func (r *ring) Read(ctx context.Context, cursor uint64) (data []byte, next uint64, reset, closed bool) {
	for {
		r.mu.Lock()
		end := r.base + uint64(len(r.buf))
		if cursor < r.base {
			cursor, reset = r.base, true
		}
		if cursor > end {
			cursor = end
		}
		if cursor < end || r.closed {
			data = append([]byte(nil), r.buf[cursor-r.base:]...)
			next, closed = end, r.closed
			r.mu.Unlock()
			return
		}
		wait := r.cond
		r.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return nil, cursor, reset, false
		}
	}
}
