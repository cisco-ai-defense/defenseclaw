// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"sync"
)

// writeBaton makes the store two writer connections take turns inside this
// process (rel-1-0-6 GAP-0490). SQLite lets one connection write at a time.
// The pool connection (grouped hook-call and observation transactions) and
// the synchronous=FULL durable connection (hook journal rows, the commit
// confirmation) both write audit.db, so when both are busy one of them gets
// SQLITE_BUSY and polls for the lock with a sleep that doubles. At the rate a
// managed gateway serves sandbox calls, both are always busy: a durable batch
// of one write took 0.8 to 1.3 s, mostly asleep between polls, while the
// holder finished in milliseconds, and the answers queued behind it past the
// hook window. A transaction takes the baton before it begins and gives it
// back when it ends, so the next one starts when the lock is free instead of
// when its poll next wakes. A writer outside this process still meets the
// SQLite busy wait as before. The zero value is ready.
//
// Waiters that an answer waits on (urgent: the correlation occurrence of a
// hook call, a batch that carries a durable write) take the baton before the
// others (the records of calls already answered). Under a hook flood the
// correlation turn of a session waited for each grouped batch of the calls
// answered before it, so a session could not correlate faster than the store
// committed batches, and the calls queued behind it past their answer window
// (rel-1-0-6 GAP-0558 to GAP-0560, #1384). Each class is served in arrival
// order; an urgent waiter still waits for the transaction in progress, and
// with both classes waiting the turns alternate.
type writeBaton struct {
	mu     sync.Mutex
	held   bool
	urgent []*batonWaiter
	normal []*batonWaiter
	// lastUrgent is set when the baton last went to an urgent waiter: with
	// both classes waiting the next turn goes to the other class, so the
	// grouped records of answered calls are never starved (each of their
	// turns carries a whole batch).
	lastUrgent bool
}

type batonWaiter struct {
	ready  chan struct{}
	handed bool
}

// acquire waits for the baton, or for ctx. The returned release must be
// called once when err is nil.
func (b *writeBaton) acquire(ctx context.Context) (release func(), err error) {
	return b.acquireClass(ctx, false)
}

// acquireUrgent is acquire for a transaction an answer waits on.
func (b *writeBaton) acquireUrgent(ctx context.Context) (release func(), err error) {
	return b.acquireClass(ctx, true)
}

func (b *writeBaton) acquireClass(ctx context.Context, urgent bool) (release func(), err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	if !b.held {
		b.held = true
		b.mu.Unlock()
		return b.release, nil
	}
	w := &batonWaiter{ready: make(chan struct{})}
	if urgent {
		b.urgent = append(b.urgent, w)
	} else {
		b.normal = append(b.normal, w)
	}
	b.mu.Unlock()
	select {
	case <-w.ready:
		return b.release, nil
	case <-ctx.Done():
		b.mu.Lock()
		if w.handed {
			// The baton was handed over as the context ended: pass it on.
			b.mu.Unlock()
			b.release()
			return nil, ctx.Err()
		}
		b.urgent = removeBatonWaiter(b.urgent, w)
		b.normal = removeBatonWaiter(b.normal, w)
		b.mu.Unlock()
		return nil, ctx.Err()
	}
}

// release hands the baton to the oldest urgent waiter, else the oldest
// other waiter, else frees it; with both waiting the classes alternate.
func (b *writeBaton) release() {
	b.mu.Lock()
	defer b.mu.Unlock()
	var next *batonWaiter
	switch {
	case len(b.urgent) > 0 && (len(b.normal) == 0 || !b.lastUrgent):
		next, b.urgent = b.urgent[0], b.urgent[1:]
		b.lastUrgent = true
	case len(b.normal) > 0:
		next, b.normal = b.normal[0], b.normal[1:]
		b.lastUrgent = false
	default:
		b.held = false
		return
	}
	next.handed = true
	close(next.ready)
}

func removeBatonWaiter(queue []*batonWaiter, w *batonWaiter) []*batonWaiter {
	for i, q := range queue {
		if q == w {
			return append(queue[:i], queue[i+1:]...)
		}
	}
	return queue
}
