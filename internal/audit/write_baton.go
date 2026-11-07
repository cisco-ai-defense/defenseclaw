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
type writeBaton struct {
	once sync.Once
	turn chan struct{}
}

// acquire waits for the baton, or for ctx. The returned release must be
// called once when err is nil.
func (b *writeBaton) acquire(ctx context.Context) (release func(), err error) {
	b.once.Do(func() { b.turn = make(chan struct{}, 1) })
	select {
	case b.turn <- struct{}{}:
		return func() { <-b.turn }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
