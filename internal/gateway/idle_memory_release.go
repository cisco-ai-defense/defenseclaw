// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"runtime/debug"
	"runtime/metrics"
	"time"
)

// The gateway gives the memory its work freed back to the operating system
// once the work stops (GAP-2013). Each hook call allocates scan and audit
// buffers that are garbage once it is answered; the Go runtime keeps that
// freed heap mapped up to its next GC goal (about twice the live heap) and
// returns the rest slowly, so an idle gateway kept the resident size its last
// burst of calls reached. After a quiet tick that follows real work, the
// gateway runs one collection and returns every free page (debug.FreeOSMemory).
// Nothing the gateway keeps is dropped: only free pages go back.
const (
	// idleMemoryReleaseTick is how often the gateway looks for a quiet spell.
	idleMemoryReleaseTick = 30 * time.Second
	// idleMemoryReleaseQuietBytes is the most a tick may allocate and still
	// count as quiet (timers, health checks and watchers keep allocating a
	// little while no agent calls).
	idleMemoryReleaseQuietBytes = 4 << 20
	// idleMemoryReleaseWorkBytes is how much must have been allocated since
	// the last release before another one is worth its collection.
	idleMemoryReleaseWorkBytes = 16 << 20
)

// idleMemoryReleaser decides, once per tick, whether the gateway is quiet
// after work. allocs reports the bytes allocated since the process started;
// release returns the free heap to the operating system.
type idleMemoryReleaser struct {
	allocs      func() uint64
	release     func()
	last        uint64
	lastRelease uint64
}

func newIdleMemoryReleaser(allocs func() uint64, release func()) *idleMemoryReleaser {
	now := allocs()
	return &idleMemoryReleaser{allocs: allocs, release: release, last: now, lastRelease: now}
}

// tick releases the free heap when this tick was quiet and enough was
// allocated since the last release, and reports whether it did. A quiet
// gateway is released once, not on every tick.
func (r *idleMemoryReleaser) tick() bool {
	now := r.allocs()
	since := now - r.last
	r.last = now
	if since > idleMemoryReleaseQuietBytes || now-r.lastRelease < idleMemoryReleaseWorkBytes {
		return false
	}
	r.release()
	r.lastRelease = r.allocs()
	r.last = r.lastRelease
	return true
}

// heapAllocatedBytes is the cumulative heap allocation of this process.
func heapAllocatedBytes() uint64 {
	sample := []metrics.Sample{{Name: "/gc/heap/allocs:bytes"}}
	metrics.Read(sample)
	if sample[0].Value.Kind() != metrics.KindUint64 {
		return 0
	}
	return sample[0].Value.Uint64()
}

// runIdleMemoryRelease runs the releaser until ctx ends.
func runIdleMemoryRelease(ctx context.Context) {
	releaser := newIdleMemoryReleaser(heapAllocatedBytes, debug.FreeOSMemory)
	ticker := time.NewTicker(idleMemoryReleaseTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			releaser.tick()
		}
	}
}
