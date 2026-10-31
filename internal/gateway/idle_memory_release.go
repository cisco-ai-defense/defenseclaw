// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"runtime/metrics"
	"slices"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// The gateway gives the memory its work freed back to the operating system
// once the work stops (GAP-2013). Each hook call allocates scan and audit
// buffers that are garbage once it is answered; the Go runtime keeps that
// freed heap mapped up to its next GC goal (about twice the live heap) and
// returns the rest slowly, so an idle gateway kept the resident size its last
// burst of calls reached. After a quiet tick that follows real work, the
// gateway runs one collection and returns every free page (debug.FreeOSMemory).
//
// A flood also filled what the gateway keeps between calls, so free pages
// alone did not bring the resident size back (rel-1-0-3 GAP-0244: 213 MB
// before 18000 calls, 334 MB after ten idle minutes). The hook correlation
// caches hold up to hookPromptCacheMaxEntries entries each, and every SQLite
// connection of the audit store keeps up to cache_size of pages outside the
// Go heap. On the same quiet tick the caches are cut to their newest
// hookIdleCacheKeepEntries entries (what the bound would have evicted next
// anyway) and SQLite frees its page caches; the next calls fill them again.
const (
	// idleMemoryReleaseTick is how often the gateway looks for a quiet spell;
	// a flood's memory is given back one to two ticks after its last call.
	idleMemoryReleaseTick = 15 * time.Second
	// idleMemoryReleaseQuietBytes is the most a tick may allocate and still
	// count as quiet (timers, health checks and watchers keep allocating a
	// little while no agent calls).
	idleMemoryReleaseQuietBytes = 4 << 20
	// idleMemoryReleaseWorkBytes is how much must have been allocated since
	// the last release before another one is worth its collection.
	idleMemoryReleaseWorkBytes = 16 << 20
	// hookIdleCacheKeepEntries is how many of the newest entries each hook
	// correlation cache keeps on an idle release: far more than the tool
	// calls an agent has in flight while its gateway is quiet.
	hookIdleCacheKeepEntries = 1024
	// idleStoreReleaseTimeout bounds the wait for the audit store's one
	// connection when SQLite frees its page caches.
	idleStoreReleaseTimeout = 2 * time.Second
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

// releaseIdleGatewayMemory gives back what a burst of calls left behind: the
// hook correlation caches keep their newest entries, the audit store's SQLite
// connections free their page caches, and the Go runtime returns every free
// page to the operating system.
func releaseIdleGatewayMemory(api *APIServer, store *audit.Store) {
	api.trimHookCachesForIdle(hookIdleCacheKeepEntries)
	if store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), idleStoreReleaseTimeout)
		if err := store.ReleaseMemory(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "[gateway] free audit store page cache: %v\n", err)
		}
		cancel()
	}
	debug.FreeOSMemory()
}

// trimHookCachesForIdle cuts each per-call hook correlation cache to its
// newest keep entries, evicting oldest first exactly as its bound does, and
// rebuilds the maps: a Go map keeps its table at its largest size after
// deletes, so only a new map gives the memory back.
func (a *APIServer) trimHookCachesForIdle(keep int) {
	if a == nil {
		return
	}
	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	for len(a.hookPhaseStates) > keep && a.evictOldestHookPhaseStateLocked() {
	}
	for len(a.hookToolInvocationOrder) > keep {
		a.evictOldestHookToolInvocationLocked()
	}
	for len(a.hookLifecycleTransitions) > keep && len(a.hookLifecycleTransitionOrder) > 0 {
		delete(a.hookLifecycleTransitions, a.hookLifecycleTransitionOrder[0])
		a.hookLifecycleTransitionOrder = a.hookLifecycleTransitionOrder[1:]
	}
	a.hookPhaseStates, a.hookPhaseStateOrder = compactHookCache(a.hookPhaseStates, a.hookPhaseStateOrder)
	a.hookToolInvocations, a.hookToolInvocationOrder = compactHookCache(a.hookToolInvocations, a.hookToolInvocationOrder)
	a.hookLifecycleTransitions, a.hookLifecycleTransitionOrder = compactHookCache(a.hookLifecycleTransitions, a.hookLifecycleTransitionOrder)
}

// compactHookCache copies a cache into a map and an order slice sized for
// what it holds now. A nil map stays nil.
func compactHookCache[V any](m map[string]V, order []string) (map[string]V, []string) {
	if m == nil {
		return nil, slices.Clip(order)
	}
	fresh := make(map[string]V, len(m))
	for key, value := range m {
		fresh[key] = value
	}
	return fresh, slices.Clone(order)
}

// runIdleMemoryRelease runs the releaser until ctx ends; release gives the
// memory back (releaseIdleGatewayMemory in the gateway).
func runIdleMemoryRelease(ctx context.Context, release func()) {
	releaser := newIdleMemoryReleaser(heapAllocatedBytes, release)
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
