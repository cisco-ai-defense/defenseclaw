// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import "time"

// getNonblocking serves cached facts and starts a cold or expired lookup
// without waiting for it. Managed macOS callers that do not select by
// directory identity still need their cached facts on every request.
func (c *identityCache[T]) getNonblocking(key string) (T, bool) {
	return c.getWithColdWait(key, false, false)
}

// getFresh waits for a lookup started for this call or one already in flight.
// A lookup completed after an earlier timeout may be consumed once within
// identityDirectoryRetry of completion; older answers require a new lookup.
// A failed or timed-out lookup never returns facts from before it. Managed
// macOS hooks use this for secondary groups: Open Directory gives no change
// notification for their removal.
//
// When the wait expires as the lookup completes, the outcome is read under
// the cache lock, not from which select case won: a lookup still in flight
// is marked for the next hook (pendingFresh), and one that has finished
// returns its answer now. Marking a finished lookup pending lost its answer:
// the completion had already counted it as served, so the next hook started
// another slow lookup and could refuse, although the answer was current.
func (c *identityCache[T]) getFresh(key string, wait time.Duration) (T, bool) {
	var zero T
	if c == nil || key == "" || c.resolve == nil || wait <= 0 {
		return zero, false
	}
	c.mu.Lock()
	entry := c.entries[key]
	if entry == nil {
		if len(c.entries) >= identityDirectoryMax {
			c.evictLocked()
		}
		entry = &identityCacheEntry[T]{}
		c.entries[key] = entry
	}
	now := c.now()
	c.dropAgedLocked(key, entry, now)
	if entry.ok && (entry.pendingFresh && entry.generation > entry.servedGeneration &&
		now.Before(entry.fetchedAt.Add(identityDirectoryRetry)) || now.Before(entry.freshUntil)) {
		entry.pendingFresh, entry.servedGeneration = false, entry.generation
		facts := entry.facts
		c.mu.Unlock()
		return facts, true
	}
	before := entry.generation
	if entry.inflight == nil && (entry.failedSince.IsZero() || !now.Before(entry.nextAttempt)) {
		c.refreshLocked(key, entry)
	}
	done := entry.inflight
	c.mu.Unlock()
	if done == nil {
		return zero, false
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	timedOut := false
	select {
	case <-done:
	case <-timer.C:
		timedOut = true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if timedOut && entry.inflight == done {
		// Still running: the next hook may use its answer once it completes.
		entry.pendingFresh = true
		return zero, false
	}
	c.dropAgedLocked(key, entry, c.now())
	if entry.ok && entry.generation > before {
		entry.pendingFresh, entry.servedGeneration = false, entry.generation
		return entry.facts, true
	}
	return zero, false
}
