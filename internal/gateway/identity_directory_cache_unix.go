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
	select {
	case <-done:
	case <-timer.C:
		c.mu.Lock()
		entry.pendingFresh = true
		c.mu.Unlock()
		return zero, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dropAgedLocked(key, entry, c.now())
	if entry.ok && entry.generation > before {
		entry.pendingFresh, entry.servedGeneration = false, entry.generation
		return entry.facts, true
	}
	return zero, false
}
