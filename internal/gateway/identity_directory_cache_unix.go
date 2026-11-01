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

// getCached serves cached facts as getNonblocking does (an expired or
// invalidated entry starts one background refresh) and reports whether they
// are current: within their lifetime, fetched after the last invalidation
// (invalidatedLocked), and settled. Facts past their lifetime are still
// served to hooks that read only memory, but they can name an account as it
// was before the directory changed it (a UPN it no longer gives). So can
// facts an invalidation made due for a refresh: they counted as current
// until their lifetime ended, and a profile assignment change let an exempt
// name they gave exempt the caller before the refresh, which the release
// waited for (review of r104 Q-identity, continuation 2, loop round 3).
// The facts and whether they are current come from the one critical section
// that started the refresh: read under a second lock, they could already be
// the refresh's answer, so the caller saw a lookup it never waited for
// (r106 CI: TestInvalidationDuringALookupIsNotCurrent read "answer 3").
func (c *identityCache[T]) getCached(key string) (facts T, current, ok bool) {
	if c == nil || key == "" || c.resolve == nil {
		return facts, false, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, _, _, _ := c.serveLocked(key)
	if !entry.ok {
		return facts, false, false
	}
	_, current = c.currentLocked(key, entry)
	if !entry.ok {
		// currentLocked dropped facts that aged out at this instant.
		return facts, false, false
	}
	return entry.facts, current && !c.unsettled(entry.facts), true
}

// getCurrent returns key's facts only when they are current: within their
// lifetime and fetched by a lookup started after the last invalidation
// (invalidatedLocked). Facts that are not wait up to wait for the refresh
// they need (the one in flight, or one started now), and a refresh that
// fails, is not due yet after a failure, or does not finish in time returns
// none: the facts from before it are never handed back as the answer. An
// exemption by a name the facts give uses it, since the directory may have
// dropped the name (review of r104 Q-identity, continuation 2, loop round
// 3). A blocking get served expired settled facts at once, and invalidated
// ones once its wait ended, so a name they gave still exempted the caller.
// A lookup that was in flight when an invalidation landed is not the
// answer either: the read waits, within the same wait, for the lookup
// started after it (continuation 3, loop round 1).
func (c *identityCache[T]) getCurrent(key string, wait time.Duration) (T, bool) {
	var zero T
	if c == nil || key == "" || c.resolve == nil || wait <= 0 {
		return zero, false
	}
	deadline := time.Now().Add(wait)
	c.mu.Lock()
	entry := c.entries[key]
	if entry == nil {
		if len(c.entries) >= identityDirectoryMax {
			c.evictLocked()
		}
		entry = &identityCacheEntry[T]{}
		c.entries[key] = entry
	}
	for {
		if facts, ok := c.currentLocked(key, entry); ok {
			c.mu.Unlock()
			return facts, true
		}
		if entry.inflight == nil && !c.now().Before(entry.nextAttempt) {
			c.refreshLocked(key, entry)
		}
		done := entry.inflight
		c.mu.Unlock()
		remaining := time.Until(deadline)
		if done == nil || remaining <= 0 {
			return zero, false
		}
		timer := time.NewTimer(remaining)
		select {
		case <-done:
			timer.Stop()
		case <-timer.C:
			return zero, false
		}
		c.mu.Lock()
	}
}

// currentLocked returns entry's facts when they are current: still served
// (dropAgedLocked), within their lifetime, and fetched by a lookup started
// after the last invalidation.
func (c *identityCache[T]) currentLocked(key string, entry *identityCacheEntry[T]) (T, bool) {
	var zero T
	now := c.now()
	c.dropAgedLocked(key, entry, now)
	if !entry.ok || now.Sub(entry.fetchedAt) >= c.lifetime(entry.facts) || c.invalidatedLocked(entry) {
		return zero, false
	}
	return entry.facts, true
}

// getFresh waits for a lookup started for this call or one already in flight.
// A lookup completed after an earlier timeout may be consumed once within
// identityDirectoryRetry of completion; older answers require a new lookup.
// A failed or timed-out lookup never returns facts from before it. Managed
// macOS hooks use this for secondary groups: Open Directory gives no change
// notification for their removal. Facts fetched before an invalidation
// (invalidatedLocked) are never shared this way: the read waits for the
// refresh, as a blocking get does.
//
// When the wait expires as the lookup completes, the outcome is read under
// the cache lock, not from which select case won: a lookup still in flight
// is marked for the next hook (pendingFresh), and one that has finished
// returns its answer now. Marking a finished lookup pending lost its answer:
// the completion had already counted it as served, so the next hook started
// another slow lookup and could refuse, although the answer was current.
//
// A lookup that was in flight when an invalidation landed answers with what
// the directory gave before it: the read starts the refresh the
// invalidation needs and waits for it, within the same wait (review of r104
// Q-identity, continuation 3, loop round 1).
func (c *identityCache[T]) getFresh(key string, wait time.Duration) (T, bool) {
	var zero T
	if c == nil || key == "" || c.resolve == nil || wait <= 0 {
		return zero, false
	}
	deadline := time.Now().Add(wait)
	for {
		facts, ok, again := c.getFreshOnce(key, wait)
		if wait = time.Until(deadline); ok || !again || wait <= 0 {
			return facts, ok
		}
	}
}

// getFreshOnce is one round of getFresh. again reports a lookup that
// finished with an answer from before an invalidation, which is not fresh:
// another round starts the lookup after it.
func (c *identityCache[T]) getFreshOnce(key string, wait time.Duration) (facts T, ok, again bool) {
	var zero T
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
	if entry.ok && !c.invalidatedLocked(entry) && (entry.pendingFresh && entry.generation > entry.servedGeneration &&
		now.Before(entry.fetchedAt.Add(identityDirectoryRetry)) || now.Before(entry.freshUntil)) {
		entry.pendingFresh, entry.servedGeneration = false, entry.generation
		facts = entry.facts
		c.mu.Unlock()
		return facts, true, false
	}
	before := entry.generation
	if entry.inflight == nil && (entry.failedSince.IsZero() || !now.Before(entry.nextAttempt)) {
		c.refreshLocked(key, entry)
	}
	done := entry.inflight
	c.mu.Unlock()
	if done == nil {
		return zero, false, false
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	timedOut := false
	select {
	case <-done:
	case <-timer.C:
		timedOut = true
	}
	if facts, ok = c.freshAfterWait(key, entry, done, before, timedOut); ok || timedOut {
		return facts, ok, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return zero, false, entry.ok && entry.generation > before && c.invalidatedLocked(entry)
}

// freshAfterWait is getFresh's outcome once its wait for the lookup done
// ends, read under the cache lock rather than from which select case won:
// a lookup still in flight is marked for the next hook (pendingFresh), and
// one that has finished returns its answer if it is newer than before and
// not from before an invalidation (invalidatedLocked).
func (c *identityCache[T]) freshAfterWait(key string, entry *identityCacheEntry[T], done chan struct{}, before uint64, timedOut bool) (T, bool) {
	var zero T
	c.mu.Lock()
	defer c.mu.Unlock()
	if timedOut && entry.inflight == done {
		// Still running: the next hook may use its answer once it completes.
		entry.pendingFresh = true
		return zero, false
	}
	c.dropAgedLocked(key, entry, c.now())
	if entry.ok && entry.generation > before && !c.invalidatedLocked(entry) {
		entry.pendingFresh, entry.servedGeneration = false, entry.generation
		return entry.facts, true
	}
	return zero, false
}
