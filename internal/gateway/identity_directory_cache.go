// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Directory facts on the hot path.
//
// Hook calls read only memory. A cached answer is served even when it is
// older than identityDirectoryTTL, and one background refresh replaces it
// (stale-while-revalidate). A key never seen before starts one shared
// lookup (singleflight), and the request that started it waits for it at
// most identityDirectoryBudget, so an account's first record after a
// gateway start (an upgrade, a restart) carries its verified facts rather
// than falling back to claimed ones. Other requests wait for an unresolved
// key only when asked to block; otherwise they get no facts this time and a
// later request finds them cached. A failed lookup is retried no sooner than
// identityDirectoryRetry.
//
// Callers block when a guardrail profile assignment selects by user or
// group, so the budget covers a cold SSSD or Active Directory lookup (often
// one to two seconds) and every request still gets its group profile while
// the first lookup is in flight or after it failed. A lookup slower than
// that selects the default profile with match default_lookup_failed; the
// budget stays well inside the hook request timeout.
//
// A resolver can call its own answer incomplete (an AD account whose UPN a
// slow domain controller has not given yet). That answer is served, but is
// refreshed after identityDirectoryIncompleteTTL, not after the full TTL.

const (
	identityDirectoryTTL    = 15 * time.Minute
	identityDirectoryBudget = 2 * time.Second
	identityDirectoryRetry  = 15 * time.Second
	identityDirectoryMax    = 4096
	// identityDirectoryIncompleteTTL is how long an incomplete answer lasts.
	identityDirectoryIncompleteTTL = 2 * time.Minute
)

// identityDirectoryCache caches directory facts per uid or SID.
type identityDirectoryCache = identityCache[useridentity.DirectoryFacts]

// identityCache is the stale-while-revalidate, singleflight cache behind
// the directory and session lookups.
type identityCache[T any] struct {
	resolve func(key string) (T, error)
	now     func() time.Time
	// incomplete, when set, marks an answer to refresh after
	// identityDirectoryIncompleteTTL.
	incomplete func(T) bool

	mu      sync.Mutex
	entries map[string]*identityCacheEntry[T]
}

type identityCacheEntry[T any] struct {
	facts       T
	ok          bool
	fetchedAt   time.Time
	nextAttempt time.Time
	inflight    chan struct{}
}

func newIdentityDirectoryCache(resolve func(string) (useridentity.DirectoryFacts, error)) *identityDirectoryCache {
	return newIdentityCache(resolve)
}

func newIdentityCache[T any](resolve func(string) (T, error)) *identityCache[T] {
	return &identityCache[T]{resolve: resolve, now: time.Now, entries: map[string]*identityCacheEntry[T]{}}
}

// get returns key's facts. ok is false when nothing is cached yet and the
// lookup did not finish within the budget (or, after the first request for
// key, the caller did not ask to block).
func (c *identityCache[T]) get(key string, block bool) (T, bool) {
	var zero T
	if c == nil || key == "" || c.resolve == nil {
		return zero, false
	}
	c.mu.Lock()
	now := c.now()
	entry := c.entries[key]
	first := entry == nil
	if first {
		if len(c.entries) >= identityDirectoryMax {
			c.evictLocked()
		}
		entry = &identityCacheEntry[T]{}
		c.entries[key] = entry
	}
	age := now.Sub(entry.fetchedAt)
	stale := !entry.ok || age >= identityDirectoryTTL ||
		(age >= identityDirectoryIncompleteTTL && c.incomplete != nil && c.incomplete(entry.facts))
	if stale && entry.inflight == nil && !now.Before(entry.nextAttempt) {
		c.refreshLocked(key, entry)
	}
	if entry.ok {
		facts := entry.facts
		c.mu.Unlock()
		return facts, true
	}
	wait := entry.inflight
	c.mu.Unlock()
	if !(block || first) || wait == nil {
		return zero, false
	}
	timer := time.NewTimer(identityDirectoryBudget)
	defer timer.Stop()
	select {
	case <-wait:
	case <-timer.C:
		return zero, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return entry.facts, entry.ok
}

func (c *identityCache[T]) refreshLocked(key string, entry *identityCacheEntry[T]) {
	done := make(chan struct{})
	entry.inflight = done
	go func() {
		facts, err := c.resolve(key)
		c.mu.Lock()
		now := c.now()
		if err == nil {
			entry.facts, entry.ok, entry.fetchedAt = facts, true, now
		}
		entry.nextAttempt = now.Add(identityDirectoryRetry)
		entry.inflight = nil
		c.mu.Unlock()
		close(done)
	}()
}

// evictLocked drops the oldest settled entry.
func (c *identityCache[T]) evictLocked() {
	oldestKey := ""
	var oldest time.Time
	for key, entry := range c.entries {
		if entry.inflight != nil {
			continue
		}
		if oldestKey == "" || entry.fetchedAt.Before(oldest) {
			oldestKey, oldest = key, entry.fetchedAt
		}
	}
	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}
