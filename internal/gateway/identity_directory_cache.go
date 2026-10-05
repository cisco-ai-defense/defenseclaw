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
// lookup (singleflight); the caller waits for it at most
// identityDirectoryBudget, and only when asked to block, otherwise it gets no
// facts this time and the next request finds them cached. A failed lookup is
// retried no sooner than identityDirectoryRetry.

const (
	identityDirectoryTTL    = 15 * time.Minute
	identityDirectoryBudget = 200 * time.Millisecond
	identityDirectoryRetry  = 15 * time.Second
	identityDirectoryMax    = 4096
)

// identityDirectoryCache caches directory facts per uid or SID.
type identityDirectoryCache = identityCache[useridentity.DirectoryFacts]

// identityCache is the stale-while-revalidate, singleflight cache behind
// the directory and session lookups.
type identityCache[T any] struct {
	resolve func(key string) (T, error)
	now     func() time.Time

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

// get returns key's facts. ok is false when nothing is cached yet (and,
// with block, the lookup did not finish within the budget).
func (c *identityCache[T]) get(key string, block bool) (T, bool) {
	var zero T
	if c == nil || key == "" || c.resolve == nil {
		return zero, false
	}
	c.mu.Lock()
	now := c.now()
	entry := c.entries[key]
	if entry == nil {
		if len(c.entries) >= identityDirectoryMax {
			c.evictLocked()
		}
		entry = &identityCacheEntry[T]{}
		c.entries[key] = entry
	}
	stale := !entry.ok || now.Sub(entry.fetchedAt) >= identityDirectoryTTL
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
	if !block || wait == nil {
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
