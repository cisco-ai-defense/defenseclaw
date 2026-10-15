// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Package verdict implements the cloud-side verdict cache service.
// It serves cached scan verdicts to IoT devices without re-running
// the full inspection pipeline for known tool hashes.
package verdict

import (
	"sync"
	"sync/atomic"
	"time"
)

// Action mirrors the device-side dclaw_action_t enum.
type Action uint8

const (
	ActionAllow    Action = 0
	ActionBlock    Action = 1
	ActionWarn     Action = 2
	ActionEscalate Action = 3
)

// CacheEntry stores a verdict with TTL metadata.
type CacheEntry struct {
	Action      Action
	Severity    uint8
	CachedAt    time.Time
	TTL         time.Duration
	LastAccess  time.Time // tracks last read for LRU eviction
	accessOrder uint64    // breaks clock-tick ties in eviction order
}

// CacheKey includes tenant and fleet identity so that verdicts for the
// same tool hash are isolated across tenants. Without this, a permissive
// tenant's ALLOW verdict would leak to a strict tenant.
type CacheKey struct {
	TenantID uint16
	FleetID  uint16
	ToolHash [32]byte
}

// TTLs per action (matching proposal §6.2)
var actionTTLs = map[Action]time.Duration{
	ActionAllow: 24 * time.Hour,
	ActionBlock: 7 * 24 * time.Hour,
	ActionWarn:  4 * time.Hour,
}

// PipelineFunc is called on cache miss to evaluate a tool hash.
// The tenant/fleet identity allows the pipeline to select the correct
// policy for evaluation.
type PipelineFunc func(tenantID, fleetID uint16, toolHash [32]byte) (Action, uint8)

// Cache is the cloud-side verdict cache.
type Cache struct {
	mu              sync.RWMutex
	entries         map[CacheKey]*CacheEntry
	maxSize         int
	pipeline        PipelineFunc
	nextAccessOrder uint64 // guarded by mu
	hits            atomic.Uint64
	misses          atomic.Uint64

	// Metrics hooks (set externally to avoid circular imports)
	onHit   func()
	onMiss  func()
	onStore func()
	onEvict func()
}

// NewCache creates a verdict cache with a max entry limit.
func NewCache(maxSize int, pipeline PipelineFunc) *Cache {
	return &Cache{
		entries:  make(map[CacheKey]*CacheEntry),
		maxSize:  maxSize,
		pipeline: pipeline,
	}
}

// SetMetricsHooks configures callbacks for cache metrics updates.
// Thread-safe: acquires the cache mutex to prevent data races with
// concurrent Lookup/Store/Invalidate/FlushAll calls that read hooks.
func (c *Cache) SetMetricsHooks(onHit, onMiss, onStore, onEvict func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onHit = onHit
	c.onMiss = onMiss
	c.onStore = onStore
	c.onEvict = onEvict
}

// Lookup checks the cache for a tool hash scoped to a tenant/fleet pair.
// Returns a copy of the cached entry and true, or a zero CacheEntry and
// false if not found or expired.
func (c *Cache) Lookup(tenantID, fleetID uint16, toolHash [32]byte) (CacheEntry, bool) {
	key := CacheKey{TenantID: tenantID, FleetID: fleetID, ToolHash: toolHash}
	c.mu.RLock()
	entry, ok := c.entries[key]
	onHit := c.onHit
	onMiss := c.onMiss
	onEvict := c.onEvict
	if !ok {
		c.mu.RUnlock()
		c.misses.Add(1)
		if onMiss != nil {
			onMiss()
		}
		return CacheEntry{}, false
	}
	expired := time.Since(entry.CachedAt) > entry.TTL
	entryCopy := *entry
	c.mu.RUnlock()

	if expired {
		deleted := false
		c.mu.Lock()
		if e, still := c.entries[key]; still && time.Since(e.CachedAt) > e.TTL {
			delete(c.entries, key)
			deleted = true
		}
		c.mu.Unlock()
		if deleted && onEvict != nil {
			onEvict()
		}
		c.misses.Add(1)
		if onMiss != nil {
			onMiss()
		}
		return CacheEntry{}, false
	}

	if time.Since(entryCopy.LastAccess) > entryCopy.TTL/8 {
		c.mu.Lock()
		if e, still := c.entries[key]; still {
			c.nextAccessOrder++
			e.LastAccess = time.Now()
			e.accessOrder = c.nextAccessOrder
		}
		c.mu.Unlock()
	}

	c.hits.Add(1)
	if onHit != nil {
		onHit()
	}
	return entryCopy, true
}

// Evaluate checks cache first, then runs pipeline on miss.
func (c *Cache) Evaluate(tenantID, fleetID uint16, toolHash [32]byte) (Action, uint8) {
	if entry, ok := c.Lookup(tenantID, fleetID, toolHash); ok {
		return entry.Action, entry.Severity
	}

	action, severity := c.pipeline(tenantID, fleetID, toolHash)
	c.Store(tenantID, fleetID, toolHash, action, severity)
	return action, severity
}

// Store adds a verdict to the cache scoped by tenant/fleet.
func (c *Cache) Store(tenantID, fleetID uint16, toolHash [32]byte, action Action, severity uint8) {
	ttl := actionTTLs[action]
	if ttl == 0 {
		ttl = time.Hour
	}

	key := CacheKey{TenantID: tenantID, FleetID: fleetID, ToolHash: toolHash}

	c.mu.Lock()
	defer c.mu.Unlock()

	_, replacing := c.entries[key]

	if !replacing && len(c.entries) >= c.maxSize {
		c.evictLRU()
	}

	now := time.Now()
	c.nextAccessOrder++
	c.entries[key] = &CacheEntry{
		Action:      action,
		Severity:    severity,
		CachedAt:    now,
		TTL:         ttl,
		LastAccess:  now,
		accessOrder: c.nextAccessOrder,
	}
	onStore := c.onStore
	if !replacing && onStore != nil {
		onStore()
	}
}

// Invalidate removes a specific hash from ALL tenants (cross-tenant
// threat intel revocation).
func (c *Cache) Invalidate(toolHash [32]byte) {
	c.mu.Lock()
	var count int
	for key := range c.entries {
		if key.ToolHash == toolHash {
			delete(c.entries, key)
			count++
		}
	}
	onEvict := c.onEvict
	c.mu.Unlock()
	if onEvict != nil {
		for i := 0; i < count; i++ {
			onEvict()
		}
	}
}

// FlushTenant clears all cache entries for a specific tenant/fleet pair
// (e.g., on per-fleet policy change).
func (c *Cache) FlushTenant(tenantID, fleetID uint16) {
	c.mu.Lock()
	var count int
	for key := range c.entries {
		if key.TenantID == tenantID && key.FleetID == fleetID {
			delete(c.entries, key)
			count++
		}
	}
	onEvict := c.onEvict
	c.mu.Unlock()
	if onEvict != nil {
		for i := 0; i < count; i++ {
			onEvict()
		}
	}
}

// FlushAll clears the entire cache (e.g., on emergency threat intel).
func (c *Cache) FlushAll() {
	c.mu.Lock()
	n := len(c.entries)
	c.entries = make(map[CacheKey]*CacheEntry)
	onEvict := c.onEvict
	c.mu.Unlock()

	if onEvict != nil {
		for i := 0; i < n; i++ {
			onEvict()
		}
	}
}

// Stats returns cache hit/miss statistics.
func (c *Cache) Stats() (hits, misses uint64, size int) {
	c.mu.RLock()
	size = len(c.entries)
	c.mu.RUnlock()
	return c.hits.Load(), c.misses.Load(), size
}

func (c *Cache) evictLRU() {
	var oldestKey CacheKey
	var oldestTime time.Time
	var oldestOrder uint64
	first := true

	samples := 0
	for key, entry := range c.entries {
		if first || entry.LastAccess.Before(oldestTime) ||
			(entry.LastAccess.Equal(oldestTime) && entry.accessOrder < oldestOrder) {
			oldestKey = key
			oldestTime = entry.LastAccess
			oldestOrder = entry.accessOrder
			first = false
		}
		samples++
		if samples >= 8 {
			break
		}
	}
	if !first {
		delete(c.entries, oldestKey)
		if c.onEvict != nil {
			c.onEvict()
		}
	}
}
