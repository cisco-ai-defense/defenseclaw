// Package verdict implements the cloud-side verdict cache service.
// It serves cached scan verdicts to IoT devices without re-running
// the full inspection pipeline for known tool hashes.
package verdict

import (
	"sync"
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
	Action   Action
	Severity uint8
	CachedAt time.Time
	TTL      time.Duration
}

// TTLs per action (matching proposal §6.2)
var actionTTLs = map[Action]time.Duration{
	ActionAllow: 24 * time.Hour,
	ActionBlock: 7 * 24 * time.Hour,
	ActionWarn:  4 * time.Hour,
}

// PipelineFunc is called on cache miss to evaluate a tool hash.
type PipelineFunc func(toolHash [32]byte) (Action, uint8)

// Cache is the cloud-side verdict cache.
type Cache struct {
	mu       sync.RWMutex
	entries  map[[32]byte]*CacheEntry
	maxSize  int
	pipeline PipelineFunc
	hits     uint64
	misses   uint64

	// Metrics hooks (set externally to avoid circular imports)
	onHit   func()
	onMiss  func()
	onStore func()
}

// NewCache creates a verdict cache with a max entry limit.
func NewCache(maxSize int, pipeline PipelineFunc) *Cache {
	return &Cache{
		entries:  make(map[[32]byte]*CacheEntry),
		maxSize:  maxSize,
		pipeline: pipeline,
	}
}

// SetMetricsHooks configures callbacks for cache metrics updates.
func (c *Cache) SetMetricsHooks(onHit, onMiss, onStore func()) {
	c.onHit = onHit
	c.onMiss = onMiss
	c.onStore = onStore
}

// Lookup checks the cache for a tool hash. Returns a copy of the cached entry and true,
// or a zero CacheEntry and false if not found or expired.
func (c *Cache) Lookup(toolHash [32]byte) (CacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[toolHash]
	if !ok {
		c.misses++
		if c.onMiss != nil {
			c.onMiss()
		}
		return CacheEntry{}, false
	}

	if time.Since(entry.CachedAt) > entry.TTL {
		delete(c.entries, toolHash)
		c.misses++
		if c.onMiss != nil {
			c.onMiss()
		}
		return CacheEntry{}, false
	}

	// Update CachedAt on access for true LRU eviction (M6)
	entry.CachedAt = time.Now()
	c.hits++
	if c.onHit != nil {
		c.onHit()
	}
	return *entry, true
}

// Evaluate checks cache first, then runs pipeline on miss.
func (c *Cache) Evaluate(toolHash [32]byte) (Action, uint8) {
	if entry, ok := c.Lookup(toolHash); ok {
		return entry.Action, entry.Severity
	}

	action, severity := c.pipeline(toolHash)
	c.Store(toolHash, action, severity)
	return action, severity
}

// Store adds a verdict to the cache.
func (c *Cache) Store(toolHash [32]byte, action Action, severity uint8) {
	ttl := actionTTLs[action]
	if ttl == 0 {
		ttl = time.Hour
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.maxSize {
		c.evictLRU()
	}

	c.entries[toolHash] = &CacheEntry{
		Action:   action,
		Severity: severity,
		CachedAt: time.Now(),
		TTL:      ttl,
	}
	if c.onStore != nil {
		c.onStore()
	}
}

// Invalidate removes a specific hash from the cache.
func (c *Cache) Invalidate(toolHash [32]byte) {
	c.mu.Lock()
	delete(c.entries, toolHash)
	c.mu.Unlock()
}

// FlushAll clears the entire cache (e.g., on policy change).
func (c *Cache) FlushAll() {
	c.mu.Lock()
	c.entries = make(map[[32]byte]*CacheEntry)
	c.mu.Unlock()
}

// Stats returns cache hit/miss statistics.
func (c *Cache) Stats() (hits, misses uint64, size int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hits, c.misses, len(c.entries)
}

func (c *Cache) evictLRU() {
	var oldestKey [32]byte
	var oldestTime time.Time
	first := true

	for key, entry := range c.entries {
		if first || entry.CachedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.CachedAt
			first = false
		}
	}
	if !first {
		delete(c.entries, oldestKey)
	}
}
