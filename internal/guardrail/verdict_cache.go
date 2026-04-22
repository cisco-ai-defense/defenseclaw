// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// VerdictSnapshot is a compact, cacheable copy of a gateway.ScanVerdict
// kept in this package to avoid an import cycle with internal/gateway.
type VerdictSnapshot struct {
	Action         string
	Severity       string
	Reason         string
	Findings       []string
	EntityCount    int
	Scanner        string
	ScannerSources []string
	JudgeFailed    bool
}

// defaultVerdictCacheMaxEntries caps the number of concurrent entries
// in a VerdictCache. The cache is a correctness-neutral optimisation
// (a miss is always safe — we re-run the judge), so an eviction under
// pressure is cheap. 4096 entries × ~500 B/entry ≈ 2 MiB upper bound
// which is negligible next to the judge response bodies we already
// retain elsewhere, but puts a hard ceiling on a pathological
// cardinality explosion (thousand-tenant fleets, attacker-driven prompt
// churn, etc.) that otherwise grows unbounded until process exit.
const defaultVerdictCacheMaxEntries = 4096

// VerdictCache caches LLM judge outcomes keyed by (generation, kind,
// model, direction, content). TTL is wall-clock: entries expire
// independently of access time (tests use short TTLs). A size cap
// bounds memory; a generation counter allows O(1) invalidation on
// rulepack reload.
type VerdictCache struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	generation uint64
	// onHit/onMiss wire OTel metrics from the gateway layer without importing telemetry here.
	onHit  func(ctx context.Context, scanner, verdict, ttlBucket string)
	onMiss func(ctx context.Context, scanner, verdict, ttlBucket string)
	byKey  map[string]cacheEntry
}

type cacheEntry struct {
	until      time.Time
	generation uint64
	verdict    *VerdictSnapshot
}

// NewVerdictCache builds a process-local verdict cache. onHit/onMiss may be nil.
func NewVerdictCache(ttl time.Duration, onHit, onMiss func(ctx context.Context, scanner, verdict, ttlBucket string)) *VerdictCache {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &VerdictCache{
		ttl:        ttl,
		maxEntries: defaultVerdictCacheMaxEntries,
		onHit:      onHit,
		onMiss:     onMiss,
		byKey:      make(map[string]cacheEntry),
	}
}

// SetMaxEntries overrides the entry cap (primarily for tests). Passing
// a non-positive value resets to the default.
func (c *VerdictCache) SetMaxEntries(n int) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if n <= 0 {
		c.maxEntries = defaultVerdictCacheMaxEntries
	} else {
		c.maxEntries = n
	}
}

// Invalidate bumps the generation counter so every currently-held
// entry becomes a miss on next Get. This is an O(1) rulepack-reload
// invalidation path: when policy/rulepack config changes, the gateway
// MUST call Invalidate so a cached verdict rendered under the old
// policy is not served under the new one. The entries stay in the
// map until the next Put-driven eviction sweep (they are never
// returned).
func (c *VerdictCache) Invalidate() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.generation++
}

// TTLBucket returns a stable label for metrics (e.g. "30s", "100ms").
func TTLBucket(ttl time.Duration) string {
	if ttl <= 0 {
		return "default"
	}
	if ttl < time.Second {
		return fmt.Sprintf("%dms", ttl.Milliseconds())
	}
	return fmt.Sprintf("%ds", int(ttl.Round(time.Second)/time.Second))
}

// Get returns a cached verdict when present and not expired. scanner is a metric label
// (e.g. llm-judge-injection). verdictMetric is used on miss as the "verdict" series label
// (typically "none").
func (c *VerdictCache) Get(ctx context.Context, kind, model, direction, content, scanner, verdictMetric string) (*VerdictSnapshot, bool) {
	if c == nil {
		return nil, false
	}
	key := cacheKey(kind, model, direction, content)
	ttlB := TTLBucket(c.ttl)

	c.mu.Lock()
	defer c.mu.Unlock()
	ent, ok := c.byKey[key]
	// Treat generation-mismatched entries as misses so rulepack reloads
	// never serve a stale policy verdict. Expired entries are also
	// misses and are evicted opportunistically to keep the map from
	// retaining dead keys between Put-driven sweeps.
	if ok && ent.generation == c.generation && time.Now().Before(ent.until) {
		v := cloneSnapshot(ent.verdict)
		if c.onHit != nil {
			c.onHit(ctx, scanner, verdictAction(v), ttlB)
		}
		return v, true
	}
	if ok {
		delete(c.byKey, key)
	}
	if c.onMiss != nil {
		c.onMiss(ctx, scanner, verdictMetric, ttlB)
	}
	return nil, false
}

// Put stores a verdict snapshot until TTL elapses.
func (c *VerdictCache) Put(kind, model, direction, content string, v *VerdictSnapshot) {
	if c == nil || v == nil {
		return
	}
	key := cacheKey(kind, model, direction, content)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictIfFullLocked(key)
	c.byKey[key] = cacheEntry{
		until:      time.Now().Add(c.ttl),
		generation: c.generation,
		verdict:    cloneSnapshot(v),
	}
}

// evictIfFullLocked enforces c.maxEntries. It first sweeps obviously
// stale entries (expired or generation-mismatched) which is bounded by
// the map size, then — if we are still at cap — drops a single
// arbitrary entry via Go's randomised map iteration. The eviction
// policy is not LRU because the cache is correctness-neutral: a miss
// costs one extra judge call, not a wrong verdict. An O(n) sweep per
// Put is acceptable because n is capped by maxEntries (4096 by
// default) and Put is not on the hottest path (pre-cache Gets short-
// circuit most traffic).
func (c *VerdictCache) evictIfFullLocked(newKey string) {
	if c.maxEntries <= 0 || len(c.byKey) < c.maxEntries {
		return
	}
	if _, replacing := c.byKey[newKey]; replacing {
		return
	}
	now := time.Now()
	for k, e := range c.byKey {
		if e.generation != c.generation || !now.Before(e.until) {
			delete(c.byKey, k)
		}
	}
	if len(c.byKey) < c.maxEntries {
		return
	}
	for k := range c.byKey {
		delete(c.byKey, k)
		break
	}
}

func verdictAction(v *VerdictSnapshot) string {
	if v == nil {
		return "none"
	}
	if v.JudgeFailed {
		return "error"
	}
	return v.Action
}

func cloneSnapshot(v *VerdictSnapshot) *VerdictSnapshot {
	if v == nil {
		return nil
	}
	cp := *v
	if len(v.Findings) > 0 {
		cp.Findings = append([]string(nil), v.Findings...)
	}
	if len(v.ScannerSources) > 0 {
		cp.ScannerSources = append([]string(nil), v.ScannerSources...)
	}
	return &cp
}

func cacheKey(kind, model, direction, content string) string {
	h := sha256.Sum256([]byte(kind + "\x00" + model + "\x00" + direction + "\x00" + content))
	return kind + ":" + hex.EncodeToString(h[:])
}
