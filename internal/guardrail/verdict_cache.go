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

// VerdictCache caches LLM judge outcomes keyed by (kind, model, direction, content).
// TTL is wall-clock: entries expire independently of access time (tests use short TTLs).
type VerdictCache struct {
	mu  sync.Mutex
	ttl time.Duration
	// onHit/onMiss wire OTel metrics from the gateway layer without importing telemetry here.
	onHit  func(ctx context.Context, scanner, verdict, ttlBucket string)
	onMiss func(ctx context.Context, scanner, verdict, ttlBucket string)
	byKey  map[string]cacheEntry
}

type cacheEntry struct {
	until   time.Time
	verdict *VerdictSnapshot
}

// NewVerdictCache builds a process-local verdict cache. onHit/onMiss may be nil.
func NewVerdictCache(ttl time.Duration, onHit, onMiss func(ctx context.Context, scanner, verdict, ttlBucket string)) *VerdictCache {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &VerdictCache{
		ttl:    ttl,
		onHit:  onHit,
		onMiss: onMiss,
		byKey:  make(map[string]cacheEntry),
	}
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
	if ok && time.Now().Before(ent.until) {
		v := cloneSnapshot(ent.verdict)
		if c.onHit != nil {
			c.onHit(ctx, scanner, verdictAction(v), ttlB)
		}
		return v, true
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
	c.byKey[key] = cacheEntry{
		until:   time.Now().Add(c.ttl),
		verdict: cloneSnapshot(v),
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
