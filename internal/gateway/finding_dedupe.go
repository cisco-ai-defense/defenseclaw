// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// Identical findings were persisted on every scan of the same content. One
// observed deployment held 2,980 hook findings covering 276 distinct contents
// — CMD-SUDO alone appeared 75 times from a single piece of text. The
// repetition carries no information: it is the same match, re-derived because
// the same bytes were scanned again.
//
// A short suppression window collapses that. The first occurrence is always
// emitted; repeats of the same (scanner, target, rule, content) inside the
// window are dropped. The window is deliberately short so a genuinely
// recurring condition still produces a periodic record rather than falling
// silent after one alert.

const (
	// findingDedupeWindow is how long a repeat is considered redundant.
	findingDedupeWindow = 10 * time.Minute
	// findingDedupeMaxEntries bounds memory. On overflow the cache is cleared
	// rather than evicted one-by-one: losing suppression state costs a
	// duplicate finding, never a missed one.
	findingDedupeMaxEntries = 4096
)

type findingDedupeCache struct {
	mu      sync.Mutex
	seen    map[string]time.Time
	window  time.Duration
	maxSize int
	now     func() time.Time
}

func newFindingDedupeCache(window time.Duration, maxSize int) *findingDedupeCache {
	return &findingDedupeCache{
		seen:    make(map[string]time.Time),
		window:  window,
		maxSize: maxSize,
		now:     time.Now,
	}
}

var defaultFindingDedupe = newFindingDedupeCache(findingDedupeWindow, findingDedupeMaxEntries)

func findingDedupeKey(scannerName, target, ruleID, evidence string) string {
	sum := sha256.Sum256([]byte(scannerName + "\x00" + target + "\x00" + ruleID + "\x00" + evidence))
	return hex.EncodeToString(sum[:])
}

// admit reports whether a finding should be persisted. It returns true for the
// first sighting and for any sighting after the window has elapsed.
func (c *findingDedupeCache) admit(scannerName, target, ruleID, evidence string) bool {
	if c == nil {
		return true
	}
	key := findingDedupeKey(scannerName, target, ruleID, evidence)
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	if last, ok := c.seen[key]; ok && now.Sub(last) < c.window {
		return false
	}
	if len(c.seen) >= c.maxSize {
		c.seen = make(map[string]time.Time, c.maxSize)
	}
	c.seen[key] = now
	return true
}

func (c *findingDedupeCache) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen = make(map[string]time.Time)
}
