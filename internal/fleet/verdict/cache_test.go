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

package verdict

import (
	"testing"
	"time"
)

func testPipeline(tenantID, fleetID uint16, hash [32]byte) (Action, uint8) {
	if hash[0] == 0xFF {
		return ActionBlock, 4 // critical
	}
	return ActionAllow, 0
}

func makeHash(seed byte) [32]byte {
	var h [32]byte
	for i := range h {
		h[i] = seed
	}
	return h
}

const testTenant uint16 = 1
const testFleet uint16 = 2

func TestCacheMissCallsPipeline(t *testing.T) {
	c := NewCache(100, testPipeline)
	hash := makeHash(0xAA)

	action, _ := c.Evaluate(testTenant, testFleet, hash)
	if action != ActionAllow {
		t.Fatalf("expected ALLOW, got %d", action)
	}

	_, misses, _ := c.Stats()
	if misses != 1 {
		t.Fatalf("expected 1 miss, got %d", misses)
	}
}

func TestCacheHitReturnsCached(t *testing.T) {
	c := NewCache(100, testPipeline)
	hash := makeHash(0xBB)

	c.Evaluate(testTenant, testFleet, hash) // miss + store
	c.Evaluate(testTenant, testFleet, hash) // hit

	hits, _, _ := c.Stats()
	if hits != 1 {
		t.Fatalf("expected 1 hit, got %d", hits)
	}
}

func TestCacheInvalidateRemovesEntry(t *testing.T) {
	c := NewCache(100, testPipeline)
	hash := makeHash(0xCC)

	c.Evaluate(testTenant, testFleet, hash) // store
	c.Invalidate(hash)

	_, found := c.Lookup(testTenant, testFleet, hash)
	if found {
		t.Fatal("expected not found after invalidate")
	}
}

func TestCacheFlushAllClears(t *testing.T) {
	c := NewCache(100, testPipeline)
	c.Evaluate(testTenant, testFleet, makeHash(0x01))
	c.Evaluate(testTenant, testFleet, makeHash(0x02))
	c.Evaluate(testTenant, testFleet, makeHash(0x03))

	c.FlushAll()
	_, _, size := c.Stats()
	if size != 0 {
		t.Fatalf("expected 0 entries after flush, got %d", size)
	}
}

func TestCacheLRUEviction(t *testing.T) {
	c := NewCache(3, testPipeline)

	c.Evaluate(testTenant, testFleet, makeHash(0x01))
	c.Evaluate(testTenant, testFleet, makeHash(0x02))
	c.Evaluate(testTenant, testFleet, makeHash(0x03))
	c.Evaluate(testTenant, testFleet, makeHash(0x04)) // should evict 0x01

	_, _, size := c.Stats()
	if size != 3 {
		t.Fatalf("expected 3 entries (LRU evicted), got %d", size)
	}

	if _, found := c.Lookup(testTenant, testFleet, makeHash(0x01)); found {
		t.Fatal("expected 0x01 to be evicted")
	}
}

// Windows can report the same clock tick for consecutive stores. Eviction
// must still choose the oldest insert rather than the first map iteration.
func TestCacheLRUEvictionWithEqualTimestamps(t *testing.T) {
	for trial := 0; trial < 32; trial++ {
		c := NewCache(3, testPipeline)
		for seed := byte(1); seed <= 3; seed++ {
			c.Store(testTenant, testFleet, makeHash(seed), ActionAllow, 0)
		}

		c.mu.Lock()
		clockTick := time.Now()
		for _, entry := range c.entries {
			entry.LastAccess = clockTick
		}
		c.mu.Unlock()

		c.Store(testTenant, testFleet, makeHash(4), ActionAllow, 0)
		if _, found := c.Lookup(testTenant, testFleet, makeHash(1)); found {
			t.Fatalf("trial %d: oldest insert survived an equal-timestamp eviction", trial)
		}
	}
}

func TestBlockVerdictCached(t *testing.T) {
	c := NewCache(100, testPipeline)
	hash := makeHash(0xFF) // pipeline returns BLOCK for 0xFF

	action, severity := c.Evaluate(testTenant, testFleet, hash)
	if action != ActionBlock {
		t.Fatalf("expected BLOCK, got %d", action)
	}
	if severity != 4 {
		t.Fatalf("expected severity 4, got %d", severity)
	}

	entry, found := c.Lookup(testTenant, testFleet, hash)
	if !found {
		t.Fatal("expected cached entry")
	}
	if entry.Action != ActionBlock {
		t.Fatalf("cached action = %d, want BLOCK", entry.Action)
	}
}

func TestTenantIsolation(t *testing.T) {
	pipelineCalls := 0
	pipeline := func(tenantID, fleetID uint16, hash [32]byte) (Action, uint8) {
		pipelineCalls++
		if tenantID == 1 {
			return ActionAllow, 0
		}
		return ActionBlock, 3
	}

	c := NewCache(100, pipeline)
	hash := makeHash(0xDD)

	action1, _ := c.Evaluate(1, 1, hash)
	if action1 != ActionAllow {
		t.Fatalf("tenant 1 expected ALLOW, got %d", action1)
	}

	action2, _ := c.Evaluate(2, 1, hash)
	if action2 != ActionBlock {
		t.Fatalf("tenant 2 expected BLOCK, got %d", action2)
	}

	if pipelineCalls != 2 {
		t.Fatalf("expected 2 pipeline calls (one per tenant), got %d", pipelineCalls)
	}

	// Verify tenant 1 still hits cache
	c.Evaluate(1, 1, hash)
	hits, _, _ := c.Stats()
	if hits != 1 {
		t.Fatalf("expected 1 cache hit for tenant 1, got %d", hits)
	}
}

func TestFlushTenant(t *testing.T) {
	c := NewCache(100, testPipeline)

	c.Evaluate(1, 1, makeHash(0x01))
	c.Evaluate(1, 1, makeHash(0x02))
	c.Evaluate(2, 1, makeHash(0x01))

	c.FlushTenant(1, 1)

	_, _, size := c.Stats()
	if size != 1 {
		t.Fatalf("expected 1 entry after FlushTenant, got %d", size)
	}

	if _, found := c.Lookup(2, 1, makeHash(0x01)); !found {
		t.Fatal("expected tenant 2 entry to survive FlushTenant(1,1)")
	}
}

func TestInvalidateAcrossTenants(t *testing.T) {
	c := NewCache(100, testPipeline)
	hash := makeHash(0xEE)

	c.Evaluate(1, 1, hash)
	c.Evaluate(2, 1, hash)
	c.Evaluate(3, 1, hash)

	c.Invalidate(hash)

	_, _, size := c.Stats()
	if size != 0 {
		t.Fatalf("expected 0 entries after cross-tenant Invalidate, got %d", size)
	}
}
