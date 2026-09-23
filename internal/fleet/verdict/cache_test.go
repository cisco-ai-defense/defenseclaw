package verdict

import (
	"testing"
)

func testPipeline(hash [32]byte) (Action, uint8) {
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

func TestCacheMissCallsPipeline(t *testing.T) {
	c := NewCache(100, testPipeline)
	hash := makeHash(0xAA)

	action, _ := c.Evaluate(hash)
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

	c.Evaluate(hash) // miss + store
	c.Evaluate(hash) // hit

	hits, _, _ := c.Stats()
	if hits != 1 {
		t.Fatalf("expected 1 hit, got %d", hits)
	}
}

func TestCacheInvalidateRemovesEntry(t *testing.T) {
	c := NewCache(100, testPipeline)
	hash := makeHash(0xCC)

	c.Evaluate(hash) // store
	c.Invalidate(hash)

	entry := c.Lookup(hash)
	if entry != nil {
		t.Fatal("expected nil after invalidate")
	}
}

func TestCacheFlushAllClears(t *testing.T) {
	c := NewCache(100, testPipeline)
	c.Evaluate(makeHash(0x01))
	c.Evaluate(makeHash(0x02))
	c.Evaluate(makeHash(0x03))

	c.FlushAll()
	_, _, size := c.Stats()
	if size != 0 {
		t.Fatalf("expected 0 entries after flush, got %d", size)
	}
}

func TestCacheLRUEviction(t *testing.T) {
	c := NewCache(3, testPipeline) // max 3 entries

	c.Evaluate(makeHash(0x01))
	c.Evaluate(makeHash(0x02))
	c.Evaluate(makeHash(0x03))
	c.Evaluate(makeHash(0x04)) // should evict 0x01

	_, _, size := c.Stats()
	if size != 3 {
		t.Fatalf("expected 3 entries (LRU evicted), got %d", size)
	}

	// 0x01 should be evicted
	if c.Lookup(makeHash(0x01)) != nil {
		t.Fatal("expected 0x01 to be evicted")
	}
}

func TestBlockVerdictCached(t *testing.T) {
	c := NewCache(100, testPipeline)
	hash := makeHash(0xFF) // pipeline returns BLOCK for 0xFF

	action, severity := c.Evaluate(hash)
	if action != ActionBlock {
		t.Fatalf("expected BLOCK, got %d", action)
	}
	if severity != 4 {
		t.Fatalf("expected severity 4, got %d", severity)
	}

	// Verify it's cached
	entry := c.Lookup(hash)
	if entry == nil {
		t.Fatal("expected cached entry")
	}
	if entry.Action != ActionBlock {
		t.Fatalf("cached action = %d, want BLOCK", entry.Action)
	}
}
