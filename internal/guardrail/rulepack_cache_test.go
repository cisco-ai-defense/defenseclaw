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

package guardrail

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingLoader returns a loader that hands back a fresh *RulePack per call
// and records how many times each directory was actually loaded. Pointer
// identity lets tests distinguish a cache hit (same pointer) from a reload
// (new pointer).
func countingLoader() (func(string) *RulePack, *sync.Map) {
	counts := &sync.Map{}
	loader := func(dir string) *RulePack {
		v, _ := counts.LoadOrStore(dir, new(int64))
		atomic.AddInt64(v.(*int64), 1)
		return &RulePack{JudgeConfigs: make(map[string]*JudgeYAML)}
	}
	return loader, counts
}

func loadCount(t *testing.T, counts *sync.Map, dir string) int64 {
	t.Helper()
	v, ok := counts.Load(dir)
	if !ok {
		return 0
	}
	return atomic.LoadInt64(v.(*int64))
}

func TestRulePackCache_DeDupesSameDir(t *testing.T) {
	loader, counts := countingLoader()
	c := newRulePackCacheWithLoader(loader)

	first := c.Load("/policies/strict")
	for i := 0; i < 10; i++ {
		got := c.Load("/policies/strict")
		if got != first {
			t.Fatalf("call %d returned a different *RulePack; cache did not de-dup", i)
		}
	}
	if n := loadCount(t, counts, "/policies/strict"); n != 1 {
		t.Errorf("loader called %d times for one dir, want 1", n)
	}
}

func TestRulePackCache_DistinctDirsLoadSeparately(t *testing.T) {
	loader, counts := countingLoader()
	c := newRulePackCacheWithLoader(loader)

	a := c.Load("/policies/strict")
	b := c.Load("/policies/permissive")
	if a == b {
		t.Fatal("distinct dirs returned the same *RulePack")
	}
	if n := loadCount(t, counts, "/policies/strict"); n != 1 {
		t.Errorf("strict loaded %d times, want 1", n)
	}
	if n := loadCount(t, counts, "/policies/permissive"); n != 1 {
		t.Errorf("permissive loaded %d times, want 1", n)
	}
}

func TestRulePackCache_NormalizesEquivalentPaths(t *testing.T) {
	loader, counts := countingLoader()
	c := newRulePackCacheWithLoader(loader)

	clean := c.Load("/policies/strict")
	trailing := c.Load("/policies/strict/")
	dotted := c.Load("/policies/./strict")
	if clean != trailing || clean != dotted {
		t.Fatal("equivalent path spellings returned different *RulePack instances")
	}
	// The loader is invoked with the first spelling seen; the cache key is
	// normalized so only one load happens regardless of spelling.
	total := loadCount(t, counts, "/policies/strict") +
		loadCount(t, counts, "/policies/strict/") +
		loadCount(t, counts, "/policies/./strict")
	if total != 1 {
		t.Errorf("equivalent spellings triggered %d loads, want 1", total)
	}
}

func TestRulePackCache_EmptyDirKey(t *testing.T) {
	loader, counts := countingLoader()
	c := newRulePackCacheWithLoader(loader)

	first := c.Load("")
	second := c.Load("")
	if first != second {
		t.Fatal("empty-dir key did not de-dup")
	}
	if n := loadCount(t, counts, ""); n != 1 {
		t.Errorf("empty dir loaded %d times, want 1", n)
	}
}

func TestRulePackCache_Concurrent_SameDir(t *testing.T) {
	var loads int64
	loader := func(dir string) *RulePack {
		atomic.AddInt64(&loads, 1)
		// Widen the race window so a broken double-check would load twice.
		time.Sleep(2 * time.Millisecond)
		return &RulePack{JudgeConfigs: make(map[string]*JudgeYAML)}
	}
	c := newRulePackCacheWithLoader(loader)

	const goroutines = 64
	var wg sync.WaitGroup
	results := make([]*RulePack, goroutines)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			results[idx] = c.Load("/policies/strict")
		}(i)
	}
	wg.Wait()

	if got := atomic.LoadInt64(&loads); got != 1 {
		t.Fatalf("concurrent loads of one dir triggered %d loads, want 1", got)
	}
	for i := 1; i < goroutines; i++ {
		if results[i] != results[0] {
			t.Fatalf("goroutine %d got a different *RulePack than goroutine 0", i)
		}
	}
}

func TestRulePackCache_Concurrent_DistinctDirs(t *testing.T) {
	loader, counts := countingLoader()
	c := newRulePackCacheWithLoader(loader)

	const dirs = 8
	const perDir = 16
	var wg sync.WaitGroup
	wg.Add(dirs * perDir)
	for d := 0; d < dirs; d++ {
		dir := fmt.Sprintf("/policies/p%d", d)
		for r := 0; r < perDir; r++ {
			go func(dir string) {
				defer wg.Done()
				c.Load(dir)
			}(dir)
		}
	}
	wg.Wait()

	for d := 0; d < dirs; d++ {
		dir := fmt.Sprintf("/policies/p%d", d)
		if n := loadCount(t, counts, dir); n != 1 {
			t.Errorf("%s loaded %d times, want 1", dir, n)
		}
	}
}

// TestRulePackCache_FallbackMatchesLoadRulePack verifies the real-loader path:
// an empty dir yields the embedded defaults (non-nil suppressions/judges),
// exactly as a direct LoadRulePack("") would, so going through the cache does
// not change graceful-fallback behavior.
func TestRulePackCache_FallbackMatchesLoadRulePack(t *testing.T) {
	c := NewRulePackCache()

	rp := c.Load("")
	if rp == nil {
		t.Fatal("cache returned nil for embedded defaults")
	}
	if rp.Suppressions == nil {
		t.Error("embedded defaults missing suppressions via cache")
	}
	if rp.PIIJudge() == nil {
		t.Error("embedded defaults missing pii judge via cache")
	}

	// A nonexistent directory must still fall back to embedded defaults
	// (LoadRulePack never returns nil), not panic or return nil.
	missing := c.Load("/nonexistent/policies/dir")
	if missing == nil {
		t.Fatal("cache returned nil for a nonexistent dir; expected embedded fallback")
	}
}

func TestRulePackCache_DeDupesOverlayCombination(t *testing.T) {
	var loads int64
	overlayLoader := func(string, []string) (*RulePack, error) {
		atomic.AddInt64(&loads, 1)
		return &RulePack{JudgeConfigs: make(map[string]*JudgeYAML)}, nil
	}
	c := newRulePackCacheWithLoaders(nil, overlayLoader)
	first, err := c.LoadWithOverlays("/policies/strict", []string{"/managed/rules"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.LoadWithOverlays("/policies/strict/", []string{"/managed/./rules"})
	if err != nil {
		t.Fatal(err)
	}
	if first != second || atomic.LoadInt64(&loads) != 1 {
		t.Fatalf("overlay combination was not cached: first=%p second=%p loads=%d", first, second, loads)
	}
}

func TestRulePackCache_DoesNotCacheOverlayFailure(t *testing.T) {
	var loads int64
	overlayLoader := func(string, []string) (*RulePack, error) {
		if atomic.AddInt64(&loads, 1) == 1 {
			return nil, fmt.Errorf("invalid overlay")
		}
		return &RulePack{JudgeConfigs: make(map[string]*JudgeYAML)}, nil
	}
	c := newRulePackCacheWithLoaders(nil, overlayLoader)
	if _, err := c.LoadWithOverlays("", []string{"/managed/rules"}); err == nil {
		t.Fatal("expected first overlay load to fail")
	}
	if _, err := c.LoadWithOverlays("", []string{"/managed/rules"}); err != nil {
		t.Fatalf("corrected overlay load was not retried: %v", err)
	}
	if atomic.LoadInt64(&loads) != 2 {
		t.Fatalf("overlay loader calls = %d, want 2", loads)
	}
}

func TestRulePackCache_OverlayLoadDoesNotBlockBaseLoad(t *testing.T) {
	overlayStarted := make(chan struct{})
	releaseOverlay := make(chan struct{})
	overlayLoader := func(string, []string) (*RulePack, error) {
		close(overlayStarted)
		<-releaseOverlay
		return &RulePack{JudgeConfigs: make(map[string]*JudgeYAML)}, nil
	}
	c := newRulePackCacheWithLoaders(func(string) *RulePack {
		return &RulePack{JudgeConfigs: make(map[string]*JudgeYAML)}
	}, overlayLoader)
	overlayDone := make(chan error, 1)
	go func() {
		_, err := c.LoadWithOverlays("/policies/strict", []string{"/managed/rules"})
		overlayDone <- err
	}()
	<-overlayStarted
	baseDone := make(chan struct{})
	go func() {
		c.Load("/policies/permissive")
		close(baseDone)
	}()
	select {
	case <-baseDone:
	case <-time.After(time.Second):
		close(releaseOverlay)
		t.Fatal("base load was blocked by unrelated overlay I/O")
	}
	close(releaseOverlay)
	if err := <-overlayDone; err != nil {
		t.Fatal(err)
	}
}
