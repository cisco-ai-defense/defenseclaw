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
	"path/filepath"
	"sync"
)

// RulePackCache de-duplicates rule-pack loads by directory path.
//
// Background: LoadRulePack reads and parses a directory of YAML files off
// disk, which is non-trivial work. In single-connector mode the gateway
// loads exactly one rule pack once at boot, so no cache is needed. With
// multi-connector support the boot loop loads a rule pack per connector via
// GuardrailConfig.EffectiveRulePackDir(connector); when several connectors
// resolve to the SAME directory (e.g. they all use the "strict" profile) a
// naive loop would read and parse that directory once per connector. This
// cache ensures each distinct directory is loaded at most once.
//
// Lifetime / invalidation: rule packs are immutable for the process lifetime
// — the production code path loads them once at boot and never hot-reloads
// (operators restart to pick up changes). The cache therefore never
// invalidates entries; it is load-once-then-serve.
//
// Ownership: the cache is an owned struct rather than a package global so it
// carries no process-wide mutable state and each test gets an isolated
// instance. The multi-connector boot loop creates one and reuses it across
// the connectors it spins up.
//
// Concurrency: Load is safe for concurrent use. It uses an RWMutex with
// double-checked locking — the common "already cached" path takes only a
// read lock, while a miss takes the write lock, re-checks, and loads under
// the lock so two goroutines racing on the same directory load it once.
type RulePackCache struct {
	mu     sync.RWMutex
	packs  map[string]*RulePack
	loader func(string) *RulePack
}

// NewRulePackCache returns an empty cache backed by the real LoadRulePack
// loader. This is the constructor production code (the multi-connector boot
// loop) should use.
func NewRulePackCache() *RulePackCache {
	return newRulePackCacheWithLoader(LoadRulePack)
}

// newRulePackCacheWithLoader builds a cache with an injectable loader so
// tests can count loads, simulate slow loads, or avoid touching disk without
// changing the de-dup / concurrency behavior under test.
func newRulePackCacheWithLoader(loader func(string) *RulePack) *RulePackCache {
	if loader == nil {
		loader = LoadRulePack
	}
	return &RulePackCache{
		packs:  make(map[string]*RulePack),
		loader: loader,
	}
}

// Load returns the rule pack for dir, loading and caching it on first use.
// Subsequent calls for the same (normalized) directory return the identical
// cached *RulePack without re-reading disk. The empty string is a valid key
// and maps to the compiled-in embedded defaults, mirroring LoadRulePack("").
func (c *RulePackCache) Load(dir string) *RulePack {
	key := normalizeRulePackDir(dir)

	// Fast path: already cached. Read lock only.
	c.mu.RLock()
	rp, ok := c.packs[key]
	c.mu.RUnlock()
	if ok {
		return rp
	}

	// Slow path: load under the write lock, re-checking first so two
	// goroutines that both missed the read-lock check do not both load.
	c.mu.Lock()
	defer c.mu.Unlock()
	if rp, ok := c.packs[key]; ok {
		return rp
	}
	rp = c.loader(dir)
	c.packs[key] = rp
	return rp
}

// normalizeRulePackDir canonicalizes a rule-pack directory into a stable
// cache key. The empty string (embedded defaults) is preserved exactly to
// match LoadRulePack's special-casing; any non-empty path is cleaned so that
// equivalent spellings such as "p/strict" and "p/strict/" share one entry.
func normalizeRulePackDir(dir string) string {
	if dir == "" {
		return ""
	}
	return filepath.Clean(dir)
}
