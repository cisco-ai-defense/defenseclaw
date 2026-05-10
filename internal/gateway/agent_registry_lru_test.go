// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestAgentRegistry_LRUEvictionAtCap pins the cap eviction contract:
// when the session map reaches agentRegistryMaxSessions, the next
// Resolve evicts the oldest entry (by LastSeen) and admits the new
// one. Without this test, a refactor that silently lifted or removed
// the cap would not fail CI — and the cap is the entire point of the
// DeepSec resource-exhaustion fix.
func TestAgentRegistry_LRUEvictionAtCap(t *testing.T) {
	r := NewAgentRegistry("test-agent", "test-agent-name")
	want := agentRegistryMaxSessions
	for i := 0; i < want+1; i++ {
		_ = r.Resolve(context.Background(), fmt.Sprintf("session-%05d", i), "agent")
	}
	r.mu.RLock()
	got := len(r.sessions)
	_, oldestStillThere := r.sessions["session-00000"]
	_, newestThere := r.sessions[fmt.Sprintf("session-%05d", want)]
	r.mu.RUnlock()
	if got != want {
		t.Fatalf("registry should be capped at %d after %d inserts, got %d",
			want, want+1, got)
	}
	if oldestStillThere {
		t.Fatalf("oldest session-00000 should have been evicted but is still present")
	}
	if !newestThere {
		t.Fatalf("newest session should be present after eviction")
	}
}

// TestAgentRegistry_EvictionTieBreakDeterministic pins that when two
// entries share the same LastSeen (common with low-resolution test
// wallclocks), eviction picks the lexicographically smallest key
// rather than relying on Go's randomized map iteration order.
func TestAgentRegistry_EvictionTieBreakDeterministic(t *testing.T) {
	r := NewAgentRegistry("test-agent", "test-agent-name")
	fixed := time.Date(2026, 5, 9, 22, 0, 0, 0, time.UTC)
	r.mu.Lock()
	r.sessions = make(map[string]sessionEntry, agentRegistryMaxSessions)
	for i := 0; i < agentRegistryMaxSessions; i++ {
		r.sessions[fmt.Sprintf("k-%05d", i)] = sessionEntry{
			AgentInstanceID: fmt.Sprintf("instance-%05d", i),
			LastSeen:        fixed,
		}
	}
	r.mu.Unlock()
	// Run eviction five times; each iteration must drop the
	// lexicographically smallest key. Asserting across multiple
	// iterations makes the determinism contract obvious.
	for i := 0; i < 5; i++ {
		expectedVictim := fmt.Sprintf("k-%05d", i)
		r.mu.Lock()
		r.evictOldestLocked()
		r.mu.Unlock()
		r.mu.RLock()
		_, stillThere := r.sessions[expectedVictim]
		r.mu.RUnlock()
		if stillThere {
			t.Fatalf("iteration %d: expected %s to be evicted (smallest key in tie), but it remains",
				i, expectedVictim)
		}
	}
}

// TestAgentRegistry_LRUEvictionUnderConcurrency stress-tests
// concurrent Resolve to ensure (a) the cap holds under contention and
// (b) no Resolve mints two distinct AgentInstanceIDs for the same
// sessionID under the double-checked locking path.
func TestAgentRegistry_LRUEvictionUnderConcurrency(t *testing.T) {
	r := NewAgentRegistry("test-agent", "test-agent-name")
	const N = 200
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			id1 := r.Resolve(context.Background(), fmt.Sprintf("c-%05d", i), "agent")
			id2 := r.Resolve(context.Background(), fmt.Sprintf("c-%05d", i), "agent")
			if id1 != id2 {
				t.Errorf("concurrent Resolve minted two ids for one session: %q vs %q", id1, id2)
			}
		}(i)
	}
	wg.Wait()
	r.mu.RLock()
	got := len(r.sessions)
	r.mu.RUnlock()
	if got > agentRegistryMaxSessions {
		t.Fatalf("registry exceeded cap under concurrent insert: %d > %d",
			got, agentRegistryMaxSessions)
	}
}
