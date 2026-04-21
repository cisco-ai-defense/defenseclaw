// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"sync"
	"testing"
)

// TestAgentRegistry_SidecarStable pins the core invariant: the
// sidecar instance id is minted once at construction and stable for
// the registry's lifetime. Everything else in the v7 observability
// contract depends on this.
func TestAgentRegistry_SidecarStable(t *testing.T) {
	r := NewAgentRegistry("agent-prod", "Prod Agent")

	first := r.SidecarInstanceID()
	if first == "" {
		t.Fatal("sidecar instance id is empty on fresh registry")
	}
	for i := 0; i < 50; i++ {
		if got := r.SidecarInstanceID(); got != first {
			t.Fatalf("sidecar instance id mutated: %q -> %q", first, got)
		}
	}
}

// TestAgentRegistry_NewSidecarIsUnique ensures two registries in
// the same process do not collide. Used in tests that simulate a
// config reload / fresh sidecar.
func TestAgentRegistry_NewSidecarIsUnique(t *testing.T) {
	a := NewAgentRegistry("", "")
	b := NewAgentRegistry("", "")
	if a.SidecarInstanceID() == b.SidecarInstanceID() {
		t.Fatalf("two registries produced the same sidecar id: %s", a.SidecarInstanceID())
	}
}

// TestAgentRegistry_SessionInstanceCached verifies that the same
// session id produces the same agent_instance_id on repeated
// lookups — this is the load-bearing contract for per-session
// aggregation in the GET /agents endpoint.
func TestAgentRegistry_SessionInstanceCached(t *testing.T) {
	r := NewAgentRegistry("agent-a", "Agent A")

	first := r.AgentInstanceForSession("session-1")
	if first == "" {
		t.Fatal("agent_instance_id empty for known session")
	}
	for i := 0; i < 10; i++ {
		if got := r.AgentInstanceForSession("session-1"); got != first {
			t.Fatalf("agent_instance_id changed on repeat lookup: %q -> %q", first, got)
		}
	}
}

// TestAgentRegistry_SessionsAreDistinct verifies that different
// sessions always get different agent_instance_ids. Otherwise
// aggregations would conflate unrelated sessions.
func TestAgentRegistry_SessionsAreDistinct(t *testing.T) {
	r := NewAgentRegistry("", "")
	a := r.AgentInstanceForSession("s1")
	b := r.AgentInstanceForSession("s2")
	if a == "" || b == "" {
		t.Fatalf("agent instance ids must be non-empty: a=%q b=%q", a, b)
	}
	if a == b {
		t.Fatalf("distinct sessions produced the same instance id: %q", a)
	}
}

// TestAgentRegistry_EmptySessionYieldsEmptyInstance exercises the
// documented contract that an empty session id surfaces as a
// missing field rather than a synthesised value.
func TestAgentRegistry_EmptySessionYieldsEmptyInstance(t *testing.T) {
	r := NewAgentRegistry("", "")
	if got := r.AgentInstanceForSession(""); got != "" {
		t.Fatalf("empty session should yield empty instance id, got %q", got)
	}
}

// TestAgentRegistry_ResolveShape pins the value object returned by
// Resolve so downstream writers can depend on the full quartet.
func TestAgentRegistry_ResolveShape(t *testing.T) {
	r := NewAgentRegistry("logical-agent", "Logical Agent")
	id := r.Resolve(context.Background(), "session-xyz", "")

	if id.AgentID != "logical-agent" {
		t.Errorf("AgentID=%q, want logical-agent", id.AgentID)
	}
	if id.AgentName != "Logical Agent" {
		t.Errorf("AgentName=%q, want Logical Agent", id.AgentName)
	}
	if id.SidecarInstanceID != r.SidecarInstanceID() {
		t.Errorf("SidecarInstanceID mismatch: resolve=%q registry=%q",
			id.SidecarInstanceID, r.SidecarInstanceID())
	}
	if id.AgentInstanceID == "" {
		t.Error("AgentInstanceID empty for non-empty session")
	}
}

// TestAgentRegistry_ResolveSessionScopedAcrossAgents pins the v7
// observability contract: agent_instance_id is session-scoped
// ("Per conversation" per docs/OBSERVABILITY-CONTRACT.md), so two
// requests in the same session MUST resolve to the same instance
// id regardless of which logical agent id they carry (header
// present vs. absent, header A vs. header B). Otherwise SIEM
// "all events in this conversation" groupings split.
func TestAgentRegistry_ResolveSessionScopedAcrossAgents(t *testing.T) {
	r := NewAgentRegistry("configured-agent", "Configured")
	ctx := context.Background()

	// Baseline: request falls back to the configured agent id.
	base := r.Resolve(ctx, "sess-42", "")
	if base.AgentInstanceID == "" {
		t.Fatal("baseline AgentInstanceID empty")
	}

	// Same session, inbound header overrides logical id. Must
	// still yield the same instance id.
	override := r.Resolve(ctx, "sess-42", "override-agent")
	if override.AgentInstanceID != base.AgentInstanceID {
		t.Errorf("same session, different agent header forked instance id: base=%q override=%q",
			base.AgentInstanceID, override.AgentInstanceID)
	}

	// Third request with a third logical id — still the same session.
	third := r.Resolve(ctx, "sess-42", "yet-another")
	if third.AgentInstanceID != base.AgentInstanceID {
		t.Errorf("third agent header forked instance id: base=%q third=%q",
			base.AgentInstanceID, third.AgentInstanceID)
	}

	// Distinct session must still mint a distinct instance id.
	other := r.Resolve(ctx, "sess-other", "override-agent")
	if other.AgentInstanceID == base.AgentInstanceID {
		t.Errorf("distinct sessions collapsed to the same instance id: %q",
			base.AgentInstanceID)
	}
}

// TestAgentRegistry_ResolveWithoutSession leaves AgentInstanceID
// blank — the "pre-session traffic" path.
func TestAgentRegistry_ResolveWithoutSession(t *testing.T) {
	r := NewAgentRegistry("", "")
	id := r.Resolve(context.Background(), "", "")
	if id.AgentInstanceID != "" {
		t.Errorf("AgentInstanceID=%q; want empty for session=\"\"", id.AgentInstanceID)
	}
	if id.SidecarInstanceID == "" {
		t.Error("SidecarInstanceID empty; want non-empty")
	}
}

// TestAgentRegistry_NilSafe guards the nil-receiver branches used by
// tests and degraded modes where the registry is not wired.
func TestAgentRegistry_NilSafe(t *testing.T) {
	var r *AgentRegistry
	if got := r.SidecarInstanceID(); got != "" {
		t.Errorf("nil.SidecarInstanceID = %q", got)
	}
	if got := r.AgentID(); got != "" {
		t.Errorf("nil.AgentID = %q", got)
	}
	if got := r.AgentName(); got != "" {
		t.Errorf("nil.AgentName = %q", got)
	}
	if got := r.AgentInstanceForSession("s"); got != "" {
		t.Errorf("nil.AgentInstanceForSession = %q", got)
	}
}

// TestAgentRegistry_ConcurrentSessions fuzzes the mutex logic so we
// do not regress on a race under parallel GET /agents traffic.
func TestAgentRegistry_ConcurrentSessions(t *testing.T) {
	r := NewAgentRegistry("", "")
	const workers = 32
	const iter = 200

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iter; i++ {
				// Reuse the same handful of session ids so every
				// worker hits the cached path after the first
				// iteration — any mutex bug will surface as
				// divergent instance ids.
				session := "session-" + string(rune('A'+id%4))
				instance := r.AgentInstanceForSession(session)
				if instance == "" {
					t.Errorf("empty instance for session %s", session)
					return
				}
				if !strings.Contains(instance, "-") {
					t.Errorf("instance id does not look like uuid: %q", instance)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	// Exactly four distinct instance ids should have been minted,
	// one per distinct session the workers used.
	seen := make(map[string]bool)
	for _, s := range []string{"session-A", "session-B", "session-C", "session-D"} {
		seen[r.AgentInstanceForSession(s)] = true
	}
	if len(seen) != 4 {
		t.Errorf("expected 4 distinct instance ids across 4 sessions, got %d", len(seen))
	}
}
