// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestVerdictCache_TTLMissHitMiss(t *testing.T) {
	var hits, misses int
	var mu sync.Mutex
	ttl := 50 * time.Millisecond
	c := NewVerdictCache(ttl,
		func(_ context.Context, _, _, _ string) {
			mu.Lock()
			hits++
			mu.Unlock()
		},
		func(_ context.Context, _, _, _ string) {
			mu.Lock()
			misses++
			mu.Unlock()
		},
	)

	ctx := context.Background()
	kind, model, dir := "injection", "gpt-test", "prompt"
	body := "xxxxxxxxxxxxxxxxxxxx malicious payload here"
	scanner := "llm-judge-injection"

	v1 := &VerdictSnapshot{Action: "allow", Severity: "NONE", Scanner: "llm-judge-injection"}
	if _, ok := c.Get(ctx, kind, model, dir, body, scanner, "none"); ok {
		t.Fatal("unexpected hit on empty cache")
	}
	c.Put(kind, model, dir, body, v1)
	if misses != 1 {
		t.Fatalf("misses=%d want 1", misses)
	}

	if got, ok := c.Get(ctx, kind, model, dir, body, scanner, "none"); !ok || got.Action != "allow" {
		t.Fatalf("second call should hit: ok=%v got=%+v", ok, got)
	}
	if hits != 1 {
		t.Fatalf("hits=%d want 1", hits)
	}

	time.Sleep(ttl + 30*time.Millisecond)

	if _, ok := c.Get(ctx, kind, model, dir, body, scanner, "none"); ok {
		t.Fatal("expected miss after TTL")
	}
	if misses != 2 {
		t.Fatalf("misses=%d want 2 after expiry", misses)
	}
}
