// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// GAP-1268: facts merged from a guardian identity record read when it was
// 59 minutes old were cached for the full TTL, so its groups and UPN applied
// until minute 74, past the record's one-hour trust. They are no longer
// served once the record they came from is untrusted: a blocking request
// waits for a lookup that no longer finds it.
func TestIdentityDirectoryCacheStopsServingFactsPastTheirRecordsTrust(t *testing.T) {
	written := time.Unix(1_800_000_000, 0)
	now := written.Add(59 * time.Minute)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	calls := 0
	cache := newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if now.Sub(written) < identitySpoolMaxAge {
			// The record is current: its groups are merged.
			return useridentity.DirectoryFacts{Groups: []string{"dc-ml-team@dclab.test"}, ResolvedAt: now}, nil
		}
		return useridentity.DirectoryFacts{ResolvedAt: now}, nil
	})
	cache.now = clock
	cache.trustedUntil = func(_ string, at time.Time) time.Time {
		if at.Sub(written) >= identitySpoolMaxAge {
			return time.Time{}
		}
		return written.Add(identitySpoolMaxAge)
	}
	if facts, ok := cache.get("94403999", true); !ok || len(facts.Groups) != 1 {
		t.Fatalf("facts at minute 59 = %+v, %v; want the record's groups", facts, ok)
	}
	mu.Lock()
	now = written.Add(61 * time.Minute) // inside the TTL, past the record's trust
	mu.Unlock()
	facts, ok := cache.get("94403999", true)
	if !ok || len(facts.Groups) != 0 {
		t.Fatalf("facts at minute 61 = %+v, %v; want a new lookup without the untrusted record's groups", facts, ok)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 2 {
		t.Fatalf("lookups = %d, want 2", calls)
	}
}

// Facts without a bound keep the TTL: no extra lookups.
func TestIdentityDirectoryCacheKeepsTheTTLWithoutARecord(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	calls := 0
	cache := newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		calls++
		return useridentity.DirectoryFacts{Principal: "alice@DCLAB.TEST", ResolvedAt: now}, nil
	})
	cache.now = func() time.Time { return now }
	cache.trustedUntil = func(string, time.Time) time.Time { return time.Time{} }
	if _, ok := cache.get("1201", true); !ok {
		t.Fatal("no facts")
	}
	now = now.Add(identityDirectoryTTL - time.Minute)
	if _, ok := cache.get("1201", true); !ok || calls != 1 {
		t.Fatalf("lookups = %d inside the TTL, want 1", calls)
	}
}
