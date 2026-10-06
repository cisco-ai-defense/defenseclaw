// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// TestIdentityDirectoryCacheWaitsForColdLookup pins the cold-cache budget: a
// blocking caller gets facts from a lookup slower than a fast local one, as a
// cold SSSD lookup is, instead of default_lookup_failed.
func TestIdentityDirectoryCacheWaitsForColdLookup(t *testing.T) {
	cache := newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		time.Sleep(400 * time.Millisecond)
		return useridentity.DirectoryFacts{Groups: []string{"dc-ml-team@dclab.test"}, ResolvedAt: time.Now()}, nil
	})
	if facts, ok := cache.get("1201", true); !ok || len(facts.Groups) != 1 {
		t.Fatalf("cold blocking lookup = %+v, %v; want the resolved facts", facts, ok)
	}
}

// TestIdentityDirectoryCacheFirstLookupWaits pins GAP-0078: the first
// request for an account after a gateway start gets its verified facts even
// when nothing asks to block, so its first hook record is not claimed.
func TestIdentityDirectoryCacheFirstLookupWaits(t *testing.T) {
	cache := newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		time.Sleep(100 * time.Millisecond)
		return useridentity.DirectoryFacts{Principal: "dcw-std1", ResolvedAt: time.Now()}, nil
	})
	if facts, ok := cache.get("S-1-5-21-1-2-3-1017", false); !ok || facts.Principal != "dcw-std1" {
		t.Fatalf("first non-blocking lookup = %+v, %v; want the resolved facts", facts, ok)
	}
}

// TestIdentityDirectoryCacheRefreshesIncompleteFacts pins GAP-0129: facts the
// resolver marks incomplete (an AD account without its UPN) are served, then
// refreshed after the short incomplete lifetime, not the full 15 minutes.
func TestIdentityDirectoryCacheRefreshesIncompleteFacts(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	calls := 0
	cache := newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		calls++
		facts := useridentity.DirectoryFacts{Principal: "alice@DCLAB.TEST", ResolvedAt: now}
		if calls > 1 {
			facts.UPN = "alice@dclab.test"
		}
		return facts, nil
	})
	cache.now = func() time.Time { return now }
	cache.incomplete = func(facts useridentity.DirectoryFacts) bool { return facts.UPN == "" }
	if facts, ok := cache.get("S-1-5-21-1-2-3-1103", false); !ok || facts.UPN != "" {
		t.Fatalf("first facts = %+v, %v; want them without the UPN", facts, ok)
	}
	now = now.Add(identityDirectoryIncompleteTTL)
	if _, ok := cache.get("S-1-5-21-1-2-3-1103", false); !ok {
		t.Fatal("the stale incomplete facts were not served while refreshing")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if facts, _ := cache.get("S-1-5-21-1-2-3-1103", false); facts.UPN != "" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("incomplete facts were not refreshed after identityDirectoryIncompleteTTL")
}
