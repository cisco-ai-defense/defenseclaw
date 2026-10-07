// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
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

// TestIdentityDirectoryCacheLogsFailureAndRecoveryOnce pins GAP-0124: an
// account whose lookup cannot finish (in more groups than are named, a
// directory that never answers) leaves one line with the reason in the
// gateway log, not one per retry, and one when it works again.
func TestIdentityDirectoryCacheLogsFailureAndRecoveryOnce(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	fail := true
	cache := newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		if fail {
			return useridentity.DirectoryFacts{}, errors.New("in 3000 groups, more than the 2048 DefenseClaw names")
		}
		return useridentity.DirectoryFacts{Principal: "dcad-manygroups@DCLAB.TEST", ResolvedAt: now}, nil
	})
	var mu sync.Mutex
	var lines []string
	cache.logf = func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, fmt.Sprintf(format, args...))
	}
	cache.now = func() time.Time { return now }
	for range 3 {
		if _, ok := cache.get("94401116", true); ok {
			t.Fatal("a failing lookup answered")
		}
		now = now.Add(identityDirectoryRetry)
	}
	fail = false
	if _, ok := cache.get("94401116", true); !ok {
		t.Fatal("the lookup did not recover")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(lines) != 2 || !strings.Contains(lines[0], "94401116 failed: in 3000 groups") ||
		!strings.Contains(lines[1], "works again after 45s") {
		t.Fatalf("log lines = %q, want one failure with its reason and one recovery", lines)
	}
}

// TestIdentityDirectoryCacheDropsFactsItCannotRefresh pins GAP-0145: facts
// whose refresh keeps failing are served for the stale-while-revalidate
// window and then dropped, so a removed user does not keep a group profile
// for the whole outage; health reports the failing account meanwhile.
func TestIdentityDirectoryCacheDropsFactsItCannotRefresh(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	var clock atomic.Int64
	clock.Store(start.UnixNano())
	advance := func(d time.Duration) { clock.Add(int64(d)) }
	var down atomic.Bool
	cache := newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		if down.Load() {
			return useridentity.DirectoryFacts{}, errors.New("sssd offline")
		}
		return useridentity.DirectoryFacts{Groups: []string{"dc-ml-team@dclab.test"}, ResolvedAt: time.Unix(0, clock.Load())}, nil
	})
	cache.now = func() time.Time { return time.Unix(0, clock.Load()) }
	cache.logf = func(string, ...any) {}
	settled := func(wantFailing int) {
		t.Helper()
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
			if cache.health().Failing == wantFailing {
				return
			}
		}
		t.Fatalf("health = %+v, want %d failing", cache.health(), wantFailing)
	}
	if _, ok := cache.get("1201", true); !ok {
		t.Fatal("no facts while the directory is up")
	}
	down.Store(true)
	advance(identityDirectoryTTL + time.Second)
	if _, ok := cache.get("1201", false); !ok {
		t.Fatal("the stale facts were not served while the refresh runs")
	}
	settled(1)
	if h := cache.health(); h.Stale != 1 || h.LastError != "sssd offline" || h.OldestAge < identityDirectoryTTL {
		t.Fatalf("health = %+v, want one failing account served stale facts", h)
	}
	advance(identityDirectoryMaxAge)
	// Block until the refresh this call starts has failed: a failure recorded
	// after the advance below would set the retry gate past the next get.
	if _, ok := cache.get("1201", true); ok {
		t.Fatal("facts older than identityDirectoryMaxAge were still served")
	}
	down.Store(false)
	advance(identityDirectoryRetry)
	if _, ok := cache.get("1201", true); !ok {
		t.Fatal("the account did not recover when the directory came back")
	}
	settled(0)
}

// TestDirectoryHealthViewNamesTheFailingLookups: doctor, status and explain
// get one message with the count, the first failure and the reason.
func TestDirectoryHealthViewNamesTheFailingLookups(t *testing.T) {
	if view, message := directoryHealthView(identityCacheHealth{}, time.Now()); view != nil || message != "" {
		t.Fatalf("a healthy directory produced %v %q", view, message)
	}
	since := time.Date(2026, 10, 6, 21, 4, 8, 0, time.UTC)
	view, message := directoryHealthView(identityCacheHealth{Failing: 3, Since: since, LastError: "getent timed out", Stale: 2, OldestAge: 25 * time.Minute}, since)
	for _, want := range []string{"failing for 3 account(s) since 21:04:08Z", "getent timed out", "default_lookup_failed", "2 account(s) are served facts up to 25m0s old"} {
		if !strings.Contains(message, want) {
			t.Errorf("message %q lacks %q", message, want)
		}
	}
	if view["failing"] != 3 || view["max_age_seconds"] != 3600 || view["message"] != message {
		t.Errorf("view = %v", view)
	}
}
