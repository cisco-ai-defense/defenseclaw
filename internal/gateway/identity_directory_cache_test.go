// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
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

// TestIdentityDirectoryCacheRefreshesPartialGroupsSoon pins GAP-0243: groups
// the enumerator took from an account's last session token (it had no active
// session) stay marked partial through the spool merge and are refreshed after
// identityDirectoryRetry, so a sign-in that brings an Entra group shows within
// about one enumerator cycle, not after the 15 minute lifetime.
func TestIdentityDirectoryCacheRefreshesPartialGroupsSoon(t *testing.T) {
	merged := mergeSpoolFacts(useridentity.DirectoryFacts{}, enterprisehooks.IdentitySpoolRecord{Facts: useridentity.DirectoryFacts{Groups: []string{"S-1-1-0"}, GroupsPartial: true}})
	if !merged.GroupsPartial {
		t.Fatalf("merged facts = %+v; the spool groups lost their partial mark", merged)
	}
	now := time.Unix(1_800_000_000, 0)
	calls := 0
	cache := newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		calls++
		return useridentity.DirectoryFacts{Groups: []string{"S-1-1-0"}, GroupsPartial: calls == 1, ResolvedAt: now}, nil
	})
	cache.now = func() time.Time { return now }
	cache.partial = func(facts useridentity.DirectoryFacts) bool { return facts.GroupsPartial }
	if facts, ok := cache.get("S-1-12-1-1-2-3-4", false); !ok || !facts.GroupsPartial {
		t.Fatalf("first facts = %+v, %v; want the partial groups", facts, ok)
	}
	now = now.Add(identityDirectoryRetry)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if facts, _ := cache.get("S-1-12-1-1-2-3-4", false); !facts.GroupsPartial {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("partial groups were not refreshed after identityDirectoryRetry")
}

// TestIdentityDirectoryCacheBlockingRequestWaitsForIncompleteRefresh pins
// GAP-0326: once incomplete facts (a group no name answered for, as a
// directory outage leaves) pass their short lifetime, a blocking request
// waits for the refresh instead of using them once more, and explain's
// refresh time follows the short lifetime.
func TestIdentityDirectoryCacheBlockingRequestWaitsForIncompleteRefresh(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	calls := 0
	cache := newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		calls++
		if calls == 1 {
			return useridentity.DirectoryFacts{Groups: []string{"940190439"}, ResolvedAt: now}, nil
		}
		return useridentity.DirectoryFacts{Groups: []string{"entra-alice", "dc-entra-ml"}, ResolvedAt: now}, nil
	})
	cache.now = func() time.Time { return now }
	cache.incomplete = func(facts useridentity.DirectoryFacts) bool { return len(facts.Groups) == 1 }
	facts, ok := cache.get("1608906209", true)
	if !ok || cache.lifetime(facts) != identityDirectoryIncompleteTTL {
		t.Fatalf("first facts = %+v, %v; want unnamed facts with the short lifetime", facts, ok)
	}
	now = now.Add(identityDirectoryIncompleteTTL)
	if facts, ok := cache.get("1608906209", true); !ok || len(facts.Groups) != 2 || cache.lifetime(facts) != identityDirectoryTTL {
		t.Fatalf("blocking request after the short lifetime got %+v, %v; want the refreshed groups", facts, ok)
	}
}

// GAP-1036: a pushed assignment for a group the user had just joined
// applied only when the facts cached before the push expired, up to
// 15 minutes later. After invalidate a blocking request gets fresh facts.
func TestIdentityDirectoryCacheBlockingRequestRefreshesAfterInvalidate(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	calls := 0
	cache := newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		calls++
		if calls == 1 {
			return useridentity.DirectoryFacts{Groups: []string{"staff"}, ResolvedAt: now}, nil
		}
		return useridentity.DirectoryFacts{Groups: []string{"staff", "upc-eng"}, ResolvedAt: now}, nil
	})
	cache.now = func() time.Time { return now }
	if facts, ok := cache.get("1001", true); !ok || len(facts.Groups) != 1 {
		t.Fatalf("first facts = %+v, %v", facts, ok)
	}
	now = now.Add(time.Minute)
	cache.invalidate()
	if facts, ok := cache.get("1001", true); !ok || len(facts.Groups) != 2 {
		t.Fatalf("blocking request after invalidate got %+v, %v; want the refreshed groups", facts, ok)
	}
}

// Expired partial groups must be refreshed before a blocking profile lookup.
func TestIdentityDirectoryCacheBlockingRequestRefreshesPartialGroups(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	calls := 0
	cache := newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		calls++
		if calls == 1 {
			return useridentity.DirectoryFacts{Groups: []string{"lenient"}, GroupsPartial: true, ResolvedAt: now}, nil
		}
		return useridentity.DirectoryFacts{Groups: []string{"strict"}, ResolvedAt: now}, nil
	})
	cache.now = func() time.Time { return now }
	cache.partial = func(facts useridentity.DirectoryFacts) bool { return facts.GroupsPartial }
	if facts, ok := cache.get("S-1-5-21-1-2-3-1103", true); !ok || !facts.GroupsPartial {
		t.Fatalf("initial partial groups = %+v, %v", facts, ok)
	}
	now = now.Add(identityDirectoryRetry)
	if facts, ok := cache.get("S-1-5-21-1-2-3-1103", true); !ok || facts.GroupsPartial || len(facts.Groups) != 1 || facts.Groups[0] != "strict" {
		t.Fatalf("blocking lookup used stale group: %+v, %v", facts, ok)
	}
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

// GAP-0696: a deleted account that keeps sending hook calls is reported as a
// failing lookup, by uid, only until the directory answers for another
// account: then its "no such account" is an answer, not a failure.
func TestIdentityDirectoryCacheDropsAGoneAccountOnceTheDirectoryAnswers(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	gone := errors.New("no such account")
	cache := newIdentityCache(func(key string) (useridentity.DirectoryFacts, error) {
		if key == "1001" {
			return useridentity.DirectoryFacts{}, gone
		}
		return useridentity.DirectoryFacts{ResolvedAt: now}, nil
	})
	cache.gone = func(err error) bool { return errors.Is(err, gone) }
	cache.confirmGone = true
	cache.now = func() time.Time { return now }
	cache.get("1001", true)
	if h := cache.health(); h.Failing != 1 || len(h.Accounts) != 1 || h.Accounts[0] != "1001" {
		t.Fatalf("before the directory answers: %+v, want uid 1001 failing", h)
	}
	now = now.Add(time.Second)
	cache.get("1002", true)
	if h := cache.health(); h.Failing != 0 {
		t.Fatalf("after the directory answered for another account: %+v, want nothing failing", h)
	}
}

// A successful local NSS lookup does not prove that a missed AD account is gone.
func TestIdentityDirectoryCacheLocalAnswerDoesNotClearDirectoryFailure(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	gone := errors.New("NSS account not found")
	cache := newIdentityCache(func(key string) (useridentity.DirectoryFacts, error) {
		if key == "ad-uid" {
			return useridentity.DirectoryFacts{}, gone
		}
		return useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal, ResolvedAt: now}, nil
	})
	cache.gone = func(err error) bool { return errors.Is(err, gone) }
	cache.now = func() time.Time { return now }
	cache.get("ad-uid", true)
	now = now.Add(time.Second)
	cache.get("local-uid", true)
	if h := cache.health(); h.Failing != 1 || len(h.Accounts) != 1 || h.Accounts[0] != "ad-uid" {
		t.Fatalf("local answer hid AD lookup failure: %+v", h)
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

func TestIdentitySpoolRecordRequiresCurrentAccountName(t *testing.T) {
	dir := t.TempDir()
	key := "15001"
	data, err := enterprisehooks.MarshalIdentitySpoolRecord(enterprisehooks.IdentitySpoolRecord{
		Key: key, User: "alice@corp.example.com", UpdatedAt: time.Now().UTC(),
		Facts: useridentity.DirectoryFacts{UPN: "alice@corp.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, key+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	oldValidate := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization = oldValidate; setIdentitySpoolDir("") })
	setIdentitySpoolDir(dir)
	if _, ok := readIdentitySpoolFactsForAccount(key, "bob@corp.example.com", time.Now()); ok {
		t.Fatal("spool facts crossed uid reuse")
	}
	if _, ok := readIdentitySpoolFactsForAccount(key, "ALICE@CORP.EXAMPLE.COM", time.Now()); !ok {
		t.Fatal("case-only account variation was rejected")
	}
}

// TestIdentitySpoolRejectsFutureRecord pins clock rollback handling: a record
// dated after the gateway's clock cannot keep old group assignments alive.
func TestIdentitySpoolRejectsFutureRecord(t *testing.T) {
	dir := t.TempDir()
	key := "15002"
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	data, err := enterprisehooks.MarshalIdentitySpoolRecord(enterprisehooks.IdentitySpoolRecord{
		Key: key, User: "alice", UpdatedAt: now.Add(time.Hour),
		Facts: useridentity.DirectoryFacts{Groups: []string{"old-group"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, key+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	oldValidate := validateManagedGuardianAuthorization
	previousDir := currentIdentitySpoolDir()
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	setIdentitySpoolDir(dir)
	t.Cleanup(func() {
		validateManagedGuardianAuthorization = oldValidate
		setIdentitySpoolDir(previousDir)
	})
	if _, ok := readIdentitySpoolFacts(key, now); ok {
		t.Fatal("future-dated spool record was trusted")
	}
	if _, ok := readIdentitySpoolFacts(key, now.Add(time.Hour)); !ok {
		t.Fatal("current spool record was rejected")
	}
}

// TestSpoolRecordInAnotherSSSDDomainClearsOwnRealm pins the managed half of
// GAP-0605: when the guardian's InfoPipe lookup by uid holds the account in
// another SSSD domain than the realm the gateway's own facts give it, the
// gateway's domain, realm, principal and directory type go, even where the
// record has none; its groups stay. A record of the same domain keeps them.
func TestSpoolRecordInAnotherSSSDDomainClearsOwnRealm(t *testing.T) {
	own := useridentity.DirectoryFacts{Source: useridentity.SourceSSSD, Domain: "dclab.test", Realm: "DCLAB.TEST",
		Principal: "dcad-bob@dclab.test", Directory: useridentity.DirectoryActiveDirectory, Groups: []string{"mail-devs"}}
	merged := mergeSpoolFacts(own, enterprisehooks.IdentitySpoolRecord{SSSDDomain: "ldapmail",
		Facts: useridentity.DirectoryFacts{Source: useridentity.SourceSSSD, Directory: useridentity.DirectoryLDAP}})
	if merged.Domain != "" || merged.Realm != "" || merged.Principal != "" || merged.Directory != useridentity.DirectoryLDAP ||
		len(merged.Groups) != 1 {
		t.Errorf("merged = %+v; want no domain, realm or principal, directory ldap and the own groups", merged)
	}
	merged = mergeSpoolFacts(own, enterprisehooks.IdentitySpoolRecord{SSSDDomain: "dclab.test",
		Facts: useridentity.DirectoryFacts{Source: useridentity.SourceSSSD, Domain: "dclab.test", Realm: "DCLAB.TEST",
			Principal: "dcad-bob@dclab.test", Directory: useridentity.DirectoryActiveDirectory}})
	if merged.Realm != "DCLAB.TEST" || merged.Principal != "dcad-bob@dclab.test" || merged.Domain != "dclab.test" {
		t.Errorf("merged = %+v; want the realm and principal of the same domain", merged)
	}
}

// GAP-1027: when the guardian's identity record lists a new group set (a
// user signed out and in again), the cached facts are dropped at the next
// request instead of serving the old groups for the rest of the TTL.
func TestSpoolGroupChangeDropsCachedFacts(t *testing.T) {
	dir := t.TempDir()
	key := "S-1-5-21-1-2-3-1105"
	write := func(groups ...string) {
		t.Helper()
		data, err := enterprisehooks.MarshalIdentitySpoolRecord(enterprisehooks.IdentitySpoolRecord{
			Key: key, User: `DCLAB\dcad-w3w2`, UpdatedAt: time.Now().UTC(), Facts: useridentity.DirectoryFacts{Groups: groups},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, key+".json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	oldValidate, previousDir := validateManagedGuardianAuthorization, currentIdentitySpoolDir()
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	setIdentitySpoolDir(dir)
	t.Cleanup(func() { validateManagedGuardianAuthorization = oldValidate; setIdentitySpoolDir(previousDir) })
	write(`DCLAB\Domain Users`)
	cache := newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		record, _ := readIdentitySpoolFacts(key, time.Now())
		return record.Facts, nil
	})
	if facts, ok := cache.get(key, true); !ok || len(facts.Groups) != 1 {
		t.Fatalf("first lookup = %+v, %v", facts, ok)
	}
	write(`DCLAB\Domain Users`, `DCLAB\dc-w3w-pilot`)
	forgetOnSpoolGroupChange(cache, key, time.Now().Add(time.Minute))
	if facts, ok := cache.get(key, true); !ok || len(facts.Groups) != 2 {
		t.Fatalf("after a new sign-in the cache served %+v, %v; want the new group set", facts, ok)
	}
}
