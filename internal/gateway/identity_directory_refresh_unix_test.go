// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"errors"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// A slow Open Directory answer can finish after one hook's wait expires.
// The next hook must consume that answer rather than starting another slow
// lookup and refusing on every request. Calls in one short hook interval
// share one answer, so exempt and profile checks do not run serial lookups.
func TestFreshDirectoryReadUsesCompletedTimedOutLookup(t *testing.T) {
	firstRelease, secondRelease := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(secondRelease) })
	var calls atomic.Int32
	cache := newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		if calls.Add(1) == 1 {
			<-firstRelease
		} else {
			<-secondRelease
		}
		return useridentity.DirectoryFacts{Groups: []string{"current"}, ResolvedAt: time.Now()}, nil
	})
	// Keep the coalescing interval under test independent of scheduler pauses.
	cache.now = func() time.Time { return time.Unix(1_000_000, 0) }
	if _, ok := cache.getFresh("501", 5*time.Millisecond); ok {
		t.Fatal("slow lookup answered before release")
	}
	close(firstRelease)
	deadline := time.Now().Add(time.Second)
	for {
		cache.mu.Lock()
		ready := cache.entries["501"].inflight == nil
		cache.mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("completed lookup was not published")
		}
		time.Sleep(time.Millisecond)
	}
	// Simulate a busy race runner pausing after publication. The cache's
	// controlled clock still puts both reads in the same hook interval.
	time.Sleep(identityDirectoryFreshCoalesce + 10*time.Millisecond)
	for i := 0; i < 2; i++ {
		if facts, ok := cache.getFresh("501", 5*time.Millisecond); !ok || !slices.Equal(facts.Groups, []string{"current"}) {
			t.Fatalf("read %d lost the completed groups: %+v, ok=%t", i, facts, ok)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("fresh reads started %d lookups, want one", got)
	}
}

func TestFreshDirectoryReadRejectsOldTimedOutAnswer(t *testing.T) {
	firstRelease, secondRelease := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(secondRelease) })
	var calls atomic.Int32
	var clock atomic.Int64
	clock.Store(time.Unix(1_000_000, 0).UnixNano())
	cache := newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		if calls.Add(1) == 1 {
			<-firstRelease
		} else {
			<-secondRelease
		}
		return useridentity.DirectoryFacts{Groups: []string{"relaxed"}, ResolvedAt: time.Now()}, nil
	})
	cache.now = func() time.Time { return time.Unix(0, clock.Load()) }
	if _, ok := cache.getFresh("501", 5*time.Millisecond); ok {
		t.Fatal("slow lookup answered before release")
	}
	close(firstRelease)
	deadline := time.Now().Add(time.Second)
	for {
		cache.mu.Lock()
		ready := cache.entries["501"].inflight == nil
		cache.mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("completed lookup was not published")
		}
		time.Sleep(time.Millisecond)
	}
	clock.Add(int64(identityDirectoryRetry + time.Nanosecond))
	if facts, ok := cache.getFresh("501", 5*time.Millisecond); ok {
		t.Fatalf("old relaxed group selected after the next hook began: %+v", facts)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("old answer did not trigger a new lookup: calls=%d", got)
	}
}

func TestManagedMacUnassignedUPNExemptionPersistsAcrossHooks(t *testing.T) {
	previousFresh := managedHookDirectoryNeedsFresh
	previousHosted, previousFacts, previousBlocking := managedServiceHosted.Load(), identityFactsEnabled.Load(), identityLookupBlocking.Load()
	previousConfirmed, previousDirectory := managedHookPeerAccountsConfirmed, managedHookPeerDirectory
	managedHookDirectoryNeedsFresh = true
	setManagedServiceHosted(true)
	setIdentityFactsEnabled(true)
	setIdentityLookupBlocking(false)
	managedHookPeerAccountsConfirmed = func() bool { return true }
	t.Cleanup(func() {
		managedHookDirectoryNeedsFresh = previousFresh
		setManagedServiceHosted(previousHosted)
		setIdentityFactsEnabled(previousFacts)
		setIdentityLookupBlocking(previousBlocking)
		managedHookPeerAccountsConfirmed = previousConfirmed
		managedHookPeerDirectory = previousDirectory
	})
	const uid = 41965
	cache := &managedHookPeerHomeCache{newResolver: func() unixidentity.Resolver {
		return &fakePeerHomeResolver{accounts: map[int]unixidentity.Account{uid: {Name: "alice", UID: uid, Home: "/Users/alice"}}}
	}, now: time.Now}
	var clock atomic.Int64
	clock.Store(time.Unix(1_000_000, 0).UnixNano())
	cache.directoriesOnce.Do(func() {
		cache.directories = newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
			return useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory,
				Source: useridentity.SourceMacOSOpenDirectory, Assurance: useridentity.AssuranceVerified,
				Domain: "corp.example.com", AccountDomain: "CORP", Realm: "CORP.EXAMPLE.COM",
				Principal: "alice@corp.example.com", ResolvedAt: time.Now()}, nil
		})
		cache.directories.now = func() time.Time { return time.Unix(0, clock.Load()) }
	})
	managedHookPeerDirectory = cache.directory
	peer := managedHookPeer{UID: uid, Name: "alice"}
	z := newManagedHookAuthorizer(config.EnterpriseEnrollmentConfig{ExemptUsers: []string{"alice@corp.example.com"}}, nil,
		func() (managedHookLedger, error) { return managedHookLedger{}, nil })
	for i := 0; i < 3; i++ {
		decision := z.decide(peer, "claudecode", "cli")
		if !decision.Allow || !decision.Exempt {
			t.Fatalf("hook %d refused an exempt UPN: %+v", i+1, decision)
		}
		clock.Add(int64(identityDirectoryFreshCoalesce + time.Nanosecond))
	}
	other := newManagedHookAuthorizer(config.EnterpriseEnrollmentConfig{ExemptUsers: []string{"alice@other.example.com"}}, nil,
		func() (managedHookLedger, error) { return managedHookLedger{}, nil })
	if decision := other.decide(peer, "claudecode", "cli"); decision.Allow || decision.Exempt {
		t.Fatalf("unverified UPN gained an exemption: %+v", decision)
	}
}

func TestManagedMacNonblockingDirectoryReadDoesNotWait(t *testing.T) {
	previous := managedHookDirectoryNeedsFresh
	previousHosted, previousFacts := managedServiceHosted.Load(), identityFactsEnabled.Load()
	previousConfirmed := managedHookPeerAccountsConfirmed
	managedHookDirectoryNeedsFresh = true
	setManagedServiceHosted(true)
	setIdentityFactsEnabled(true)
	managedHookPeerAccountsConfirmed = func() bool { return true }
	t.Cleanup(func() {
		managedHookDirectoryNeedsFresh = previous
		setManagedServiceHosted(previousHosted)
		setIdentityFactsEnabled(previousFacts)
		managedHookPeerAccountsConfirmed = previousConfirmed
	})
	const uid = 41964
	cache := &managedHookPeerHomeCache{newResolver: func() unixidentity.Resolver {
		return &fakePeerHomeResolver{accounts: map[int]unixidentity.Account{uid: {Name: "macuser", UID: uid, Home: "/Users/macuser"}}}
	}, now: time.Now}
	release := make(chan struct{})
	releaseLookup := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseLookup)
	var clock atomic.Int64
	clock.Store(time.Unix(1_000_000, 0).UnixNano())
	cache.directoriesOnce.Do(func() {
		cache.directories = newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
			<-release
			return useridentity.DirectoryFacts{ResolvedAt: time.Now()}, nil
		})
		cache.directories.now = func() time.Time { return time.Unix(0, clock.Load()) }
	})
	started := time.Now()
	if _, ok := cache.directory(uid, false); ok {
		t.Fatal("slow telemetry lookup unexpectedly answered")
	}
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("nonblocking directory read waited %s", elapsed)
	}
	releaseLookup()
	deadline := time.Now().Add(time.Second)
	for {
		cache.directories.mu.Lock()
		ready := cache.directories.entries[strconv.Itoa(uid)].inflight == nil
		cache.directories.mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("background lookup was not published")
		}
		time.Sleep(time.Millisecond)
	}
	for i := 0; i < 3; i++ {
		clock.Add(int64(identityDirectoryFreshCoalesce + time.Nanosecond))
		if facts, ok := cache.directory(uid, false); !ok || facts.ResolvedAt.IsZero() {
			t.Fatalf("cached nonblocking read %d lost directory facts: %+v, ok=%t", i, facts, ok)
		}
	}
}

// Managed macOS hooks must not reuse a former secondary membership while
// the directory can answer with the new membership, or during an outage.
func TestManagedMacHookRefreshesSecondaryGroupsBeforeDecision(t *testing.T) {
	previous := managedHookDirectoryNeedsFresh
	previousHosted, previousFacts := managedServiceHosted.Load(), identityFactsEnabled.Load()
	previousConfirmed := managedHookPeerAccountsConfirmed
	managedHookDirectoryNeedsFresh = true
	setManagedServiceHosted(true)
	setIdentityFactsEnabled(true)
	managedHookPeerAccountsConfirmed = func() bool { return true }
	t.Cleanup(func() {
		managedHookDirectoryNeedsFresh = previous
		setManagedServiceHosted(previousHosted)
		setIdentityFactsEnabled(previousFacts)
		managedHookPeerAccountsConfirmed = previousConfirmed
	})
	const uid = 41963
	cache := &managedHookPeerHomeCache{newResolver: func() unixidentity.Resolver {
		return &fakePeerHomeResolver{accounts: map[int]unixidentity.Account{
			uid: {Name: "macuser", UID: uid, Home: "/Users/macuser"},
		}}
	}, now: time.Now}
	now := time.Now()
	var mu sync.Mutex
	groups := []string{"relaxed"}
	failed := false
	cache.directoriesOnce.Do(func() {
		cache.directories = newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
			mu.Lock()
			defer mu.Unlock()
			if failed {
				return useridentity.DirectoryFacts{}, errors.New("Open Directory unavailable")
			}
			return useridentity.DirectoryFacts{Groups: slices.Clone(groups), ResolvedAt: time.Now()}, nil
		})
		cache.directories.now = func() time.Time { return now }
	})
	read := func() (useridentity.DirectoryFacts, bool) { return cache.directory(uid, true) }
	if first, ok := read(); !ok || !slices.Contains(first.Groups, "relaxed") {
		t.Fatalf("initial groups = %v, ok=%t", first.Groups, ok)
	}
	mu.Lock()
	groups = []string{"staff"}
	mu.Unlock()
	now = now.Add(identityDirectoryFreshCoalesce + time.Nanosecond)
	if next, ok := read(); !ok || slices.Contains(next.Groups, "relaxed") {
		t.Fatalf("removed secondary group still reached the hook: %v, ok=%t", next.Groups, ok)
	}
	mu.Lock()
	failed = true
	mu.Unlock()
	now = now.Add(identityDirectoryFreshCoalesce + time.Nanosecond)
	if stale, ok := read(); ok {
		t.Fatalf("directory outage reused former groups: %v", stale.Groups)
	}
	if stale, err := cache.explainDirectory(uid); err == nil {
		t.Fatalf("explain reported stale groups that hooks refuse: %v", stale.Groups)
	}
}

// Review of GAP-0551 (loop 1): a uid handed from one domain's alice to
// another domain's alice with the same home is another account, which its
// SID tells. The facts cached for the first are looked up again for the
// second, on the hook path and in explain, as soon as the account cache
// names the new holder; an incarnation SSSD cannot name (an outage) keeps
// the facts, which are served through it.
func TestManagedHookPeerDirectoryForgetsAnotherDomainsNamesake(t *testing.T) {
	const uid = 41101
	const corp, other = "sid:S-1-5-21-1-1-1-1105", "sid:S-1-5-21-2-2-2-1105"
	for _, path := range []string{"hook", "explain"} {
		t.Run(path, func(t *testing.T) {
			previousFacts, previousIncarnation := identityFactsEnabled.Load(), managedHookPeerAccountIncarnation
			setIdentityFactsEnabled(true)
			t.Cleanup(func() {
				setIdentityFactsEnabled(previousFacts)
				managedHookPeerAccountIncarnation = previousIncarnation
			})
			var mu sync.Mutex
			incarnation, known := corp, true
			managedHookPeerAccountIncarnation = func(unixidentity.Account) (string, bool) {
				mu.Lock()
				defer mu.Unlock()
				return incarnation, known
			}
			holds := func(sid string, ok bool) {
				mu.Lock()
				incarnation, known = sid, ok
				mu.Unlock()
			}
			now := time.Unix(1_000_000, 0)
			cache := &managedHookPeerHomeCache{
				newResolver: func() unixidentity.Resolver {
					return &fakePeerHomeResolver{accounts: map[int]unixidentity.Account{uid: {Name: "alice", UID: uid, Home: "/home/alice"}}}
				},
				now: func() time.Time { return now },
			}
			var lookups atomic.Int32
			var group atomic.Value
			group.Store("corp-strict")
			cache.directoriesOnce.Do(func() {
				cache.directories = newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
					lookups.Add(1)
					return useridentity.DirectoryFacts{Groups: []string{group.Load().(string)}, ResolvedAt: time.Now()}, nil
				})
			})
			groups := func() []string {
				t.Helper()
				if path == "explain" {
					facts, err := cache.explainDirectory(uid)
					if err != nil {
						t.Fatalf("explain facts: %v", err)
					}
					return facts.Groups
				}
				facts, ok := cache.directory(uid, true)
				if !ok {
					t.Fatal("no hook facts")
				}
				return facts.Groups
			}
			next := func() { now = now.Add(managedHookPeerHomeTTL + time.Second) }
			if got := groups(); !slices.Equal(got, []string{"corp-strict"}) {
				t.Fatalf("first facts = %v", got)
			}
			next()
			if got := groups(); !slices.Equal(got, []string{"corp-strict"}) || lookups.Load() != 1 {
				t.Fatalf("same account again: facts %v after %d lookups; want the cached ones", got, lookups.Load())
			}
			holds("", false)
			next()
			if got := groups(); !slices.Equal(got, []string{"corp-strict"}) || lookups.Load() != 1 {
				t.Fatalf("SSSD not answering: facts %v after %d lookups; want the cached ones", got, lookups.Load())
			}
			group.Store("other-open")
			holds(other, true)
			next()
			if got := groups(); !slices.Equal(got, []string{"other-open"}) || lookups.Load() != 2 {
				t.Fatalf("the other domain's alice got %v after %d lookups; want its own facts", got, lookups.Load())
			}
		})
	}
}

// Review of GAP-0551 (loop 1): facts cached while the incarnation of the
// account was unknown cannot be matched to the account that holds the uid
// once it is known, so they are looked up again, once.
func TestManagedHookPeerDirectoryRechecksFactsOfAnUnknownIncarnation(t *testing.T) {
	const uid = 41102
	previousFacts, previousIncarnation := identityFactsEnabled.Load(), managedHookPeerAccountIncarnation
	setIdentityFactsEnabled(true)
	t.Cleanup(func() {
		setIdentityFactsEnabled(previousFacts)
		managedHookPeerAccountIncarnation = previousIncarnation
	})
	var known atomic.Bool
	managedHookPeerAccountIncarnation = func(unixidentity.Account) (string, bool) {
		if known.Load() {
			return "sid:S-1-5-21-2-2-2-1106", true
		}
		return "", false
	}
	now := time.Unix(2_000_000, 0)
	cache := &managedHookPeerHomeCache{
		newResolver: func() unixidentity.Resolver {
			return &fakePeerHomeResolver{accounts: map[int]unixidentity.Account{uid: {Name: "bob", UID: uid, Home: "/home/bob"}}}
		},
		now: func() time.Time { return now },
	}
	var lookups atomic.Int32
	cache.directoriesOnce.Do(func() {
		cache.directories = newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
			lookups.Add(1)
			return useridentity.DirectoryFacts{Groups: []string{"staff"}, ResolvedAt: time.Now()}, nil
		})
	})
	cache.directory(uid, true)
	known.Store(true)
	for range 2 {
		now = now.Add(managedHookPeerHomeTTL + time.Second)
		cache.directory(uid, true)
	}
	if got := lookups.Load(); got != 2 {
		t.Fatalf("%d lookups; want the facts of the unknown incarnation looked up again once", got)
	}
}

// Review of GAP-1263 (loop 1): rows keep the domains of the account their
// agent ran as. Once OTHER's alice holds the uid CORP's alice left,
// alice@OTHER (and OTHER\alice, through the resolved account's domains)
// lists OTHER's rows and the rows without a domain, not CORP's, and the
// listing retires CORP's row rather than showing it as OTHER's.
func TestAgentIdentityRowsFollowTheirAccountDomain(t *testing.T) {
	const uid = 1_870_401_263
	id := strconv.Itoa(uid)
	previous, previousFacts, previousName := managedHookPeerHomes, identityFactsEnabled.Load(), userScopedIdentityName
	managedHookPeerHomes = &managedHookPeerHomeCache{
		newResolver: func() unixidentity.Resolver {
			return &fakePeerHomeResolver{accounts: map[int]unixidentity.Account{uid: {Name: "alice", UID: uid, Home: "/home/alice"}}}
		},
		now: time.Now,
	}
	setIdentityFactsEnabled(true)
	userScopedIdentityName = func(got string) string {
		if got == id {
			return "alice"
		}
		return ""
	}
	t.Cleanup(func() {
		managedHookPeerHomes = previous
		setIdentityFactsEnabled(previousFacts)
		userScopedIdentityName = previousName
	})
	facts := useridentity.DirectoryFacts{Domain: "other.example", Realm: "OTHER.EXAMPLE", Groups: []string{"other-open"}, ResolvedAt: time.Now()}
	managedHookPeerHomes.directoriesOnce.Do(func() {
		managedHookPeerHomes.directories = newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) { return facts, nil })
	})
	if _, ok := managedHookPeerHomes.directory(uid, true); !ok {
		t.Fatal("the hook path did not cache the facts")
	}
	if got := agentIdentityAccountDomains(id); got != "other.example" {
		t.Fatalf("recorded domains = %q, want other.example", got)
	}
	row := func(agent, domains string) inventory.AgentIdentityRecord {
		return inventory.AgentIdentityRecord{AgentID: agent, UserID: id, UserName: "alice", UserDomain: domains, Connector: "codex", LastSeen: time.Now()}
	}
	pending := map[string]inventory.AgentIdentityRecord{
		"agt-corp": row("agt-corp", "corp.example corp"), "agt-other": row("agt-other", "other.example"), "agt-legacy": row("agt-legacy", ""),
	}
	for _, user := range []string{"alice@other.example", `OTHER\alice`} {
		filter := inventory.AgentIdentityFilter{User: user, UserIDs: []string{id}, UserDomains: adminViewAccountDomains([]string{id})}
		var listed []string
		for _, r := range mergeAgentIdentityRows(nil, pending, nil, filter) {
			listed = append(listed, r.AgentID)
		}
		slices.Sort(listed)
		if !slices.Equal(listed, []string{"agt-legacy", "agt-other"}) {
			t.Errorf("%s lists %v; want OTHER's row and the row without a domain", user, listed)
		}
	}
	rows := []agentIdentityRow{{AgentIdentityRecord: pending["agt-corp"]}, {AgentIdentityRecord: pending["agt-other"]}, {AgentIdentityRecord: pending["agt-legacy"]}}
	nameAgentIdentityRows(rows)
	if !rows[0].Retired || rows[1].Retired || rows[2].Retired {
		t.Fatalf("retired = %v %v %v; want only CORP's row retired", rows[0].Retired, rows[1].Retired, rows[2].Retired)
	}
}
