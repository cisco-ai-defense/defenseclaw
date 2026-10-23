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
	previousConfirmed, previousHomes := managedHookPeerAccountsConfirmed, managedHookPeerHomes
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
		managedHookPeerHomes = previousHomes
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
	managedHookPeerHomes = cache
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

// Review of r104 Q-identity (loop rounds 1 and 2): when the wait of a fresh
// read expires as its lookup completes, the outcome is read under the cache
// lock. The losing order is set here without the scheduler: the reader's wait
// has expired and the completion has already published its outcome when the
// reader takes the lock (freshAfterWait with timedOut). The reader used to
// mark the answer it had missed as pending after the completion had counted
// it as served, so the next hook started another slow lookup. The reader
// returns the completed answer, and a failure that completes at the boundary
// leaves nothing pending. An earlier version of this test ordered the two by
// sleeping while holding the cache lock, which no scheduler guarantees.
func TestFreshDirectoryReadKeepsAnswerCompletedAtTimeout(t *testing.T) {
	for _, tc := range []struct {
		name string
		fail bool
	}{{"answer", false}, {"failure", true}} {
		t.Run(tc.name, func(t *testing.T) {
			release := make(chan struct{})
			var calls atomic.Int32
			cache := newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
				if calls.Add(1) == 1 {
					<-release
				}
				if tc.fail {
					return useridentity.DirectoryFacts{}, errors.New("Open Directory unavailable")
				}
				return useridentity.DirectoryFacts{Groups: []string{"current"}, ResolvedAt: time.Now()}, nil
			})
			var clock atomic.Int64
			clock.Store(time.Unix(1_000_000, 0).UnixNano())
			cache.now = func() time.Time { return time.Unix(0, clock.Load()) }
			// The fresh read's lookup, started as getFresh starts it.
			cache.mu.Lock()
			entry := &identityCacheEntry[useridentity.DirectoryFacts]{}
			cache.entries["501"] = entry
			before := entry.generation
			cache.refreshLocked("501", entry)
			done := entry.inflight
			cache.mu.Unlock()
			// The completion publishes its outcome and releases the lock
			// before done closes; only then does the timed-out reader read.
			close(release)
			<-done
			facts, ok := cache.freshAfterWait("501", entry, done, before, true)
			cache.mu.Lock()
			pending := entry.pendingFresh
			cache.mu.Unlock()
			if tc.fail {
				if ok || pending {
					t.Fatalf("failed lookup at the boundary: ok=%t pending=%t; want no facts and nothing pending", ok, pending)
				}
				return
			}
			if !ok || !slices.Equal(facts.Groups, []string{"current"}) || pending {
				t.Fatalf("answer completed at the timeout was lost: %+v ok=%t pending=%t", facts, ok, pending)
			}
			// A later hook still asks the directory again.
			clock.Add(int64(identityDirectoryFreshCoalesce + time.Nanosecond))
			if _, ok := cache.getFresh("501", time.Second); !ok || calls.Load() != 2 {
				t.Fatalf("next hook: ok=%t after %d lookups; want a new lookup", ok, calls.Load())
			}
		})
	}
}

// A wait that expires while the lookup still runs marks its answer for the
// next hook, which uses it once without another lookup.
func TestFreshDirectoryReadMarksLookupStillRunningAtTimeout(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	cache := newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		calls.Add(1)
		<-release
		return useridentity.DirectoryFacts{Groups: []string{"current"}, ResolvedAt: time.Now()}, nil
	})
	var clock atomic.Int64
	clock.Store(time.Unix(1_000_000, 0).UnixNano())
	cache.now = func() time.Time { return time.Unix(0, clock.Load()) }
	cache.mu.Lock()
	entry := &identityCacheEntry[useridentity.DirectoryFacts]{}
	cache.entries["501"] = entry
	before := entry.generation
	cache.refreshLocked("501", entry)
	done := entry.inflight
	cache.mu.Unlock()
	if _, ok := cache.freshAfterWait("501", entry, done, before, true); ok {
		t.Fatal("a lookup still running answered")
	}
	cache.mu.Lock()
	pending := entry.pendingFresh
	cache.mu.Unlock()
	if !pending {
		t.Fatal("a lookup still running at the timeout was not marked for the next hook")
	}
	close(release)
	<-done
	clock.Add(int64(identityDirectoryFreshCoalesce + time.Nanosecond))
	if facts, ok := cache.getFresh("501", time.Second); !ok || !slices.Equal(facts.Groups, []string{"current"}) || calls.Load() != 1 {
		t.Fatalf("next hook: %+v ok=%t after %d lookups; want the late answer without another lookup", facts, ok, calls.Load())
	}
}

// managedMacExemptFixture makes the hook path a managed Mac's: uid is alice's
// account and its directory facts come from resolve, cached with the
// predicates the gateway's own cache uses.
func managedMacExemptFixture(t *testing.T, uid int, resolve func() (useridentity.DirectoryFacts, error)) (*managedHookPeerHomeCache, *atomic.Int64) {
	t.Helper()
	previousFresh := managedHookDirectoryNeedsFresh
	previousHosted, previousFacts := managedServiceHosted.Load(), identityFactsEnabled.Load()
	previousConfirmed, previousHomes := managedHookPeerAccountsConfirmed, managedHookPeerHomes
	managedHookDirectoryNeedsFresh = true
	setManagedServiceHosted(true)
	setIdentityFactsEnabled(true)
	managedHookPeerAccountsConfirmed = func() bool { return true }
	cache := &managedHookPeerHomeCache{newResolver: func() unixidentity.Resolver {
		return &fakePeerHomeResolver{accounts: map[int]unixidentity.Account{uid: {Name: "alice", UID: uid, Home: "/Users/alice"}}}
	}, now: time.Now}
	clock := new(atomic.Int64)
	clock.Store(time.Unix(1_000_000, 0).UnixNano())
	cache.directoriesOnce.Do(func() {
		cache.directories = newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) { return resolve() })
		cache.directories.now = func() time.Time { return time.Unix(0, clock.Load()) }
		cache.directories.incomplete = func(facts useridentity.DirectoryFacts) bool {
			return hasUnnamedGroup(facts) || awaitingSpoolUPN(facts) || facts.OnlyPrimaryGroup
		}
		cache.directories.settling = openDirectorySettling
	})
	managedHookPeerHomes = cache
	t.Cleanup(func() {
		managedHookDirectoryNeedsFresh = previousFresh
		setManagedServiceHosted(previousHosted)
		setIdentityFactsEnabled(previousFacts)
		managedHookPeerAccountsConfirmed = previousConfirmed
		managedHookPeerHomes = previousHomes
	})
	return cache, clock
}

func managedMacAliceFacts() useridentity.DirectoryFacts {
	return useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory,
		Source: useridentity.SourceMacOSOpenDirectory, Assurance: useridentity.AssuranceVerified,
		Domain: "corp.example.com", AccountDomain: "CORP", Realm: "CORP.EXAMPLE.COM",
		Principal: "alice@corp.example.com", UPN: "alice@corp.example.com",
		Groups: []string{"staff", "dc-devs"}, ResolvedAt: time.Now()}
}

func waitDirectoryPublished(t *testing.T, cache *managedHookPeerHomeCache, uid int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		cache.directories.mu.Lock()
		entry := cache.directories.entries[strconv.Itoa(uid)]
		ready := entry != nil && entry.inflight == nil
		cache.directories.mu.Unlock()
		if ready {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("directory lookup was not published")
		}
		time.Sleep(time.Millisecond)
	}
}

// Review of r104 Q-identity (loop round 1): with UPN or DOMAIN\user
// exempt_users entries, a managed Mac waited for a fresh Open Directory
// answer on every hook of every enrolled caller the entries did not name by
// uid or exact name, up to 2 s a hook. Settled cached facts of the account
// that holds the uid now reject a caller they do not name without a lookup.
func TestManagedMacExemptNonmatchUsesCachedNames(t *testing.T) {
	const uid = 41966
	var lookups atomic.Int32
	release := make(chan struct{})
	releaseLookup := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseLookup)
	cache, clock := managedMacExemptFixture(t, uid, func() (useridentity.DirectoryFacts, error) {
		if lookups.Add(1) > 1 {
			<-release // the directory has become slow
		}
		return managedMacAliceFacts(), nil
	})
	if _, ok := cache.directory(uid, true); !ok {
		t.Fatal("first lookup returned no facts")
	}
	peerUID := uid
	ledger := managedHookLedger{Targets: []managedHookLedgerTarget{{UID: &peerUID, Connector: "codex", OK: true}}}
	peer := managedHookPeer{UID: uid, Name: "alice"}
	for _, exempt := range [][]string{
		{"carol@corp.example.com"}, {`CORP\carol`}, {`OTHER\alice`}, {"alice@other.example.com", "CORP\\bob"},
	} {
		z := newManagedHookAuthorizer(config.EnterpriseEnrollmentConfig{ExemptUsers: exempt}, nil,
			func() (managedHookLedger, error) { return ledger, nil })
		for hook := 1; hook <= 3; hook++ {
			clock.Add(int64(identityDirectoryFreshCoalesce + time.Nanosecond))
			started := time.Now()
			decision := z.decide(peer, "codex", "cli")
			if elapsed := time.Since(started); elapsed > 300*time.Millisecond {
				t.Fatalf("exempt_users %v, hook %d: enrolled caller waited %s for the directory", exempt, hook, elapsed)
			}
			if !decision.Allow || decision.Exempt {
				t.Fatalf("exempt_users %v, hook %d: %+v; want an enrolled, not exempt, allow", exempt, hook, decision)
			}
		}
	}
	if got := lookups.Load(); got != 1 {
		t.Fatalf("nonmatching callers started %d directory lookups; want only the first", got)
	}
}

// Review of r104 Q-identity (loop round 2): a healthy Open Directory that
// answers in about a second (0.9-1.5 s on a busy Mac) must not cost a UPN or
// DOMAIN\name exemption. The first hook after a start waits for the cold
// answer within identityDirectoryBudget, as before 1.0.4; later hooks use the
// cached names without another lookup, also after the facts expire, when one
// background refresh replaces them while hooks keep the exemption. A 750 ms
// fresh read on every hook denied each of these hooks or every other one.
func TestManagedMacExemptSurvivesSlowHealthyDirectory(t *testing.T) {
	const slowAnswer = 1100 * time.Millisecond // past the old 750 ms wait, inside the budget
	for i, entry := range []string{"alice@corp.example.com", `CORP\alice`} {
		t.Run(entry, func(t *testing.T) {
			uid := 41970 + i
			var lookups atomic.Int32
			refresh := make(chan struct{})
			releaseRefresh := sync.OnceFunc(func() { close(refresh) })
			t.Cleanup(releaseRefresh)
			_, clock := managedMacExemptFixture(t, uid, func() (useridentity.DirectoryFacts, error) {
				if lookups.Add(1) == 1 {
					time.Sleep(slowAnswer)
				} else {
					<-refresh // the background refresh is slower still
				}
				return managedMacAliceFacts(), nil
			})
			z := newManagedHookAuthorizer(config.EnterpriseEnrollmentConfig{ExemptUsers: []string{entry}}, nil,
				func() (managedHookLedger, error) { return managedHookLedger{}, nil })
			peer := managedHookPeer{UID: uid, Name: "alice"}
			if decision := z.decide(peer, "codex", "cli"); !decision.Allow || !decision.Exempt {
				t.Fatalf("hook 1: a healthy directory answering in %s denied the exemption: %+v", slowAnswer, decision)
			}
			for hook := 2; hook <= 6; hook++ {
				clock.Add(int64(identityDirectoryFreshCoalesce + time.Second))
				if decision := z.decide(peer, "codex", "cli"); !decision.Allow || !decision.Exempt {
					t.Fatalf("hook %d: cached names lost the exemption: %+v", hook, decision)
				}
			}
			if got := lookups.Load(); got != 1 {
				t.Fatalf("hooks 2-6 started %d more directory lookups; want none", got-1)
			}
			// Past the facts' lifetime the refresh runs in the background
			// (it never answers here), and the hooks do not wait for it.
			clock.Add(int64(identityDirectoryTTL))
			for hook := 7; hook <= 8; hook++ {
				if decision := z.decide(peer, "codex", "cli"); !decision.Allow || !decision.Exempt {
					t.Fatalf("hook %d: expired cached names lost the exemption during a refresh: %+v", hook, decision)
				}
			}
			deadline := time.Now().Add(2 * time.Second)
			for lookups.Load() < 2 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if got := lookups.Load(); got != 2 {
				t.Fatalf("expired facts started %d lookups in all; want one background refresh after the first", got)
			}
		})
	}
}

// A cold answer slower than identityDirectoryBudget costs that hook its
// exemption (enrollment then decides; here it refuses) within the budget,
// never the call's deadline, and nothing is exempted without verified facts.
// The late answer serves the next hook without another lookup.
func TestManagedMacExemptColdLookupBoundedByBudget(t *testing.T) {
	const uid = 41967
	var lookups atomic.Int32
	release := make(chan struct{})
	releaseLookup := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseLookup)
	cache, clock := managedMacExemptFixture(t, uid, func() (useridentity.DirectoryFacts, error) {
		lookups.Add(1)
		<-release
		return managedMacAliceFacts(), nil
	})
	peer := managedHookPeer{UID: uid, Name: "alice"}
	z := newManagedHookAuthorizer(config.EnterpriseEnrollmentConfig{ExemptUsers: []string{"alice@corp.example.com"}}, nil,
		func() (managedHookLedger, error) { return managedHookLedger{}, nil })
	started := time.Now()
	decision := z.decide(peer, "codex", "cli")
	if elapsed := time.Since(started); elapsed > identityDirectoryBudget+time.Second {
		t.Fatalf("an unanswered directory held the hook %s; want at most about %s", elapsed, identityDirectoryBudget)
	}
	if decision.Allow || decision.Exempt {
		t.Fatalf("exemption without verified facts: %+v", decision)
	}
	releaseLookup()
	waitDirectoryPublished(t, cache, uid)
	clock.Add(int64(identityDirectoryFreshCoalesce + time.Second))
	if decision := z.decide(peer, "codex", "cli"); !decision.Allow || !decision.Exempt {
		t.Fatalf("next hook lost the late answer: %+v", decision)
	}
	if got := lookups.Load(); got != 1 {
		t.Fatalf("next hook started another lookup instead of using the late answer: %d lookups", got)
	}
}

// An unsettled cached answer (only the primary group so far) binds no name it
// lacks: without the UPN it does not reject a UPN exemption, and the current
// answer decides, also when that answer takes about a second. An unsettled
// answer that already gives the UPN exempts without waiting for the
// directory: a name it gives is verified for the account holding the uid.
func TestManagedMacExemptUnsettledCacheWaitsForNames(t *testing.T) {
	primaryOnly := func(withUPN bool) useridentity.DirectoryFacts {
		facts := useridentity.DirectoryFacts{Source: useridentity.SourceMacOSOpenDirectory,
			Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now()}
		if withUPN {
			facts = managedMacAliceFacts()
		}
		facts.Groups, facts.OnlyPrimaryGroup = []string{"staff"}, true
		return facts
	}
	for i, tc := range []struct {
		name        string
		cachedUPN   bool
		answerAfter time.Duration // < 0: the current lookup never answers
		wantLookups int32
	}{
		{"current answer gives the UPN", false, 0, 2},
		{"slow current answer gives the UPN", false, 1100 * time.Millisecond, 2},
		{"cached answer gives the UPN", true, -1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uid := 41975 + i
			var lookups atomic.Int32
			never := make(chan struct{})
			releaseNever := sync.OnceFunc(func() { close(never) })
			t.Cleanup(releaseNever)
			cache, clock := managedMacExemptFixture(t, uid, func() (useridentity.DirectoryFacts, error) {
				if lookups.Add(1) == 1 {
					return primaryOnly(tc.cachedUPN), nil
				}
				if tc.answerAfter < 0 {
					<-never
				} else {
					time.Sleep(tc.answerAfter)
				}
				return managedMacAliceFacts(), nil
			})
			if _, ok := cache.directory(uid, true); !ok {
				t.Fatal("first lookup returned no facts")
			}
			clock.Add(int64(identityDirectoryFreshCoalesce + time.Nanosecond))
			z := newManagedHookAuthorizer(config.EnterpriseEnrollmentConfig{ExemptUsers: []string{"alice@corp.example.com"}}, nil,
				func() (managedHookLedger, error) { return managedHookLedger{}, nil })
			if decision := z.decide(managedHookPeer{UID: uid, Name: "alice"}, "codex", "cli"); !decision.Allow || !decision.Exempt {
				t.Fatalf("unsettled cached answer: UPN exemption refused: %+v", decision)
			}
			if got := lookups.Load(); got != tc.wantLookups {
				t.Fatalf("%d directory lookups; want %d", got, tc.wantLookups)
			}
		})
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
