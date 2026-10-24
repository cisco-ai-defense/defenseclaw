// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// listedAccounts is a local account list the fake source digests.
type listedAccounts struct {
	mu       sync.Mutex
	accounts map[string]unixidentity.LocalAccountRecord
	calls    int
	fail     bool
	gate     chan struct{} // when set, a listing waits on it
}

// byUID lists accounts by name and uid, each with a record of its own.
func byUID(uids map[string]int) map[string]unixidentity.LocalAccountRecord {
	records := make(map[string]unixidentity.LocalAccountRecord, len(uids))
	for name, uid := range uids {
		records[name] = unixidentity.LocalAccountRecord{UID: uid, RecordID: "record-" + name, Home: "/Users/" + name, PrimaryGID: "20"}
	}
	return records
}

func (l *listedAccounts) set(accounts map[string]unixidentity.LocalAccountRecord) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.accounts = accounts
}

func (l *listedAccounts) setFail(fail bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fail = fail
}

func (l *listedAccounts) list() (managedHookPeerListing, error) {
	l.mu.Lock()
	l.calls++
	gate, fail := l.gate, l.fail
	accounts := make(map[string]unixidentity.LocalAccountRecord, len(l.accounts))
	for name, account := range l.accounts {
		accounts[name] = account
	}
	l.mu.Unlock()
	if gate != nil {
		<-gate
	}
	if fail {
		return managedHookPeerListing{}, errors.New("dscl failed")
	}
	return localAccountsListing(accounts)
}

func unreadableStat() string { return "" }

func waitListed(t *testing.T, s *managedHookPeerAccountsSource) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		done := !s.refreshing
		s.mu.Unlock()
		if done {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("background listing did not finish")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestLocalAccountsListingIsOrderFreeAndSeesEveryRecordField(t *testing.T) {
	alice := unixidentity.LocalAccountRecord{UID: 501, RecordID: "0A1B-OLD", Home: "/Users/alice", PrimaryGID: "20"}
	bob := unixidentity.LocalAccountRecord{UID: 502, RecordID: "0B2C", Home: "/Users/bob", PrimaryGID: "20"}
	a, err := localAccountsListing(map[string]unixidentity.LocalAccountRecord{"alice": alice, "bob": bob})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := localAccountsListing(map[string]unixidentity.LocalAccountRecord{"bob": bob, "alice": alice}); a.stamp != b.stamp {
		t.Fatalf("stamp depends on order: %q %q", a.stamp, b.stamp)
	}
	with := func(change func(*unixidentity.LocalAccountRecord)) unixidentity.LocalAccountRecord {
		changed := alice
		change(&changed)
		return changed
	}
	for label, changed := range map[string]unixidentity.LocalAccountRecord{
		"uid":           with(func(r *unixidentity.LocalAccountRecord) { r.UID = 503 }),
		"record":        with(func(r *unixidentity.LocalAccountRecord) { r.RecordID = "0A1B-NEW" }), // deleted, created again
		"home":          with(func(r *unixidentity.LocalAccountRecord) { r.Home = "/Users/alice2" }),
		"primary group": with(func(r *unixidentity.LocalAccountRecord) { r.PrimaryGID = "80" }),
	} {
		b, _ := localAccountsListing(map[string]unixidentity.LocalAccountRecord{"alice": changed, "bob": bob})
		if b.stamp == a.stamp || b.records["alice"] == a.records["alice"] || b.records["bob"] != a.records["bob"] {
			t.Fatalf("%s change: stamp %q -> %q, alice %q -> %q", label, a.stamp, b.stamp, a.records["alice"], b.records["alice"])
		}
	}
	for _, changed := range []map[string]unixidentity.LocalAccountRecord{{"alicf": alice, "bob": bob}, {"alice": alice}} {
		if b, _ := localAccountsListing(changed); b.stamp == a.stamp {
			t.Fatalf("stamp unchanged for %v", changed)
		}
	}
	if _, err := localAccountsListing(nil); err == nil {
		t.Fatal("an empty list has a stamp")
	}
}

func TestAccountsSourcePrefersTheReadableFile(t *testing.T) {
	listing := &listedAccounts{accounts: byUID(map[string]int{"alice": 501})}
	s := &managedHookPeerAccountsSource{stat: func() string { return "file" }, list: listing.list, now: time.Now}
	s.refresh()
	if got := s.get(); got != "file" || listing.calls != 0 || s.record("alice") != "" {
		t.Fatalf("get = %q after %d listings, want the file stamp, no listing and no record", got, listing.calls)
	}
	if got := (&managedHookPeerAccountsSource{stat: unreadableStat, now: time.Now}).get(); got != "" {
		t.Fatalf("no source = %q, want empty", got)
	}
	if got := (&managedHookPeerAccountsSource{now: time.Now}).get(); got != "" {
		t.Fatalf("no stat and no listing = %q, want empty", got)
	}
}

// GAP-0669: on macOS the service account cannot read the dslocal users
// directory, so the stamp was always "" there.
func TestAccountsSourceListsWhenTheFileIsUnreadable(t *testing.T) {
	listing := &listedAccounts{accounts: byUID(map[string]int{"alice": 501})}
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	s := &managedHookPeerAccountsSource{stat: unreadableStat, list: listing.list, now: func() time.Time { return time.Unix(0, clock.Load()) }}
	s.get() // a request never waits for the first listing
	waitListed(t, s)
	before := s.get()
	if before == "" || s.record("alice") == "" {
		t.Fatal("no listed stamp or record after the first listing")
	}
	listing.set(byUID(map[string]int{"alice": 502}))
	if got := s.get(); got != before {
		t.Fatalf("a request listed again inside the interval: %q", got)
	}
	clock.Add(int64(managedHookPeerListedStampInterval))
	s.get()
	waitListed(t, s)
	after := s.get()
	if after == before || after == "" {
		t.Fatalf("stamp after the interval = %q, before %q", after, before)
	}
	listing.set(byUID(map[string]int{"alice": 503}))
	s.refresh() // explain: at once
	if got := s.get(); got == after || got == "" {
		t.Fatalf("refresh did not list at once: %q", got)
	}
	listing.setFail(true)
	s.refresh()
	if got := s.get(); got != "" || s.record("alice") != "" {
		t.Fatalf("a failed listing kept a stamp %q or a record", got)
	}
}

// A slow background listing that started before a change must not put
// back the stamp from before it over the one explain listed after it.
func TestAccountsSourceKeepsTheLaterListing(t *testing.T) {
	gate := make(chan struct{})
	listing := &listedAccounts{accounts: byUID(map[string]int{"alice": 501}), gate: gate}
	s := &managedHookPeerAccountsSource{stat: unreadableStat, list: listing.list, now: time.Now}
	s.get() // starts a listing that waits on the gate
	for {
		listing.mu.Lock()
		started := listing.calls == 1
		listing.mu.Unlock()
		if started {
			break
		}
		time.Sleep(time.Millisecond)
	}
	listing.mu.Lock()
	listing.accounts, listing.gate = byUID(map[string]int{"alice": 502}), nil
	listing.mu.Unlock()
	s.refresh()
	want, _ := localAccountsListing(byUID(map[string]int{"alice": 502}))
	if got := s.get(); got != want.stamp {
		t.Fatalf("after refresh = %q, want %q", got, want.stamp)
	}
	close(gate) // the first listing ends now, with the old accounts
	waitListed(t, s)
	if got := s.get(); got != want.stamp {
		t.Fatalf("the older listing replaced the later one: %q", got)
	}
}

// installListedAccounts makes listing the gateway's only account stamp
// source and homes its account cache, with identity facts on, outside
// Secure Client.
func installListedAccounts(t *testing.T, listing *listedAccounts, homes *managedHookPeerHomeCache) {
	t.Helper()
	previous, enabled, source := managedHookPeerHomes, identityFactsEnabled.Load(), managedHookPeerAccounts
	previousManaged := ManagedEnterpriseActive()
	managedHookPeerAccounts = &managedHookPeerAccountsSource{list: listing.list, now: time.Now}
	managedHookPeerHomes = homes
	setIdentityFactsEnabled(true)
	SetManagedEnterpriseActive(false)
	t.Cleanup(func() {
		managedHookPeerHomes, managedHookPeerAccounts = previous, source
		setIdentityFactsEnabled(enabled)
		SetManagedEnterpriseActive(previousManaged)
	})
}

// GAP-0669: with only the listed stamp, explain by the name of a removed
// local account recreated with a new uid resolves the live account alone.
func TestL1ListedStampDropsRemovedNamesakeAtOnce(t *testing.T) {
	const oldUID, liveUID = 94101, 94102
	old := unixidentity.Account{Name: "alice", UID: oldUID, Home: "/Users/Shared/alice"}
	live := unixidentity.Account{Name: "alice", UID: liveUID, Home: "/Users/Shared/alice"}
	resolver := &changingHolderAccounts{accounts: map[int]unixidentity.Account{oldUID: old}}
	listing := &listedAccounts{accounts: byUID(map[string]int{"alice": oldUID})}
	installListedAccounts(t, listing, holderTestCache(t, resolver, useridentity.DirectoryLocal, time.Now))
	managedHookPeerAccountsRefresh()
	if _, err := managedHookPeerHomes.explainDirectory(oldUID); err != nil {
		t.Fatal(err)
	}
	delete(resolver.accounts, oldUID)
	resolver.accounts[liveUID] = live
	listing.set(byUID(map[string]int{"alice": liveUID}))
	if twins, _ := sameNameProfileAccounts(context.Background(), resolver, "alice", live); len(twins) != 0 {
		t.Fatalf("bare name alice names the removed uid too: %+v", twins)
	}
	if uid, _, ok := managedHookPeerHomes.cachedHolder("alice"); ok {
		t.Fatalf("removed alice is still a cached subject at uid %d", uid)
	}
}

// accountFacts resolves a local account's directory facts with its groups,
// counting lookups.
type accountFacts struct {
	mu       sync.Mutex
	groups   []string
	resolves int
}

func (f *accountFacts) set(groups ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.groups = groups
}

func (f *accountFacts) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.resolves
}

func factsTestCache(t *testing.T, resolver *changingHolderAccounts, facts *accountFacts) *managedHookPeerHomeCache {
	t.Helper()
	cache := &managedHookPeerHomeCache{newResolver: func() unixidentity.Resolver { return resolver }, now: time.Now}
	cache.directoriesOnce.Do(func() {
		directories := newIdentityDirectoryCache(func(key string) (useridentity.DirectoryFacts, error) {
			uid, err := strconv.Atoi(key)
			if err != nil {
				return useridentity.DirectoryFacts{}, err
			}
			account, err := resolver.LookupUID(uid)
			if err != nil {
				return useridentity.DirectoryFacts{}, err
			}
			facts.mu.Lock()
			defer facts.mu.Unlock()
			facts.resolves++
			return useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal, Principal: account.Name,
				Groups: slices.Clone(facts.groups), ResolvedAt: time.Now()}, nil
		})
		directories.now, directories.logf, directories.trustedUntil = time.Now, nil, nil
		cache.directories = directories
	})
	return cache
}

// GAP-0669 review: a local account deleted and created again under the
// same name and uid (macOS: a new GeneratedUID), or whose home or primary
// group changed, is looked up again at once: the hook path, explain and the
// account cache get the live record's home and groups (which select its
// guardrail profile), not the cached ones of the account before it.
func TestL1SameNameAndUIDReplacementRevalidatesCachedFacts(t *testing.T) {
	const uid = 94201
	before := unixidentity.LocalAccountRecord{UID: uid, RecordID: "0A1B-OLD", Home: "/Users/Shared/alice", PrimaryGID: "20"}
	for _, tc := range []struct {
		name  string
		after unixidentity.LocalAccountRecord
	}{
		{"deleted and created again", unixidentity.LocalAccountRecord{UID: uid, RecordID: "0A1B-NEW", Home: before.Home, PrimaryGID: "20"}},
		{"created again with another home", unixidentity.LocalAccountRecord{UID: uid, RecordID: "0A1B-NEW", Home: "/Users/Shared/alice-2", PrimaryGID: "20"}},
		{"home moved", unixidentity.LocalAccountRecord{UID: uid, RecordID: before.RecordID, Home: "/Users/Shared/alice-2", PrimaryGID: "20"}},
		{"primary group changed", unixidentity.LocalAccountRecord{UID: uid, RecordID: before.RecordID, Home: before.Home, PrimaryGID: "80"}},
	} {
		for _, path := range []string{"hook", "explain"} {
			t.Run(tc.name+"/"+path, func(t *testing.T) {
				resolver := &changingHolderAccounts{accounts: map[int]unixidentity.Account{uid: {Name: "alice", UID: uid, Home: before.Home}}}
				facts := &accountFacts{groups: []string{"staff", "dc-admins"}}
				listing := &listedAccounts{accounts: map[string]unixidentity.LocalAccountRecord{"alice": before}}
				installListedAccounts(t, listing, factsTestCache(t, resolver, facts))
				managedHookPeerAccountsRefresh()
				if got, ok := managedHookPeerDirectory(uid, true); !ok || !slices.Contains(got.Groups, "dc-admins") {
					t.Fatalf("first facts = %+v, %v", got, ok)
				}
				if home := managedHookPeerHome(uid); home != before.Home {
					t.Fatalf("first home = %q", home)
				}
				// The same listing again changes nothing: no lookup.
				managedHookPeerAccountsRefresh()
				managedHookPeerDirectory(uid, true)
				if _, _, ok := managedHookPeerHomes.cachedHolder("alice"); !ok || facts.count() != 1 {
					t.Fatalf("unchanged listing: holder %v after %d lookups, want held after 1", ok, facts.count())
				}

				resolver.accounts[uid] = unixidentity.Account{Name: "alice", UID: uid, Home: tc.after.Home}
				facts.set("staff")
				listing.set(map[string]unixidentity.LocalAccountRecord{"alice": tc.after})
				managedHookPeerAccountsRefresh() // the listing the next request starts
				switch path {
				case "hook":
					if home := managedHookPeerHome(uid); home != tc.after.Home {
						t.Fatalf("home after the change = %q, want %q", home, tc.after.Home)
					}
					got, ok := managedHookPeerDirectory(uid, true)
					if !ok || slices.Contains(got.Groups, "dc-admins") || facts.count() != 2 {
						t.Fatalf("hook facts after the change = %+v, %v after %d lookups: the former account's", got, ok, facts.count())
					}
				case "explain":
					if _, _, ok := managedHookPeerHomes.cachedHolder("alice"); ok {
						t.Fatal("explain still names the former account's cached facts")
					}
					got, err := managedHookPeerHomes.explainDirectory(uid)
					if err != nil || slices.Contains(got.Groups, "dc-admins") || facts.count() != 2 {
						t.Fatalf("explain facts after the change = %+v, %v after %d lookups", got, err, facts.count())
					}
				}
			})
		}
	}
}

// A listing that fails gives no record: the cached facts stay (the TTL
// applies, as before), and the same record listed again changes nothing.
func TestL1FailedListingKeepsCachedFacts(t *testing.T) {
	const uid = 94301
	record := unixidentity.LocalAccountRecord{UID: uid, RecordID: "0C3D", Home: "/Users/Shared/bob", PrimaryGID: "20"}
	resolver := &changingHolderAccounts{accounts: map[int]unixidentity.Account{uid: {Name: "bob", UID: uid, Home: record.Home}}}
	facts := &accountFacts{groups: []string{"staff", "dc-admins"}}
	listing := &listedAccounts{accounts: map[string]unixidentity.LocalAccountRecord{"bob": record}}
	installListedAccounts(t, listing, factsTestCache(t, resolver, facts))
	managedHookPeerAccountsRefresh()
	managedHookPeerDirectory(uid, true)
	listing.setFail(true)
	managedHookPeerAccountsRefresh()
	managedHookPeerDirectory(uid, true)
	listing.setFail(false)
	managedHookPeerAccountsRefresh()
	got, ok := managedHookPeerDirectory(uid, true)
	if _, _, held := managedHookPeerHomes.cachedHolder("bob"); !ok || !held || !slices.Contains(got.Groups, "dc-admins") || facts.count() != 1 {
		t.Fatalf("facts %+v, %v, held %v after %d lookups, want the cached facts after 1", got, ok, held, facts.count())
	}
}
