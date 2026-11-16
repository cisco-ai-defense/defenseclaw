// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// GAP-0392: after an idle period, the first request found the listing
// expired, read the old stamp while a listing started in the background,
// and could select the former groups' profile. The request now waits for
// that listing (bounded); a listing that has not ended by then confirms no
// account, and an account's own record newer than the listing expires it
// (GAP-0494).
func TestExpiredOrOutdatedListingConfirmsNoAccount(t *testing.T) {
	listing := &listedAccounts{accounts: byUID(map[string]int{"alice": 501})}
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	s := &managedHookPeerAccountsSource{stat: unreadableStat, list: listing.list, now: func() time.Time { return time.Unix(0, clock.Load()) }}
	if s.get() == "" || !s.confirmed() {
		t.Fatal("the first listing did not confirm the accounts within the wait")
	}
	// Idle past the interval; the next listing is slow.
	clock.Add(int64(managedHookPeerListedStampInterval))
	gate := make(chan struct{})
	listing.mu.Lock()
	listing.gate = gate
	listing.mu.Unlock()
	if got := s.get(); got != "" || s.confirmed() || s.record("alice") != "" {
		t.Fatalf("an expired listing served stamp %q (confirmed %v)", got, s.confirmed())
	}
	listing.mu.Lock()
	listing.gate = nil
	listing.mu.Unlock()
	close(gate)
	waitListed(t, s)
	if !s.confirmed() || s.get() == "" {
		t.Fatal("the listing that ended did not confirm the accounts")
	}
	s.invalidate()
	if s.confirmed() {
		t.Fatal("an invalidated listing still confirms the accounts")
	}
	if s.get() == "" || !s.confirmed() {
		t.Fatal("the next listing did not confirm the accounts again")
	}
}

// A request whose listing does not confirm the account gets no directory
// facts: its groups are unproven, so the request takes the strictest
// combination of every profile its groups may select, the former ones
// included, never the former groups' profile as proven.
func TestUnconfirmedListingServesNoDirectoryFacts(t *testing.T) {
	previous := managedHookPeerAccountsConfirmed
	t.Cleanup(func() { managedHookPeerAccountsConfirmed = previous })
	confirmed := false
	managedHookPeerAccountsConfirmed = func() bool { return confirmed }
	cache := &managedHookPeerHomeCache{newResolver: func() unixidentity.Resolver { return nil }, now: time.Now}
	cache.directoriesOnce.Do(func() {
		directories := newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
			return useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal, Groups: []string{"former-team"}, ResolvedAt: time.Now()}, nil
		})
		directories.now, directories.logf, directories.trustedUntil = time.Now, nil, nil
		cache.directories = directories
	})
	if facts, ok := cache.directory(501, true); ok || len(facts.Groups) != 0 {
		t.Fatalf("unconfirmed listing served %+v", facts)
	}
	confirmed = true
	if facts, ok := cache.directory(501, true); !ok || len(facts.Groups) != 1 {
		t.Fatalf("confirmed listing served %+v, %v", facts, ok)
	}
}

// An account recheck that finds the account's own record changed since the
// listing (deleted and created again under the same name, uid and home, or
// another primary group) expires the listing.
func TestAccountRecheckExpiresAnOutdatedListing(t *testing.T) {
	previousChanged, previousInvalidate := managedHookPeerRecordChanged, managedHookPeerAccountsInvalidate
	t.Cleanup(func() {
		managedHookPeerRecordChanged, managedHookPeerAccountsInvalidate = previousChanged, previousInvalidate
	})
	invalidated := 0
	managedHookPeerAccountsInvalidate = func() { invalidated++ }
	changed := true
	managedHookPeerRecordChanged = func(unixidentity.Account) bool { return changed }
	resolver := &changingHolderAccounts{accounts: map[int]unixidentity.Account{501: {Name: "alice", UID: 501, Home: "/Users/alice"}}}
	cache := &managedHookPeerHomeCache{newResolver: func() unixidentity.Resolver { return resolver }, now: time.Now}
	entry := &managedHookPeerAccount{}
	cache.recheckAccount(501, entry, resolver)
	if invalidated != 1 {
		t.Fatalf("a changed record expired the listing %d times; want once", invalidated)
	}
	changed = false
	entry.checked = time.Time{}
	cache.recheckAccount(501, entry, resolver)
	if invalidated != 1 {
		t.Fatal("an unchanged record expired the listing")
	}
}
