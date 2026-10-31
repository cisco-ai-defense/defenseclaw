// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"errors"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// GAP-0551 on a managed Mac: the hooks read every call's directory facts
// fresh and get none while the directory does not answer. Open Directory
// still answered the bare name and the uid from its own cache, so explain by
// them read the facts as the hooks do and reported default_lookup_failed,
// but DOMAIN\name and the UPN, which it did not answer, were served the
// cached facts and reported the cached group profile. Every spelling must
// report what the hooks get, through the outage and after it.
func TestManagedMacExplainGivesEverySpellingTheHooksAnswerThroughAnOutage(t *testing.T) {
	const uid = 1_261_800_551
	id := strconv.Itoa(uid)
	resolver := &lockedPeerResolver{accounts: map[int]unixidentity.Account{uid: {Name: "alice", UID: uid, Home: "/Users/alice"}}}
	previousHomes, previousFresh := managedHookPeerHomes, managedHookDirectoryNeedsFresh
	previousHosted, previousFacts, previousBlocking := managedServiceHosted.Load(), identityFactsEnabled.Load(), identityLookupBlocking.Load()
	previousConfirmed, previousIncarnation := managedHookPeerAccountsConfirmed, managedHookPeerAccountIncarnation
	previousAccount, previousLocal := profileExplainAccount, profileExplainLocalAccount
	t.Cleanup(func() {
		managedHookPeerHomes, managedHookDirectoryNeedsFresh = previousHomes, previousFresh
		setManagedServiceHosted(previousHosted)
		setIdentityFactsEnabled(previousFacts)
		setIdentityLookupBlocking(previousBlocking)
		managedHookPeerAccountsConfirmed, managedHookPeerAccountIncarnation = previousConfirmed, previousIncarnation
		profileExplainAccount, profileExplainLocalAccount = previousAccount, previousLocal
	})
	managedHookDirectoryNeedsFresh = true
	setManagedServiceHosted(true)
	setIdentityFactsEnabled(true)
	setIdentityLookupBlocking(true)
	managedHookPeerAccountsConfirmed = func() bool { return true }
	// macOS: the gateway names no account incarnation itself.
	managedHookPeerAccountIncarnation = func(unixidentity.Account) (string, bool) { return "", false }
	// Open Directory answers the bare name and the uid (from its cache in
	// the outage), not the qualified spellings.
	profileExplainAccount = func(name string) (string, string, error) {
		if name == "alice" || name == id {
			return id, "alice", nil
		}
		return "", "", unixidentity.ErrNotFound
	}
	profileExplainLocalAccount = func(int, string) error { return errors.New("not an account of the local directory node") }

	var down atomic.Bool
	var clock atomic.Int64
	clock.Store(time.Unix(1_000_000, 0).UnixNano())
	managedHookPeerHomes = &managedHookPeerHomeCache{newResolver: func() unixidentity.Resolver { return resolver }, now: time.Now}
	managedHookPeerHomes.directoriesOnce.Do(func() {
		managedHookPeerHomes.directories = newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
			if down.Load() {
				return useridentity.DirectoryFacts{}, errors.New("the domain controllers of CORP do not answer")
			}
			return useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory,
				Source: useridentity.SourceMacOSOpenDirectory, Assurance: useridentity.AssuranceVerified,
				Domain: "corp.example.com", AccountDomain: "CORP", Realm: "CORP.EXAMPLE.COM",
				UPN: "alice@corp.example.com", Principal: "alice@corp.example.com",
				Groups: []string{"engineering"}, ResolvedAt: time.Now()}, nil
		})
		managedHookPeerHomes.directories.now = func() time.Time { return time.Unix(0, clock.Load()) }
	})
	if _, ok := managedHookPeerHomes.directory(uid, true); !ok {
		t.Fatal("the hook path did not get the facts")
	}
	spellings := []string{"alice", id, `CORP\alice`, `corp\ALICE`, "alice@corp.example.com"}

	down.Store(true)
	clock.Add(int64(identityDirectoryFreshCoalesce + time.Nanosecond))
	if facts, ok := managedHookPeerHomes.directory(uid, true); ok {
		t.Fatalf("the hooks kept facts through the outage: %+v", facts)
	}
	for _, spelled := range spellings {
		subject, err := lookupDirectoryProfileSubject(spelled)
		if err != nil || subject.UserID != id || !subject.LookupFailed || len(subject.Groups) != 0 || subject.Principal != "" {
			t.Fatalf("explain %s during the outage = %+v, %v; want what the hooks get: no facts (default_lookup_failed)", spelled, subject, err)
		}
	}

	down.Store(false)
	clock.Add(int64(identityDirectoryRetry + time.Nanosecond))
	for _, spelled := range spellings {
		subject, err := lookupDirectoryProfileSubject(spelled)
		if err != nil || subject.UserID != id || subject.LookupFailed || !slices.Contains(subject.Groups, "engineering") {
			t.Fatalf("explain %s once the directory answers = %+v, %v; want its current facts", spelled, subject, err)
		}
	}
	if subject, err := lookupDirectoryProfileSubject(`OTHER\alice`); err == nil && subject.UserID == id {
		t.Fatalf("another domain's spelling found the account: %+v", subject)
	}
}
