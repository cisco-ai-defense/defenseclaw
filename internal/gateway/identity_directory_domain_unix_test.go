// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// GAP-1263: a qualified --user filter for a deleted account lists only the
// uid the gateway knew in that domain, not a deleted namesake of another.
func TestRemovedAccountFilterKeepsDomainsApart(t *testing.T) {
	const east, west, unknown = "3999001", "3999002", "3999003"
	previous := managedHookPeerLastName
	managedHookPeerLastName = func(uid int) string {
		return map[int]string{3999001: "alice@east.example", 3999002: "alice@west.example"}[uid]
	}
	t.Cleanup(func() { managedHookPeerLastName = previous })
	for _, tc := range []struct {
		filter, id string
		want       bool
	}{
		{"alice@east.example", east, true},
		{"alice@east.example", west, false},
		{"alice@EAST.EXAMPLE", east, true},
		{"alice@west.example", west, true},
		{"alice@east.example", unknown, false},
	} {
		if got := adminViewDomainCouldHold(tc.filter, tc.id); got != tc.want {
			t.Errorf("adminViewDomainCouldHold(%q, %s) = %v, want %v", tc.filter, tc.id, got, tc.want)
		}
	}
}

// GAP-0551: during a directory outage, the UPN and DOMAIN\name spellings
// explain accepts find the facts the hooks cached for the account.
func TestProfileExplainDuringOutageAcceptsEverySpelling(t *testing.T) {
	const uid = 1_870_400_551
	const name = "alice"
	accounts := map[int]unixidentity.Account{uid: {Name: name, UID: uid, Home: "/home/" + name}}
	previous, previousFacts, previousIncarnation := managedHookPeerHomes, identityFactsEnabled.Load(), managedHookPeerAccountIncarnation
	managedHookPeerHomes = &managedHookPeerHomeCache{
		newResolver: func() unixidentity.Resolver { return &fakePeerHomeResolver{accounts: accounts} },
		now:         time.Now,
	}
	// SSSDs offline cache still names the accounts SID: a spelling only
	// the cached facts confirm needs the incarnation they were cached for
	// (review of r104 W2B, loop round 3).
	managedHookPeerAccountIncarnation = func(unixidentity.Account) (string, bool) { return "sid:S-1-5-21-1-2-3-551", true }
	setIdentityFactsEnabled(true)
	t.Cleanup(func() {
		managedHookPeerHomes, managedHookPeerAccountIncarnation = previous, previousIncarnation
		setIdentityFactsEnabled(previousFacts)
	})
	facts := useridentity.DirectoryFacts{
		Domain: "corp.example", AccountDomain: "CORP", Realm: "CORP.EXAMPLE", UPN: "alice.smith@corp.example",
		Principal: "alice.smith@corp.example", Groups: []string{"engineering"}, ResolvedAt: time.Now(),
	}
	managedHookPeerHomes.directoriesOnce.Do(func() {
		managedHookPeerHomes.directories = newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) { return facts, nil })
	})
	if _, ok := managedHookPeerHomes.directory(uid, true); !ok {
		t.Fatal("the hook path did not cache the facts")
	}
	for _, spelled := range []string{"alice.smith@corp.example", `CORP\alice`, "alice@corp.example", "1870400551"} {
		subject, err := profileExplainUnresolved(spelled, unixidentity.ErrNotFound)
		if err != nil || subject.UserID != "1870400551" || subject.cachedFactsAge <= 0 {
			t.Fatalf("explain %s during the outage = %+v, %v; want the cached facts", spelled, subject, err)
		}
	}
	if subject, err := profileExplainUnresolved(`OTHER\alice`, unixidentity.ErrNotFound); err == nil && subject.UserID == "1870400551" {
		t.Fatalf("another domain's spelling found the cached account: %+v", subject)
	}
}

// GAP-0551 on SSSD with fully qualified names (alice@corp.example): during
// an outage the account database answers for no uid, and explain by
// CORP\alice was refused (the holder of the uid could not be confirmed)
// while the name and the uid were served the cached facts the hooks apply.
func TestProfileExplainDuringOutageServesTheDomainSpellingOfTheAccountName(t *testing.T) {
	const uid = 1_870_400_561
	const id = "1870400561"
	resolver := &lockedPeerResolver{accounts: map[int]unixidentity.Account{uid: {Name: "alice@corp.example", UID: uid, Home: "/home/alice@corp.example"}}}
	previous, previousFacts, previousIncarnation := managedHookPeerHomes, identityFactsEnabled.Load(), managedHookPeerAccountIncarnation
	managedHookPeerHomes = &managedHookPeerHomeCache{newResolver: func() unixidentity.Resolver { return resolver }, now: time.Now}
	managedHookPeerAccountIncarnation = func(unixidentity.Account) (string, bool) { return "sid:S-1-5-21-1-2-3-561", true }
	setIdentityFactsEnabled(true)
	t.Cleanup(func() {
		managedHookPeerHomes, managedHookPeerAccountIncarnation = previous, previousIncarnation
		setIdentityFactsEnabled(previousFacts)
	})
	facts := useridentity.DirectoryFacts{
		Domain: "corp.example", AccountDomain: "CORP", Realm: "CORP.EXAMPLE", UPN: "alice@corp.example",
		Principal: "alice@corp.example", Groups: []string{"engineering"}, ResolvedAt: time.Now(),
	}
	managedHookPeerHomes.directoriesOnce.Do(func() {
		managedHookPeerHomes.directories = newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) { return facts, nil })
	})
	if _, ok := managedHookPeerHomes.directory(uid, true); !ok {
		t.Fatal("the hook path did not cache the facts")
	}
	// The outage: SSSD answers for nobody.
	resolver.mu.Lock()
	delete(resolver.accounts, uid)
	resolver.mu.Unlock()
	for _, spelled := range []string{`CORP\alice`, `corp\ALICE`, "alice@corp.example", id} {
		subject, err := profileExplainUnresolved(spelled, unixidentity.ErrNotFound)
		if err != nil || subject.UserID != id || subject.cachedFactsAge <= 0 || len(subject.Groups) == 0 {
			t.Fatalf("explain %s during the outage = %+v, %v; want the cached facts", spelled, subject, err)
		}
	}
	if subject, err := profileExplainUnresolved(`OTHER\alice`, unixidentity.ErrNotFound); err == nil && subject.UserID == id {
		t.Fatalf("another domain's spelling found the cached account: %+v", subject)
	}
}
