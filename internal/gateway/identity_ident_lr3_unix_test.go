// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Review of r104 W2B, loop round 3. The gateway keeps CORP's alice's facts
// for uid 1870400552 (UPN alice.smith@corp.example). The directory hands the
// uid to another account, or the account database cannot confirm who holds
// it, and the lookup of the UPN fails before a hook rechecks the uid:
// explain by the UPN found the former holder's facts through them
// (cachedFactsSpell) and showed its groups and profile. rel/1.0.4 did not
// take that spelling from cached facts. A spelling only the facts confirm
// is now served only while the account database names the holder and the
// incarnation the facts were cached for; a uid that changed hands drops
// them for every spelling. The bare name and the uid keep the outage
// behavior of rel/1.0.4 (GAP-0899), and so do CORP\alice and
// alice@corp.example, which spell the account name (GAP-0551).
func TestACachedQualifiedSpellingNeedsTheHolderOfTheUIDNow(t *testing.T) {
	const uid = 1_870_400_552
	const id = "1870400552"
	const corp, other = "sid:S-1-5-21-1-2-3-552", "sid:S-1-5-21-9-9-9-552"
	alice := unixidentity.Account{Name: "alice", UID: uid, Home: "/home/alice"}
	previous, previousFacts, previousIncarnation := managedHookPeerHomes, identityFactsEnabled.Load(), managedHookPeerAccountIncarnation
	t.Cleanup(func() {
		managedHookPeerHomes, managedHookPeerAccountIncarnation = previous, previousIncarnation
		setIdentityFactsEnabled(previousFacts)
	})
	setIdentityFactsEnabled(true)
	var mu sync.Mutex
	incarnation, known := corp, true
	managedHookPeerAccountIncarnation = func(unixidentity.Account) (string, bool) {
		mu.Lock()
		defer mu.Unlock()
		return incarnation, known
	}
	holds := func(token string, ok bool) {
		mu.Lock()
		incarnation, known = token, ok
		mu.Unlock()
	}
	facts := useridentity.DirectoryFacts{
		Domain: "corp.example", AccountDomain: "CORP", Realm: "CORP.EXAMPLE", UPN: "alice.smith@corp.example",
		Principal: "alice.smith@corp.example", Groups: []string{"strict-devs"}, ResolvedAt: time.Now(),
	}
	// fresh caches CORP's alice's facts the way a hook call does.
	fresh := func(t *testing.T) *lockedPeerResolver {
		t.Helper()
		holds(corp, true)
		resolver := &lockedPeerResolver{accounts: map[int]unixidentity.Account{uid: alice}}
		managedHookPeerHomes = &managedHookPeerHomeCache{newResolver: func() unixidentity.Resolver { return resolver }, now: time.Now}
		managedHookPeerHomes.directoriesOnce.Do(func() {
			managedHookPeerHomes.directories = newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
				// The directory answers for whoever holds the uid now.
				if holder, err := resolver.LookupUID(uid); err == nil && holder.Name != "alice" {
					return useridentity.DirectoryFacts{Groups: []string{"bob-open"}, ResolvedAt: time.Now()}, nil
				}
				return facts, nil
			})
		})
		if _, ok := managedHookPeerHomes.directory(uid, true); !ok {
			t.Fatal("the hook path did not cache the facts")
		}
		return resolver
	}
	qualified := []string{"alice.smith@corp.example", `CORP\alice`, "alice@corp.example"}
	const alias = "alice.smith@corp.example"
	names := []string{"alice", id, `CORP\alice`, "alice@corp.example"}
	served := func(t *testing.T, spelled string) {
		t.Helper()
		subject, err := profileExplainUnresolved(spelled, unixidentity.ErrNotFound)
		if err != nil || subject.UserID != id || subject.cachedFactsAge <= 0 {
			t.Fatalf("explain %s = %+v, %v; want the cached facts", spelled, subject, err)
		}
	}
	notServed := func(t *testing.T, spelled, why string) {
		t.Helper()
		subject, err := profileExplainUnresolved(spelled, unixidentity.ErrNotFound)
		if err == nil || subject.UserID == id || len(subject.Groups) > 0 || !strings.Contains(err.Error(), why) {
			t.Fatalf("explain %s = %+v, %v; want refused, saying %q", spelled, subject, err, why)
		}
	}
	dropped := func(t *testing.T) {
		t.Helper()
		if _, _, ok := managedHookPeerHomes.directoryCache().peek(id); ok {
			t.Fatal("the former holder's facts are still served to hooks")
		}
	}

	t.Run("the holder and its incarnation are confirmed", func(t *testing.T) {
		fresh(t)
		for _, spelled := range append(qualified, "alice", id) {
			served(t, spelled)
		}
	})
	t.Run("the directory names no incarnation now", func(t *testing.T) {
		fresh(t)
		holds("", false)
		notServed(t, alias, "cannot confirm that the account that holds uid "+id)
		for _, spelled := range names {
			served(t, spelled)
		}
	})
	t.Run("the account database does not name the uid now", func(t *testing.T) {
		resolver := fresh(t)
		resolver.mu.Lock()
		delete(resolver.accounts, uid)
		resolver.mu.Unlock()
		notServed(t, alias, "does not name the account that holds uid "+id)
		for _, spelled := range names {
			served(t, spelled)
		}
	})
	t.Run("the uid and the UPN went to another account", func(t *testing.T) {
		resolver := fresh(t)
		resolver.set(uid, unixidentity.Account{Name: "bob", UID: uid, Home: "/home/bob"})
		notServed(t, "alice.smith@corp.example", "alice.smith@corp.example")
		dropped(t)
		for _, spelled := range append(qualified, "alice", id) {
			if subject, _ := profileExplainUnresolved(spelled, unixidentity.ErrNotFound); slices.Contains(subject.Groups, "strict-devs") {
				t.Fatalf("explain %s after the handoff = %+v; want no former facts", spelled, subject)
			}
		}
	})
	t.Run("OTHER's alice holds the uid with the same name and home", func(t *testing.T) {
		fresh(t)
		holds(other, true)
		notServed(t, "alice.smith@corp.example", "alice.smith@corp.example")
		dropped(t)
	})
	t.Run("the bare name of a uid handed to another account", func(t *testing.T) {
		resolver := fresh(t)
		resolver.set(uid, unixidentity.Account{Name: "bob", UID: uid, Home: "/home/bob"})
		if subject, _ := profileExplainUnresolved("alice", unixidentity.ErrNotFound); subject.UserID == id {
			t.Fatalf("explain alice after the handoff = %+v; want no former facts", subject)
		}
		dropped(t)
	})
}
