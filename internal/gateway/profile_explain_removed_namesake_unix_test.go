// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

type changingHolderAccounts struct {
	unixidentity.Resolver
	accounts map[int]unixidentity.Account
	down     bool
}

func (r *changingHolderAccounts) LookupUID(uid int) (unixidentity.Account, error) {
	if r.down {
		return unixidentity.Account{}, errors.New("account database unavailable")
	}
	if account, ok := r.accounts[uid]; ok {
		return account, nil
	}
	return unixidentity.Account{}, unixidentity.ErrNotFound
}

func (r *changingHolderAccounts) LookupUser(name string) (unixidentity.Account, error) {
	if r.down {
		return unixidentity.Account{}, errors.New("account database unavailable")
	}
	for _, account := range r.accounts {
		if useridentity.EqualFold(account.Name, name) {
			return account, nil
		}
	}
	return unixidentity.Account{}, unixidentity.ErrNotFound
}

func holderTestCache(t *testing.T, resolver *changingHolderAccounts, directory useridentity.Directory, now func() time.Time) *managedHookPeerHomeCache {
	t.Helper()
	cache := &managedHookPeerHomeCache{newResolver: func() unixidentity.Resolver { return resolver }, now: now}
	cache.directoriesOnce.Do(func() {
		facts := newIdentityDirectoryCache(func(key string) (useridentity.DirectoryFacts, error) {
			uid, err := strconv.Atoi(key)
			if err != nil {
				return useridentity.DirectoryFacts{}, err
			}
			account, err := resolver.LookupUID(uid)
			if err != nil {
				return useridentity.DirectoryFacts{}, err
			}
			return useridentity.DirectoryFacts{Directory: directory, Principal: account.Name, ResolvedAt: now()}, nil
		})
		facts.now, facts.logf, facts.trustedUntil = now, nil, nil
		cache.directories = facts
	})
	return cache
}

func TestL1ExplainedRemovedNamesakeDoesNotPoisonLiveName(t *testing.T) {
	const oldUID, liveUID = 94001, 94002
	old := unixidentity.Account{Name: "alice", UID: oldUID, Home: "/home/old-alice"}
	live := unixidentity.Account{Name: "alice", UID: liveUID, Home: "/home/live-alice"}
	resolver := &changingHolderAccounts{accounts: map[int]unixidentity.Account{oldUID: old}}
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()) }
	previous, enabled, stampFn := managedHookPeerHomes, identityFactsEnabled.Load(), managedHookPeerAccountsStamp
	stamp := "before"
	managedHookPeerAccountsStamp = func() string { return stamp }
	managedHookPeerHomes = holderTestCache(t, resolver, useridentity.DirectoryLocal, now)
	setIdentityFactsEnabled(true)
	t.Cleanup(func() {
		managedHookPeerHomes, managedHookPeerAccountsStamp = previous, stampFn
		setIdentityFactsEnabled(enabled)
	})
	if _, err := managedHookPeerHomes.explainDirectory(oldUID); err != nil {
		t.Fatal(err)
	}
	delete(resolver.accounts, oldUID)
	resolver.accounts[liveUID] = live
	stamp = "after" // local account database changed when alice was removed
	if twins, _ := sameNameProfileAccounts(context.Background(), resolver, "alice", live); len(twins) != 0 {
		t.Fatalf("bare name alice became ambiguous from removed uid: %+v", twins)
	}
	if uid, _, ok := managedHookPeerHomes.cachedHolder("alice"); ok {
		t.Fatalf("removed alice remained a cached subject at uid %d", uid)
	}
	if _, err := managedHookPeerHomes.explainDirectory(liveUID); err != nil {
		t.Fatal(err)
	}
	if uid, name, ok := managedHookPeerHomes.cachedHolder("alice"); !ok || uid != liveUID || name != "alice" {
		t.Fatalf("bare name resolves to uid %d, %q, %t; want live alice", uid, name, ok)
	}
}

func TestL1ExplainedDirectoryHolderSurvivesOutageOnlyWhileFactsAreServed(t *testing.T) {
	const uid = 94011
	account := unixidentity.Account{Name: "alice", UID: uid, Home: "/home/alice"}
	resolver := &changingHolderAccounts{accounts: map[int]unixidentity.Account{uid: account}}
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()) }
	previous, enabled, stampFn := managedHookPeerHomes, identityFactsEnabled.Load(), managedHookPeerAccountsStamp
	managedHookPeerAccountsStamp = func() string { return "same" }
	managedHookPeerHomes = holderTestCache(t, resolver, useridentity.DirectoryActiveDirectory, now)
	setIdentityFactsEnabled(true)
	t.Cleanup(func() {
		managedHookPeerHomes, managedHookPeerAccountsStamp = previous, stampFn
		setIdentityFactsEnabled(enabled)
	})
	if _, err := managedHookPeerHomes.explainDirectory(uid); err != nil {
		t.Fatal(err)
	}
	resolver.down = true
	if gotUID, _, ok := managedHookPeerHomes.cachedHolder("alice"); !ok || gotUID != uid {
		t.Fatalf("cached name during outage = %d, %t", gotUID, ok)
	}
	if _, err := profileExplainCachedSubject("alice", now()); err != nil {
		t.Fatal("explain lost the account whose cached facts hooks still serve")
	}
	clock.Add(int64(identityDirectoryMaxAge + time.Minute))
	if gotUID, _, ok := managedHookPeerHomes.cachedHolder("alice"); ok {
		t.Fatalf("expired directory holder still names uid %d", gotUID)
	}
	if _, err := profileExplainCachedSubject("alice", now()); err == nil {
		t.Fatal("explain used facts the hooks no longer serve")
	}
}

func TestL1SecureClientAccountCacheIgnoresPasswdStamp(t *testing.T) {
	previousManaged, previousStamp := ManagedEnterpriseActive(), managedHookPeerAccountsStamp
	t.Cleanup(func() {
		SetManagedEnterpriseActive(previousManaged)
		managedHookPeerAccountsStamp = previousStamp
	})
	stamp := "before"
	managedHookPeerAccountsStamp = func() string { return stamp }

	for _, test := range []struct {
		name             string
		managed          bool
		wantResolverRuns int
		wantName         string
	}{
		{name: "Secure Client", managed: true, wantResolverRuns: 1, wantName: "alice"},
		{name: "managed gateway", managed: false, wantResolverRuns: 2, wantName: "reassigned"},
	} {
		t.Run(test.name, func(t *testing.T) {
			SetManagedEnterpriseActive(test.managed)
			stamp = "before"
			const uid = 94021
			resolverRuns := 0
			now := time.Unix(1_000_000, 0)
			cache := &managedHookPeerHomeCache{
				newResolver: func() unixidentity.Resolver {
					resolverRuns++
					name := "alice"
					if resolverRuns > 1 {
						name = "reassigned"
					}
					return &changingHolderAccounts{accounts: map[int]unixidentity.Account{
						uid: {Name: name, UID: uid, Home: "/home/" + name},
					}}
				},
				now: func() time.Time { return now },
			}
			if account, ok := cache.account(uid); !ok || account.Name != "alice" {
				t.Fatalf("first account = %+v, %t", account, ok)
			}
			stamp = "after"
			account, ok := cache.account(uid)
			if !ok || account.Name != test.wantName || resolverRuns != test.wantResolverRuns {
				t.Fatalf("account after passwd change = %+v, %t; resolver runs = %d; want name %q and %d runs",
					account, ok, resolverRuns, test.wantName, test.wantResolverRuns)
			}
		})
	}
}
