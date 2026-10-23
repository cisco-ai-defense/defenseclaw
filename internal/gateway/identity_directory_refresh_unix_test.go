// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

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
