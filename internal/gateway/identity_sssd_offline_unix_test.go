//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// GAP-0191: with SSSD offline, an account whose memberships SSSD never looked
// up is listed in its primary group only, and got the default profile as a
// verified "default". While the hook guardian lists the account's SSSD domain
// offline, that answer is a failed lookup that also drops the facts cached
// before; an account SSSD lists in other groups, another domain's accounts
// and other backends are not affected.
func TestSSSDGroupsUnavailableWhileTheGuardianFindsSSSDOffline(t *testing.T) {
	t.Cleanup(func() { openDirectoryOfflineAt.Store(0) })
	now := time.Unix(1_800_000_000, 0)
	away := func(domain string) bool { return domain == "" || domain == "dclab.test" }
	primaryOnly := useridentity.DirectoryFacts{Source: useridentity.SourceSSSD, Domain: "dclab.test", OnlyPrimaryGroup: true,
		Groups: []string{"domain users@dclab.test"}}
	record := &enterprisehooks.IdentitySpoolRecord{SSSDDomain: "DCLab.Test"}
	err := sssdGroupsUnavailable(record, primaryOnly, away, now)
	var unconfirmed *identityFactsUnconfirmedError
	if err == nil || !errors.As(err, &unconfirmed) || !strings.Contains(err.Error(), "SSSD is offline for dclab.test") {
		t.Fatalf("err = %v, want a lookup failure that drops cached facts", err)
	}
	if got := openDirectoryOfflineAt.Load(); got != now.UnixNano() {
		t.Fatalf("outage noted at %d, want %d", got, now.UnixNano())
	}
	noDomain := primaryOnly
	noDomain.Domain = ""
	for name, facts := range map[string]useridentity.DirectoryFacts{"no record": primaryOnly, "no domain": noDomain} {
		if err := sssdGroupsUnavailable(nil, facts, away, now); err == nil {
			t.Fatalf("%s: resolved during the outage", name)
		}
	}
	listed := primaryOnly
	listed.OnlyPrimaryGroup = false
	winbind := primaryOnly
	winbind.Source = useridentity.SourceWinbind
	other := &enterprisehooks.IdentitySpoolRecord{SSSDDomain: "emea.example.com"}
	for name, tc := range map[string]struct {
		record      *enterprisehooks.IdentitySpoolRecord
		facts       useridentity.DirectoryFacts
		unreachable func(string) bool
	}{
		"memberships listed": {record, listed, away},
		"another domain":     {other, primaryOnly, away},
		"nothing away":       {record, primaryOnly, func(string) bool { return false }},
		"no guardian":        {record, primaryOnly, nil},
		"winbind":            {record, winbind, away},
	} {
		if err := sssdGroupsUnavailable(tc.record, tc.facts, tc.unreachable, now); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// TestSSSDOfflineTimeline pins GAP-0191 on the hook path's cache: an account
// SSSD lists in its primary group only is refreshed after the incomplete
// lifetime, so once the guardian finds SSSD offline the facts cached from
// that answer are dropped and requests needing the missing groups are
// refused with the fact named (directory_lookups_failing in status and
// verify). Once SSSD is
// online again (the guardian flushed SSSD's caches and removed the domain),
// the next lookup, one retry cycle later, gets the account's groups.
func TestSSSDOfflineTimeline(t *testing.T) {
	t.Cleanup(func() { openDirectoryOfflineAt.Store(0) })
	start := time.Unix(1_800_000_000, 0)
	var clock atomic.Int64
	clock.Store(start.UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()) }
	at := func(d time.Duration) { clock.Store(start.Add(d).UnixNano()) }
	var offline, memberships atomic.Bool
	cache := newIdentityDirectoryCache(func(string) (useridentity.DirectoryFacts, error) {
		facts := useridentity.DirectoryFacts{Source: useridentity.SourceSSSD, Domain: "dclab.test", ResolvedAt: now(),
			Groups: []string{"domain users@dclab.test"}, OnlyPrimaryGroup: true}
		if memberships.Load() {
			facts.Groups, facts.OnlyPrimaryGroup = append(facts.Groups, "dc-r102-devs@dclab.test"), false
		}
		if err := sssdGroupsUnavailable(nil, facts, func(string) bool { return offline.Load() }, now()); err != nil {
			return useridentity.DirectoryFacts{}, err
		}
		return facts, nil
	})
	cache.logf = func(string, ...any) {}
	cache.now = now
	cache.settling = openDirectorySettling
	cache.incomplete = managedHookPeerHomes.directoryCache().incomplete
	const key = "94405134"
	if facts, ok := cache.get(key, true); !ok || !facts.OnlyPrimaryGroup {
		t.Fatalf("before the guardian finds SSSD offline: %+v, %t", facts, ok)
	}
	if got := cache.lifetime(useridentity.DirectoryFacts{Source: useridentity.SourceSSSD, OnlyPrimaryGroup: true}); got != identityDirectoryIncompleteTTL {
		t.Fatalf("primary-group-only facts live %s, want %s", got, identityDirectoryIncompleteTTL)
	}
	offline.Store(true)
	at(identityDirectoryIncompleteTTL + time.Second)
	if facts, ok := cache.get(key, true); ok {
		t.Fatalf("SSSD offline: facts %+v served, want default_lookup_failed", facts)
	}
	if _, reason, failing := cache.failing(key); !failing || !strings.Contains(reason, "SSSD is offline for dclab.test") {
		t.Fatalf("failing = %t (%q), want the reason", failing, reason)
	}
	if h := cache.health(); h.Failing != 1 {
		t.Fatalf("health = %+v, want one failing account", h)
	}
	offline.Store(false)
	memberships.Store(true)
	at(identityDirectoryIncompleteTTL + time.Second + identityDirectoryRetry)
	facts, ok := cache.get(key, true)
	if !ok || facts.OnlyPrimaryGroup || len(facts.Groups) != 2 {
		t.Fatalf("SSSD online again: %+v, %t; want the account's groups", facts, ok)
	}
	if _, _, failing := cache.failing(key); failing {
		t.Fatal("still failing after SSSD answered")
	}
}
