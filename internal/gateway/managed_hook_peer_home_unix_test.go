// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"errors"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/peercred"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

type fakePeerHomeResolver struct {
	unixidentity.Resolver
	accounts map[int]unixidentity.Account
	calls    int
}

func (f *fakePeerHomeResolver) LookupUID(uid int) (unixidentity.Account, error) {
	f.calls++
	account, ok := f.accounts[uid]
	if !ok {
		return unixidentity.Account{}, errors.New("not found")
	}
	return account, nil
}

func TestManagedHookPeerHomeResolvesTheCallersHome(t *testing.T) {
	resolver := &fakePeerHomeResolver{accounts: map[int]unixidentity.Account{
		1001: {Name: "alice", UID: 1001, Home: "/home/alice"},
		1002: {Name: "bob", UID: 1002, Home: "relative/home"},
		1005: {Name: "mismatch", UID: 4242, Home: "/home/mismatch"},
		1006: {Name: "trailing", UID: 1006, Home: "/Users/carol/"},
	}}
	now := time.Unix(1_000_000, 0)
	cache := &managedHookPeerHomeCache{
		newResolver: func() unixidentity.Resolver { return resolver },
		now:         func() time.Time { return now },
	}
	for _, test := range []struct {
		uid  int
		want string
	}{
		{1001, "/home/alice"},
		{1002, ""},
		{1005, ""},
		{1006, "/Users/carol"},
	} {
		if got := cache.lookup(test.uid); got != test.want {
			t.Fatalf("lookup(%d)=%q want %q", test.uid, got, test.want)
		}
	}
}

func TestManagedHookPeerHomeRefreshesTheResolverAfterTTL(t *testing.T) {
	created := 0
	now := time.Unix(1_000_000, 0)
	cache := &managedHookPeerHomeCache{
		newResolver: func() unixidentity.Resolver {
			created++
			return &fakePeerHomeResolver{accounts: map[int]unixidentity.Account{
				1001: {Name: "alice", UID: 1001, Home: "/home/alice"},
			}}
		},
		now: func() time.Time { return now },
	}
	cache.lookup(1001)
	cache.lookup(1001)
	if created != 1 {
		t.Fatalf("resolver created %d times inside the TTL", created)
	}
	now = now.Add(managedHookPeerHomeTTL + time.Second)
	cache.lookup(1001)
	if created != 2 {
		t.Fatalf("resolver not refreshed after the TTL (created %d)", created)
	}
}

func TestManagedHookConnContextRecordsTheCallersHome(t *testing.T) {
	previous := managedHookPeerHome
	managedHookPeerHome = func(uid int) string {
		if uid == 1001 {
			return "/home/alice"
		}
		return ""
	}
	t.Cleanup(func() { managedHookPeerHome = previous })
	peer := managedHookPeerFor(peercred.Credentials{UID: 1001, GID: 1001, PID: 42})
	if peer.Home != "/home/alice" || peer.UID != 1001 {
		t.Fatalf("peer=%+v", peer)
	}
}

// TestManagedHookPeerNameResolvesDirectoryUsers: a directory (LDAP, SSSD,
// AD) account is not in /etc/passwd, which is all os/user reads in a
// cgo-free build. The hook-socket caller's name must come from the same
// platform account database as its home, so exempt_users entries naming
// such an account match and its events carry the name.
func TestManagedHookPeerNameResolvesDirectoryUsers(t *testing.T) {
	const directoryUID = 1_870_400_123 // outside any local passwd range
	previous := managedHookPeerHomes
	managedHookPeerHomes = &managedHookPeerHomeCache{
		newResolver: func() unixidentity.Resolver {
			return &fakePeerHomeResolver{accounts: map[int]unixidentity.Account{
				directoryUID: {Name: "svc-release", UID: directoryUID, Home: "/home/svc-release"},
				1005:         {Name: "mismatch", UID: 4242, Home: "/home/mismatch"},
			}}
		},
		now: time.Now,
	}
	t.Cleanup(func() { managedHookPeerHomes = previous })

	peer := managedHookPeerFor(peercred.Credentials{UID: directoryUID, GID: directoryUID, PID: 42})
	if peer.Name != "svc-release" || peer.Home != "/home/svc-release" {
		t.Fatalf("directory caller peer = %+v, want name svc-release and its home", peer)
	}
	if name := managedHookPeerName(1005); name != "" {
		t.Fatalf("an answer for another uid must not name the caller: %q", name)
	}
	if name := managedHookPeerName(4040); name != "" {
		t.Fatalf("an unknown uid must stay unnamed: %q", name)
	}

	authorizer := newManagedHookAuthorizer(config.EnterpriseEnrollmentConfig{
		UnenrolledUsers: config.EnterpriseUnenrolledDeny,
		ExemptUsers:     []string{"svc-release"},
	}, nil, func() (managedHookLedger, error) { return managedHookLedger{}, nil })
	if decision := authorizer.decide(peer, "claudecode", ""); !decision.Allow || !decision.Exempt {
		t.Fatalf("exempt directory user by name: %+v, want an exempt allow", decision)
	}
}

// TestUnnamedGroupMakesDirectoryFactsIncomplete pins GAP-0138: a group that
// is still a number was not named by the directory (a cold or offline
// SSSD), so the facts refresh after the incomplete lifetime, not 15 minutes.
func TestUnnamedGroupMakesDirectoryFactsIncomplete(t *testing.T) {
	named := useridentity.DirectoryFacts{Groups: []string{"dc-ml-team@dclab.test", "domain users@dclab.test"}}
	unnamed := useridentity.DirectoryFacts{Groups: []string{"dc-ml-team@dclab.test", "94400513"}}
	if hasUnnamedGroup(named) || !hasUnnamedGroup(unnamed) {
		t.Fatalf("hasUnnamedGroup(named) = %t, (unnamed) = %t; want false, true", hasUnnamedGroup(named), hasUnnamedGroup(unnamed))
	}
}
