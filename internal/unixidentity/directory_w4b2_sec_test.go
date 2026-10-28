//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestW4B2UnnamedSSSDGroupNeedsDomainAnswer(t *testing.T) {
	const account = "alice:x:1001:1001::/home/alice:/bin/sh\n"
	accountHost(t, account, "", "passwd: files\ngroup: files ldap sss\n")
	startFakeNSLCD(t, &fakeNSLCD{members: map[string][]int{"alice": {5200}}})
	sssdConfiguredHost(t)
	startFakeSSSD(t, nil) // The responder is live while its domain is offline.
	old := sssdDomainsOnline
	t.Cleanup(func() { sssdDomainsOnline = old })
	sssdDomainsOnline = func(context.Context) error { return errors.New("SSSD domain is offline") }
	r := newFakeNSS(&fakeRun{results: map[string]commandResult{
		"passwd 1001": {stdout: []byte(account)}, "-s files passwd 1001": {stdout: []byte(account)},
		"initgroups alice": {stdout: []byte("alice 1001 5200\n")},
		"group 1001 5200":  {stdout: []byte("staff:x:1001:\n"), exitCode: getentExitNotFound},
	}})
	// The gid stays unconfirmed (or the lookup fails): an offline domain
	// behind a live responder never proves it unnamed.
	if facts, err := r.DirectoryFactsForUID(1001, time.Now()); err == nil && len(facts.UnconfirmedGroups) == 0 {
		t.Fatalf("facts = %+v, %v; an unnamed GID needs a domain answer", facts, err)
	}
}

func TestW4B2OfflineSSSDCannotProveUIDUnshared(t *testing.T) {
	const account = "alice:x:1001:1001::/home/alice:/bin/sh\n"
	accountHost(t, account, "staff:x:1001:\n", "passwd: files sss\ngroup: files\n")
	sssdConfiguredHost(t)
	startFakeSSSD(t, nil) // getent -s sss misses an uncached UID.
	old := sssdDomainsOnline
	t.Cleanup(func() { sssdDomainsOnline = old })
	sssdDomainsOnline = func(context.Context) error { return errors.New("SSSD domain is offline") }
	r := newFakeNSS(&fakeRun{results: map[string]commandResult{
		"passwd 1001": {stdout: []byte(account)}, "-s files passwd 1001": {stdout: []byte(account)},
		"initgroups alice": {stdout: []byte("alice 1001\n")}, "group 1001": {stdout: []byte("staff:x:1001:\n")},
	}})
	if facts, err := r.DirectoryFactsForUID(1001, time.Now()); err == nil || !strings.Contains(err.Error(), "offline") {
		t.Fatalf("facts = %+v, %v; an offline domain cannot prove UID ownership", facts, err)
	}
	if err := ConfirmLocalAccount(r, 1001, "alice"); err == nil {
		t.Fatal("ConfirmLocalAccount certified a UID while SSSD was offline")
	}
}

func TestW4B2SameNameLDAPEntriesShareUID(t *testing.T) {
	const uid = 41201
	const line = "alice:*:41201:41201::/home/alice:/bin/bash\n"
	accountHost(t, "root:x:0:0::/root:/bin/sh\n", "", "passwd: files ldap\ngroup: files\n")
	startFakeNSLCD(t, &fakeNSLCD{
		passwd: map[string]Account{"uid:41201": {Name: "alice", UID: uid, GID: uid}},
		more:   map[string][]Account{"uid:41201": {{Name: "alice", UID: uid, GID: uid, Home: "/different-search-base"}}},
	})
	r := newFakeNSS(&fakeRun{results: map[string]commandResult{
		"passwd 41201": {stdout: []byte(line)}, "-s ldap passwd 41201": {stdout: []byte(line)},
	}})
	_, err := r.DirectoryFactsWithoutGroupsForUID(uid, time.Now())
	var shared *SharedUIDError
	if !errors.As(err, &shared) || len(shared.Accounts) != 2 {
		t.Fatalf("same-name LDAP holders: %v; want both entries counted", err)
	}
}
