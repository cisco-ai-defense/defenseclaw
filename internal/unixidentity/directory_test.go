//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// TestDirectoryFactsFailAsAWholeNotInPart: a getent that timed out for the
// groups, or for the directory service that owns the account, used to
// leave facts without groups (or taking the account for a local one) that
// the gateway cached as resolved for 15 minutes: the account selected the
// default profile as "default", not "default_lookup_failed" (GAP-0114).
// Now the lookup fails, and an account in more groups than are named has
// no facts rather than part of its membership.
func TestDirectoryFactsFailAsAWholeNotInPart(t *testing.T) {
	nss := filepath.Join(t.TempDir(), "nsswitch.conf")
	if err := os.WriteFile(nss, []byte("passwd: sss files\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := nsswitchPath
	nsswitchPath = nss
	t.Cleanup(func() { nsswitchPath = orig })
	const account = "alice@corp.example.com:*:1001:1001::/home/alice:/bin/bash\n"
	const owns, initgroups, groups = "-s sss passwd 1001", "initgroups alice@corp.example.com", "group 1001 5001 5002"
	fake := func() *fakeRun {
		return &fakeRun{errs: map[string]error{}, results: map[string]commandResult{
			"passwd 1001": {stdout: []byte(account)},
			owns:          {stdout: []byte(account)},
			initgroups:    {stdout: []byte("alice@corp.example.com 1001 5001 5002\n")},
			// getent exits 2 with the groups it found when one id has none.
			groups: {exitCode: getentExitNotFound, stdout: []byte("alice@corp.example.com:*:1001:\nml-team@corp.example.com:*:5001:\n")},
		}}
	}
	facts, err := newFakeNSS(fake()).DirectoryFactsForUID(1001, time.Now())
	if err != nil || facts.Source != useridentity.SourceSSSD ||
		!reflect.DeepEqual(facts.Groups, []string{"alice@corp.example.com", "ml-team@corp.example.com", "5002"}) {
		t.Fatalf("facts = %+v, %v", facts, err)
	}

	// A directory that says the account is not its own: a local account.
	f := fake()
	delete(f.results, owns)
	if facts, err := newFakeNSS(f).DirectoryFactsForUID(1001, time.Now()); err != nil || facts.Directory != useridentity.DirectoryLocal {
		t.Fatalf("local facts = %+v, %v", facts, err)
	}

	// A lookup that did not finish, or failed, is no facts at all.
	for _, step := range []string{owns, initgroups, groups} {
		f := fake()
		f.errs[step] = errors.New("getent timed out")
		if facts, err := newFakeNSS(f).DirectoryFactsForUID(1001, time.Now()); err == nil {
			t.Errorf("%q timed out: facts = %+v, want an error", step, facts)
		}
	}
	f = fake()
	f.results[groups] = commandResult{exitCode: 1}
	if facts, err := newFakeNSS(f).DirectoryFactsForUID(1001, time.Now()); err == nil {
		t.Errorf("getent group exit 1: facts = %+v, want an error", facts)
	}

	// 400 groups are all named (with the primary group); more than the
	// bound fail.
	for _, tc := range []struct {
		count int
		fails bool
	}{{400, false}, {maxDirectoryGroups - 1, false}, {maxDirectoryGroups, true}} {
		var ids, lines []string
		for i := range tc.count {
			ids = append(ids, fmt.Sprint(7000+i))
			lines = append(lines, fmt.Sprintf("g%d@corp.example.com:*:%d:", i, 7000+i))
		}
		f := fake()
		f.results[initgroups] = commandResult{stdout: []byte("alice@corp.example.com 1001 " + strings.Join(ids, " ") + "\n")}
		f.results["group 1001 "+strings.Join(ids, " ")] = commandResult{stdout: []byte(strings.Join(lines, "\n") + "\n")}
		facts, err := newFakeNSS(f).DirectoryFactsForUID(1001, time.Now())
		if (err != nil) != tc.fails || (err == nil && len(facts.Groups) != tc.count+1) {
			t.Errorf("%d groups: %d named, err %v", tc.count, len(facts.Groups), err)
		}
	}
}
