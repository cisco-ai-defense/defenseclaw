//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// sssdConfiguredHost makes sssdConfigured true for the test, with SSSD's
// NSS responder stopped until the test starts a fake one.
func sssdConfiguredHost(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	oldConf, oldSocket := sssdConfPath, sssdNSSSocket
	t.Cleanup(func() { sssdConfPath, sssdNSSSocket = oldConf, oldSocket })
	sssdConfPath, sssdNSSSocket = filepath.Join(dir, "sssd.conf"), filepath.Join(dir, "no-sssd", "nss")
	writeTestFile(t, sssdConfPath, "[sssd]\ndomains = corp.example.com\n")
}

// Review of GAP-0212 (loop 4): getent group exits 2 both when no group has
// a gid and when the directory cannot answer, so a membership LDAP confirmed
// (gid 5200) kept its gid as a number while getent group 5200 failed: a
// strict assignment by the group's name missed it, and the lookup did not
// fail. A gid getent names no group for stays a number only once every
// directory service of the group line shows it has none; nslcd's completed
// search for the gid names it.
//
// r104 identity: a gid whose lack of a name is not proved is reported in
// UnconfirmedGroups (never a name another provider gives on its own), and
// the gateway treats every group entry it may be as possibly matching.
// Either that, or a failed lookup, is fail closed; a proven number is not.
func TestAnUnnamedGroupNeedsADefinitiveMiss(t *testing.T) {
	localLine := []byte("alice:x:1001:5100::/home/alice:/bin/sh\n")
	results := map[string]commandResult{
		"passwd 1001": {stdout: localLine}, "passwd alice": {stdout: localLine},
		"-s files passwd 1001":     {stdout: localLine},
		"-s ldap initgroups alice": {stdout: []byte("alice 5200\n")},
		"-s nis initgroups alice":  {stdout: []byte("alice 5200\n")},
		// getent group 5100 and 5200 exit 2 (the fake's default).
	}
	members := map[string][]int{"alice": {5200}}
	for _, tc := range []struct {
		name, nss  string
		nslcd      *fakeNSLCD
		sssd       string // "", "stopped" or "running"
		ok         bool
		wantGroups []string
	}{
		{"nslcd names the group, glibc did not", "group: files ldap\n",
			&fakeNSLCD{members: members, groups: map[int]string{5200: "strict-devs"}}, "", false, nil},
		{"nslcd's search for the gid fails", "group: files ldap\n",
			&fakeNSLCD{members: members, groups: map[int]string{5200: "strict-devs"}, incomplete: map[string]bool{"gid:5200": true}}, "", false, nil},
		{"nslcd is down for the gid", "group: files ldap\n", nil, "", false, nil},
		{"nslcd completes and holds no such group", "group: files ldap\n",
			&fakeNSLCD{members: members}, "", true, []string{"5100", "5200", "local-team"}},
		{"NIS cannot show a miss", "group: files nis\n", nil, "", false, nil},
		{"SSSD stopped", "group: files ldap sss\n", &fakeNSLCD{members: members}, "stopped", false, nil},
		{"SSSD answers", "group: files ldap sss\n", &fakeNSLCD{members: members}, "running", true, []string{"5100", "5200", "local-team"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			accountHost(t, string(localLine), "local-team:x:7000:alice\n", "passwd: files\n"+tc.nss)
			if tc.nslcd != nil {
				startFakeNSLCD(t, tc.nslcd)
			}
			switch tc.sssd {
			case "stopped":
				sssdConfiguredHost(t)
			case "running":
				sssdConfiguredHost(t)
				startFakeSSSD(t, nil)
			}
			facts, err := newFakeNSS(&fakeRun{results: results}).DirectoryFactsForUID(1001, time.Now())
			// ok: every gid is proven. Otherwise the lookup fails or
			// reports 5200 unconfirmed, and no provider's own name for it
			// is taken.
			proven := err == nil && !slices.Contains(facts.UnconfirmedGroups, "5200")
			if tc.ok != proven || slices.Contains(facts.Groups, "strict-devs") {
				t.Fatalf("facts = %+v, %v; want proven %v", facts, err, tc.ok)
			}
			if got := slices.Sorted(slices.Values(facts.Groups)); tc.ok && !slices.Equal(got, tc.wantGroups) {
				t.Fatalf("groups = %v, want %v", got, tc.wantGroups)
			}
		})
	}
	// A directory account: SSSD lists gid 5300, which getent cannot name
	// while SSSD stopped answering after initgroups.
	t.Run("directory account", func(t *testing.T) {
		line := []byte("bob:*:41301:41301::/home/bob:/bin/bash\n")
		accountHost(t, "root:x:0:0::/root:/bin/sh\n", "", "passwd: files ldap\ngroup: files ldap\n")
		startFakeNSLCD(t, &fakeNSLCD{passwd: map[string]Account{"uid:41301": {Name: "bob", UID: 41301, GID: 41301}},
			incomplete: map[string]bool{"gid:5300": true}})
		r := newFakeNSS(&fakeRun{results: map[string]commandResult{
			"passwd 41301": {stdout: line}, "-s ldap passwd 41301": {stdout: line},
			"initgroups bob": {stdout: []byte("bob 41301 5300\n")}, "group 41301 5300": {stdout: []byte("bob:*:41301:\n"), exitCode: getentExitNotFound},
		}})
		if facts, err := r.DirectoryFactsForUID(41301, time.Now()); err == nil && !slices.Contains(facts.UnconfirmedGroups, "5300") {
			t.Fatalf("facts = %+v; want gid 5300 unconfirmed while LDAP cannot name it", facts)
		}
	})
}

// Review of GAP-0551 (loop 4): with files before a directory on the passwd
// line, a directory that did not answer for the uid was skipped, so a
// logged-in LDAP account sharing a local uid got the local account's facts
// while its lookup timed out. Two accounts of one uid inside one service
// passed too. Whether the uid is shared must now be shown: a directory's
// "no such account" counts only when it is definitive (nslcd completes the
// search), and the entries of /etc/passwd and nslcd's search by uid are
// counted.
func TestUIDOwnershipNeedsADefinitiveAnswer(t *testing.T) {
	const uid = 1001
	localLine := "alice:x:1001:1001::/home/alice:/bin/bash\n"
	localResults := func() map[string]commandResult {
		return map[string]commandResult{
			"passwd 1001": {stdout: []byte(localLine)}, "-s files passwd 1001": {stdout: []byte(localLine)},
			"initgroups alice": {stdout: []byte("alice 1001\n")}, "group 1001": {stdout: []byte("alice:x:1001:\n")},
		}
	}
	shared := func(t *testing.T, err error) {
		t.Helper()
		var sharedErr *SharedUIDError
		if !errors.As(err, &sharedErr) {
			t.Fatalf("err = %v; want the uid refused as held by two accounts", err)
		}
	}
	for _, tc := range []struct {
		name  string
		nslcd *fakeNSLCD
		errs  map[string]error
		ok    bool
	}{
		{"nslcd's uid search fails", &fakeNSLCD{incomplete: map[string]bool{"uid:1001": true}}, nil, false},
		{"nslcd is down", nil, nil, false},
		{"getent times out", &fakeNSLCD{}, map[string]error{"-s ldap passwd 1001": errors.New("getent timed out")}, false},
		{"nslcd completes and holds none", &fakeNSLCD{}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			accountHost(t, localLine, "alice:x:1001:\n", "passwd: files ldap\ngroup: files\n")
			if tc.nslcd != nil {
				startFakeNSLCD(t, tc.nslcd)
			}
			r := newFakeNSS(&fakeRun{results: localResults(), errs: tc.errs})
			facts, err := r.DirectoryFactsForUID(uid, time.Now())
			if tc.ok != (err == nil) || tc.ok && facts.Directory != useridentity.DirectoryLocal {
				t.Fatalf("facts = %+v, %v; want ok %v", facts, err, tc.ok)
			}
			if err := ConfirmLocalAccount(NewCachingResolver(r), uid, "alice"); tc.ok != (err == nil) {
				t.Fatalf("ConfirmLocalAccount = %v; want ok %v", err, tc.ok)
			}
		})
	}
	t.Run("nslcd holds the uid under another name", func(t *testing.T) {
		accountHost(t, localLine, "alice:x:1001:\n", "passwd: files ldap\n")
		startFakeNSLCD(t, &fakeNSLCD{passwd: map[string]Account{"uid:1001": {Name: "mallory", UID: uid}}})
		_, err := newFakeNSS(&fakeRun{results: localResults()}).DirectoryFactsForUID(uid, time.Now())
		if err == nil {
			t.Fatal("a local account's facts were served while nslcd holds another account of its uid")
		}
	})
	t.Run("two LDAP accounts of one uid", func(t *testing.T) {
		line := []byte("alice:*:41201:41201::/home/alice:/bin/bash\n")
		accountHost(t, "root:x:0:0::/root:/bin/sh\n", "", "passwd: files ldap\ngroup: files\n")
		startFakeNSLCD(t, &fakeNSLCD{
			passwd: map[string]Account{"uid:41201": {Name: "alice", UID: 41201}},
			more:   map[string][]Account{"uid:41201": {{Name: "alice2", UID: 41201}}},
		})
		r := newFakeNSS(&fakeRun{results: map[string]commandResult{
			"passwd 41201": {stdout: line}, "-s ldap passwd 41201": {stdout: line},
		}})
		_, err := r.DirectoryFactsWithoutGroupsForUID(41201, time.Now())
		shared(t, err)
	})
	t.Run("two /etc/passwd entries of one uid", func(t *testing.T) {
		accountHost(t, localLine+"alice2:x:1001:1001::/home/alice2:/bin/bash\n", "alice:x:1001:\n", "passwd: files\n")
		r := newFakeNSS(&fakeRun{results: localResults()})
		_, err := r.DirectoryFactsForUID(uid, time.Now())
		shared(t, err)
		shared(t, ConfirmLocalAccount(r, uid, "alice"))
	})
	t.Run("ConfirmLocalAccount names the NSS owner only", func(t *testing.T) {
		const sid = "S-1-5-21-7-7-7-1001"
		adLine := "alice:*:1001:1001:Alice (CORP):/home/alice:/bin/bash\n"
		accountHost(t, localLine, "", "passwd: sss files\n")
		startFakeSSSD(t, map[string]string{"uid:1001": sid, "sid:" + sid: "1001"})
		r := newFakeNSS(&fakeRun{results: map[string]commandResult{
			"passwd 1001": {stdout: []byte(adLine)}, "-s sss passwd 1001": {stdout: []byte(adLine)},
		}})
		if err := ConfirmLocalAccount(r, uid, "alice"); err == nil {
			t.Fatal("ConfirmLocalAccount took an SSSD account for the local one")
		}
		accountHost(t, localLine, "", "passwd: files\n")
		if err := ConfirmLocalAccount(newFakeNSS(&fakeRun{results: localResults()}), uid, "alice"); err != nil {
			t.Fatalf("ConfirmLocalAccount of a plain local account = %v", err)
		}
		if err := ConfirmLocalAccount(NewOSUserResolver(t.Context()), uid, "alice"); err == nil {
			t.Fatal("a resolver that cannot ask NSS services confirmed the account")
		}
	})
	t.Run("bare name while ownership is unknown", func(t *testing.T) {
		sameNameHost(t, func(context.Context) ([]Realm, error) { return nil, nil }, "", "passwd: files ldap\n")
		accountHost(t, localLine, "", "passwd: files ldap\n")
		// nslcd completes the search by name (no LDAP alice), not the one
		// by uid.
		startFakeNSLCD(t, &fakeNSLCD{incomplete: map[string]bool{"uid:1001": true}})
		r := newFakeNSS(&fakeRun{results: map[string]commandResult{
			"passwd alice": {stdout: []byte(localLine)}, "-s files passwd alice": {stdout: []byte(localLine)},
			"passwd 1001": {stdout: []byte(localLine)}, "-s files passwd 1001": {stdout: []byte(localLine)},
		}})
		twins, err := SameNameAccounts(t.Context(), r, Account{Name: "alice", UID: uid})
		var unknown *useridentity.NamesakesUnknownError
		if len(twins) != 0 || !errors.As(err, &unknown) || !strings.Contains(err.Error(), "uid 1001") {
			t.Fatalf("twins = %+v, %v; want the bare name refused while nslcd cannot show who holds the uid", twins, err)
		}
	})
}
