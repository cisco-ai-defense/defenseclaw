//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// accountHost points the local account files, nsswitch.conf and the
// directory sockets at test files; nothing answers until a test says so.
func accountHost(t *testing.T, passwd, group, nss string) {
	t.Helper()
	dir := t.TempDir()
	oldPasswd, oldGroup, oldNSS, oldSamba, oldSocket, oldPipes := localPasswdPath, localGroupPath, nsswitchPath, sambaConfPath, sssdNSSSocket, winbindPipes
	t.Cleanup(func() {
		localPasswdPath, localGroupPath, nsswitchPath, sambaConfPath, sssdNSSSocket, winbindPipes = oldPasswd, oldGroup, oldNSS, oldSamba, oldSocket, oldPipes
	})
	localPasswdPath, localGroupPath, nsswitchPath = filepath.Join(dir, "passwd"), filepath.Join(dir, "group"), filepath.Join(dir, "nsswitch.conf")
	sambaConfPath, sssdNSSSocket = filepath.Join(dir, "smb.conf"), filepath.Join(dir, "no-sssd", "nss")
	winbindPipes = []string{filepath.Join(dir, "no-winbind", "pipe")}
	writeTestFile(t, localPasswdPath, passwd)
	writeTestFile(t, localGroupPath, group)
	writeTestFile(t, nsswitchPath, nss)
}

// Review of GAP-0550 (loop 1): getent answers a member-list directory that
// cannot be reached (nslcd without LDAP, ypbind down) the way it answers one
// that lists nothing: "no such account" and an initgroups line with no
// group. Such an answer counts only once the directory shows that it
// answers, so a strict profile's LDAP group is not dropped for a local or a
// directory account; compat asks NIS only for the + lines of /etc/group.
func TestMemberListDirectoryMustShowItAnswers(t *testing.T) {
	localLine := []byte("alice:x:1001:5100::/home/alice:/bin/sh\n")
	local := Account{Name: "alice", UID: 1001, GID: 5100}
	localResults := func(extra map[string]commandResult) map[string]commandResult {
		results := map[string]commandResult{
			"passwd 1001": {stdout: localLine}, "passwd alice": {stdout: localLine},
			"-s ldap initgroups alice": {stdout: []byte("alice\n")},
		}
		for key, result := range extra {
			results[key] = result
		}
		return results
	}
	const ldapNSS = "passwd: files ldap\ninitgroups: files ldap\ngroup: files ldap\n"
	for _, tc := range []struct {
		name  string
		nslcd *fakeNSLCD
		ok    bool
	}{
		{"nslcd does not answer", nil, false},
		{"nslcd does not complete the search", &fakeNSLCD{incomplete: map[string]bool{"member:alice": true}}, false},
		{"nslcd completes it with no group", &fakeNSLCD{}, true},
	} {
		t.Run("local account/"+tc.name, func(t *testing.T) {
			accountHost(t, string(localLine), "local-team:x:7000:alice\n", ldapNSS)
			if tc.nslcd != nil {
				startFakeNSLCD(t, tc.nslcd)
			}
			r := newFakeNSS(&fakeRun{results: localResults(nil)})
			ids, err := r.GroupIDs(local)
			if tc.ok != (err == nil) {
				t.Fatalf("group ids = %v, %v; want ok %v", ids, err, tc.ok)
			}
			facts, err := r.DirectoryFactsForUID(1001, time.Now())
			if tc.ok != (err == nil) || tc.ok && !reflect.DeepEqual(facts.Groups, []string{"5100", "local-team"}) {
				t.Fatalf("facts = %+v, %v; want ok %v", facts, err, tc.ok)
			}
		})
	}

	t.Run("directory account", func(t *testing.T) {
		bobLine := []byte("bob:*:70001:70001::/home/bob:/bin/sh\n")
		accountHost(t, "", "", "passwd: files sss\ninitgroups: sss ldap\ngroup: sss ldap\n")
		results := map[string]commandResult{
			"passwd bob": {stdout: bobLine}, "-s sss passwd bob": {stdout: bobLine},
			"initgroups bob": {stdout: []byte("bob 70001 7100\n")}, "-s ldap initgroups bob": {stdout: []byte("bob\n")},
		}
		bob := Account{Name: "bob", UID: 70001, GID: 70001}
		if ids, err := newFakeNSS(&fakeRun{results: results}).GroupIDs(bob); err == nil {
			t.Fatalf("group ids = %v without LDAP showing that it answers", ids)
		}
		startFakeNSLCD(t, &fakeNSLCD{})
		if ids, err := newFakeNSS(&fakeRun{results: results}).GroupIDs(bob); err != nil || !reflect.DeepEqual(ids, []int{7100, 70001}) {
			t.Fatalf("group ids = %v, %v; want [7100 70001]", ids, err)
		}
	})

	t.Run("compat", func(t *testing.T) {
		const nss = "passwd: files\ngroup: compat\n"
		accountHost(t, string(localLine), "local-team:x:7000:alice\n", nss)
		r := newFakeNSS(&fakeRun{results: localResults(nil)})
		if facts, err := r.DirectoryFactsForUID(1001, time.Now()); err != nil || !reflect.DeepEqual(facts.Groups, []string{"5100", "local-team"}) {
			t.Fatalf("facts = %+v, %v; compat without a + line asks no NIS", facts, err)
		}
		accountHost(t, string(localLine), "local-team:x:7000:alice\n+:::\n", nss)
		if facts, err := r.DirectoryFactsForUID(1001, time.Now()); err == nil {
			t.Fatalf("facts = %+v while the NIS a + line includes does not answer", facts)
		}
	})
}

// Review of GAP-1131 (loop 1): a bare name is checked against each passwd
// service on its own, so a twin behind the account NSS answers first is
// found (an LDAP or NIS account behind a local one, the local account behind
// an SSSD one), a service that does not show it answers leaves the name
// unknown, and the domains of the SSSD configuration are asked next to the
// ones realmd lists.
func TestSameNameAccountsAsksEveryProvider(t *testing.T) {
	localLine := "alice:x:1001:1001::/home/alice:/bin/bash\n"
	local := Account{Name: "alice", UID: 1001}
	noRealm := func(context.Context) ([]Realm, error) { return nil, nil }
	corpRealm := func(context.Context) ([]Realm, error) {
		return []Realm{{Name: "CORP.EXAMPLE", Domain: "corp.example"}}, nil
	}
	refused := func(t *testing.T, twins []Account, err error) {
		t.Helper()
		var unknown *useridentity.NamesakesUnknownError
		if len(twins) != 0 || !errors.As(err, &unknown) {
			t.Fatalf("twins = %+v, %v; want the bare name refused", twins, err)
		}
	}
	twinOf := func(t *testing.T, twins []Account, err error, uid int) {
		t.Helper()
		if err != nil || len(twins) != 1 || twins[0].UID != uid {
			t.Fatalf("twins = %+v, %v; want the account of uid %d", twins, err, uid)
		}
	}
	host := func(t *testing.T, realms func(context.Context) ([]Realm, error), krb5, passwd, nss string) {
		sameNameHost(t, realms, krb5, nss)
		accountHost(t, passwd, "", nss)
	}

	t.Run("LDAP twin of a local account", func(t *testing.T) {
		host(t, noRealm, "", localLine, "passwd: files ldap\n")
		r := newFakeNSS(&fakeRun{results: map[string]commandResult{
			"passwd alice":          {stdout: []byte(localLine)},
			"-s files passwd alice": {stdout: []byte(localLine)},
			"-s ldap passwd alice":  {stdout: []byte("alice:*:7001:7001::/home/alice:/bin/bash\n")},
		}})
		twins, err := SameNameAccounts(context.Background(), r, local)
		twinOf(t, twins, err, 7001)
	})
	t.Run("LDAP that does not answer", func(t *testing.T) {
		host(t, noRealm, "", localLine, "passwd: files ldap\n")
		results := map[string]commandResult{"passwd alice": {stdout: []byte(localLine)}}
		twins, err := SameNameAccounts(context.Background(), newFakeNSS(&fakeRun{results: results}), local)
		refused(t, twins, err)
		startFakeNSLCD(t, &fakeNSLCD{})
		if twins, err := SameNameAccounts(context.Background(), newFakeNSS(&fakeRun{results: results}), local); err != nil || len(twins) != 0 {
			t.Fatalf("twins = %+v, %v; an answering LDAP without the name leaves the local account", twins, err)
		}
	})
	t.Run("local twin of an SSSD account", func(t *testing.T) {
		host(t, noRealm, "", localLine, "passwd: sss files\n")
		sssdLine := "alice:*:2001:2001::/home/alice:/bin/bash\n"
		r := newFakeNSS(&fakeRun{results: map[string]commandResult{
			"passwd alice":          {stdout: []byte(sssdLine)},
			"-s sss passwd alice":   {stdout: []byte(sssdLine)},
			"-s files passwd alice": {stdout: []byte(localLine)},
		}})
		twins, err := SameNameAccounts(context.Background(), r, Account{Name: "alice", UID: 2001})
		twinOf(t, twins, err, 1001)
	})
	t.Run("NIS twin through compat", func(t *testing.T) {
		results := map[string]commandResult{
			"passwd alice":        {stdout: []byte(localLine)},
			"-s nis passwd alice": {stdout: []byte("alice:*:7002:7002::/home/alice:/bin/bash\n")},
		}
		host(t, noRealm, "", localLine+"+@staff::::::\n", "passwd: compat\n")
		twins, err := SameNameAccounts(context.Background(), newFakeNSS(&fakeRun{results: results}), local)
		twinOf(t, twins, err, 7002)
		host(t, noRealm, "", localLine, "passwd: compat\n")
		if twins, err := SameNameAccounts(context.Background(), newFakeNSS(&fakeRun{results: results}), local); err != nil || len(twins) != 0 {
			t.Fatalf("twins = %+v, %v; compat without a + line asks no NIS", twins, err)
		}
	})
	t.Run("a second SSSD domain realmd does not list", func(t *testing.T) {
		for name, configure := range map[string]func(t *testing.T){
			"sssd.conf": func(t *testing.T) {
				writeTestFile(t, sssdConfPath, "[sssd]\ndomains = corp.example, other.example\n")
			},
			"a conf.d snippet": func(t *testing.T) {
				writeTestFile(t, filepath.Join(sssdConfDir, "other.conf"), "[domain/other.example]\nid_provider = ldap\n")
			},
		} {
			t.Run(name, func(t *testing.T) {
				host(t, corpRealm, "", localLine, "passwd: files sss\n")
				configure(t)
				startFakeSSSD(t, nil)
				r := newFakeNSS(&fakeRun{results: map[string]commandResult{
					"passwd alice":               {stdout: []byte(localLine)},
					"passwd alice@other.example": {stdout: []byte("alice@other.example:*:3001:3001::/home/alice:/bin/bash\n")},
				}})
				twins, err := SameNameAccounts(context.Background(), r, local)
				twinOf(t, twins, err, 3001)
			})
		}
		t.Run("a domain without a DNS name", func(t *testing.T) {
			host(t, corpRealm, "", localLine, "passwd: files sss\n")
			writeTestFile(t, filepath.Join(sssdConfDir, "ldap.conf"), "[domain/LDAP]\nid_provider = ldap\n")
			startFakeSSSD(t, nil)
			r := newFakeNSS(&fakeRun{results: map[string]commandResult{
				"passwd alice":      {stdout: []byte(localLine)},
				"passwd alice@ldap": {stdout: []byte("alice@ldap:*:3002:3002::/home/alice:/bin/bash\n")},
			}})
			twins, err := SameNameAccounts(context.Background(), r, local)
			twinOf(t, twins, err, 3002)
		})
	})
	t.Run("only part of the domains known", func(t *testing.T) {
		failing := func(context.Context) ([]Realm, error) { return nil, errors.New("realmd timed out") }
		host(t, failing, "[libdefaults]\n  default_realm = CORP.EXAMPLE\n", localLine, "passwd: files sss\n")
		// sssd.conf is there but cannot be read (root only); a directory in
		// its place reads as unreadable to root too.
		if err := os.MkdirAll(sssdConfPath, 0o755); err != nil {
			t.Fatal(err)
		}
		startFakeSSSD(t, nil)
		r := newFakeNSS(&fakeRun{results: map[string]commandResult{"passwd alice": {stdout: []byte(localLine)}}})
		twins, err := SameNameAccounts(context.Background(), r, local)
		refused(t, twins, err)
	})
	t.Run("SSSD that does not answer", func(t *testing.T) {
		host(t, corpRealm, "", localLine, "passwd: files sss\n")
		writeTestFile(t, sssdConfPath, "[sssd]\ndomains = corp.example\n")
		r := newFakeNSS(&fakeRun{results: map[string]commandResult{"passwd alice": {stdout: []byte(localLine)}}})
		twins, err := SameNameAccounts(context.Background(), r, local)
		refused(t, twins, err)
		startFakeSSSD(t, nil)
		if twins, err := SameNameAccounts(context.Background(), r, local); err != nil || len(twins) != 0 {
			t.Fatalf("twins = %+v, %v; an answering SSSD without the name leaves the local account", twins, err)
		}
	})
	t.Run("winbind that does not answer", func(t *testing.T) {
		host(t, corpRealm, "", localLine, "passwd: files winbind\n")
		writeTestFile(t, sambaConfPath, "[global]\nworkgroup = CORP\n")
		r := newFakeNSS(&fakeRun{results: map[string]commandResult{"passwd alice": {stdout: []byte(localLine)}}})
		twins, err := SameNameAccounts(context.Background(), r, local)
		refused(t, twins, err)
		if !strings.Contains(err.Error(), "winbindd") {
			t.Fatalf("refusal %v does not name winbindd", err)
		}
	})
}

// Review of GAP-0551 (loop 1): the incarnation of an account tells two
// accounts of one name, uid and home apart by the SID SSSD holds for the
// uid; it is unknown while SSSD does not answer.
func TestAccountIncarnation(t *testing.T) {
	const uid = 41101
	line := []byte("alice:*:41101:41101::/home/alice:/bin/bash\n")
	accountHost(t, "root:x:0:0::/root:/bin/sh\n", "", "passwd: files sss\n")
	r := newFakeNSS(&fakeRun{results: map[string]commandResult{"-s sss passwd 41101": {stdout: line}}})
	if got, known := r.AccountIncarnation(uid, "alice"); known || got != "" {
		t.Fatalf("incarnation while SSSD is stopped = %q, %v; want unknown", got, known)
	}
	const corp, other = "S-1-5-21-1-1-1-1105", "S-1-5-21-2-2-2-1105"
	startFakeSSSD(t, map[string]string{"uid:41101": corp, "sid:" + corp: "41101"})
	if got, known := r.AccountIncarnation(uid, "alice"); !known || got != "sid:"+corp {
		t.Fatalf("incarnation = %q, %v; want sid:%s", got, known, corp)
	}
	startFakeSSSD(t, map[string]string{"uid:41101": other, "sid:" + other: "41101"})
	if got, _ := r.AccountIncarnation(uid, "alice"); got != "sid:"+other {
		t.Fatalf("incarnation of the other domain's account = %q", got)
	}
	startFakeSSSD(t, nil)
	if got, known := r.AccountIncarnation(uid, "alice"); !known || got != "sss" {
		t.Fatalf("incarnation of an SSSD account without a SID = %q, %v", got, known)
	}
	if got, known := newFakeNSS(&fakeRun{}).AccountIncarnation(uid, "alice"); known || got != "" {
		t.Fatalf("incarnation of an account no NSS service holds = %q, %v; want unknown", got, known)
	}
	if got, known := r.AccountIncarnation(0, "root"); !known || got != "files" {
		t.Fatalf("incarnation of a local account = %q, %v", got, known)
	}
}
