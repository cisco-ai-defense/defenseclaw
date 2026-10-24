//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// The tests of this package never read the SSSD publications of the host
// they run on or ask its winbind: a test that needs them says so.
func init() {
	sssdPubconfKrb5Dir = filepath.Join(os.TempDir(), "defenseclaw-test-no-sss-pubconf")
	winbindTrustedDomains = func(context.Context) ([]string, error) { return nil, nil }
}

// listenWinbindd stands in for a winbindd that accepts connections.
func listenWinbindd(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pipe")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	previous := winbindPipes
	winbindPipes = []string{path}
	t.Cleanup(func() { winbindPipes = previous; ln.Close() })
}

// Review of GAP-1131 (loop 2): realmd names only the realms it joined, so a
// realm it lists does not make the list of domains whole. While SSSD serves
// accounts and its configuration cannot be read in full, a bare name is
// refused whatever realmd lists, and the trusted subdomains SSSD publishes,
// the configured trusted child domains and the domains winbind serves are
// asked for a twin too. With qualified names a bare lookup asks none of
// them, so the twin went unseen and the local account was taken.
func TestSameNameAccountsDoesNotStopAtRealmdsRealms(t *testing.T) {
	ctx := context.Background()
	localLine := "alice:x:1001:1001::/home/alice:/bin/bash\n"
	local := Account{Name: "alice", UID: 1001}
	corp := func(context.Context) ([]Realm, error) {
		return []Realm{{Name: "CORP.EXAMPLE", Domain: "corp.example", ClientSoftware: "sssd"}}, nil
	}
	host := func(t *testing.T, nss string) {
		t.Helper()
		sameNameHost(t, corp, "", nss)
		accountHost(t, localLine, "", nss)
	}
	resolver := func(twinName, twinLine string) *NSSResolver {
		results := map[string]commandResult{
			"passwd alice":          {stdout: []byte(localLine)},
			"-s files passwd alice": {stdout: []byte(localLine)},
		}
		if twinName != "" {
			results["passwd "+twinName] = commandResult{stdout: []byte(twinLine)}
		}
		return newFakeNSS(&fakeRun{results: results})
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
	const otherTwin = "alice@other.example:*:3001:3001::/home/alice:/bin/bash\n"

	t.Run("SSSD configuration that cannot be read", func(t *testing.T) {
		for name, listed := range map[string]func(){
			"realmd lists a realm": func() {},
			"realmd listed one before": func() {
				hostRealms = func(context.Context) ([]Realm, error) { return nil, errors.New("realmd timed out") }
				lastListedRealms = func() []Realm { return []Realm{{Name: "CORP.EXAMPLE", Domain: "corp.example"}} }
			},
		} {
			t.Run(name, func(t *testing.T) {
				host(t, "passwd: files sss\n")
				listed()
				// sssd.conf is readable by root only; a directory in its
				// place reads as unreadable to root too.
				if err := os.MkdirAll(sssdConfPath, 0o755); err != nil {
					t.Fatal(err)
				}
				startFakeSSSD(t, nil)
				twins, err := SameNameAccounts(ctx, resolver("alice@other.example", otherTwin), local)
				refused(t, twins, err)
			})
		}
	})
	t.Run("SSSD configuration read in full", func(t *testing.T) {
		host(t, "passwd: files sss\n")
		writeTestFile(t, sssdConfPath, "[sssd]\ndomains = corp.example\n[domain/corp.example]\nid_provider = ad\n")
		startFakeSSSD(t, nil)
		if twins, err := SameNameAccounts(ctx, resolver("", ""), local); err != nil || len(twins) != 0 {
			t.Fatalf("twins = %+v, %v; every domain is known and none holds the name", twins, err)
		}
	})
	t.Run("a trusted subdomain SSSD published", func(t *testing.T) {
		host(t, "passwd: files sss\n")
		writeTestFile(t, sssdConfPath, "[sssd]\ndomains = corp.example\n")
		previous := sssdPubconfKrb5Dir
		t.Cleanup(func() { sssdPubconfKrb5Dir = previous })
		sssdPubconfKrb5Dir = t.TempDir()
		writeTestFile(t, filepath.Join(sssdPubconfKrb5Dir, "domain_realm_corp_example"),
			"[domain_realm]\n.child.corp.example = CHILD.CORP.EXAMPLE\nchild.corp.example = CHILD.CORP.EXAMPLE\n")
		startFakeSSSD(t, nil)
		twins, err := SameNameAccounts(ctx, resolver("alice@child.corp.example", "alice@child.corp.example:*:3002:3002::/home/alice:/bin/bash\n"), local)
		twinOf(t, twins, err, 3002)
	})
	t.Run("a configured trusted child domain", func(t *testing.T) {
		host(t, "passwd: files sss\n")
		writeTestFile(t, sssdConfPath, "[sssd]\ndomains = corp.example\n")
		useridentity.SetTrustedADChildDomains([]string{"emea.corp.example"})
		t.Cleanup(func() { useridentity.SetTrustedADChildDomains(nil) })
		startFakeSSSD(t, nil)
		twins, err := SameNameAccounts(ctx, resolver("alice@emea.corp.example", "alice@emea.corp.example:*:3003:3003::/home/alice:/bin/bash\n"), local)
		twinOf(t, twins, err, 3003)
	})
	t.Run("domains winbind serves", func(t *testing.T) {
		winbind := func(t *testing.T, smb string, trusts func(context.Context) ([]string, error)) {
			t.Helper()
			host(t, "passwd: files winbind\n")
			writeTestFile(t, sambaConfPath, smb)
			listenWinbindd(t)
			previous := winbindTrustedDomains
			t.Cleanup(func() { winbindTrustedDomains = previous })
			winbindTrustedDomains = trusts
		}
		const smb = "[global]\nworkgroup = CORP\nsecurity = ads\n"
		twinLine := `OTHER\alice:*:3004:3004::/home/alice:/bin/bash` + "\n"
		winbind(t, smb, func(context.Context) ([]string, error) { return []string{"CORP", "OTHER"}, nil })
		twins, err := SameNameAccounts(ctx, resolver(`OTHER\alice`, twinLine), local)
		twinOf(t, twins, err, 3004)

		winbind(t, smb, func(context.Context) ([]string, error) {
			return nil, errors.New("wbinfo -m: could not obtain domain list")
		})
		twins, err = SameNameAccounts(ctx, resolver(`OTHER\alice`, twinLine), local)
		refused(t, twins, err)

		asked := false
		winbind(t, smb+"allow trusted domains = no\n", func(context.Context) ([]string, error) { asked = true; return nil, errors.New("not asked") })
		if twins, err := SameNameAccounts(ctx, resolver("", ""), local); err != nil || len(twins) != 0 || asked {
			t.Fatalf("twins = %+v, %v (wbinfo asked %v); without trusts winbind serves its workgroup only", twins, err, asked)
		}
	})
}

// Review of GAP-0551 (loop 2): the incarnation of an account is named by the
// NSS service that answers its uid. With "passwd: files ldap sss", an LDAP
// account that took over the uid, name and home of an SSSD account is not
// named by the SID SSSD still caches for the uid, and an LDAP that cannot
// show that it answers leaves the owner unknown instead of handing the uid
// to SSSD's cached account.
func TestAccountIncarnationNamesTheNSSOwner(t *testing.T) {
	const uid = 41201
	const sid = "S-1-5-21-1-1-1-1201"
	line := commandResult{stdout: []byte("alice:*:41201:41201::/home/alice:/bin/bash\n")}
	for _, tc := range []struct {
		name, nss, account string
		results            map[string]commandResult
		want               string
		known              bool
		nslcd              bool
	}{
		{"LDAP holds the uid", "passwd: files ldap sss\n", "alice",
			map[string]commandResult{"-s ldap passwd 41201": line, "-s sss passwd 41201": line}, "nss:ldap", true, false},
		{"NIS holds the uid", "passwd: files nis sss\n", "alice",
			map[string]commandResult{"-s nis passwd 41201": line, "-s sss passwd 41201": line}, "nss:nis", true, false},
		{"LDAP that does not answer", "passwd: files ldap sss\n", "alice",
			map[string]commandResult{"-s sss passwd 41201": line}, "", false, false},
		{"LDAP that answers without the uid", "passwd: files ldap sss\n", "alice",
			map[string]commandResult{"-s sss passwd 41201": line}, "sid:" + sid, true, true},
		{"SSSD before LDAP", "passwd: files sss ldap\n", "alice",
			map[string]commandResult{"-s sss passwd 41201": line, "-s ldap passwd 41201": line}, "sid:" + sid, true, false},
		{"the owner names another account", "passwd: files ldap sss\n", "bob",
			map[string]commandResult{"-s ldap passwd 41201": line}, "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			accountHost(t, "root:x:0:0::/root:/bin/sh\n", "", tc.nss)
			startFakeSSSD(t, map[string]string{"uid:41201": sid, "sid:" + sid: "41201"})
			if tc.nslcd {
				startFakeNSLCD(t, &fakeNSLCD{})
			}
			got, known := newFakeNSS(&fakeRun{results: tc.results}).AccountIncarnation(uid, tc.account)
			if got != tc.want || known != tc.known {
				t.Fatalf("incarnation = %q, %v; want %q, %v", got, known, tc.want, tc.known)
			}
		})
	}
}

// Review of GAP-0551 (loop 2): the handoff itself. On one host with
// "passwd: files ldap sss", SSSD's account holds the uid while LDAP answers
// without it; then an LDAP account of the same name and home takes the uid
// over while SSSD still caches its SID. The incarnation changes, which makes
// the gateway drop the facts and the guardian record it holds for the uid.
func TestAccountIncarnationChangesWhenLDAPTakesOverAnSSSDUID(t *testing.T) {
	// An nslcd that completes every search (nslcdSearchesComplete).
	startFakeNSLCD(t, &fakeNSLCD{})
	const sid = "S-1-5-21-1-1-1-1203"
	line := commandResult{stdout: []byte("dave:*:41203:41203::/home/dave:/bin/bash\n")}
	accountHost(t, "root:x:0:0::/root:/bin/sh\n", "", "passwd: files ldap sss\n")
	startFakeSSSD(t, map[string]string{"uid:41203": sid, "sid:" + sid: "41203"})
	results := map[string]commandResult{"-s sss passwd 41203": line}
	r := newFakeNSS(&fakeRun{results: results})
	before, known := r.AccountIncarnation(41203, "dave")
	if !known || before != "sid:"+sid {
		t.Fatalf("incarnation of the SSSD account = %q, %v", before, known)
	}
	results["-s ldap passwd 41203"] = line
	after, known := newFakeNSS(&fakeRun{results: results}).AccountIncarnation(41203, "dave")
	if !known || after == before || after != "nss:ldap" {
		t.Fatalf("incarnation after LDAP took the uid over = %q, %v; want nss:ldap, not SSSD's cached %s", after, known, before)
	}
}

// Review of GAP-0551 (loop 2): an account's facts are those of the NSS
// service that answers its uid, never SSSD's cached account under a uid a
// NIS service holds, nor SSSD's while an LDAP before it cannot answer. Since
// loop 3 the NIS account gets none at all while SSSD still holds an account
// under its uid: the uid does not tell the two apart (SharedUIDError).
func TestDirectoryFactsAreTheNSSOwners(t *testing.T) {
	const sid = "S-1-5-21-1-1-1-1202"
	line := commandResult{stdout: []byte("carol:*:41202:41202::/home/carol:/bin/bash\n")}
	sids := map[string]string{"uid:41202": sid, "sid:" + sid: "41202"}

	accountHost(t, "root:x:0:0::/root:/bin/sh\n", "", "passwd: files nis sss\n")
	startFakeSSSD(t, sids)
	r := newFakeNSS(&fakeRun{results: map[string]commandResult{
		"passwd 41202": line, "-s nis passwd 41202": line, "-s sss passwd 41202": line,
	}})
	facts, err := r.DirectoryFactsWithoutGroupsForUID(41202, time.Now())
	var shared *SharedUIDError
	if !errors.As(err, &shared) {
		t.Fatalf("facts of the NIS account = %+v, %v; want none while SSSD holds an account under its uid", facts, err)
	}

	accountHost(t, "root:x:0:0::/root:/bin/sh\n", "", "passwd: files ldap sss\n")
	startFakeSSSD(t, sids)
	r = newFakeNSS(&fakeRun{results: map[string]commandResult{"passwd 41202": line, "-s sss passwd 41202": line}})
	if facts, err := r.DirectoryFactsWithoutGroupsForUID(41202, time.Now()); err == nil {
		t.Fatalf("facts = %+v while the LDAP before SSSD cannot answer; want the lookup to fail", facts)
	}
}
