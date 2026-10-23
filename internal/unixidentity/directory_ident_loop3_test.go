//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Review of GAP-0551 (loop 3): the account of a uid is the one NSS answers
// it with, in the order of the passwd line. With "passwd: sss files" an AD
// alice and a local alice of one uid were taken for the local account, so
// the AD account's groups and domain selected no profile. Two accounts of
// one uid in any order are refused (fail closed); SSSD's files domain
// passing the local entry on (RHEL 8) is the local account.
func TestTheNSSOwnerOfASharedUIDIsNotTakenForTheLocalAccount(t *testing.T) {
	const uid = 1001
	const sid = "S-1-5-21-7-7-7-1001"
	localLine := "alice:x:1001:1001::/home/alice:/bin/bash\n"
	adLine := "alice:*:1001:1001:Alice (CORP):/home/alice:/bin/bash\n"
	adSIDs := map[string]string{"uid:1001": sid, "sid:" + sid: "1001"}
	shared := func(t *testing.T, err error) {
		t.Helper()
		var sharedErr *SharedUIDError
		if !errors.As(err, &sharedErr) || sharedErr.UID != uid {
			t.Fatalf("err = %v; want the uid refused as held by two accounts", err)
		}
	}
	t.Run("SSSD first", func(t *testing.T) {
		accountHost(t, localLine, "", "passwd: sss files\n")
		startFakeSSSD(t, adSIDs)
		r := newFakeNSS(&fakeRun{results: map[string]commandResult{
			"passwd 1001": {stdout: []byte(adLine)}, "-s sss passwd 1001": {stdout: []byte(adLine)},
			"-s files passwd 1001": {stdout: []byte(localLine)},
		}})
		facts, err := r.DirectoryFactsForUID(uid, time.Now())
		if err == nil {
			t.Fatalf("facts = %+v; the AD account NSS names first was taken for the local one", facts)
		}
		shared(t, err)
		if got, known := r.AccountIncarnation(uid, "alice"); !known || got != "sid:"+sid {
			t.Fatalf("incarnation = %q, %v; want the SID of the SSSD account NSS answers the uid with", got, known)
		}
	})
	t.Run("files first", func(t *testing.T) {
		accountHost(t, localLine, "", "passwd: files sss\n")
		startFakeSSSD(t, adSIDs)
		r := newFakeNSS(&fakeRun{results: map[string]commandResult{
			"passwd 1001": {stdout: []byte(localLine)}, "-s files passwd 1001": {stdout: []byte(localLine)},
			"-s sss passwd 1001": {stdout: []byte(adLine)},
		}})
		_, err := r.DirectoryFactsForUID(uid, time.Now())
		shared(t, err)
		if got, known := r.AccountIncarnation(uid, "alice"); !known || got != "files" {
			t.Fatalf("incarnation = %q, %v; want files, which NSS answers the uid with", got, known)
		}
	})
	t.Run("SSSD's files domain passes the local entry on", func(t *testing.T) {
		accountHost(t, localLine, "", "passwd: sss files\n")
		startFakeSSSD(t, nil)
		r := newFakeNSS(&fakeRun{results: map[string]commandResult{
			"passwd 1001": {stdout: []byte(localLine)}, "-s sss passwd 1001": {stdout: []byte(localLine)},
			"-s files passwd 1001": {stdout: []byte(localLine)},
		}})
		facts, err := r.DirectoryFactsForUID(uid, time.Now())
		if err != nil || facts.Directory != useridentity.DirectoryLocal || facts.Source != useridentity.SourceNSSFiles {
			t.Fatalf("facts = %+v, %v; want the local account", facts, err)
		}
		if got, known := r.AccountIncarnation(uid, "alice"); !known || got != "files" {
			t.Fatalf("incarnation = %q, %v; want files", got, known)
		}
	})
	t.Run("SSSD holds no such uid", func(t *testing.T) {
		accountHost(t, localLine, "", "passwd: sss files\n")
		startFakeSSSD(t, nil)
		r := newFakeNSS(&fakeRun{results: map[string]commandResult{
			"passwd 1001": {stdout: []byte(localLine)}, "-s files passwd 1001": {stdout: []byte(localLine)},
		}})
		if facts, err := r.DirectoryFactsForUID(uid, time.Now()); err != nil || facts.Directory != useridentity.DirectoryLocal {
			t.Fatalf("facts = %+v, %v; want the local account", facts, err)
		}
	})
	t.Run("SSSD stopped behind the local entry", func(t *testing.T) {
		accountHost(t, localLine, "", "passwd: files sss\n")
		r := newFakeNSS(&fakeRun{results: map[string]commandResult{
			"passwd 1001": {stdout: []byte(localLine)}, "-s files passwd 1001": {stdout: []byte(localLine)},
		}})
		if facts, err := r.DirectoryFactsForUID(uid, time.Now()); err != nil || facts.Directory != useridentity.DirectoryLocal {
			t.Fatalf("facts = %+v, %v; an unavailable SSSD must not fail a local account", facts, err)
		}
	})
	t.Run("bare name", func(t *testing.T) {
		for _, nss := range []string{"passwd: sss files\n", "passwd: files sss\n"} {
			sameNameHost(t, func(context.Context) ([]Realm, error) { return nil, nil }, "", nss)
			accountHost(t, localLine, "", nss)
			startFakeSSSD(t, adSIDs)
			first := localLine
			if strings.HasPrefix(nss, "passwd: sss") {
				first = adLine
			}
			r := newFakeNSS(&fakeRun{results: map[string]commandResult{
				"passwd alice": {stdout: []byte(first)}, "passwd 1001": {stdout: []byte(first)},
				"-s sss passwd alice": {stdout: []byte(adLine)}, "-s sss passwd 1001": {stdout: []byte(adLine)},
				"-s files passwd alice": {stdout: []byte(localLine)}, "-s files passwd 1001": {stdout: []byte(localLine)},
			}})
			twins, err := SameNameAccounts(context.Background(), r, Account{Name: "alice", UID: uid})
			if len(twins) != 0 {
				t.Fatalf("%s: twins = %+v", nss, twins)
			}
			shared(t, err)
		}
	})
	t.Run("bare name of another domain's account of the uid", func(t *testing.T) {
		sameNameHost(t, func(context.Context) ([]Realm, error) {
			return []Realm{{Name: "OTHER.EXAMPLE", Domain: "other.example"}}, nil
		}, "", "passwd: files\n")
		accountHost(t, localLine, "", "passwd: files\n")
		r := newFakeNSS(&fakeRun{results: map[string]commandResult{
			"passwd alice": {stdout: []byte(localLine)}, "-s files passwd alice": {stdout: []byte(localLine)},
			"passwd alice@other.example": {stdout: []byte("alice@other.example:*:1001:1001::/home/alice:/bin/bash\n")},
		}})
		_, err := SameNameAccounts(context.Background(), r, Account{Name: "alice", UID: uid})
		shared(t, err)
	})
}

// Review of GAP-0551 (loop 3): a winbind account is named by the SID
// winbind maps its uid to. Deleted and created again with the same RFC 2307
// uid, qualified name and home, it has another SID, so it is another
// incarnation; a SID winbind cannot give leaves it unknown.
func TestWinbindIncarnationIsTheAccountSID(t *testing.T) {
	line := commandResult{stdout: []byte(`CORP\alice:*:50001:50001::/home/CORP/alice:/bin/bash` + "\n")}
	accountHost(t, "root:x:0:0::/root:/bin/sh\n", "", "passwd: files winbind\n")
	r := newFakeNSS(&fakeRun{results: map[string]commandResult{"-s winbind passwd 50001": line}})
	previous := winbindUIDSID
	t.Cleanup(func() { winbindUIDSID = previous })
	incarnation := func(sid string, err error) (string, bool) {
		winbindUIDSID = func(_ context.Context, uid int) (string, error) {
			if uid != 50001 {
				return "", fmt.Errorf("asked for uid %d", uid)
			}
			return sid, err
		}
		return r.AccountIncarnation(50001, `CORP\alice`)
	}
	first, known := incarnation("S-1-5-21-9-9-9-1105", nil)
	if !known || first != "sid:S-1-5-21-9-9-9-1105" {
		t.Fatalf("incarnation = %q, %v; want the account's SID", first, known)
	}
	again, known := incarnation("S-1-5-21-9-9-9-2207", nil)
	if !known || again == first {
		t.Fatalf("incarnation of the account created again = %q, %v; want another than %q", again, known, first)
	}
	if got, known := incarnation("", errors.New("winbindd is not running")); known {
		t.Fatalf("incarnation = %q while winbind gives no SID; want unknown", got)
	}
}

// Review of GAP-0550 (loop 3): an LDAP or NIS answer that names no group
// counts only when the search itself completed. A provider that still
// enumerates an unrelated group, or answers another account, while the
// account's own searches fail no longer certifies them; nslcd tells a
// search that completed from one that failed.
func TestMemberListAnswerCountsOnlyForACompletedSearch(t *testing.T) {
	localLine := []byte("alice:x:1001:5100::/home/alice:/bin/sh\n")
	local := Account{Name: "alice", UID: 1001, GID: 5100}
	results := func(extra map[string]commandResult) map[string]commandResult {
		out := map[string]commandResult{
			"passwd 1001": {stdout: localLine}, "passwd alice": {stdout: localLine},
			"-s files passwd 1001":     {stdout: localLine},
			"-s ldap initgroups alice": {stdout: []byte("alice\n")},
			"-s nis initgroups alice":  {stdout: []byte("alice\n")},
			// Unrelated entries the provider still enumerates.
			"-s ldap group":  {stdout: []byte("unrelated:*:9000:bob\n")},
			"-s ldap passwd": {stdout: []byte("bob:*:7001:7001::/home/bob:/bin/sh\n")},
			"-s nis group":   {stdout: []byte("unrelated:*:9000:bob\n")},
		}
		for key, result := range extra {
			out[key] = result
		}
		return out
	}
	unrelatedAnswers := &fakeNSLCD{
		passwd:  map[string]Account{"name:bob": {Name: "bob", UID: 7001, GID: 7001}},
		members: map[string][]int{"bob": {9000}},
	}
	for _, tc := range []struct {
		name, nss  string
		nslcd      *fakeNSLCD
		extra      map[string]commandResult
		ok         bool
		wantGroups []string
	}{
		{"the account search fails", "group: files ldap\n",
			&fakeNSLCD{passwd: unrelatedAnswers.passwd, members: unrelatedAnswers.members, incomplete: map[string]bool{"name:alice": true}}, nil, false, nil},
		{"the member search fails", "group: files ldap\n",
			&fakeNSLCD{passwd: unrelatedAnswers.passwd, members: unrelatedAnswers.members, incomplete: map[string]bool{"member:alice": true}}, nil, false, nil},
		{"the member search fails after some groups", "group: files ldap\n",
			&fakeNSLCD{incomplete: map[string]bool{"member:alice": true}},
			map[string]commandResult{"-s ldap initgroups alice": {stdout: []byte("alice 7001\n")}}, false, nil},
		{"NIS lists nothing", "group: files nis\n", nil, nil, false, nil},
		{"both searches complete", "group: files ldap\n", unrelatedAnswers, nil, true, []string{"5100", "local-team"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			accountHost(t, string(localLine), "local-team:x:7000:alice\n", "passwd: files\n"+tc.nss)
			if tc.nslcd != nil {
				startFakeNSLCD(t, tc.nslcd)
			}
			r := newFakeNSS(&fakeRun{results: results(tc.extra)})
			if ids, err := r.GroupIDs(local); tc.ok != (err == nil) {
				t.Fatalf("group ids = %v, %v; want ok %v", ids, err, tc.ok)
			}
			facts, err := r.DirectoryFactsForUID(1001, time.Now())
			if tc.ok != (err == nil) || tc.ok && strings.Join(facts.Groups, ",") != strings.Join(tc.wantGroups, ",") {
				t.Fatalf("facts = %+v, %v; want ok %v", facts, err, tc.ok)
			}
		})
	}

	t.Run("owner walk", func(t *testing.T) {
		const sid = "S-1-5-21-1-1-1-1201"
		line := commandResult{stdout: []byte("alice:*:41201:41201::/home/alice:/bin/bash\n")}
		for name, nslcd := range map[string]*fakeNSLCD{
			"the LDAP uid search fails":      {incomplete: map[string]bool{"uid:41201": true}},
			"LDAP holds the uid after all":   {passwd: map[string]Account{"uid:41201": {Name: "alice", UID: 41201}}},
			"only unrelated searches answer": {incomplete: map[string]bool{"uid:41201": true}, passwd: unrelatedAnswers.passwd},
		} {
			t.Run(name, func(t *testing.T) {
				accountHost(t, "root:x:0:0::/root:/bin/sh\n", "", "passwd: files ldap sss\n")
				startFakeSSSD(t, map[string]string{"uid:41201": sid, "sid:" + sid: "41201"})
				startFakeNSLCD(t, nslcd)
				r := newFakeNSS(&fakeRun{results: map[string]commandResult{
					"-s sss passwd 41201": line, "-s ldap group": {stdout: []byte("unrelated:*:9000:bob\n")},
				}})
				if got, known := r.AccountIncarnation(41201, "alice"); known {
					t.Fatalf("incarnation = %q; want unknown while LDAP's uid search did not complete", got)
				}
			})
		}
	})
}

// Review of GAP-1131 (loop 3): SSSD's and winbind's responders answer an
// account they do not cache with "no such account" also while the domain is
// offline, so a socket that accepts a connection does not rule a twin out.
// A bare name is accepted only while every domain they serve is online.
func TestSameNameAccountsNeedsTheDirectoryOnline(t *testing.T) {
	localLine := "alice:x:1001:1001::/home/alice:/bin/bash\n"
	local := Account{Name: "alice", UID: 1001}
	r := newFakeNSS(&fakeRun{results: map[string]commandResult{
		"passwd alice": {stdout: []byte(localLine)}, "-s files passwd alice": {stdout: []byte(localLine)},
		"passwd 1001": {stdout: []byte(localLine)}, "-s files passwd 1001": {stdout: []byte(localLine)},
	}})
	noRealm := func(context.Context) ([]Realm, error) { return nil, nil }
	check := func(t *testing.T, online error, wantRefused bool) {
		t.Helper()
		twins, err := SameNameAccounts(context.Background(), r, local)
		var unknown *useridentity.NamesakesUnknownError
		if refused := errors.As(err, &unknown); refused != wantRefused || len(twins) != 0 {
			t.Fatalf("online check %v: twins = %+v, %v; want refused %v", online, twins, err, wantRefused)
		}
	}
	t.Run("SSSD", func(t *testing.T) {
		for _, online := range []error{errors.New("SSSD domain corp.example is offline"), nil} {
			sameNameHost(t, noRealm, "", "passwd: files sss\n")
			accountHost(t, localLine, "", "passwd: files sss\n")
			writeTestFile(t, sssdConfPath, "[sssd]\ndomains = corp.example\n[domain/corp.example]\nid_provider = ad\n")
			startFakeSSSD(t, nil)
			previous := sssdDomainsOnline
			t.Cleanup(func() { sssdDomainsOnline = previous })
			sssdDomainsOnline = func(context.Context) error { return online }
			check(t, online, online != nil)
		}
	})
	t.Run("winbind", func(t *testing.T) {
		for _, online := range []error{errors.New("winbind domain CORP has no active connection"), nil} {
			sameNameHost(t, noRealm, "", "passwd: files winbind\n")
			accountHost(t, localLine, "", "passwd: files winbind\n")
			writeTestFile(t, sambaConfPath, "[global]\nworkgroup = CORP\nsecurity = ads\nallow trusted domains = no\n")
			listenWinbindd(t)
			previous := winbindDomainsOnline
			t.Cleanup(func() { winbindDomainsOnline = previous })
			winbindDomainsOnline = func(context.Context) error { return online }
			check(t, online, online != nil)
		}
	})
	if !parseSSSDOnline("Online status: Online\n\nActive servers:\nAD Global Catalog: dc1.corp.example\n") ||
		parseSSSDOnline("Online status: Offline\n") || parseSSSDOnline("") {
		t.Fatal("sssctl domain-status --online is not read as written")
	}
	if err := parseWinbindOnline("BUILTIN : active connection\nHOST : active connection\nCORP : active connection\n"); err != nil {
		t.Fatalf("every domain online: %v", err)
	}
	for _, output := range []string{"BUILTIN : active connection\nCORP : no active connection\n", "", "CORP offline\n"} {
		if err := parseWinbindOnline(output); err == nil {
			t.Fatalf("wbinfo --online-status %q read as online", output)
		}
	}
}

// Review of GAP-1131 (loop 3): a host with more domains than a bare name is
// asked in refuses the name: a twin in the first domain past the bound went
// unasked, and no twin and no error came back. The SSSD publications and
// wbinfo lists are read one past the bound, so they show it too.
func TestSameNameAccountsRefusesPastTheDomainBound(t *testing.T) {
	ctx := context.Background()
	localLine := "alice:x:1001:1001::/home/alice:/bin/bash\n"
	local := Account{Name: "alice", UID: 1001}
	noRealm := func(context.Context) ([]Realm, error) { return nil, nil }
	domains := make([]string, maxSameNameRealms+1)
	for i := range domains {
		domains[i] = fmt.Sprintf("d%02d.example", i+1)
	}
	omitted := domains[maxSameNameRealms]
	resolver := func(twin string) *NSSResolver {
		return newFakeNSS(&fakeRun{results: map[string]commandResult{
			"passwd alice": {stdout: []byte(localLine)}, "-s files passwd alice": {stdout: []byte(localLine)},
			"passwd " + twin: {stdout: []byte(twin + ":*:3065:3065::/home/alice:/bin/bash\n")},
		}})
	}
	refused := func(t *testing.T, twins []Account, err error) {
		t.Helper()
		var unknown *useridentity.NamesakesUnknownError
		if len(twins) != 0 || !errors.As(err, &unknown) {
			t.Fatalf("twins = %+v, %v; want the bare name refused", twins, err)
		}
	}
	t.Run("SSSD configuration", func(t *testing.T) {
		sameNameHost(t, noRealm, "", "passwd: files sss\n")
		accountHost(t, localLine, "", "passwd: files sss\n")
		writeTestFile(t, sssdConfPath, "[sssd]\ndomains = "+strings.Join(domains, ", ")+"\n")
		startFakeSSSD(t, nil)
		twins, err := SameNameAccounts(ctx, resolver("alice@"+omitted), local)
		refused(t, twins, err)
	})
	t.Run("SSSD publications", func(t *testing.T) {
		sameNameHost(t, noRealm, "", "passwd: files sss\n")
		accountHost(t, localLine, "", "passwd: files sss\n")
		writeTestFile(t, sssdConfPath, "[sssd]\ndomains = d01.example\n")
		previous := sssdPubconfKrb5Dir
		t.Cleanup(func() { sssdPubconfKrb5Dir = previous })
		sssdPubconfKrb5Dir = t.TempDir()
		var mappings strings.Builder
		mappings.WriteString("[domain_realm]\n")
		for _, domain := range domains {
			fmt.Fprintf(&mappings, "%s = %s\n", domain, strings.ToUpper(domain))
		}
		writeTestFile(t, filepath.Join(sssdPubconfKrb5Dir, "domain_realm_d01_example"), mappings.String())
		startFakeSSSD(t, nil)
		if got := sssdSubdomains(); len(got) <= maxSameNameRealms {
			t.Fatalf("published domains read = %d; want one past the bound", len(got))
		}
		twins, err := SameNameAccounts(ctx, resolver("alice@"+omitted), local)
		refused(t, twins, err)
	})
	t.Run("winbind", func(t *testing.T) {
		sameNameHost(t, noRealm, "", "passwd: files winbind\n")
		accountHost(t, localLine, "", "passwd: files winbind\n")
		writeTestFile(t, sambaConfPath, "[global]\nworkgroup = CORP\nsecurity = ads\n")
		listenWinbindd(t)
		var listing strings.Builder
		for i := range maxSameNameRealms + 5 {
			fmt.Fprintf(&listing, "D%02d\n", i+1)
		}
		names := parseWbinfoDomains(listing.String())
		if len(names) <= maxSameNameRealms {
			t.Fatalf("wbinfo domains read = %d; want one past the bound", len(names))
		}
		previous := winbindTrustedDomains
		t.Cleanup(func() { winbindTrustedDomains = previous })
		winbindTrustedDomains = func(context.Context) ([]string, error) { return names, nil }
		twin := names[len(names)-1] + `\alice`
		twins, err := SameNameAccounts(ctx, resolver(twin), local)
		refused(t, twins, err)
	})
	t.Run("at the bound", func(t *testing.T) {
		sameNameHost(t, noRealm, "", "passwd: files sss\n")
		accountHost(t, localLine, "", "passwd: files sss\n")
		writeTestFile(t, sssdConfPath, "[sssd]\ndomains = "+strings.Join(domains[:maxSameNameRealms], ", ")+"\n")
		startFakeSSSD(t, nil)
		if twins, err := SameNameAccounts(ctx, resolver("alice@"+domains[maxSameNameRealms-1]), local); err != nil || len(twins) != 1 {
			t.Fatalf("twins = %+v, %v; want the twin of the last domain asked", twins, err)
		}
	})

}
