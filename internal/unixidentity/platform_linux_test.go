//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

func TestLinuxLocalAccountsAndDirectoryConfiguration(t *testing.T) {
	dir := t.TempDir()
	origPasswd, origNSS := localPasswdPath, nsswitchPath
	t.Cleanup(func() { localPasswdPath, nsswitchPath = origPasswd, origNSS })
	localPasswdPath = filepath.Join(dir, "passwd")
	nsswitchPath = filepath.Join(dir, "nsswitch.conf")
	if err := os.WriteFile(localPasswdPath, []byte("alice:x:1000:1000::/home/alice:/bin/bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	local, err := LocalAccounts(context.Background())
	if err != nil || local["alice"] != 1000 || len(local) != 1 {
		t.Fatalf("LocalAccounts = %v, %v", local, err)
	}
	if DirectoryConfigured() {
		t.Fatal("a missing nsswitch.conf is glibc's files-only default")
	}
	if err := os.WriteFile(nsswitchPath, []byte("passwd: sss files systemd\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !DirectoryConfigured() {
		t.Fatal("an sss passwd source is a directory")
	}
	if err := os.Chmod(nsswitchPath, 0o000); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 && !DirectoryConfigured() {
		t.Fatal("an unreadable nsswitch.conf must be treated as a directory host")
	}
}

// Tests never ask the host's realmd; the ones about realms set hostRealms.
func init() { hostRealms = func(context.Context) ([]Realm, error) { return nil, nil } }

// A per-user gateway resolves the directory type of an SSSD account from the
// realm realmd reports, as the root guardian does: only when a qualified
// account name names that realm and its NSS backend. A bare SSSD name or
// an SSSD domain no joined realm covers gets no directory type. A local account
// SSSD's files provider answers for (the implicit files domain of RHEL 8)
// stays local: it was reported as the AD account lee@CORP.EXAMPLE.COM. A
// winbind account of the realm reports its DNS domain, as Windows does, not
// the NetBIOS name CORP; the NetBIOS domain of a trusted domain gets no
// realm facts.
func TestDirectoryFactsForUIDTakesTheRealmFromRealmd(t *testing.T) {
	origNSS, origRealms, origPasswd := nsswitchPath, hostRealms, localPasswdPath
	t.Cleanup(func() { nsswitchPath, hostRealms, localPasswdPath = origNSS, origRealms, origPasswd })
	nsswitchPath = filepath.Join(t.TempDir(), "nsswitch.conf")
	localPasswdPath = filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(nsswitchPath, []byte("passwd: sss files winbind systemd\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localPasswdPath, []byte("lee:x:1000:70000::/home/lee:/bin/bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hostRealms = func(context.Context) ([]Realm, error) {
		return []Realm{{Domain: "corp.example.com", Name: "CORP.EXAMPLE.COM", ServerSoftware: "active-directory",
			ClientSoftware: "winbind", NetBIOS: netBIOSName([]string{`CORP\%U`})}}, nil
	}
	accounts := map[int]string{
		70001: "alice@corp.example.com",
		70002: "bob@emea.corp.example.com",
		70003: "carol",
		70004: "dave@ldap.example.org",
		1000:  "lee",
		70005: `CORP\erin`,
		70006: `EMEA\frank`,
	}
	winbind := map[int]bool{70005: true, 70006: true}
	f := &fakeRun{results: map[string]commandResult{"group 70000": {stdout: []byte("users:*:70000:\n")}}}
	for uid, name := range accounts {
		line := commandResult{stdout: []byte(name + ":*:" + strconv.Itoa(uid) + ":70000::/home/" + name + ":/bin/bash\n")}
		f.results["passwd "+strconv.Itoa(uid)] = line
		service := "sss"
		if winbind[uid] {
			service = "winbind"
		}
		f.results["-s "+service+" passwd "+strconv.Itoa(uid)] = line
		f.results["-s "+service+" passwd "+name] = line
		f.results["initgroups "+name] = commandResult{stdout: []byte(name + " 70000\n")}
	}
	type view struct {
		directory                        useridentity.Directory
		source, domain, realm, principal string
	}
	ad, sssd := useridentity.DirectoryActiveDirectory, useridentity.SourceSSSD
	want := map[int]view{
		70001: {"", sssd, "corp.example.com", "CORP.EXAMPLE.COM", "alice@corp.example.com"},
		70002: {"", sssd, "emea.corp.example.com", "EMEA.CORP.EXAMPLE.COM", "bob@emea.corp.example.com"},
		70003: {"", sssd, "", "", ""},
		70004: {"", sssd, "ldap.example.org", "LDAP.EXAMPLE.ORG", "dave@ldap.example.org"},
		1000:  {useridentity.DirectoryLocal, useridentity.SourceNSSFiles, "", "", ""},
		70005: {ad, useridentity.SourceWinbind, "corp.example.com", "CORP.EXAMPLE.COM", "erin@corp.example.com"},
		70006: {ad, useridentity.SourceWinbind, "emea", "", ""},
	}
	r := newFakeNSS(f)
	for uid, expected := range want {
		facts, err := r.DirectoryFactsForUID(uid, time.Now())
		if err != nil {
			t.Fatalf("uid %d: %v", uid, err)
		}
		got := view{facts.Directory, facts.Source, facts.Domain, facts.Realm, facts.Principal}
		if got != expected || facts.Assurance != useridentity.AssuranceVerified {
			t.Errorf("uid %d (%s) = %+v, want %+v, verified", uid, accounts[uid], facts, expected)
		}
	}
	// With winbind use default domain only the names of other domains are
	// qualified, and realmd reports the format %U.
	if realm, ok := realmFor("emea", useridentity.SourceWinbind, []Realm{{Domain: "corp.example.com", ClientSoftware: "winbind", NetBIOS: netBIOSName([]string{"%U"})}}, nil); ok {
		t.Errorf("a trusted NetBIOS domain took the realm %+v", realm)
	}
}

// A bare SSSD name (use_fully_qualified_names = False) takes the joined
// realm only when SSSD resolves name@domain to the same account (GAP-0497):
// not an account of a plain LDAP domain, not one that shares its short name
// with an AD account, and not when SSSD does not answer. Nor does an LDAP
// account named by an e-mail address in the joined domain, which SSSD
// resolves to the AD account of that short name (GAP-0568).
func TestBareSSSDAccountTakesOnlyTheRealmSSSDConfirms(t *testing.T) {
	origNSS, origRealms, origPasswd := nsswitchPath, hostRealms, localPasswdPath
	t.Cleanup(func() { nsswitchPath, hostRealms, localPasswdPath = origNSS, origRealms, origPasswd })
	dir := t.TempDir()
	nsswitchPath, localPasswdPath = filepath.Join(dir, "nsswitch.conf"), filepath.Join(dir, "passwd")
	if err := os.WriteFile(nsswitchPath, []byte("passwd: files sss\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localPasswdPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	hostRealms = func(context.Context) ([]Realm, error) {
		return []Realm{{Domain: "corp.example.com", Name: "CORP.EXAMPLE.COM",
			ServerSoftware: "active-directory", ClientSoftware: "sssd"}}, nil
	}
	line := func(name string, uid int) commandResult {
		id := strconv.Itoa(uid)
		return commandResult{stdout: []byte(name + ":*:" + id + ":" + id + "::/home/" + name + ":/bin/bash\n")}
	}
	f := &fakeRun{results: map[string]commandResult{}, errs: map[string]error{}}
	for uid, name := range map[int]string{80001: "alice", 80002: "bob", 80003: "carol", 80004: "dave", 80005: "erin@corp.example.com"} {
		f.results["passwd "+strconv.Itoa(uid)] = line(name, uid)
		f.results["-s sss passwd "+strconv.Itoa(uid)] = line(name, uid)
	}
	f.results["-s sss passwd alice@corp.example.com"] = line("alice", 80001)
	f.results["-s sss passwd carol@corp.example.com"] = line("carol", 90003)
	f.errs["-s sss passwd dave@corp.example.com"] = context.DeadlineExceeded
	f.results["-s sss passwd erin@corp.example.com"] = line("erin", 90005)
	r := newFakeNSS(f)
	for uid, principal := range map[int]string{80001: "alice@corp.example.com", 80002: "", 80003: "", 80004: "", 80005: ""} {
		facts, err := r.DirectoryFactsWithoutGroupsForUID(uid, time.Now())
		if err != nil {
			t.Fatalf("uid %d: %v", uid, err)
		}
		want := useridentity.DirectoryFacts{Source: useridentity.SourceSSSD}
		if principal != "" {
			want = useridentity.DirectoryFacts{Source: useridentity.SourceSSSD, Directory: useridentity.DirectoryActiveDirectory,
				Domain: "corp.example.com", Realm: "CORP.EXAMPLE.COM", Principal: principal}
		}
		got := useridentity.DirectoryFacts{Source: facts.Source, Directory: facts.Directory, Domain: facts.Domain,
			Realm: facts.Realm, Principal: facts.Principal}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("uid %d = %+v, want %+v", uid, got, want)
		}
	}
}

func TestFailedRealmdQueryDoesNotCacheEmptyRealms(t *testing.T) {
	realmCache.mu.Lock()
	oldRealms, oldFetched := realmCache.realms, realmCache.fetched
	realmCache.realms, realmCache.fetched = nil, time.Time{}
	realmCache.mu.Unlock()
	t.Cleanup(func() {
		realmCache.mu.Lock()
		realmCache.realms, realmCache.fetched = oldRealms, oldFetched
		realmCache.mu.Unlock()
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cachedRealms(ctx)
	realmCache.mu.Lock()
	fetched := realmCache.fetched
	realmCache.mu.Unlock()
	if !fetched.IsZero() {
		t.Fatal("a failed realmd query was cached as an empty answer")
	}
	oldRealmsFn, oldNSS, oldPasswd := hostRealms, nsswitchPath, localPasswdPath
	t.Cleanup(func() { hostRealms, nsswitchPath, localPasswdPath = oldRealmsFn, oldNSS, oldPasswd })
	hostRealms = func(context.Context) ([]Realm, error) { return nil, context.DeadlineExceeded }
	dir := t.TempDir()
	nsswitchPath, localPasswdPath = filepath.Join(dir, "nsswitch.conf"), filepath.Join(dir, "passwd")
	if err := os.WriteFile(nsswitchPath, []byte("passwd: sss files\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localPasswdPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	const name = "alice@corp.example.com"
	f := &fakeRun{results: map[string]commandResult{
		"passwd 80001":          {stdout: []byte(name + ":*:80001:80001::/home/alice:/bin/bash\n")},
		"-s sss passwd 80001":   {stdout: []byte(name + ":*:80001:80001::/home/alice:/bin/bash\n")},
		"-s sss passwd " + name: {stdout: []byte(name + ":*:80001:80001::/home/alice:/bin/bash\n")},
		"initgroups " + name:    {stdout: []byte(name + " 80001\n")},
		"group 80001":           {stdout: []byte(name + ":*:80001:\n")},
	}}
	if facts, err := newFakeNSS(f).DirectoryFactsForUID(80001, time.Now()); err == nil {
		t.Fatalf("realmd failure produced cacheable facts: %+v", facts)
	}
}
