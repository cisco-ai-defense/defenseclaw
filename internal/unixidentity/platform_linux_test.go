//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"os"
	"path/filepath"
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
func init() { hostRealms = func(context.Context) []Realm { return nil } }

// A per-user gateway resolves the directory type of an SSSD account from the
// realm realmd reports, as the root guardian does: by the account's DNS
// domain or a parent of it, or the only realm for a bare name. An SSSD
// domain no joined realm covers gets no directory type.
func TestDirectoryFactsForUIDTakesTheRealmFromRealmd(t *testing.T) {
	origNSS, origRealms := nsswitchPath, hostRealms
	t.Cleanup(func() { nsswitchPath, hostRealms = origNSS, origRealms })
	nsswitchPath = filepath.Join(t.TempDir(), "nsswitch.conf")
	if err := os.WriteFile(nsswitchPath, []byte("passwd: files sss systemd\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hostRealms = func(context.Context) []Realm {
		return []Realm{{Domain: "corp.example.com", Name: "CORP.EXAMPLE.COM", ServerSoftware: "active-directory"}}
	}
	accounts := map[int]string{
		70001: "alice@corp.example.com",
		70002: "bob@emea.corp.example.com",
		70003: "carol",
		70004: "dave@ldap.example.org",
	}
	f := &fakeRun{results: map[string]commandResult{"group 70000": {stdout: []byte("users:*:70000:\n")}}}
	for uid, name := range accounts {
		line := commandResult{stdout: []byte(name + ":*:" + strconv.Itoa(uid) + ":70000::/home/" + name + ":/bin/bash\n")}
		f.results["passwd "+strconv.Itoa(uid)] = line
		f.results["-s sss passwd "+strconv.Itoa(uid)] = line
		f.results["initgroups "+name] = commandResult{stdout: []byte(name + " 70000\n")}
	}
	type view struct {
		directory                useridentity.Directory
		domain, realm, principal string
	}
	ad := useridentity.DirectoryActiveDirectory
	want := map[int]view{
		70001: {ad, "corp.example.com", "CORP.EXAMPLE.COM", "alice@corp.example.com"},
		70002: {ad, "emea.corp.example.com", "EMEA.CORP.EXAMPLE.COM", "bob@emea.corp.example.com"},
		70003: {ad, "corp.example.com", "CORP.EXAMPLE.COM", "carol@corp.example.com"},
		70004: {"", "ldap.example.org", "LDAP.EXAMPLE.ORG", "dave@ldap.example.org"},
	}
	r := newFakeNSS(f)
	for uid, expected := range want {
		facts, err := r.DirectoryFactsForUID(uid, time.Now())
		if err != nil {
			t.Fatalf("uid %d: %v", uid, err)
		}
		got := view{facts.Directory, facts.Domain, facts.Realm, facts.Principal}
		if got != expected || facts.Source != useridentity.SourceSSSD || facts.Assurance != useridentity.AssuranceVerified {
			t.Errorf("uid %d (%s) = %+v source %q, want %+v from sssd, verified", uid, accounts[uid], facts, facts.Source, expected)
		}
	}
}
