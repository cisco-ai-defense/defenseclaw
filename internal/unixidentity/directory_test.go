//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

func TestQualifiedUserNameUsesSpellingNSSKnows(t *testing.T) {
	previous := hostRealms
	hostRealms = func(context.Context) ([]Realm, error) {
		return []Realm{{Domain: "corp.example.com", NetBIOS: "CORP"}}, nil
	}
	t.Cleanup(func() { hostRealms = previous })
	user := "CORP\\alice:*:1001:1001::/home/alice:/bin/bash\n"
	r := newFakeNSS(&fakeRun{results: map[string]commandResult{
		`passwd CORP\alice`: {stdout: []byte(user)},
	}})
	if got := QualifiedUserName(context.Background(), r, "alice"); got != `CORP\alice` {
		t.Fatalf("qualified account = %q", got)
	}
	if got := QualifiedUserName(context.Background(), r, `CORP\alice`); got != "" {
		t.Fatalf("already-qualified account changed to %q", got)
	}
}

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
	startFakeSSSD(t, nil)
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

	// 400 groups are all named (with the primary group), in several getent
	// calls: one call for all of them outlasted a cold SSSD (GAP-0138). The
	// calls run one at a time, because SSSD answers one at a time and the
	// later of several at once ran out of their five seconds (GAP-0230). More
	// than the bound fail, and so does one batch that did not finish.
	for _, tc := range []struct {
		count   int
		fails   bool
		timeout int // index of the batch whose getent times out, -1 for none
	}{{400, false, -1}, {maxDirectoryGroups - 1, false, -1}, {maxDirectoryGroups, true, -1}, {400, true, 3}} {
		// The primary group leads the ids, and the batches are cut from them.
		ids := []string{"1001"}
		lines := []string{"alice@corp.example.com:*:1001:"}
		for i := range tc.count {
			ids = append(ids, fmt.Sprint(7000+i))
			lines = append(lines, fmt.Sprintf("g%d@corp.example.com:*:%d:", i, 7000+i))
		}
		f := fake()
		f.results[initgroups] = commandResult{stdout: []byte("alice@corp.example.com " + strings.Join(ids, " ") + "\n")}
		for start := 0; start < len(ids); start += groupQueryBatch {
			end := min(start+groupQueryBatch, len(ids))
			key := "group " + strings.Join(ids[start:end], " ")
			f.results[key] = commandResult{stdout: []byte(strings.Join(lines[start:end], "\n") + "\n")}
			if start/groupQueryBatch == tc.timeout {
				f.errs[key] = errors.New("getent timed out")
			}
		}
		resolver := newFakeNSS(f)
		run := resolver.runner
		var inflight, peak atomic.Int32
		resolver.runner = func(ctx context.Context, path string, args []string, filters ...outputFilter) (commandResult, error) {
			n := inflight.Add(1)
			defer inflight.Add(-1)
			for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
			}
			time.Sleep(time.Millisecond)
			return run(ctx, path, args, filters...)
		}
		facts, err := resolver.DirectoryFactsForUID(1001, time.Now())
		if (err != nil) != tc.fails || (err == nil && len(facts.Groups) != tc.count+1) {
			t.Errorf("%d groups: %d named, err %v", tc.count, len(facts.Groups), err)
		}
		if peak.Load() != 1 {
			t.Errorf("%d groups: %d getent calls at once, want one at a time", tc.count, peak.Load())
		}
	}
}

// TestDirectoryFactsNameLargeDirectoryGroups: getent prints every member of
// a group, and a batch that held one Active Directory group of a few
// thousand members passed the 64 KiB output limit, so the lookup failed for
// each of its members and none got a group profile. A real getent run (a
// script) checks that the member lists never count against the limit.
func TestDirectoryFactsNameLargeDirectoryGroups(t *testing.T) {
	dir := t.TempDir()
	orig := nsswitchPath
	nsswitchPath = filepath.Join(dir, "nsswitch.conf")
	t.Cleanup(func() { nsswitchPath = orig })
	members := make([]string, 4000)
	for i := range members {
		members[i] = fmt.Sprintf("user%d@corp.example.com", i)
	}
	groups := "alice@corp.example.com:*:1001:\nall-staff@corp.example.com:*:5001:" + strings.Join(members, ",") + "\n"
	script := filepath.Join(dir, "getent")
	body := "#!/bin/sh\ncase \"$*\" in\n" +
		"\"passwd 1001\") echo \"alice@corp.example.com:*:1001:1001::/home/alice:/bin/bash\" ;;\n" +
		"\"initgroups alice@corp.example.com\") echo \"alice@corp.example.com 1001 5001\" ;;\n" +
		"\"group 1001 5001\") cat \"$(dirname \"$0\")/group\" ;;\n" +
		"*) exit 2 ;;\nesac\n"
	for path, content := range map[string]string{nsswitchPath: "passwd: files\n", filepath.Join(dir, "group"): groups, script: body} {
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	r := &NSSResolver{path: script, runner: runTrustedCommand}
	facts, err := r.DirectoryFactsForUID(1001, time.Now())
	if err != nil || !reflect.DeepEqual(facts.Groups, []string{"alice@corp.example.com", "all-staff@corp.example.com"}) {
		t.Fatalf("facts = %+v, %v", facts, err)
	}
}

// TestEntraNSSAccountReportsItsUPN: the aad module names an Entra ID account
// by its UPN. DefenseClaw reported it as a Kerberos principal with an
// upper-case realm (alice@CONTOSO.ONMICROSOFT.COM) and no UPN, while Windows
// reports the lower-case UPN for the same user, so records from the two
// OSes did not join (seen live on an Ubuntu VM with AADSSHLoginForLinux).
func TestEntraNSSAccountReportsItsUPN(t *testing.T) {
	nss := filepath.Join(t.TempDir(), "nsswitch.conf")
	if err := os.WriteFile(nss, []byte("passwd: files systemd aad\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := nsswitchPath
	nsswitchPath = nss
	t.Cleanup(func() { nsswitchPath = orig })
	const account = "alice@Contoso.onmicrosoft.com::9246366:9246366:Alice:/home/alice:/bin/bash\n"
	f := &fakeRun{results: map[string]commandResult{
		"passwd 9246366":                           {stdout: []byte(account)},
		"-s aad passwd 9246366":                    {stdout: []byte(account)},
		"initgroups alice@Contoso.onmicrosoft.com": {stdout: []byte("alice@Contoso.onmicrosoft.com 9246366\n")},
		"group 9246366":                            {stdout: []byte("alice@Contoso.onmicrosoft.com::9246366:\n")},
	}}
	facts, err := newFakeNSS(f).DirectoryFactsForUID(9246366, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	const upn = "alice@contoso.onmicrosoft.com"
	if facts.Directory != useridentity.DirectoryEntraID || facts.Source != "nss_aad" || facts.UPN != upn ||
		facts.Principal != upn || facts.Domain != "contoso.onmicrosoft.com" || facts.Realm != "" {
		t.Fatalf("facts = %+v", facts)
	}
}

// TestGroupNameLookupDefinitive pins GAP-0292: Himmelblau answers an Entra
// group only by gid or object id, so a host whose group line names it gives
// no definitive "no such group" by name; other hosts do.
func TestGroupNameLookupDefinitive(t *testing.T) {
	nss := filepath.Join(t.TempDir(), "nsswitch.conf")
	orig := nsswitchPath
	nsswitchPath = nss
	t.Cleanup(func() { nsswitchPath = orig })
	for content, want := range map[string]bool{
		"passwd: files himmelblau\ngroup: files himmelblau systemd\n": false,
		"passwd: files sss\ngroup: files sss\n":                       true,
	} {
		if err := os.WriteFile(nss, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := GroupNameLookupDefinitive(); got != want {
			t.Errorf("GroupNameLookupDefinitive(%q) = %t, want %t", content, got, want)
		}
	}
}

// A local passwd entry must remain resolvable while a directory backend is unavailable.
func TestDirectoryFactsLocalAccountSkipsDirectoryProbe(t *testing.T) {
	dir := t.TempDir()
	oldPasswd, oldNSS := localPasswdPath, nsswitchPath
	t.Cleanup(func() { localPasswdPath, nsswitchPath = oldPasswd, oldNSS })
	localPasswdPath, nsswitchPath = filepath.Join(dir, "passwd"), filepath.Join(dir, "nsswitch.conf")
	if err := os.WriteFile(localPasswdPath, []byte("opsadmin:x:1001:1001::/home/opsadmin:/bin/bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nsswitchPath, []byte("passwd: files sss\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &fakeRun{errs: map[string]error{"-s sss passwd 1001": errors.New("getent timed out")}, results: map[string]commandResult{
		"passwd 1001":         {stdout: []byte("opsadmin:x:1001:1001::/home/opsadmin:/bin/bash\n")},
		"initgroups opsadmin": {stdout: []byte("opsadmin 1001\n")},
		"group 1001":          {stdout: []byte("opsadmin:x:1001:\n")},
	}}
	facts, err := newFakeNSS(f).DirectoryFactsForUID(1001, time.Now())
	if err != nil || facts.Directory != useridentity.DirectoryLocal || len(facts.Groups) != 1 {
		t.Fatalf("local facts = %+v, %v", facts, err)
	}
}

func TestDirectoryFactsWithoutGroupsSkipsNaming(t *testing.T) {
	dir := t.TempDir()
	oldPasswd, oldNSS := localPasswdPath, nsswitchPath
	t.Cleanup(func() { localPasswdPath, nsswitchPath = oldPasswd, oldNSS })
	localPasswdPath, nsswitchPath = filepath.Join(dir, "passwd"), filepath.Join(dir, "nsswitch.conf")
	if err := os.WriteFile(localPasswdPath, []byte("opsadmin:x:1001:1001::/home/opsadmin:/bin/bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nsswitchPath, []byte("passwd: files sss\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &fakeRun{errs: map[string]error{"initgroups opsadmin": errors.New("group lookup timed out")}, results: map[string]commandResult{
		"passwd 1001": {stdout: []byte("opsadmin:x:1001:1001::/home/opsadmin:/bin/bash\n")},
	}}
	facts, err := newFakeNSS(f).DirectoryFactsWithoutGroupsForUID(1001, time.Now())
	if err != nil || facts.Directory != useridentity.DirectoryLocal || len(facts.Groups) != 0 {
		t.Fatalf("spool facts = %+v, %v", facts, err)
	}
}
