//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

func TestParsePasswdLine(t *testing.T) {
	account, err := ParsePasswdLine("alice:x:1001:1002:Alice Example,,,:/home/alice:/bin/bash\n")
	if err != nil {
		t.Fatal(err)
	}
	want := Account{Name: "alice", UID: 1001, GID: 1002, Gecos: "Alice Example,,,", Home: "/home/alice", Shell: "/bin/bash"}
	if account != want {
		t.Fatalf("ParsePasswdLine = %+v, want %+v", account, want)
	}
	for _, bad := range []string{
		"",
		"alice:x:1001:1002:/home/alice:/bin/bash",          // 6 fields
		"alice:x:1001:1002:g:/home/alice:/bin/bash:extra",  // 8 fields
		":x:1001:1002:g:/home/alice:/bin/bash",             // empty name
		"al ice:x:1001:1002:g:/home/alice:/bin/bash",       // space
		"alice:x:-1:1002:g:/home/alice:/bin/bash",          // negative
		"alice:x:1001:abc:g:/home/alice:/bin/bash",         // non-numeric gid
		"alice:x:99999999999:1002:g:/home/alice:/bin/bash", // overflow
		"alice:x:4294967295:1002:g:/home/alice:/bin/bash",  // (uid_t)-1
		"ali/ce:x:1001:1002:g:/home/alice:/bin/bash",       // slash
	} {
		if _, err := ParsePasswdLine(bad); err == nil {
			t.Errorf("ParsePasswdLine(%q) accepted a malformed entry", bad)
		}
	}
}

func TestParseGroupAndInitgroups(t *testing.T) {
	group, err := ParseGroupLine("ai-devs:*:5001:alice,bob,,\n")
	if err != nil {
		t.Fatal(err)
	}
	if group.Name != "ai-devs" || group.GID != 5001 {
		t.Fatalf("unexpected group %+v", group)
	}
	if _, err := ParseGroupLine("ai-devs:*:5001"); err == nil {
		t.Fatal("short group entry accepted")
	}
	ids, err := ParseInitgroups("alice 1002 27 5001 27\n", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ids, []int{27, 1002, 5001}) {
		t.Fatalf("ParseInitgroups = %v", ids)
	}
	if _, err := ParseInitgroups("mallory 1 2", "alice"); err == nil {
		t.Fatal("initgroups output for another user accepted")
	}
	if _, err := ParseInitgroups("alice 1 x", "alice"); err == nil {
		t.Fatal("non-numeric initgroups gid accepted")
	}
	if got := withPrimary([]int{27, 5001}, 1002); !reflect.DeepEqual(got, []int{27, 1002, 5001}) {
		t.Fatalf("withPrimary = %v", got)
	}
}

func TestParseLoginDefsUIDRange(t *testing.T) {
	content := "# comment\nUID_MIN\t\t 2000\nUID_MAX 3000\nGID_MIN 100\n"
	if lo, hi := ParseLoginDefsUIDRange(content, 1000, 60000); lo != 2000 || hi != 3000 {
		t.Fatalf("range = %d-%d", lo, hi)
	}
	if lo, hi := ParseLoginDefsUIDRange("UID_MIN 9000\nUID_MAX 10\n", 1000, 60000); lo != 1000 || hi != 60000 {
		t.Fatalf("inverted range must fall back to defaults, got %d-%d", lo, hi)
	}
	if lo, hi := ParseLoginDefsUIDRange("UID_MIN abc\n", 1000, 60000); lo != 1000 || hi != 60000 {
		t.Fatalf("malformed value must keep defaults, got %d-%d", lo, hi)
	}
}

type fakeRun struct {
	mu      sync.Mutex
	calls   [][]string
	results map[string]commandResult
	errs    map[string]error
}

func (f *fakeRun) run(_ context.Context, path string, args []string, _ ...outputFilter) (commandResult, error) {
	key := strings.Join(args, " ")
	f.mu.Lock()
	f.calls = append(f.calls, append([]string{path}, args...))
	f.mu.Unlock()
	if err := f.errs[key]; err != nil {
		return commandResult{}, err
	}
	if result, ok := f.results[key]; ok {
		return result, nil
	}
	return commandResult{exitCode: getentExitNotFound}, nil
}

func newFakeNSS(f *fakeRun) *NSSResolver {
	return &NSSResolver{path: "/usr/bin/getent", runner: f.run}
}

func TestNSSResolverLookups(t *testing.T) {
	f := &fakeRun{results: map[string]commandResult{
		"passwd ldapuser":     {stdout: []byte("ldapuser:*:70001:70001:LDAP User:/home/ldapuser:/bin/bash\n")},
		"passwd 70001":        {stdout: []byte("ldapuser:*:70001:70001:LDAP User:/home/ldapuser:/bin/bash\n")},
		"passwd spoof":        {stdout: []byte("root:x:0:0:root:/root:/bin/bash\n")},
		"passwd twice":        {stdout: []byte("twice:x:1:1::/h:/bin/sh\ntwice:x:1:1::/h:/bin/sh\n")},
		"initgroups ldapuser": {stdout: []byte("ldapuser 70001 5001\n")},
		"group ai-devs":       {stdout: []byte("ai-devs:*:5001:ldapuser\n")},
		"group 5001":          {stdout: []byte("ai-devs:*:5001:ldapuser\n")},
		"passwd broken":       {exitCode: 1},
	}, errs: map[string]error{"passwd outage": errors.New("sssd timed out")}}
	r := newFakeNSS(f)
	account, err := r.LookupUser("ldapuser")
	if err != nil || account.UID != 70001 || account.Home != "/home/ldapuser" {
		t.Fatalf("LookupUser = %+v, %v", account, err)
	}
	if byUID, err := r.LookupUID(70001); err != nil || byUID.Name != "ldapuser" {
		t.Fatalf("LookupUID = %+v, %v", byUID, err)
	}
	if _, err := r.LookupUser("nobody-here"); !IsNotFound(err) {
		t.Fatalf("missing user error = %v, want ErrNotFound", err)
	}
	if _, err := r.LookupUser("outage"); err == nil || IsNotFound(err) {
		t.Fatalf("directory outage must be transient, got %v", err)
	}
	if _, err := r.LookupUser("broken"); err == nil || IsNotFound(err) {
		t.Fatalf("getent failure must be transient, got %v", err)
	}
	// GAP-0072: SSSD answers a principal in any case with its canonical name.
	f.results["passwd LDAPUser@EXAMPLE.TEST"] = commandResult{stdout: []byte("ldapuser@example.test:*:70002:70002::/home/ldapuser:/bin/bash\n")}
	if upper, err := r.LookupUser("LDAPUser@EXAMPLE.TEST"); err != nil || upper.UID != 70002 {
		t.Fatalf("a principal in another case = %+v, %v", upper, err)
	}
	if _, err := r.LookupUser("spoof"); err == nil {
		t.Fatal("an answer for a different account was accepted")
	}
	if _, err := r.LookupUser("twice"); err == nil {
		t.Fatal("multiple answers were accepted")
	}
	if _, err := r.LookupUser("-s"); err == nil {
		t.Fatal("option-looking key was passed to getent")
	}
	ids, err := r.GroupIDs(account)
	if err != nil || !reflect.DeepEqual(ids, []int{5001, 70001}) {
		t.Fatalf("GroupIDs = %v, %v", ids, err)
	}
	if group, err := r.LookupGroup("ai-devs"); err != nil || group.GID != 5001 {
		t.Fatalf("LookupGroup = %+v, %v", group, err)
	}
	if group, err := r.LookupGroupID(5001); err != nil || group.Name != "ai-devs" {
		t.Fatalf("LookupGroupID = %+v, %v", group, err)
	}
}

func TestNSSResolverListUsersSkipsMalformedRows(t *testing.T) {
	f := &fakeRun{results: map[string]commandResult{
		"passwd": {stdout: []byte("b:x:1002:1002::/home/b:/bin/bash\nbad line\na:x:1001:1001::/home/a:/bin/bash\n")},
	}}
	accounts, complete, err := newFakeNSS(f).ListUsers()
	if err != nil || complete {
		t.Fatalf("ListUsers err=%v complete=%v", err, complete)
	}
	if len(accounts) != 2 || accounts[0].Name != "a" || accounts[1].Name != "b" {
		t.Fatalf("ListUsers = %+v", accounts)
	}
	f.results["passwd"] = commandResult{exitCode: getentExitNoEnumerate}
	if accounts, _, err := newFakeNSS(f).ListUsers(); err != nil || len(accounts) != 0 {
		t.Fatalf("enumeration-unsupported backend must return empty, got %+v %v", accounts, err)
	}
}

type countingResolver struct {
	Resolver
	lookups int
	err     error
}

func (c *countingResolver) LookupUser(name string) (Account, error) {
	c.lookups++
	if c.err != nil {
		return Account{}, c.err
	}
	return Account{Name: name, UID: 1500, GID: 1500}, nil
}

func TestCachingResolverNeverCachesTransientErrors(t *testing.T) {
	inner := &countingResolver{err: errors.New("ldap down")}
	cache := NewCachingResolver(inner)
	for i := 0; i < 2; i++ {
		if _, err := cache.LookupUser("alice"); err == nil {
			t.Fatal("expected transient error")
		}
	}
	if inner.lookups != 2 {
		t.Fatalf("transient error was cached (%d lookups)", inner.lookups)
	}
	inner.err = nil
	for i := 0; i < 3; i++ {
		if _, err := cache.LookupUser("alice"); err != nil {
			t.Fatal(err)
		}
	}
	if inner.lookups != 3 {
		t.Fatalf("definitive answer was not cached (%d lookups)", inner.lookups)
	}
	cache.Reset()
	_, _ = cache.LookupUser("alice")
	if inner.lookups != 4 {
		t.Fatal("Reset did not drop the cache")
	}
}

func TestValidateTrustedToolRejectsUserOwnedBinary(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "getent")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: temp files are root-owned")
	}
	if err := validateTrustedTool(tool); err == nil {
		t.Fatal("a user-owned getent was trusted")
	}
	if err := validateTrustedTool("relative/getent"); err == nil {
		t.Fatal("a relative tool path was trusted")
	}
}

func TestRunTrustedCommandBoundsAndExitCodes(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "tool")
	body := "#!/bin/sh\n" +
		"case \"$1\" in\n" +
		"  env) env ;;\n" +
		"  big) head -c 200000 /dev/zero ;;\n" +
		"  code) exit 2 ;;\n" +
		"esac\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_LEAK_CHECK", "secret")
	result, err := runTrustedCommand(context.Background(), script, []string{"env"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(result.stdout), "DEFENSECLAW_LEAK_CHECK") {
		t.Fatal("the caller environment leaked into the directory tool")
	}
	if _, err := runTrustedCommand(context.Background(), script, []string{"big"}); !errors.Is(err, errOutputLimit) {
		t.Fatalf("oversized output error = %v, want errOutputLimit", err)
	}
	result, err = runTrustedCommand(context.Background(), script, []string{"code"})
	if err != nil || result.exitCode != 2 {
		t.Fatalf("exit code = %d, err = %v", result.exitCode, err)
	}
}

func FuzzParsePasswdLine(f *testing.F) {
	for _, seed := range []string{
		"alice:x:1001:1002:Alice:/home/alice:/bin/bash",
		"::::::",
		"a:b:c:d:e:f:g",
		"root:x:0:0:root:/root:/bin/bash",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		account, err := ParsePasswdLine(line)
		if err != nil {
			return
		}
		if account.Name == "" || account.UID < 0 || account.GID < 0 || strings.ContainsAny(account.Name, ":,/ ") {
			t.Fatalf("accepted invalid account %+v from %q", account, line)
		}
	})
}

func FuzzParseInitgroups(f *testing.F) {
	f.Add("alice 1 2 3", "alice")
	f.Add("", "alice")
	f.Fuzz(func(t *testing.T, output, user string) {
		ids, err := ParseInitgroups(output, user)
		if err != nil {
			return
		}
		for _, id := range ids {
			if id < 0 {
				t.Fatalf("negative gid from %q", output)
			}
		}
	})
}

// spellingResolver answers getent passwd like winbind and SSSD: a key in
// another spelling (or a UPN search) answers the account it finds.
type spellingResolver struct {
	Resolver
	answers map[string]Account
}

func (s spellingResolver) LookupUser(name string) (Account, error) {
	account, ok := s.answers[name]
	switch {
	case !ok:
		return Account{}, ErrNotFound
	case account.Name != name:
		return Account{}, &NameMismatchError{Key: name, Answered: account}
	}
	return account, nil
}

func (s spellingResolver) LookupUID(uid int) (Account, error) {
	for _, account := range s.answers {
		if account.UID == uid {
			return account, nil
		}
	}
	return Account{}, ErrNotFound
}

// GAP-0711, GAP-0740: profile-explain and policy --user take the spellings
// getent takes for the same account, and never another account a UPN or
// e-mail search answers.
func TestLookupAccountSpelling(t *testing.T) {
	eli6 := Account{Name: `DCLAB\dcad-eli6`, UID: 2003912}
	eli7 := Account{Name: "dcad-eli7", UID: 2003913}
	ldap := Account{Name: "ldapcarol", UID: 4001}
	r := spellingResolver{answers: map[string]Account{
		`DCLAB\dcad-eli6`: eli6, "dcad-eli6@dclab.test": eli6, "dcad-eli6": eli6,
		"dcad-eli7": eli7, `DCLAB\dcad-eli7`: eli7, "eli7.alt@alt.dclab.test": eli7,
		"carol@dclab.test": ldap,
	}}
	facts := func(uid int) (useridentity.DirectoryFacts, bool) {
		switch uid {
		case eli6.UID:
			return useridentity.DirectoryFacts{Domain: "dclab.test", Realm: "DCLAB.TEST"}, true
		case eli7.UID:
			return useridentity.DirectoryFacts{Domain: "dclab.test", UPN: "eli7.alt@alt.dclab.test"}, true
		}
		return useridentity.DirectoryFacts{Domain: "dclab.test"}, true
	}
	for _, tt := range []struct {
		name  string
		facts bool
		want  int
	}{
		{"dcad-eli6@dclab.test", true, eli6.UID},
		{"dcad-eli6@dclab.test", false, -1},
		{"dcad-eli6", false, eli6.UID},
		{`DCLAB\dcad-eli7`, false, eli7.UID},
		{"eli7.alt@alt.dclab.test", true, eli7.UID},
		{"carol@dclab.test", true, -1},
	} {
		lookupFacts := facts
		if !tt.facts {
			lookupFacts = nil
		}
		got, err := LookupAccountSpelling(r, tt.name, lookupFacts)
		if tt.want < 0 && err == nil || tt.want >= 0 && (err != nil || got.UID != tt.want) {
			t.Fatalf("LookupAccountSpelling(%q, facts=%v) = %+v, %v; want uid %d", tt.name, tt.facts, got, err, tt.want)
		}
	}
}
