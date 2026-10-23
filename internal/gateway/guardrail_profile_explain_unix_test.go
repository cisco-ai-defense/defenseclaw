// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

func TestProfileExplainUnknownAccountNamesGetentSpelling(t *testing.T) {
	previous := profileExplainQualifiedName
	profileExplainQualifiedName = func(context.Context, string) string { return "dcad-eli6@dclab.test" }
	t.Cleanup(func() { profileExplainQualifiedName = previous })
	_, err := profileExplainUnresolved("dcad-eli6", nil)
	if err == nil || !strings.Contains(err.Error(), `no account named "dcad-eli6"`) ||
		!strings.Contains(err.Error(), `getent passwd knows "dcad-eli6@dclab.test"`) {
		t.Fatalf("unknown account explanation = %v", err)
	}
}

// GAP-1095: a DOMAIN\user users entry selects nobody when the host resolves
// it to an account whose domain it does not confirm, or knows no account or
// no domain by it; the assignment warnings status and explain show name it.
func TestUnmatchedUserEntryWarns(t *testing.T) {
	account, facts, groups := profileExplainAccount, profileExplainDirectoryFacts, profileGroupExists
	t.Cleanup(func() {
		profileExplainAccount, profileExplainDirectoryFacts, profileGroupExists = account, facts, groups
	})
	profileExplainAccount = func(name string) (string, string, error) {
		switch name {
		case `NB\alice`:
			return "1001", "alice", nil
		case `CORP\bob`:
			return "1002", "bob", nil
		case "ent-alice":
			// macOS takes no dclab.test\ent-alice spelling; the bare name
			// names the AD account.
			return "1003", "ent-alice", nil
		case "ent-carol":
			return "2500", "ent-carol", nil
		}
		return "", "", unixidentity.ErrNotFound
	}
	profileExplainDirectoryFacts = func(id string) (useridentity.DirectoryFacts, error) {
		return map[string]useridentity.DirectoryFacts{
			"1001": {Domain: "corp.example.com", ResolvedAt: time.Now()},
			"1002": {Domain: "corp.example.com", AccountDomain: "CORP", ResolvedAt: time.Now()},
			"1003": {Directory: useridentity.DirectoryActiveDirectory, Domain: "dclab.test", AccountDomain: "DCLAB", ResolvedAt: time.Now()},
			"2500": {Directory: useridentity.DirectoryLocal, Source: useridentity.SourceNSSFiles, ResolvedAt: time.Now()},
		}[id], nil
	}
	profileGroupExists = func(_ context.Context, name string) (bool, error) { return name == `CORP\domain users`, nil }
	set := &guardrailProfileSet{assignments: []config.ProfileAssignment{{Profile: "strict",
		Match: config.ProfileMatch{Users: []string{`NB\alice`, `CORP\bob`, `CORP\gone`, `LONGFIRSTLABEL16\alice`, "carol",
			`dclab.test\ent-alice`, "ent-alice", "ent-carol", `.\ent-carol`}}}}}
	got := set.unknownGroupWarningsWith(func(context.Context, string) (bool, error) { return true, nil }, nil, nil, profileUserEntryUnmatched(),
		func() identityCacheHealth { return identityCacheHealth{} }, 2*time.Second)
	// GAP-0310, GAP-0395: dclab.test\ent-alice selects the AD ent-alice, as
	// the matcher does, so it is not reported; GAP-0305: a bare name of a
	// local account is.
	want := []string{`users entry "NB\\alice" names uid 1001, but this host confirms that account's domain as corp.example.com, not NB`,
		`users entry "CORP\\gone" names no account this host knows`, `users entry "LONGFIRSTLABEL16\\alice" names LONGFIRSTLABEL16, a domain`,
		`users entry "ent-carol" names the local account ent-carol (uid 2500) of this host, which a bare name does not select`}
	if len(got) != len(want) {
		t.Fatalf("warnings = %q", got)
	}
	for i, fragment := range want {
		if !strings.Contains(got[i], fragment) || i < 3 && !strings.Contains(got[i], "selects nobody") {
			t.Fatalf("warning %d = %q, want %q", i, got[i], fragment)
		}
	}
	subject, err := lookupDirectoryProfileSubject("ent-alice")
	if err != nil || !userEntryMatches(&subject, `dclab.test\ent-alice`) {
		t.Fatalf("the matcher must select %+v (%v) by the entry the warning accepts", subject, err)
	}
}

// GAP-0361: a uid the account database cannot name now (a cold gateway with
// the domain controller away) is explained as its hook calls are decided: a
// users entry naming the uid selects its profile, as the hook's
// kernel-verified uid does; a request needing other missing facts is refused
// and names them (default_lookup_failed). Explain used to report only the match.
func TestProfileExplainUIDTheDirectoryCannotNameMatchesItsUsersEntry(t *testing.T) {
	prevFacts, prevCached, prevBlocking := profileExplainDirectoryFacts, profileExplainCachedSubject, identityLookupBlocking.Load()
	t.Cleanup(func() {
		profileExplainDirectoryFacts, profileExplainCachedSubject = prevFacts, prevCached
		setIdentityLookupBlocking(prevBlocking)
	})
	lookupCalls := 0
	profileExplainDirectoryFacts = func(string) (useridentity.DirectoryFacts, error) {
		lookupCalls++
		return useridentity.DirectoryFacts{}, errors.New("SSSD NSS responder: i/o timeout")
	}
	profileExplainCachedSubject = func(string, time.Time) (profileSubject, error) { return profileSubject{}, errNoCachedHolder }
	setIdentityLookupBlocking(true)
	subject, err := profileExplainUnresolved("94404076", unixidentity.ErrNotFound)
	if err != nil || subject.UserID != "94404076" || !subject.LookupFailed || !subject.accountUnresolved ||
		!strings.Contains(subject.LookupError, "account database names no account") {
		t.Fatalf("subject %+v, err %v; want the uid with the lookup failure", subject, err)
	}
	if lookupCalls != 0 {
		t.Fatalf("unknown-account explain started %d directory lookup(s); it must not add a false health warning", lookupCalls)
	}
	set := &guardrailProfileSet{
		profiles: map[string]config.DerivedGuardrailProfile{"contractors": {Digest: "d1"}, "engineering": {Digest: "d2"}, "offline-floor": {Digest: "d3"}},
		assignments: []config.ProfileAssignment{
			{Profile: "contractors", Match: config.ProfileMatch{Users: []string{"94404076"}}},
			{Profile: "engineering", Match: config.ProfileMatch{Groups: []string{"dc-sbx-devs@dclab.test"}}},
		},
		defaultProfile: "offline-floor",
	}
	// r104 identity: the uid entry matches, and the group entry may: the
	// profile that covers the others, or their strictest combination,
	// decides.
	if decision := set.match(&subject, profileSubjectLookup, "claudecode", ""); decision.Match != profileMatchDefaultLookupFailed ||
		!slices.Contains(decision.Candidates, "contractors") || !slices.Contains(decision.Candidates, "engineering") {
		t.Fatalf("decision = %+v; want contractors (by the uid entry) and engineering among the candidates", decision)
	}
	other, _ := profileExplainUnresolved("94404077", unixidentity.ErrNotFound)
	if decision := set.match(&other, profileSubjectLookup, "claudecode", ""); decision.Match != profileMatchDefaultLookupFailed {
		t.Fatalf("decision = %+v; want default_lookup_failed for a uid no entry names", decision)
	}
}
