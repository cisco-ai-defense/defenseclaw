// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
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
		}
		return "", "", unixidentity.ErrNotFound
	}
	profileExplainDirectoryFacts = func(id string) (useridentity.DirectoryFacts, error) {
		return map[string]useridentity.DirectoryFacts{
			"1001": {Domain: "corp.example.com", ResolvedAt: time.Now()},
			"1002": {Domain: "corp.example.com", AccountDomain: "CORP", ResolvedAt: time.Now()},
		}[id], nil
	}
	profileGroupExists = func(_ context.Context, name string) (bool, error) { return name == `CORP\domain users`, nil }
	set := &guardrailProfileSet{assignments: []config.ProfileAssignment{{Profile: "strict",
		Match: config.ProfileMatch{Users: []string{`NB\alice`, `CORP\bob`, `CORP\gone`, `LONGFIRSTLABEL16\alice`, "carol"}}}}}
	got := set.unknownGroupWarningsWith(func(context.Context, string) (bool, error) { return true, nil }, nil, profileUserEntryUnmatched(),
		func() identityCacheHealth { return identityCacheHealth{} }, 2*time.Second)
	want := []string{`users entry "NB\\alice" names uid 1001, but this host confirms that account's domain as corp.example.com, not NB`,
		`users entry "CORP\\gone" names no account this host knows`, `users entry "LONGFIRSTLABEL16\\alice" names LONGFIRSTLABEL16, a domain`}
	if len(got) != len(want) {
		t.Fatalf("warnings = %q", got)
	}
	for i, fragment := range want {
		if !strings.Contains(got[i], fragment) || !strings.Contains(got[i], "selects nobody") {
			t.Fatalf("warning %d = %q, want %q", i, got[i], fragment)
		}
	}
}
