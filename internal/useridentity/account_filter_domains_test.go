// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import "testing"

// Review of GAP-1263 (loop 1): after CORP\alice's uid was handed to
// OTHER\alice, a qualified filter that resolves to that uid selects only the
// rows recorded for an account of its domain. A row recorded without a
// domain (an older build's) is still selected by its uid, and another
// spelling of the resolved account's domain still selects its rows.
func TestAccountFilterKeepsAPriorHoldersRowsOut(t *testing.T) {
	const uid = "5000"
	corp, other := "corp.example corp", "other.example other"
	for _, tc := range []struct {
		filter, accountDomains, rowDomains string
		want                               bool
	}{
		{"alice@other.example", "", other, true},
		{"alice@other.example", "", corp, false},
		{"alice@OTHER.EXAMPLE", "", other, true},
		{`OTHER\alice`, "", other, true},
		{`OTHER\alice`, "", corp, false},
		{`OTHER\alice`, "other.example", "other.example", true},
		{`OTHER\alice`, "other.example", "corp.example", false},
		{"alice@other.example", "", "", true},
		{"alice", "", corp, true},
		{uid, "", corp, true},
	} {
		f := NewAccountFilter(tc.filter, uid).WithAccountDomains(tc.accountDomains)
		if got := f.MatchesIn(uid, "alice", tc.rowDomains, ""); got != tc.want {
			t.Errorf("filter %q (account domains %q) on a row of %q = %v, want %v", tc.filter, tc.accountDomains, tc.rowDomains, got, tc.want)
		}
	}
	// A deleted account's rows by its qualified name follow their domain too.
	removed := NewAccountFilter("alice@other.example").WithRemovedAccounts(func(string) bool { return true })
	if removed.MatchesIn(uid, "alice", corp, "") || !removed.MatchesIn(uid, "alice", other, "") || !removed.MatchesIn(uid, "alice", "", "") {
		t.Error("a removed account's qualified filter does not follow the rows' domains")
	}
}

// A qualified filter that resolves to a live account must not take a
// tokenless row of a previous holder merely because its recorded name is
// identical. A name-only lookup remains useful after account deletion.
func TestQualifiedAccountFilterRejectsPriorUIDWithTheSameRecordedName(t *testing.T) {
	resolved := NewAccountFilter(`CORP\alice`, "2002")
	if resolved.MatchesIn("1001", `CORP\alice`, "corp", "") || !resolved.MatchesIn("2002", "alice", "corp", "") {
		t.Fatal("resolved account filter selected the old UID or missed the live UID")
	}
	unresolved := NewAccountFilter(`CORP\alice`)
	if !unresolved.MatchesIn("1001", `CORP\alice`, "corp", "") {
		t.Fatal("unresolved qualified name lost its recorded-name fallback")
	}
}

// Since loop 3 the provenance names only the domains that own the account:
// a UPN suffix is an alias two domains' accounts can share.
func TestAccountDomainsNamesTheOwningDomains(t *testing.T) {
	facts := DirectoryFacts{
		Domain: "corp.example", AccountDomain: "CORP", Realm: "CORP.EXAMPLE",
		UPN: "alice.smith@corp.com", Principal: "alice@CORP.EXAMPLE", Directory: DirectoryActiveDirectory,
	}
	if got := AccountDomains(facts); got != "corp.example corp" {
		t.Errorf("AccountDomains = %q", got)
	}
	if got := AccountDomains(DirectoryFacts{Directory: DirectoryLocal, AccountDomain: "HOST1"}); got != ". host1" {
		t.Errorf("AccountDomains of a local account = %q", got)
	}
	if got := AccountDomains(DirectoryFacts{}); got != "" {
		t.Errorf("AccountDomains of facts without a domain = %q", got)
	}
}
