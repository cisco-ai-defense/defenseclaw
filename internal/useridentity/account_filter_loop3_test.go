// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import "testing"

// Review of GAP-1263 (loop 3): once CORP's uid passed to OTHER, both
// accounts can have UPNs under one suffix (login.example), and a provenance
// that named UPN suffixes made CORP's row read as OTHER's. Rows are told
// apart by the account token where both sides name one, and by the owning
// domains otherwise. A row that names no provenance at all (written before
// inventory v7, or before the account's facts were cached) is not selected
// by the uid once another account is known to have held it.
func TestAccountFilterMatchesRowsOfTheResolvedAccountOnly(t *testing.T) {
	const uid = "5000"
	const corpToken, otherToken = "sid:S-1-5-21-1-1-1-1105", "sid:S-1-5-21-2-2-2-1105"
	corpFacts := DirectoryFacts{Domain: "corp.example", AccountDomain: "CORP", Realm: "CORP.EXAMPLE", UPN: "alice@login.example", Principal: "alice@login.example"}
	otherFacts := DirectoryFacts{Domain: "other.example", AccountDomain: "OTHER", Realm: "OTHER.EXAMPLE", UPN: "alice@login.example", Principal: "alice@login.example"}
	corp, other := AccountDomains(corpFacts), AccountDomains(otherFacts)
	for _, tc := range []struct {
		name, filter       string
		incarnation        string
		holderChanged      bool
		rowDomains, rowInc string
		want               bool
	}{
		{"shared UPN suffix, CORP's row", `OTHER\alice`, otherToken, true, corp, corpToken, false},
		{"shared UPN suffix, CORP's row, UPN spelling", "alice@login.example", otherToken, true, corp, corpToken, false},
		{"shared UPN suffix, OTHER's row", "alice@login.example", otherToken, true, other, otherToken, true},
		{"token decides over overlapping domains", `OTHER\alice`, otherToken, true, other + " corp.example", corpToken, false},
		{"row without a token, other domains", `OTHER\alice`, otherToken, false, corp, "", false},
		{"row without provenance after the uid moved", `OTHER\alice`, otherToken, true, "", "", false},
		{"row with domains but no token after the uid moved", `OTHER\alice`, otherToken, true, other, "", false},
		{"row without provenance, one holder known", `OTHER\alice`, otherToken, false, "", "", true},
		{"no token known now: domains decide", `OTHER\alice`, "", false, other, otherToken, true},
		// GAP-0422: a bare filter given the uid its name names now does not
		// list that uid's rows of another holder; without the uid it names
		// every alice, as before.
		{"bare filter given the uid", "alice", otherToken, true, corp, corpToken, false},
		{"bare filter given the uid, own row", "alice", otherToken, true, other, otherToken, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := NewAccountFilter(tc.filter, uid).WithAccountDomains(other).WithAccountIncarnation(tc.incarnation, tc.holderChanged)
			if got := f.MatchesIn(uid, "alice", tc.rowDomains, tc.rowInc); got != tc.want {
				t.Fatalf("filter %q on a row of %q (%q) = %v, want %v", tc.filter, tc.rowDomains, tc.rowInc, got, tc.want)
			}
		})
	}
	if f := NewAccountFilter("alice").WithAccountIncarnation(otherToken, true); !f.MatchesIn(uid, "alice", corp, corpToken) {
		t.Fatal("a bare filter without the uid no longer names every alice")
	}
	if f := NewAccountFilter("alice", uid).WithAccountIncarnation(otherToken, true); !f.MatchesIn("5001", "alice", corp, corpToken) {
		t.Fatal("a bare filter given one uid dropped another uid's alice")
	}
	// A Windows SID is never handed on: its rows match by the SID.
	sid := "S-1-5-21-1-1-1-1105"
	if f := NewAccountFilter(`CORP\alice`, sid).WithAccountIncarnation("", true); !f.MatchesIn(sid, "alice", "", "") {
		t.Fatal("a SID row without provenance is not selected by its SID")
	}
	if f := NewAccountFilter(`OTHER\alice`, uid).WithAccountIncarnation("", true); f.MatchesIn("99999", `OTHER\alice`, "", "old-holder") {
		t.Fatal("an unproven uid holder selected a same-name row from another uid")
	}
	// Rows of the views that keep no provenance keep being selected by id.
	if f := NewAccountFilter(`OTHER\alice`, uid).WithAccountIncarnation(otherToken, true); !f.Matches(uid, "alice") {
		t.Fatal("an IDE row of the resolved uid is no longer selected")
	}
}
