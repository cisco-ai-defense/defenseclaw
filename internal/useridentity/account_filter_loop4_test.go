// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import "testing"

// Review of GAP-1263 (loop 4): CORP\alice was deleted and created again
// with a new SID, the same RFC 2307 uid and the same qualified name. A
// filter of CORP\alice selected the former holder's rows by their recorded
// name before the account tokens were compared, and listed that history
// for the new account. A qualified filter's name match now also needs the
// row to be the resolved account's: the tokens agree, or the row names none
// while no other account is known to have held the uid.
func TestQualifiedNameMatchNeedsTheResolvedAccount(t *testing.T) {
	const uid, otherUID = "5000", "5001"
	const oldToken, newToken = "sid:S-1-5-21-1-1-1-1105", "sid:S-1-5-21-1-1-1-2207"
	domains := "corp.example corp corp.example"
	for _, tc := range []struct {
		name, filter   string
		holderChanged  bool
		rowID, rowName string
		rowToken       string
		want           bool
	}{
		{"former holder, same DOMAIN\\name", `CORP\alice`, true, uid, `CORP\alice`, oldToken, false},
		{"former holder, another case", `CORP\alice`, true, uid, `corp\ALICE`, oldToken, false},
		{"former holder, user@domain", "alice@corp.example", true, uid, "alice@corp.example", oldToken, false},
		{"former holder of the name under another uid", `CORP\alice`, true, otherUID, `CORP\alice`, oldToken, false},
		{"the account's own row", `CORP\alice`, true, uid, `CORP\alice`, newToken, true},
		{"the account's own row, another spelling", `CORP\alice`, true, uid, `corp\Alice`, newToken, true},
		{"no token, uid handed on", `CORP\alice`, true, uid, `CORP\alice`, "", false},
		{"no token, one holder known", `CORP\alice`, false, uid, `CORP\alice`, "", true},
		// GAP-0325: a filter resolved to a live account never takes a
		// tokenless row of another uid by its recorded name.
		{"no token, a deleted account's other uid", `CORP\alice`, true, otherUID, `CORP\alice`, "", false},
		// GAP-0422: given the uid it names now, a bare filter does not take
		// the former holder's rows of that uid; another uid's alice stays.
		{"bare filter, former holder of its uid", "alice", true, uid, `CORP\alice`, oldToken, false},
		{"bare filter, another uid's alice", "alice", true, otherUID, `CORP\alice`, oldToken, true},
		{"bare filter, its own row", "alice", true, uid, `CORP\alice`, newToken, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := NewAccountFilter(tc.filter, uid).WithAccountDomains(domains).WithAccountIncarnation(newToken, tc.holderChanged)
			if got := f.MatchesIn(tc.rowID, tc.rowName, domains, tc.rowToken); got != tc.want {
				t.Fatalf("filter %q on row %s %q (%q) = %v, want %v", tc.filter, tc.rowID, tc.rowName, tc.rowToken, got, tc.want)
			}
		})
	}
	// The views that keep no provenance (IDE plugins, discovery) still
	// match by the recorded name.
	if f := NewAccountFilter(`CORP\alice`, uid).WithAccountIncarnation(newToken, true); !f.Matches(uid, `CORP\alice`) {
		t.Fatal("a row without provenance is no longer selected by its name")
	}
	// No token known for the resolved account: the recorded name decides,
	// as before.
	if f := NewAccountFilter(`CORP\alice`, uid).WithAccountIncarnation("", false); !f.MatchesIn(uid, `CORP\alice`, domains, oldToken) {
		t.Fatal("a row is not selected by its name while the account's token is unknown")
	}
}
