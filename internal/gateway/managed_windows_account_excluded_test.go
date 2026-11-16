// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
)

// GAP-0979: the standalone Windows hook passes an account of exclude_users
// only on the gateway answer, and the gateway judges the SID that connected
// against its current configuration. An account the list does not name, a
// SID that is not a user account, an entry the account lookup cannot judge
// and an account removed from the list since the last answer are all "no",
// and nothing outside the configuration can change the answer.
func TestWindowsAccountExcludedNowFollowsTheCurrentExcludeUsers(t *testing.T) {
	const alice = "S-1-5-21-1004336348-1177238915-682003330-1001"
	const bob = "S-1-5-21-1004336348-1177238915-682003330-1002"
	previousAccount, previousHome := ownStatusWindowsAccount, userScopedIdentityHome
	t.Cleanup(func() { ownStatusWindowsAccount, userScopedIdentityHome = previousAccount, previousHome })
	ownStatusWindowsAccount = func(sid string) (string, string) {
		if sid == alice {
			return "alice", "CONTOSO"
		}
		return "bob", "CONTOSO"
	}
	userScopedIdentityHome = func(sid string) string {
		if sid == alice {
			return `C:\Users\alice`
		}
		return `C:\Users\bob`
	}
	api := ownStatusExcludedFixture(t, []string{`CONTOSO\alice`}, nil)
	for _, tc := range []struct {
		name string
		sid  string
		want bool
	}{
		{"a named account is excluded", alice, true},
		{"an account the list does not name is not", bob, false},
		{"a SID that is not a user account is not", "S-1-5-18", false},
		{"an empty SID is not", "", false},
	} {
		if got := api.windowsAccountExcludedNow(tc.sid); got != tc.want {
			t.Errorf("%s: windowsAccountExcludedNow(%q) = %t, want %t", tc.name, tc.sid, got, tc.want)
		}
	}

	// The list the gateway holds now decides: taking the account off it ends
	// the pass at the next question, with nothing else to revoke.
	api = ownStatusExcludedFixture(t, nil, nil)
	if api.windowsAccountExcludedNow(alice) {
		t.Fatal("an account removed from exclude_users is still reported excluded")
	}

	// A name the lookup cannot give leaves a name entry unjudged: no pass.
	ownStatusWindowsAccount = func(string) (string, string) { return "", "" }
	api = ownStatusExcludedFixture(t, []string{`CONTOSO\alice`}, nil)
	if api.windowsAccountExcludedNow(alice) {
		t.Fatal("an account the lookup could not name was reported excluded by a name entry")
	}
	// An entry that is the SID itself needs no lookup.
	api = ownStatusExcludedFixture(t, []string{alice}, nil)
	if !api.windowsAccountExcludedNow(alice) || api.windowsAccountExcludedNow(bob) {
		t.Fatal("a SID entry must exclude exactly that SID")
	}
}
