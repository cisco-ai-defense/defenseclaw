//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// GAP-0759: the dot-backslash spelling names the local account of that name
// and resolves to the account its uid resolves to; a directory namesake, a
// name no local account has and a uid held under another name never answer
// for it. Other spellings are LookupAccountSpelling unchanged.
func TestLookupAdminAccountSpellingLocal(t *testing.T) {
	local := Account{Name: "short", UID: 1059}
	directory := Account{Name: "short@dclab.test", UID: 94408157}
	other := Account{Name: "shared", UID: 1070}
	r := spellingResolver{answers: map[string]Account{
		"short": local, "short@dclab.test": directory, "shared": other,
		"Dup": {Name: "Dup", UID: 1080}, "dup": {Name: "dup", UID: 1081},
	}}
	prev := LocalSpellingAccounts
	t.Cleanup(func() { LocalSpellingAccounts = prev })
	locals := map[string]int{"short": 1059, "ghost": 1071, "taken": 1070, "Dup": 1080, "dup": 1081}
	LocalSpellingAccounts = func(context.Context) (map[string]int, error) { return locals, nil }
	for _, tt := range []struct {
		name string
		want int
	}{
		{`.\short`, 1059},
		{`.\SHORT`, 1059}, // a case variant of the one local account (review M1)
		{`.\Short`, 1059},
		{`.\Dup`, 1080}, // an exact name wins over its case variants
		{`.\dup`, 1081},
		{`.\DUP`, -1}, // two accounts differ only in case: names neither
		{` .\short `, 1059},
		{`.\ghost`, -1},  // in the passwd file, not answered by NSS
		{`.\taken`, -1},  // its uid answers under another name
		{`.\nobody`, -1}, // no local account
		{`.\`, -1},       // no name
		{`.\short@dclab.test`, -1},
		{`.\DCLAB\short`, -1},
		{"short@dclab.test", 94408157}, // other spellings are unchanged
		{"short", 1059},
	} {
		got, err := LookupAdminAccountSpelling(r, tt.name, nil)
		if tt.want < 0 && err == nil || tt.want >= 0 && (err != nil || got.UID != tt.want) {
			t.Fatalf("LookupAdminAccountSpelling(%q) = %+v, %v; want uid %d", tt.name, got, err, tt.want)
		}
		if err != nil {
			said := AccountLookupError(tt.name, "", err).Error()
			if strings.Contains(said, "unixidentity:") {
				t.Fatalf("the lookup error of %q keeps the package prefix: %s", tt.name, said)
			}
			if IsNotFound(err) && !strings.Contains(said, "no local account named") {
				t.Fatalf("the not-found sentence of %q does not name the local spelling: %s", tt.name, said)
			}
		}
	}
	// An unreadable local database is not a missing account.
	LocalSpellingAccounts = func(context.Context) (map[string]int, error) { return nil, errors.New("unreadable") }
	if _, err := LookupAdminAccountSpelling(r, `.\short`, nil); err == nil || IsNotFound(err) {
		t.Fatalf("unreadable database: %v; want an error that is not not-found", err)
	}
}
