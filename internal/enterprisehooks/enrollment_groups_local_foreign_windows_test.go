// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// testComputerName is the computer name the group directory stubs report.
const testComputerName = "WS01"

// W2B-G-enum review loop 5: once a cached exclude_groups name stopped
// resolving, every user was pending, local accounts included, so a new local
// account got no hook rows although no directory group can hold a local
// account. Before review loop 4 the cached SID decided them "not a member".
// A name written DOMAIN\group with another domain than this computer, cached
// as a directory group, now leaves local accounts certainly outside it
// without using the cached SID; every other unverified entry stays pending
// for them.
func TestUnverifiedGroupOfAnotherDomainStillLeavesLocalAccountsEnrolled(t *testing.T) {
	const localGroupSID = testMachineDomainSID + "-1010"
	for _, tc := range []struct {
		name      string
		include   []string
		exclude   []string
		cached    map[string]string
		user      string
		signedIn  bool
		computer  string
		noMachine bool
		want      windowsEnrollmentDecision
	}{
		{name: "local account signed in", exclude: []string{`CONTOSO\Contractors`}, user: testLocalUserSID, signedIn: true,
			want: windowsEnrollmentEnrolled},
		{name: "local account signed out, never cached", exclude: []string{`CONTOSO\Contractors`}, user: testLocalUserSID,
			want: windowsEnrollmentEnrolled},
		{name: "a DNS domain name", exclude: []string{`contoso.test\Contractors`}, cached: map[string]string{`contoso.test\contractors`: testDomainGroupSID},
			user: testLocalUserSID, signedIn: true, want: windowsEnrollmentEnrolled},
		{name: "include_groups: certain non-member, as when the name resolves", include: []string{`CONTOSO\Contractors`}, user: testLocalUserSID,
			signedIn: true, want: windowsEnrollmentExcluded},
		{name: "a directory user stays pending", exclude: []string{`CONTOSO\Contractors`}, user: testDomainUserA, signedIn: true,
			want: windowsEnrollmentUndecided},
		{name: "an unqualified name can name a local group", exclude: []string{`Contractors`}, cached: map[string]string{`contractors`: testDomainGroupSID},
			user: testLocalUserSID, signedIn: true, want: windowsEnrollmentUndecided},
		{name: "the computer's own name", exclude: []string{testComputerName + `\Contractors`},
			cached: map[string]string{strings.ToLower(testComputerName) + `\contractors`: testDomainGroupSID}, user: testLocalUserSID, signedIn: true,
			want: windowsEnrollmentUndecided},
		{name: "the computer's own name in another case", exclude: []string{`ws01\Contractors`}, cached: map[string]string{`ws01\contractors`: testDomainGroupSID},
			user: testLocalUserSID, signedIn: true, want: windowsEnrollmentUndecided},
		{name: "BUILTIN", exclude: []string{`BUILTIN\Contractors`}, cached: map[string]string{`builtin\contractors`: testDomainGroupSID},
			user: testLocalUserSID, signedIn: true, want: windowsEnrollmentUndecided},
		{name: "an NT authority", exclude: []string{`NT AUTHORITY\Contractors`}, cached: map[string]string{`nt authority\contractors`: testDomainGroupSID},
			user: testLocalUserSID, signedIn: true, want: windowsEnrollmentUndecided},
		{name: "cached as a local group", exclude: []string{`CONTOSO\Contractors`}, cached: map[string]string{`contoso\contractors`: localGroupSID},
			user: testLocalUserSID, signedIn: true, want: windowsEnrollmentUndecided},
		{name: "cached as a well-known group", exclude: []string{`CONTOSO\Contractors`}, cached: map[string]string{`contoso\contractors`: "S-1-5-4"},
			user: testLocalUserSID, signedIn: true, want: windowsEnrollmentUndecided},
		{name: "the computer name is unreadable", exclude: []string{`CONTOSO\Contractors`}, user: testLocalUserSID, signedIn: true, computer: "-",
			want: windowsEnrollmentUndecided},
		{name: "the machine SID is unreadable", exclude: []string{`CONTOSO\Contractors`}, user: testLocalUserSID, signedIn: true, noMachine: true,
			want: windowsEnrollmentUndecided},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubRecreatedGroupDirectory(t, func(string) (string, error, bool) {
				return "", errors.New("the domain controller is unreachable"), false
			})
			if tc.computer == "-" {
				windowsComputerName = func() (string, error) { return "", errors.New("unreadable") }
			}
			if tc.noMachine {
				windowsMachineAccountDomainSID = func() (string, error) { return "", errors.New("unreadable") }
			}
			cache := NewWindowsEnrollmentGroupCache()
			cache.Names = map[string]string{`contoso\contractors`: testDomainGroupSID}
			if tc.cached != nil {
				cache.Names = tc.cached
			}
			sessions := map[string][]string{}
			if tc.signedIn {
				sessions[tc.user] = []string{}
			}
			groups := newWindowsEnrollmentGroups(tc.include, tc.exclude, sessions, nil, cache, nil)
			if got, reason := groups.decide(tc.user); got != tc.want {
				t.Fatalf("decision %d (%s), want %d", got, reason, tc.want)
			}
		})
	}
}

// The enumerator end to end: a new local account signed in while a cached
// exclude_groups name of the domain does not resolve gets its row, and the
// guardian's eligibility walk lists it; a directory user does not.
func TestEnumerateWindowsEnrollsANewLocalAccountWhileADomainExcludeGroupDoesNotResolve(t *testing.T) {
	stubMachineWinGet(t, nil)
	previousActive, previousSignedIn := windowsActiveSessionGroups, windowsSignedInSessionUsers
	t.Cleanup(func() { windowsActiveSessionGroups, windowsSignedInSessionUsers = previousActive, previousSignedIn })
	windowsActiveSessionGroups, windowsSignedInSessionUsers = readWindowsActiveSessionGroups, readWindowsSignedInSessionUsers
	for _, tc := range []struct {
		user         string
		wantRows     string
		wantEligible int
	}{
		{user: testLocalUserSID, wantRows: testLocalUserSID, wantEligible: 1},
		{user: testDomainUserA},
	} {
		t.Run(tc.user, func(t *testing.T) {
			stubRecreatedGroupDirectory(t, func(string) (string, error, bool) {
				return "", errors.New("the domain controller is unreachable"), false
			})
			stubWindowsSessionAPI(t, []windowsSession{{id: 1, state: windows.WTSActive}}, map[uint32]string{1: tc.user}, nil, nil)
			stubWindowsSessionTokenGroups(map[uint32][]string{1: {}}, nil)
			exclude := []string{`CONTOSO\Contractors`}
			home := codexProfile(t, "0.150.0")
			injectWindowsProfileList(t, map[string]string{tc.user: home})
			newCache := func() *WindowsEnrollmentGroupCache {
				cache := NewWindowsEnrollmentGroupCache()
				cache.Names[`contoso\contractors`] = testDomainGroupSID
				return cache
			}
			eligible, err := WindowsStandaloneEligibleProfilesFor(context.Background(), EnumerateOptions{ExcludeGroups: exclude, GroupCache: newCache()})
			if err != nil || len(eligible) != tc.wantEligible {
				t.Fatalf("eligible profiles %+v (%v), want %d", eligible, err, tc.wantEligible)
			}
			manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("codex"), EnumerateOptions{
				ExistingManifestPath: writeWindowsTestManifest(t),
				ExcludeGroups:        exclude,
				GroupCache:           newCache(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := manifestSIDs(manifest); got != tc.wantRows {
				t.Fatalf("rows for %q, want %q", got, tc.wantRows)
			}
		})
	}
}
