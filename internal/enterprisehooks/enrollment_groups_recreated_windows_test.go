// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// testRecreatedGroupSID is the SID of a group recreated under the name of
// testDomainGroupSID's group.
const testRecreatedGroupSID = "S-1-5-21-111111111-222222222-333333333-1207"

// testOtherGroupSID is a group listed by SID, which needs no lookup.
const testOtherGroupSID = "S-1-5-21-111111111-222222222-333333333-1209"

// stubRecreatedGroupDirectory answers group name lookups with answer(name):
// a SID, an error, or a call that blocks until release is called (stuck).
// It shortens the lookup waits and drains the lookups still running at
// cleanup.
func stubRecreatedGroupDirectory(t *testing.T, answer func(name string) (sid string, err error, stuck bool)) (release func()) {
	t.Helper()
	held := make(chan struct{})
	var once sync.Once
	release = func() { once.Do(func() { close(held) }) }
	previousResolve, previousMembers, previousMachine := windowsResolveGroupName, windowsLocalGroupDirectMembers, windowsMachineAccountDomainSID
	previousTimeout, previousLimit := windowsGroupNameLookupTimeout, windowsGroupNameLookupCycleLimit
	previousComputer := windowsComputerName
	t.Cleanup(func() {
		release()
		waitIdentityLookupGateIdle(t, &windowsGroupNameLookupGate)
		windowsResolveGroupName, windowsLocalGroupDirectMembers, windowsMachineAccountDomainSID = previousResolve, previousMembers, previousMachine
		windowsGroupNameLookupTimeout, windowsGroupNameLookupCycleLimit = previousTimeout, previousLimit
		windowsComputerName = previousComputer
	})
	windowsComputerName = func() (string, error) { return testComputerName, nil }
	windowsGroupNameLookupTimeout, windowsGroupNameLookupCycleLimit = 30*time.Millisecond, 200*time.Millisecond
	windowsMachineAccountDomainSID = func() (string, error) { return testMachineDomainSID, nil }
	windowsLocalGroupDirectMembers = func(string) ([]string, error) { return nil, errors.New("not a local group") }
	var mu sync.Mutex
	windowsResolveGroupName = func(name string) (string, error) {
		mu.Lock()
		sid, err, stuck := answer(name)
		mu.Unlock()
		if stuck {
			<-held
			return "", errors.New("the lookup was abandoned")
		}
		return sid, err
	}
	return release
}

// W2B-G-enum review loop 3: an exclude_groups name kept the SID cached when
// it last resolved whenever its lookup timed out, was still running from an
// earlier cycle, or failed. A group deleted and recreated under the same
// name has another SID, so a user whose token holds the new SID was judged
// not excluded and the enumerator published their row despite the
// exclusion; an include_groups name could likewise revoke a member of the
// recreated group. A name that does not resolve this cycle now keeps its
// cached SID only for the users it lists: a decision that rests on a user
// not being in it is pending until the name resolves again.
//
// Review loop 4: the cached SID still decided the users it listed, so a
// holder of the old SID was excluded by an exclude_groups name, or admitted
// by an include_groups name and given a new row, although the recreated
// group may not hold them. The cached SID now decides no one: every user the
// entry would decide is pending, and only another entry still excludes or
// admits.
func TestWindowsGroupNameThatDoesNotResolveNowKeepsNoExclusionOfARecreatedGroup(t *testing.T) {
	for _, failure := range []struct {
		name  string
		stuck bool
		err   error
	}{
		{name: "lookup never returns", stuck: true},
		{name: "directory unreachable", err: errors.New("the domain controller is unreachable")},
		{name: "name not mapped while offline", err: windows.ERROR_NONE_MAPPED},
	} {
		t.Run(failure.name, func(t *testing.T) {
			var mu sync.Mutex
			state := "old"
			setState := func(next string) { mu.Lock(); state = next; mu.Unlock() }
			release := stubRecreatedGroupDirectory(t, func(string) (string, error, bool) {
				mu.Lock()
				defer mu.Unlock()
				switch state {
				case "old":
					return testDomainGroupSID, nil, false
				case "new":
					return testRecreatedGroupSID, nil, false
				}
				return "", failure.err, failure.stuck
			})
			exclude := []string{`CONTOSO\Contractors`}
			cache := NewWindowsEnrollmentGroupCache()
			first := newWindowsEnrollmentGroups(nil, exclude, map[string][]string{testDomainUserA: {}}, nil, cache, nil)
			if got, reason := first.decide(testDomainUserA); got != windowsEnrollmentEnrolled {
				t.Fatalf("before the change: %d (%s), want enrolled", got, reason)
			}
			if cache.Names[`contoso\contractors`] != testDomainGroupSID {
				t.Fatalf("names cached %v, want the old SID", cache.Names)
			}

			// The group is deleted and recreated under its name; the user's
			// new token holds the new SID, and the lookup does not answer.
			// Two cycles: a stuck lookup is still running at the second.
			setState("failing")
			recreated := map[string][]string{testDomainUserA: {testRecreatedGroupSID}}
			for cycle := 1; cycle <= 2; cycle++ {
				groups := newWindowsEnrollmentGroups(nil, exclude, recreated, nil, cache, nil)
				if got, reason := groups.decide(testDomainUserA); got != windowsEnrollmentUndecided || !strings.Contains(reason, "did not resolve this cycle") {
					t.Fatalf("cycle %d: member of the recreated group: %d (%s), want pending, never enrolled", cycle, got, reason)
				}
				// Nor is a holder of the cached SID excluded on it: the
				// recreated group may not hold them.
				old := newWindowsEnrollmentGroups(nil, exclude, map[string][]string{testDomainUserB: {testDomainGroupSID}}, nil, cache, nil)
				if got, reason := old.decide(testDomainUserB); got != windowsEnrollmentUndecided || !strings.Contains(reason, "did not resolve this cycle") {
					t.Fatalf("cycle %d: holder of the cached SID: %d (%s), want pending, never excluded on it", cycle, got, reason)
				}
				// Another exclude_groups entry still excludes, in either order.
				for _, list := range [][]string{append([]string{testOtherGroupSID}, exclude...), append(append([]string(nil), exclude...), testOtherGroupSID)} {
					other := newWindowsEnrollmentGroups(nil, list, map[string][]string{testDomainUserB: {testDomainGroupSID, testOtherGroupSID}}, nil, cache, nil)
					if got, reason := other.decide(testDomainUserB); got != windowsEnrollmentExcluded {
						t.Fatalf("cycle %d: %v: member of another excluded group: %d (%s), want excluded", cycle, list, got, reason)
					}
				}
				// A local account is in no group of the CONTOSO domain, whatever
				// its SID is now (review loop 5): it stays enrolled.
				local := newWindowsEnrollmentGroups(nil, exclude, map[string][]string{testLocalUserSID: {}}, nil, cache, nil)
				if got, reason := local.decide(testLocalUserSID); got != windowsEnrollmentEnrolled {
					t.Fatalf("cycle %d: local account: %d (%s), want enrolled", cycle, got, reason)
				}
				if cache.Names[`contoso\contractors`] != testDomainGroupSID {
					t.Fatalf("cycle %d: the cached SID was dropped: %v", cycle, cache.Names)
				}
			}

			// include_groups: a member of the recreated group is not revoked,
			// a holder of the cached SID is not admitted on it, and another
			// entry still admits, in either order.
			cache.Names[`contoso\developers`] = testDomainDevelopersSID
			for _, tc := range []struct {
				name    string
				include []string
				token   []string
				want    windowsEnrollmentDecision
			}{
				{"member of the recreated group", []string{`CONTOSO\Developers`}, []string{"S-1-5-21-111111111-222222222-333333333-1208"}, windowsEnrollmentUndecided},
				{"holder of the cached SID", []string{`CONTOSO\Developers`}, []string{testDomainDevelopersSID}, windowsEnrollmentUndecided},
				{"admitted by an entry listed after", []string{`CONTOSO\Developers`, testOtherGroupSID}, []string{testDomainDevelopersSID, testOtherGroupSID}, windowsEnrollmentEnrolled},
				{"admitted by an entry listed before", []string{testOtherGroupSID, `CONTOSO\Developers`}, []string{testOtherGroupSID}, windowsEnrollmentEnrolled},
			} {
				includes := newWindowsEnrollmentGroups(tc.include, nil, map[string][]string{testDomainUserA: tc.token}, nil, cache, nil)
				got, reason := includes.decide(testDomainUserA)
				if got != tc.want || (tc.want == windowsEnrollmentUndecided && !strings.Contains(reason, "did not resolve this cycle")) {
					t.Fatalf("include, %s: %d (%s), want %d", tc.name, got, reason, tc.want)
				}
			}

			// Once the name resolves again, its new SID decides.
			setState("new")
			release()
			waitIdentityLookupGateIdle(t, &windowsGroupNameLookupGate)
			groups := newWindowsEnrollmentGroups(nil, exclude, recreated, nil, cache, nil)
			if got, reason := groups.decide(testDomainUserA); got != windowsEnrollmentExcluded {
				t.Fatalf("after the name resolves again: %d (%s), want excluded", got, reason)
			}
			if cache.Names[`contoso\contractors`] != testRecreatedGroupSID {
				t.Fatalf("names cached %v, want the new SID", cache.Names)
			}
		})
	}
}

// The enumerator and the eligibility walk end to end, while the name does
// not resolve: the user's token holds the recreated group's SID, or still the
// cached one (review loop 4), for an exclude_groups or an include_groups
// name. Either way no row is published or revoked on the cached SID, and a
// signed-in user without a row is reported pending.
func TestEnumerateWindowsPublishesNoRowOnTheCachedSIDOfAnUnresolvedExcludeGroup(t *testing.T) {
	stubMachineWinGet(t, nil)
	previousActive, previousSignedIn := windowsActiveSessionGroups, windowsSignedInSessionUsers
	t.Cleanup(func() { windowsActiveSessionGroups, windowsSignedInSessionUsers = previousActive, previousSignedIn })
	windowsActiveSessionGroups, windowsSignedInSessionUsers = readWindowsActiveSessionGroups, readWindowsSignedInSessionUsers
	for _, tc := range []struct {
		name string
		// include: the name is an include_groups entry, not an
		// exclude_groups one. holder: the user's token holds the cached
		// (old) SID instead of the recreated group's.
		include, holder bool
		resolves        bool
		cached          bool
		rows            bool
		wantRows        string
		wantExcluded    string
		wantPending     bool
		wantEligible    int
	}{
		{name: "no row: none is published", cached: true, wantPending: true},
		{name: "an existing row is kept, never revoked", cached: true, rows: true, wantRows: testDomainUserA},
		{name: "holder of the cached SID without a row: reported, not excluded", holder: true, cached: true, wantPending: true},
		{name: "holder of the cached SID: its row is kept", holder: true, cached: true, rows: true, wantRows: testDomainUserA},
		{name: "include, holder of the cached SID without a row: none is published", include: true, holder: true, cached: true, wantPending: true},
		{name: "include, holder of the cached SID: its row is kept", include: true, holder: true, cached: true, rows: true, wantRows: testDomainUserA},
		{name: "include, member of the recreated group: its row is kept", include: true, cached: true, rows: true, wantRows: testDomainUserA},
		{name: "control: the name resolves to the new SID", resolves: true, cached: true, rows: true, wantExcluded: testDomainUserA},
		{name: "control: a name never resolved excludes no one", wantRows: testDomainUserA, wantEligible: 1},
		{name: "include control: the name resolves to the new SID the user holds", include: true, resolves: true, cached: true, wantRows: testDomainUserA, wantEligible: 1},
		{name: "include control: the name resolves, and the old SID admits no one", include: true, holder: true, resolves: true, cached: true, rows: true, wantExcluded: testDomainUserA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubRecreatedGroupDirectory(t, func(string) (string, error, bool) {
				if tc.resolves {
					return testRecreatedGroupSID, nil, false
				}
				return "", errors.New("the domain controller is unreachable"), false
			})
			stubWindowsSessionAPI(t, []windowsSession{{id: 1, state: windows.WTSActive}}, map[uint32]string{1: testDomainUserA}, nil, nil)
			token := testRecreatedGroupSID
			if tc.holder {
				token = testDomainGroupSID
			}
			stubWindowsSessionTokenGroups(map[uint32][]string{1: {token}}, nil)
			var include, exclude []string
			if tc.include {
				include = []string{`CONTOSO\Contractors`}
			} else {
				exclude = []string{`CONTOSO\Contractors`}
			}
			home := codexProfile(t, "0.150.0")
			injectWindowsProfileList(t, map[string]string{testDomainUserA: home})
			enabled := true
			var rows []ManifestTarget
			if tc.rows {
				rows = append(rows, ManifestTarget{SID: testDomainUserA, Connector: "codex", UserHome: home, DataDir: home + `\.defenseclaw`, AgentVersion: "0.150.0", Enabled: &enabled})
			}
			newCache := func() *WindowsEnrollmentGroupCache {
				cache := NewWindowsEnrollmentGroupCache()
				cache.Users[testDomainUserA] = []string{}
				if tc.cached {
					cache.Names[`contoso\contractors`] = testDomainGroupSID
				}
				return cache
			}
			eligible, err := WindowsStandaloneEligibleProfilesFor(context.Background(), EnumerateOptions{
				IncludeGroups: include, ExcludeGroups: exclude, GroupCache: newCache(),
			})
			if err != nil || len(eligible) != tc.wantEligible {
				t.Fatalf("eligible profiles %+v (%v), want %d", eligible, err, tc.wantEligible)
			}
			var excluded []string
			pending := 0
			manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("codex"), EnumerateOptions{
				ExistingManifestPath: writeWindowsTestManifest(t, rows...),
				IncludeGroups:        include,
				ExcludeGroups:        exclude,
				GroupCache:           newCache(),
				ReportExcluded:       func(target ManifestTarget) { excluded = append(excluded, target.SID) },
				ReportUnprotected: func(agent UnprotectedAgent) {
					if strings.Contains(agent.Reason, "pending") {
						pending++
					}
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := manifestSIDs(manifest); got != tc.wantRows {
				t.Fatalf("rows for %q, want %q", got, tc.wantRows)
			}
			if got := strings.Join(excluded, ","); got != tc.wantExcluded {
				t.Fatalf("excluded %q, want %q", got, tc.wantExcluded)
			}
			if tc.wantPending && pending != 1 {
				t.Fatalf("pending reports %d, want 1: the signed-in user can run the agent", pending)
			}
		})
	}
}
