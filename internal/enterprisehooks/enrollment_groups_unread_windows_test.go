// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

const testDomainDevelopersSID = "S-1-5-21-111111111-222222222-333333333-1106"

// stubWindowsSessionTokenGroups replaces the token group read of the stubbed
// sessions (stubWindowsSessionAPI): groups and errs are keyed by session id.
func stubWindowsSessionTokenGroups(groups map[uint32][]string, errs map[uint32]error) {
	windowsSessionAPI.tokenGroups = func(token windows.Token) ([]string, error) {
		id := uint32(token) - 1000
		if err := errs[id]; err != nil {
			return nil, err
		}
		return append([]string{}, groups[id]...), nil
	}
}

// W2B-G-enum review loop 2: an active session whose token groups could not
// be read was left out with no error, and so was every session whose user
// could not be identified, so group evaluation used the membership cached at
// the user's earlier sign-in. After a group change, an include_groups or
// exclude_groups decision then dropped the existing rows of a user who is
// signed in now. The read now names what it missed, and a decision that rests
// on those cached groups changes nothing that cycle.
func TestReadWindowsActiveSessionGroupsNamesTheSessionsItCouldNotRead(t *testing.T) {
	sessions := []windowsSession{{id: 1, state: windows.WTSActive}, {id: 2, state: windows.WTSActive}, {id: 3, state: windows.WTSActive}}
	tokens := map[uint32]string{1: testDomainUserA, 2: testDomainUserB, 3: testDomainUserB}
	stubWindowsSessionAPI(t, sessions, tokens, nil, nil)

	stubWindowsSessionTokenGroups(map[uint32][]string{1: {testDomainGroupSID}, 2: {}, 3: {}}, nil)
	groups, err := readWindowsActiveSessionGroups()
	if err != nil || len(groups) != 2 {
		t.Fatalf("complete read: groups %v, err %v; want both users and no error", groups, err)
	}

	// B's second session is unreadable: B is unread, A is read.
	stubWindowsSessionTokenGroups(map[uint32][]string{1: {testDomainGroupSID}, 2: {}}, map[uint32]error{3: windows.ERROR_ACCESS_DENIED})
	groups, err = readWindowsActiveSessionGroups()
	unread, anyone := windowsSessionGroupsInDoubt(err)
	if _, ok := groups[testDomainUserB]; ok || len(groups[testDomainUserA]) != 1 {
		t.Fatalf("groups %v, want A only: B has a session whose groups were not read", groups)
	}
	if !unread[testDomainUserB] || unread[testDomainUserA] || anyone || errors.Is(err, errWindowsSessionsUnidentified) {
		t.Fatalf("err %v: unread %v, anyone %v; want B unread and every session's user identified", err, unread, anyone)
	}

	// A session whose user cannot be identified puts anyone in doubt.
	stubWindowsSessionAPI(t, append(sessions, windowsSession{id: 4, state: windows.WTSActive}), tokens, map[uint32]error{4: windows.ERROR_ACCESS_DENIED}, nil)
	stubWindowsSessionTokenGroups(map[uint32][]string{1: {}, 2: {}, 3: {}}, nil)
	groups, err = readWindowsActiveSessionGroups()
	if _, anyone := windowsSessionGroupsInDoubt(err); !anyone || !errors.Is(err, errWindowsSessionsUnidentified) || len(groups) != 2 {
		t.Fatalf("unidentified session: groups %v, err %v; want the users read and anyone in doubt", groups, err)
	}

	// Sessions that cannot be listed at all put anyone in doubt too.
	if _, anyone := windowsSessionGroupsInDoubt(errors.New("enumerate Windows sessions: access denied")); !anyone {
		t.Fatal("an unlisted session read must put anyone in doubt")
	}
}

// The enumerator end to end, with an existing row and stale cached groups.
func TestEnumerateWindowsKeepsRowsWhileAnActiveSessionsGroupsAreUnreadable(t *testing.T) {
	stubMachineWinGet(t, nil)
	stubGroupDirectory(t, map[string]string{
		`contoso\developers`:  testDomainDevelopersSID,
		`contoso\contractors`: testDomainGroupSID,
	}, map[string][]string{})
	previousActive, previousSignedIn := windowsActiveSessionGroups, windowsSignedInSessionUsers
	t.Cleanup(func() { windowsActiveSessionGroups, windowsSignedInSessionUsers = previousActive, previousSignedIn })
	windowsActiveSessionGroups, windowsSignedInSessionUsers = readWindowsActiveSessionGroups, readWindowsSignedInSessionUsers
	activeA := []windowsSession{{id: 1, state: windows.WTSActive}}
	unidentified := []windowsSession{{id: 2, state: windows.WTSActive}}
	include, exclude := []string{`CONTOSO\Developers`}, []string{`CONTOSO\Contractors`}
	for _, tc := range []struct {
		name             string
		include, exclude []string
		cache            map[string][]string
		sessions         []windowsSession
		tokenErrs        map[uint32]error
		groups           map[uint32][]string
		groupErrs        map[uint32]error
		rows             []string
		wantRows         string
		wantExcluded     string
		wantPending      string
	}{
		{
			name: "include: a signed-in user's token groups are unreadable", include: include,
			cache: map[string][]string{testDomainUserA: {}}, sessions: activeA,
			groupErrs: map[uint32]error{1: windows.ERROR_ACCESS_DENIED}, rows: []string{testDomainUserA},
			wantRows: testDomainUserA,
		},
		{
			name: "exclude: a signed-in user's token groups are unreadable", exclude: exclude,
			cache: map[string][]string{testDomainUserA: {testDomainGroupSID}}, sessions: activeA,
			groupErrs: map[uint32]error{1: windows.ERROR_ACCESS_DENIED}, rows: []string{testDomainUserA},
			wantRows: testDomainUserA,
		},
		{
			name: "include: a session's user cannot be identified", include: include,
			cache: map[string][]string{testDomainUserA: {}}, sessions: unidentified,
			tokenErrs: map[uint32]error{2: windows.ERROR_ACCESS_DENIED}, rows: []string{testDomainUserA},
			wantRows: testDomainUserA,
		},
		{
			name: "exclude: a session's user cannot be identified", exclude: exclude,
			cache: map[string][]string{testDomainUserA: {testDomainGroupSID}}, sessions: unidentified,
			tokenErrs: map[uint32]error{2: windows.ERROR_ACCESS_DENIED}, rows: []string{testDomainUserA},
			wantRows: testDomainUserA,
		},
		{
			name: "no new row on cached groups in doubt", include: include,
			cache: map[string][]string{testDomainUserA: {testDomainDevelopersSID}}, sessions: activeA,
			groupErrs:   map[uint32]error{1: windows.ERROR_ACCESS_DENIED},
			wantPending: testDomainUserA,
		},
		{
			name: "a user without rows whom the cache excludes stays excluded", exclude: exclude,
			cache: map[string][]string{testDomainUserA: {testDomainGroupSID}}, sessions: unidentified,
			tokenErrs:    map[uint32]error{2: windows.ERROR_ACCESS_DENIED},
			wantExcluded: testDomainUserA,
		},
		{
			name: "a complete read decides a signed-out user from the cache", include: include,
			cache: map[string][]string{testDomainUserA: {}}, rows: []string{testDomainUserA},
			wantExcluded: testDomainUserA,
		},
		{
			name: "a token read this cycle decides", include: include,
			cache: map[string][]string{testDomainUserA: {testDomainDevelopersSID}}, sessions: activeA,
			groups: map[uint32][]string{1: {}}, rows: []string{testDomainUserA},
			wantExcluded: testDomainUserA,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubWindowsSessionAPI(t, tc.sessions, map[uint32]string{1: testDomainUserA}, tc.tokenErrs, nil)
			stubWindowsSessionTokenGroups(tc.groups, tc.groupErrs)
			home := codexProfile(t, "0.150.0")
			injectWindowsProfileList(t, map[string]string{testDomainUserA: home})
			enabled := true
			var rows []ManifestTarget
			for _, sid := range tc.rows {
				rows = append(rows, ManifestTarget{SID: sid, Connector: "codex", UserHome: home, DataDir: home + `\.defenseclaw`, AgentVersion: "0.150.0", Enabled: &enabled})
			}
			cache := NewWindowsEnrollmentGroupCache()
			for sid, groups := range tc.cache {
				cache.Users[sid] = groups
			}
			var excluded []string
			var pending []UnprotectedAgent
			manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("codex"), EnumerateOptions{
				ExistingManifestPath: writeWindowsTestManifest(t, rows...),
				IncludeGroups:        tc.include,
				ExcludeGroups:        tc.exclude,
				GroupCache:           cache,
				ReportExcluded:       func(target ManifestTarget) { excluded = append(excluded, target.SID) },
				ReportUnprotected: func(agent UnprotectedAgent) {
					if strings.Contains(agent.Reason, "pending") {
						pending = append(pending, agent)
					}
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := manifestSIDs(manifest); got != tc.wantRows {
				t.Fatalf("rows for %q, want %q", got, tc.wantRows)
			}
			sort.Strings(excluded)
			if got := strings.Join(excluded, ","); got != tc.wantExcluded {
				t.Fatalf("excluded %q, want %q", got, tc.wantExcluded)
			}
			if tc.wantPending != "" && (len(pending) != 1 || pending[0].SID != tc.wantPending) {
				t.Fatalf("pending reports %+v, want one for %s: a signed-in user can run the agent", pending, tc.wantPending)
			}
		})
	}
}

// What the account database says is not in doubt: a local account is never
// in a directory group, and the local account database lists a local
// group's direct members, whatever the user's token holds.
func TestWindowsEnrollmentGroupsInDoubtKeepTheAccountDatabaseAnswer(t *testing.T) {
	stubGroupDirectory(t, map[string]string{`contoso\developers`: testDomainDevelopersSID}, map[string][]string{
		testLocalDevelopers: {testLocalUserSID},
	})
	cache := NewWindowsEnrollmentGroupCache()
	cache.Users[testLocalUserSID] = []string{testDomainDevelopersSID}
	unread := &windowsSessionGroupsIncomplete{unread: map[string]bool{canonicalManifestTargetSID(testLocalUserSID): true}}

	include := newWindowsEnrollmentGroups([]string{`CONTOSO\Developers`}, nil, nil, unread, cache, nil)
	if decision, reason, inDoubt := include.evaluate(testLocalUserSID); decision != windowsEnrollmentExcluded || inDoubt {
		t.Fatalf("local account, include a directory group: %v %q in doubt %v; want excluded for certain", decision, reason, inDoubt)
	}
	exclude := newWindowsEnrollmentGroups(nil, []string{testLocalDevelopers}, nil, unread, cache, nil)
	if decision, reason, inDoubt := exclude.evaluate(testLocalUserSID); decision != windowsEnrollmentExcluded || inDoubt {
		t.Fatalf("direct member of an excluded local group: %v %q in doubt %v; want excluded for certain", decision, reason, inDoubt)
	}
	// A directory user's directory membership is known only from a token.
	cache.Users[testDomainUserA] = []string{}
	anyone := newWindowsEnrollmentGroups([]string{`CONTOSO\Developers`}, nil, nil, &windowsSessionGroupsIncomplete{unidentified: true}, cache, nil)
	if decision, reason := anyone.decide(testDomainUserA); decision != windowsEnrollmentUndecided || !strings.Contains(reason, "could not be identified") {
		t.Fatalf("directory user while a session is unidentified: %v %q; want pending", decision, reason)
	}
}

// The same class in the enrollment's own lookups: the account name and the
// group name lookups gave up waiting but started a new native call for the
// same SID or name on every cycle, so an account or group the domain
// controller never answers for added one stuck call per cycle and used its
// timeout of the shared cycle budget each time; a few of them left every
// later profile and group without a lookup on every cycle. A lookup still
// running now fails at once, and the others get the budget from the next
// cycle on.
func TestWindowsEnrollmentLookupsThatNeverReturnHoldOnlyTheirOwnKey(t *testing.T) {
	release := make(chan struct{})
	var stuckCalls atomic.Int32
	stuck := func(key string) bool {
		return strings.HasPrefix(key, "S-1-5-21-9-9-9-") || strings.HasPrefix(key, "stuck")
	}
	previousAccount, previousTimeout, previousBudget := windowsEnrollmentLookupAccountSID, windowsEnrollmentLookupTimeout, windowsEnrollmentLookupBudget
	previousResolve, previousNameTimeout, previousNameLimit := windowsResolveGroupName, windowsGroupNameLookupTimeout, windowsGroupNameLookupCycleLimit
	previousMachine := windowsMachineAccountDomainSID
	t.Cleanup(func() {
		close(release)
		waitIdentityLookupGateIdle(t, &windowsEnrollmentAccountLookupGate)
		waitIdentityLookupGateIdle(t, &windowsGroupNameLookupGate)
		windowsEnrollmentLookupAccountSID, windowsEnrollmentLookupTimeout, windowsEnrollmentLookupBudget = previousAccount, previousTimeout, previousBudget
		windowsResolveGroupName, windowsGroupNameLookupTimeout, windowsGroupNameLookupCycleLimit = previousResolve, previousNameTimeout, previousNameLimit
		windowsMachineAccountDomainSID = previousMachine
	})
	windowsMachineAccountDomainSID = func() (string, error) { return testMachineDomainSID, nil }
	windowsEnrollmentLookupTimeout, windowsEnrollmentLookupBudget = 30*time.Millisecond, 100*time.Millisecond
	windowsGroupNameLookupTimeout, windowsGroupNameLookupCycleLimit = 30*time.Millisecond, 100*time.Millisecond
	windowsEnrollmentLookupAccountSID = func(sid string) (string, string, error) {
		if stuck(sid) {
			stuckCalls.Add(1)
			<-release
		}
		return "alice", "CONTOSO", nil
	}
	windowsResolveGroupName = func(name string) (string, error) {
		if stuck(name) {
			stuckCalls.Add(1)
			<-release
		}
		return testDomainDevelopersSID, nil
	}
	stuckSIDs := []string{"S-1-5-21-9-9-9-1001", "S-1-5-21-9-9-9-1002", "S-1-5-21-9-9-9-1003", "S-1-5-21-9-9-9-1004"}
	names := []string{"stuck1", "stuck2", "stuck3", "stuck4", `CONTOSO\Developers`}
	for cycle := 1; cycle <= 4; cycle++ {
		lookup := newWindowsEnrollmentAccountLookup()
		for _, sid := range stuckSIDs {
			if _, _, err := lookup(sid); err == nil {
				t.Fatalf("cycle %d: the lookup of %s that never returns must fail", cycle, sid)
			}
		}
		_, _, accountErr := lookup(testDomainUserA)
		groups := newWindowsEnrollmentGroups(names, nil, nil, nil, NewWindowsEnrollmentGroupCache(), nil)
		resolved := groups.include[len(groups.include)-1].sid
		if cycle > 1 && (accountErr != nil || resolved != testDomainDevelopersSID) {
			t.Fatalf("cycle %d: account lookup err %v, group resolved to %q; want both answered once the stuck lookups are known", cycle, accountErr, resolved)
		}
	}
	if got := stuckCalls.Load(); got != int32(len(stuckSIDs)+len(names)-1) {
		t.Fatalf("stuck lookups started = %d, want one per stuck SID and name", got)
	}
}
