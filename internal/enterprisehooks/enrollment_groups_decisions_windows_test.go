// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

const testLocalUserThree = testMachineDomainSID + "-1003"

func claudeProfile(t *testing.T, version string) string {
	t.Helper()
	home := t.TempDir()
	writeWindowsAgentPackageJSON(t, filepath.Join(home, "AppData", "Roaming", "npm", "node_modules", "@anthropic-ai", "claude-code"), version)
	return home
}

func writeWindowsTestManifest(t *testing.T, targets ...ManifestTarget) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "targets.yaml")
	raw, err := marshalTargetsManifest(Manifest{Version: 1, Targets: targets})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func manifestSIDs(manifest Manifest) string {
	sids := make([]string, 0, len(manifest.Targets))
	for _, target := range manifest.Targets {
		sids = append(sids, target.SID)
	}
	sort.Strings(sids)
	return strings.Join(sids, ",")
}

// A group name that does not resolve on Windows. A shared cross-platform
// config can list a Linux group (wheel) that no Windows computer has; it used
// to leave every user pending, the signed-in ones too, with no new rows and no
// report. An exclusion that cannot be evaluated now excludes no one, as on
// Linux and macOS.
func TestEnumerateWindowsGroupThatDoesNotResolve(t *testing.T) {
	stubMachineWinGet(t, nil)
	stubGroupDirectory(t, map[string]string{}, map[string][]string{})
	// stubGroupDirectory makes testMachineDomainSID the account domain of this
	// computer, so the local accounts below must also resolve: the standalone
	// enumerator revokes a local SID that LookupAccountSid does not map as a
	// deleted account (GAP-0430).
	previousLookup := windowsEnrollmentLookupAccountSID
	t.Cleanup(func() { windowsEnrollmentLookupAccountSID = previousLookup })
	windowsEnrollmentLookupAccountSID = func(sid string) (string, string, error) {
		return "user" + sid[strings.LastIndex(sid, "-")+1:], "TESTPC", nil
	}
	stubActiveSessions(t, map[string][]string{testLocalUserSID: {"S-1-5-32-545"}})
	injectWindowsProfileList(t, map[string]string{
		testLocalUserSID: codexProfile(t, "0.150.0"), // signed in
		testLocalUserTwo: codexProfile(t, "0.150.0"), // signed out, never cached
	})
	var logged []string
	var reported []UnprotectedAgent
	manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("codex"), EnumerateOptions{
		ExcludeGroups:     []string{"wheel"},
		GroupCache:        NewWindowsEnrollmentGroupCache(),
		Logger:            func(subject, reason string) { logged = append(logged, subject+": "+reason) },
		ReportUnprotected: func(agent UnprotectedAgent) { reported = append(reported, agent) },
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{testLocalUserSID, testLocalUserTwo}
	sort.Strings(want)
	if got := manifestSIDs(manifest); got != strings.Join(want, ",") {
		t.Fatalf("targets = %s, want both users enrolled; log:\n%s", got, strings.Join(logged, "\n"))
	}
	if len(reported) != 0 {
		t.Fatalf("reported = %+v, want nothing", reported)
	}
	log := strings.Join(logged, "\n")
	if !strings.Contains(log, `exclude_groups "wheel" does not resolve`) || !strings.Contains(log, "excludes no one") {
		t.Fatalf("the unresolved entry must be logged as excluding no one:\n%s", log)
	}
	if strings.Contains(log, "until the user signs in") {
		t.Fatalf("no user may be reported pending on sign-in for an unresolved name:\n%s", log)
	}

	// An include_groups name that does not resolve cannot admit anyone, and
	// must not revoke anyone either: users no other entry admits are pending
	// (known rows kept, no new rows). A signed-in pending user can run the
	// agent already installed, so it is reported with the real reason; a
	// signed-out one is not, since nothing runs until they sign in.
	t.Run("include group", func(t *testing.T) {
		stubMachineWinGet(t, nil)
		stubGroupDirectory(t, map[string]string{}, map[string][]string{})
		stubActiveSessions(t, map[string][]string{testLocalUserSID: {"S-1-5-32-545"}})
		signedOutHome := codexProfile(t, "0.150.0")
		injectWindowsProfileList(t, map[string]string{
			testLocalUserSID:   codexProfile(t, "0.150.0"), // signed in, no row
			testLocalUserTwo:   signedOutHome,              // signed out, known row
			testLocalUserThree: codexProfile(t, "0.150.0"), // signed out, no row
		})
		enabled := true
		path := writeWindowsTestManifest(t, ManifestTarget{
			SID: testLocalUserTwo, Connector: "codex", UserHome: signedOutHome,
			DataDir: filepath.Join(signedOutHome, ".defenseclaw"), AgentVersion: "0.150.0", Enabled: &enabled,
		})
		var reported []UnprotectedAgent
		manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("codex"), EnumerateOptions{
			ExistingManifestPath: path,
			IncludeGroups:        []string{"Develpers"},
			GroupCache:           NewWindowsEnrollmentGroupCache(),
			ReportUnprotected:    func(agent UnprotectedAgent) { reported = append(reported, agent) },
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := manifestSIDs(manifest); got != testLocalUserTwo {
			t.Fatalf("targets = %s, want only the pending user's existing row", got)
		}
		if len(reported) != 1 {
			t.Fatalf("reported = %+v, want the signed-in pending user's codex only", reported)
		}
		got := reported[0]
		if got.SID != testLocalUserSID || got.Connector != "codex" || got.Version != "0.150.0" || got.Code != UnprotectedCodeAgentUnprotected {
			t.Fatalf("reported = %+v", got)
		}
		if !strings.Contains(got.Reason, `include_groups "Develpers" does not resolve`) || !strings.Contains(got.Reason, "pending") ||
			strings.Contains(got.Reason, "until the user signs in") {
			t.Fatalf("reason %q must name the unresolved entry, not a sign-in", got.Reason)
		}
		// A member of another, resolvable include group is still admitted.
		stubGroupDirectory(t, map[string]string{"developers": testLocalDevelopers}, map[string][]string{testLocalDevelopers: {testLocalUserThree}})
		groups := newWindowsEnrollmentGroups([]string{"Develpers", "Developers"}, nil, nil, NewWindowsEnrollmentGroupCache(), nil)
		if decision, reason := groups.decide(testLocalUserThree); decision != windowsEnrollmentEnrolled {
			t.Fatalf("a member of a resolvable include group: %d (%s)", decision, reason)
		}
	})
}

// Well-known groups other than Everyone (Authenticated Users, INTERACTIVE)
// are assigned at sign-in and listed by no account database. A signed-out
// local account with no cached token used to be decided as a non-member of
// them: excluded by include_groups (its rows dropped) and never excluded by
// exclude_groups.
func TestWindowsEnrollmentGroupsDecideWellKnownGroupsFromTokens(t *testing.T) {
	const everyone, authenticated, interactive, users = "S-1-1-0", "S-1-5-11", "S-1-5-4", "S-1-5-32-545"
	stubGroupDirectory(t, map[string]string{}, map[string][]string{
		// BUILTIN\Users: a direct member plus the well-known groups Windows
		// puts there.
		users:               {authenticated, interactive, testLocalUserSID},
		testLocalDevelopers: {everyone},
	})
	sessions := map[string][]string{testDomainUserA: {everyone, authenticated, interactive}}
	for _, tc := range []struct {
		name             string
		include, exclude []string
		sid              string
		want             windowsEnrollmentDecision
	}{
		{"include Everyone admits a signed-out local account", []string{everyone}, nil, testLocalUserTwo, windowsEnrollmentEnrolled},
		{"include Authenticated Users leaves a signed-out local account pending", []string{authenticated}, nil, testLocalUserTwo, windowsEnrollmentUndecided},
		{"exclude INTERACTIVE excludes a signed-in user whose token has it", nil, []string{interactive}, testDomainUserA, windowsEnrollmentExcluded},
		{"a local group reached through a well-known member is unknown for a signed-out non-member", []string{users}, nil, testLocalUserTwo, windowsEnrollmentUndecided},
	} {
		t.Run(tc.name, func(t *testing.T) {
			groups := newWindowsEnrollmentGroups(tc.include, tc.exclude, sessions, NewWindowsEnrollmentGroupCache(), nil)
			if got, reason := groups.decide(tc.sid); got != tc.want {
				t.Fatalf("decision %d (%s), want %d", got, reason, tc.want)
			}
		})
	}

	// Named groups decide from the signed-in token, the cached token groups and
	// local account membership; resolved names and tokens are cached for offline
	// cycles, unresolved names never exclude, and SIDs need no lookup.
	t.Run("tokens, cache and local accounts", func(t *testing.T) {
		stubGroupDirectory(t,
			map[string]string{"developers": testLocalDevelopers, `contoso\contractors`: testDomainGroupSID},
			map[string][]string{testLocalDevelopers: {testLocalUserSID, testDomainUserC}},
		)
		cache := NewWindowsEnrollmentGroupCache()
		cache.Users[testDomainUserB] = []string{testLocalDevelopers}
		sessions := map[string][]string{testDomainUserA: {testDomainGroupSID, testLocalDevelopers}}
		groups := newWindowsEnrollmentGroups([]string{"Developers"}, []string{`CONTOSO\Contractors`}, sessions, cache, nil)

		for sid, want := range map[string]windowsEnrollmentDecision{
			testLocalUserSID: windowsEnrollmentEnrolled,  // local account, direct member of Developers
			testLocalUserTwo: windowsEnrollmentExcluded,  // local account, not a member
			testDomainUserA:  windowsEnrollmentExcluded,  // signed in; token lists the excluded group
			testDomainUserB:  windowsEnrollmentEnrolled,  // signed out; cached token lists Developers
			testDomainUserC:  windowsEnrollmentUndecided, // direct member, but exclusion is unknown until sign-in
			testEntraUserSID: windowsEnrollmentUndecided, // never signed in since install: pending
		} {
			if got, reason := groups.decide(sid); got != want {
				t.Errorf("%s: decision %d (%s), want %d", sid, got, reason, want)
			}
		}
		if got := cache.Users[testDomainUserA]; len(got) != 2 {
			t.Fatalf("the signed-in user's token groups must be cached: %v", cache.Users)
		}
		if cache.Names["developers"] != testLocalDevelopers || cache.Names[`contoso\contractors`] != testDomainGroupSID {
			t.Fatalf("resolved names must be cached: %v", cache.Names)
		}

		// Off the network the names no longer resolve; the cached SIDs keep
		// deciding.
		stubGroupDirectory(t, map[string]string{}, map[string][]string{testLocalDevelopers: {testLocalUserSID}})
		offline := newWindowsEnrollmentGroups([]string{"Developers"}, []string{`CONTOSO\Contractors`}, nil, cache, nil)
		if got, reason := offline.decide(testDomainUserA); got != windowsEnrollmentExcluded {
			t.Fatalf("cached membership off the network: %d (%s)", got, reason)
		}
		// An exclude_groups name that never resolved excludes no one; an
		// include_groups one leaves the users no other entry admits pending,
		// never excluded.
		unknown := newWindowsEnrollmentGroups(nil, []string{`CONTOSO\Offline`}, nil, NewWindowsEnrollmentGroupCache(), nil)
		if got, reason := unknown.decide(testLocalUserSID); got != windowsEnrollmentEnrolled {
			t.Fatalf("unresolved exclude group: %d (%s), want enrolled", got, reason)
		}
		unknownInclude := newWindowsEnrollmentGroups([]string{`CONTOSO\Offline`}, nil, nil, NewWindowsEnrollmentGroupCache(), nil)
		if got, _ := unknownInclude.decide(testLocalUserSID); got != windowsEnrollmentUndecided {
			t.Fatalf("unresolved include group: %d, want undecided", got)
		}
		// SIDs work without any lookup, including Entra ID groups.
		const entraGroup = "S-1-12-1-1111111111-2222222222-3333333333-4044444444"
		bySID := newWindowsEnrollmentGroups([]string{entraGroup}, nil, map[string][]string{testEntraUserSID: {entraGroup}}, NewWindowsEnrollmentGroupCache(), nil)
		if got, _ := bySID.decide(testEntraUserSID); got != windowsEnrollmentEnrolled {
			t.Fatalf("Entra ID group by SID: %d", got)
		}
	})
}

// A known Claude Code row used to follow its user to any verified version,
// older ones too. The one machine-wide Claude policy is rendered from the
// oldest enrolled contract, so one user editing their package.json moved
// every user from claudecode-hooks-v2 to v1, which lacks hooks v2 has.
func TestStandaloneKnownClaudeRowNeverMovesTheSharedPolicyToAnOlderContract(t *testing.T) {
	stubMachineWinGet(t, nil)
	const older, newer = "2.1.160", "2.1.230"
	v2 := connector.ResolveHookContract("claudecode", newer).Contract.ContractID
	if v1 := connector.ResolveHookContract("claudecode", older).Contract.ContractID; v1 == "" || v1 == v2 {
		t.Fatalf("fixture versions must resolve to two contracts: %q %q", v1, v2)
	}
	enabled := true
	key := previousManifestKey(testLocalUserSID, "claudecode")
	previous := map[string]ManifestTarget{key: {SID: testLocalUserSID, Connector: "claudecode", AgentVersion: newer, Enabled: &enabled}}
	var reported []UnprotectedAgent
	rowContext := windowsStandaloneRowContext{sessionActive: true, user: "alice", report: func(agent UnprotectedAgent) { reported = append(reported, agent) }}

	row := ManifestTarget{SID: testLocalUserSID, Connector: "claudecode", UserHome: claudeProfile(t, older)}
	if !applyStandaloneRowStateFor(&row, previous, nil, rowContext) || row.AgentVersion != newer {
		t.Fatalf("row = %+v, want it kept at %s", row, newer)
	}
	if len(reported) != 1 || reported[0].Version != older || reported[0].Code != UnprotectedCodeAgentUnprotected ||
		!strings.Contains(reported[0].Reason, "older hook contract") || !strings.Contains(reported[0].Reason, "the row stays enrolled at "+newer) {
		t.Fatalf("reported = %+v, want the refused downgrade", reported)
	}
	other := ManifestTarget{SID: testLocalUserTwo, Connector: "claudecode", AgentVersion: newer, Enabled: &enabled}
	if got := WindowsStandaloneClaudeMachinePolicyContract(Manifest{Targets: []ManifestTarget{row, other}}); got != v2 {
		t.Fatalf("shared contract = %q, want %q", got, v2)
	}

	// An upgrade is still followed, and reports nothing.
	previous[key] = ManifestTarget{SID: testLocalUserSID, Connector: "claudecode", AgentVersion: older, Enabled: &enabled}
	reported = nil
	row = ManifestTarget{SID: testLocalUserSID, Connector: "claudecode", UserHome: claudeProfile(t, newer)}
	if !applyStandaloneRowStateFor(&row, previous, nil, rowContext) || row.AgentVersion != newer || len(reported) != 0 {
		t.Fatalf("upgrade: row = %+v reported = %+v, want it followed", row, reported)
	}
}

// platformVerify must fail once the row records another version than the
// hooks were rendered for, for each runtime that verifies against its own
// stored lock (Codex, Cursor, Copilot), so the guardian's repair re-renders
// them. The Secure Client profile is unchanged.
func TestWindowsPlatformVerifyAsksForARepairWhenTheEnrolledVersionMoved(t *testing.T) {
	previous := windowsManagedVerify
	t.Cleanup(func() { windowsManagedVerify = previous })
	for _, tc := range []struct{ connector, rendered, enrolled string }{
		{"codex", "0.140.0", "0.150.0"},
		{"cursor", "2.5.0", "2.6.0"},
		{"copilot", "1.0.40", "1.0.90"},
	} {
		t.Run(tc.connector, func(t *testing.T) {
			windowsManagedVerify = func(_ context.Context, opts InstallOptions) (InstallResult, error) {
				// The runtime's verify passed against its stored lock, which
				// records the version its hooks were rendered for.
				return InstallResult{Connector: opts.ConnectorName, AgentVersion: tc.rendered}, nil
			}
			opts := InstallOptions{ConnectorName: tc.connector, AgentVersion: tc.enrolled}
			setStandaloneProfileForTest(t, true)
			_, handled, err := platformVerify(context.Background(), opts)
			if !handled || err == nil || !strings.Contains(err.Error(), "repair re-renders them") {
				t.Fatalf("standalone verify after the version moved: handled=%t err=%v, want a repair", handled, err)
			}
			opts.AgentVersion = tc.rendered
			if _, _, err := platformVerify(context.Background(), opts); err != nil {
				t.Fatalf("an unchanged version must verify: %v", err)
			}
			setStandaloneProfileForTest(t, false)
			opts.AgentVersion = tc.enrolled
			if _, _, err := platformVerify(context.Background(), opts); err != nil {
				t.Fatalf("Secure Client verify changed: %v", err)
			}
		})
	}
	setStandaloneProfileForTest(t, true)
	amp := InstallResult{Connector: "amp", AgentVersion: "0.0.1785334225 (released 2026-09-01)"}
	if err := requireWindowsStandaloneAgentVersionUnchanged(InstallOptions{ConnectorName: "amp", AgentVersion: "0.0.1785334225"}, amp); err != nil {
		t.Fatalf("Amp's release suffix is not a version change: %v", err)
	}
}

// The guardian's foreign-hook cleanup covers the profiles enrollment
// admits, with the group filters decided as the enumerator decides them
// and from the enumerator's cache, which it only reads.
func TestWindowsStandaloneEligibleProfilesApplyTheGroupFilters(t *testing.T) {
	stubGroupDirectory(t, map[string]string{`contoso\contractors`: testDomainGroupSID}, map[string][]string{})
	stubActiveSessions(t, map[string][]string{testDomainUserA: {testDomainGroupSID}})
	injectWindowsProfileList(t, map[string]string{
		testDomainUserA:  t.TempDir(), // signed in, member of the excluded group
		testDomainUserB:  t.TempDir(), // signed out, cached as a non-member
		testDomainUserC:  t.TempDir(), // signed out, never seen: pending
		testLocalUserSID: t.TempDir(), // local account: never in a directory group
	})
	cache := NewWindowsEnrollmentGroupCache()
	cache.Users[testDomainUserB] = []string{"S-1-5-32-545"}
	eligible, err := WindowsStandaloneEligibleProfilesFor(context.Background(), EnumerateOptions{
		ExcludeGroups: []string{`CONTOSO\Contractors`},
		GroupCache:    cache,
	})
	if err != nil {
		t.Fatal(err)
	}
	var sids []string
	for _, profile := range eligible {
		sids = append(sids, profile.SID)
	}
	sort.Strings(sids)
	want := []string{testDomainUserB, testLocalUserSID}
	sort.Strings(want)
	if strings.Join(sids, ",") != strings.Join(want, ",") {
		t.Fatalf("eligible = %v, want %v (excluded and pending users skipped)", sids, want)
	}
	if _, added := cache.Users[testDomainUserA]; added || len(cache.Users) != 1 || len(cache.Names) != 0 {
		t.Fatalf("the guardian must not change the enumerator's cache: %+v", cache)
	}
	// An exclude_groups entry that does not resolve excludes no one here
	// either.
	eligible, err = WindowsStandaloneEligibleProfilesFor(context.Background(), EnumerateOptions{ExcludeGroups: []string{"wheel"}})
	if err != nil || len(eligible) != 4 {
		t.Fatalf("eligible with an unresolved exclude group = %+v, %v; want every profile", eligible, err)
	}
}
