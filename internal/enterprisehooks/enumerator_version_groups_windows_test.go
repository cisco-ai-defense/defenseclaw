// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const (
	testMachineDomainSID = "S-1-5-21-1004336348-1177238915-682003330"
	testLocalDevelopers  = testMachineDomainSID + "-2001"
	testDomainGroupSID   = "S-1-5-21-111111111-222222222-333333333-1105"
	testDomainUserA      = "S-1-5-21-111111111-222222222-333333333-3001"
	testDomainUserB      = "S-1-5-21-111111111-222222222-333333333-3002"
	testDomainUserC      = "S-1-5-21-111111111-222222222-333333333-3003"
	testLocalUserTwo     = testMachineDomainSID + "-1002"
)

func stubActiveSessions(t *testing.T, sessions map[string][]string) {
	t.Helper()
	previous := windowsActiveSessionGroups
	t.Cleanup(func() { windowsActiveSessionGroups = previous })
	windowsActiveSessionGroups = func() (map[string][]string, error) {
		out := map[string][]string{}
		for sid, groups := range sessions {
			out[sid] = append([]string{}, groups...)
		}
		return out, nil
	}
}

func stubGroupDirectory(t *testing.T, names map[string]string, localMembers map[string][]string) {
	t.Helper()
	previousResolve, previousMembers, previousMachine := windowsResolveGroupName, windowsLocalGroupDirectMembers, windowsMachineAccountDomainSID
	t.Cleanup(func() {
		windowsResolveGroupName, windowsLocalGroupDirectMembers, windowsMachineAccountDomainSID = previousResolve, previousMembers, previousMachine
	})
	windowsResolveGroupName = func(name string) (string, error) {
		if sid, ok := names[strings.ToLower(name)]; ok {
			return sid, nil
		}
		return "", errors.New("the domain controller is unreachable")
	}
	windowsLocalGroupDirectMembers = func(sid string) ([]string, error) {
		members, ok := localMembers[sid]
		if !ok {
			return nil, errors.New("not a local group")
		}
		return members, nil
	}
	windowsMachineAccountDomainSID = func() (string, error) { return testMachineDomainSID, nil }
}

// While the user is signed in, a known row follows an agent upgrade to a
// version with a known hook contract; a signed-out user's row keeps its
// version, since the guardian could not repair it until they sign in.
func TestStandaloneKnownRowFollowsAVerifiedUpgradeWhileSignedIn(t *testing.T) {
	stubMachineWinGet(t, nil)
	enabled := true
	prior := ManifestTarget{SID: testLocalUserSID, Connector: "codex", AgentVersion: "0.140.0", Enabled: &enabled}
	previous := map[string]ManifestTarget{previousManifestKey(prior.SID, prior.Connector): prior}
	home := codexProfile(t, "0.150.0")

	row := ManifestTarget{SID: testLocalUserSID, Connector: "codex", UserHome: home}
	if !applyStandaloneRowStateFor(&row, previous, nil, windowsStandaloneRowContext{}) || row.AgentVersion != "0.140.0" {
		t.Fatalf("signed-out row = %+v, want it kept at 0.140.0", row)
	}

	var logged []string
	row = ManifestTarget{SID: testLocalUserSID, Connector: "codex", UserHome: home}
	if !applyStandaloneRowStateFor(&row, previous, func(_, reason string) { logged = append(logged, reason) }, windowsStandaloneRowContext{sessionActive: true}) {
		t.Fatal("signed-in row was dropped")
	}
	if row.AgentVersion != "0.150.0" || !row.IsEnabled() {
		t.Fatalf("signed-in row = %+v, want it at the upgraded, verified 0.150.0", row)
	}
	if !strings.Contains(strings.Join(logged, "\n"), "changed from 0.140.0 to 0.150.0, which has a known hook contract") {
		t.Fatalf("the version change must be logged; log:\n%s", strings.Join(logged, "\n"))
	}
}

// An upgrade to a version with no verified hook contract keeps the row at
// its last verified version and is reported as hook_contract_unverified.
func TestStandaloneKnownRowReportsAnUnverifiedUpgrade(t *testing.T) {
	stubMachineWinGet(t, nil)
	enabled := true
	prior := ManifestTarget{SID: testLocalUserSID, Connector: "cursor", AgentVersion: "2.5.0", Enabled: &enabled}
	previous := map[string]ManifestTarget{previousManifestKey(prior.SID, prior.Connector): prior}
	var reported []UnprotectedAgent
	row := ManifestTarget{SID: testLocalUserSID, Connector: "cursor", UserHome: cursorProfile(t, "4.1.0")}
	rowContext := windowsStandaloneRowContext{sessionActive: true, user: "alice", report: func(agent UnprotectedAgent) { reported = append(reported, agent) }}
	if !applyStandaloneRowStateFor(&row, previous, nil, rowContext) || row.AgentVersion != "2.5.0" {
		t.Fatalf("row = %+v, want it kept at its verified 2.5.0", row)
	}
	if len(reported) != 1 || reported[0].Code != UnprotectedCodeHookContractUnverified || reported[0].Version != "4.1.0" ||
		reported[0].SID != testLocalUserSID || reported[0].User != "alice" {
		t.Fatalf("reported = %+v, want one hook_contract_unverified entry for cursor 4.1.0", reported)
	}
	// The user stays enrolled at the old version; the report must not say
	// the machine policy refuses them.
	if !strings.Contains(reported[0].Reason, "the row stays enrolled at 2.5.0") || strings.Contains(reported[0].Reason, "until it is enrolled") {
		t.Fatalf("reason %q must say the row stays enrolled at its verified version", reported[0].Reason)
	}
	if !strings.Contains(reported[0].Message(), "cursor 4.1.0 for user alice ("+testLocalUserSID+") is not protected") {
		t.Fatalf("message = %q", reported[0].Message())
	}
}

// A CLI found at a version the guardian cannot admit used to be only
// logged; it is now reported, so status and verify show the gap.
func TestEnumerateWindowsReportsAgentsItCannotAdmit(t *testing.T) {
	stubMachineWinGet(t, nil)
	stubActiveSessions(t, nil)
	cursorHome := cursorProfile(t, "4.1.0")
	codexHome := codexProfile(t, "0.125.0")
	injectWindowsProfileList(t, map[string]string{
		testLocalUserSID: cursorHome,
		testLocalUserTwo: codexHome,
	})
	var reported []UnprotectedAgent
	cfg := standaloneEnumeratorConfig("cursor")
	enabled := true
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"codex": {Enabled: &enabled}, "cursor": {Enabled: &enabled}}
	manifest, err := EnumerateWindows(context.Background(), cfg, EnumerateOptions{
		ReportUnprotected: func(agent UnprotectedAgent) { reported = append(reported, agent) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Targets) != 0 {
		t.Fatalf("targets = %+v, want none", manifest.Targets)
	}
	codes := map[string]string{}
	for _, agent := range reported {
		codes[agent.Connector+"/"+agent.SID] = agent.Code
	}
	if codes["cursor/"+testLocalUserSID] != UnprotectedCodeHookContractUnverified ||
		codes["codex/"+testLocalUserTwo] != UnprotectedCodeAgentUnprotected || len(reported) != 2 {
		t.Fatalf("reported = %+v", reported)
	}
	for _, agent := range reported {
		if agent.User != filepath.Base(cursorHome) && agent.User != filepath.Base(codexHome) {
			t.Fatalf("reported user %q is not the profile directory name", agent.User)
		}
		if !strings.Contains(agent.Reason, "machine-policy hooks refuse this user's tool calls") {
			t.Fatalf("reason %q must say what happens to the unenrolled user", agent.Reason)
		}
	}
}

// End to end: an excluded member loses its rows, a pending (unknown) user
// keeps its existing rows and gets no new ones, and a member is enrolled.
func TestEnumerateWindowsAppliesGroupFilters(t *testing.T) {
	stubMachineWinGet(t, nil)
	stubGroupDirectory(t, map[string]string{`contoso\contractors`: testDomainGroupSID}, map[string][]string{})
	stubActiveSessions(t, map[string][]string{testDomainUserA: {testDomainGroupSID}, testDomainUserB: {}})
	injectWindowsProfileList(t, map[string]string{
		testDomainUserA: codexProfile(t, "0.150.0"),
		testDomainUserB: codexProfile(t, "0.150.0"),
		testDomainUserC: codexProfile(t, "0.150.0"),
	})
	enabled := true
	existing := Manifest{Version: 1, Targets: []ManifestTarget{
		{SID: testDomainUserA, Connector: "codex", UserHome: `C:\Users\a`, DataDir: `C:\Users\a\.defenseclaw`, AgentVersion: "0.150.0", Enabled: &enabled},
		{SID: testDomainUserC, Connector: "codex", UserHome: `C:\Users\c`, DataDir: `C:\Users\c\.defenseclaw`, AgentVersion: "0.150.0", Enabled: &enabled},
	}}
	path := filepath.Join(t.TempDir(), "targets.yaml")
	raw, err := marshalTargetsManifest(existing)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cache := NewWindowsEnrollmentGroupCache()
	manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("codex"), EnumerateOptions{
		ExistingManifestPath: path,
		ExcludeGroups:        []string{`CONTOSO\Contractors`},
		GroupCache:           cache,
	})
	if err != nil {
		t.Fatal(err)
	}
	var sids []string
	for _, target := range manifest.Targets {
		sids = append(sids, target.SID)
	}
	if strings.Join(sids, ",") != testDomainUserB+","+testDomainUserC {
		t.Fatalf("targets = %v, want the non-member and the pending user's existing row", sids)
	}
	if _, cached := cache.Users[testDomainUserB]; !cached {
		t.Fatalf("signed-in users must be cached: %v", cache.Users)
	}
	if _, cached := cache.Users[testDomainUserC]; cached {
		t.Fatalf("a signed-out user without a cache entry must stay unknown: %v", cache.Users)
	}
}

// The group primitives read this host's real account database: the machine
// account domain SID, a BUILTIN group by name, and its direct members.
func TestWindowsEnrollmentGroupPrimitivesAgainstThisHost(t *testing.T) {
	machine, err := readWindowsMachineAccountDomainSID()
	if err != nil || !strings.HasPrefix(machine, "S-1-5-21-") {
		t.Fatalf("machine account domain SID = %q, %v", machine, err)
	}
	administrators, err := resolveWindowsGroupName("Administrators")
	if err != nil || administrators != "S-1-5-32-544" {
		t.Fatalf("Administrators = %q, %v", administrators, err)
	}
	if _, err := resolveWindowsGroupName(`BUILTIN\Administrators`); err != nil {
		t.Fatalf("BUILTIN\\Administrators: %v", err)
	}
	members, err := readWindowsLocalGroupDirectMembers(administrators)
	if err != nil || len(members) == 0 {
		t.Fatalf("Administrators members = %v, %v", members, err)
	}
	if _, err := readWindowsLocalGroupDirectMembers(machine + "-500"); err == nil {
		t.Fatal("a user SID must not read as a local group")
	}
	if _, err := readWindowsActiveSessionGroups(); err != nil {
		t.Fatalf("active sessions: %v", err)
	}
}

// A known row dropped because the user removed the agent is no gap and is
// not reported; one dropped while the agent is still installed is.
func TestStandaloneDroppedKnownRowIsReportedOnlyWhileInstalled(t *testing.T) {
	stubMachineWinGet(t, nil)
	enabled := true
	prior := ManifestTarget{SID: testLocalUserSID, Connector: "codex", AgentVersion: "0.125.0", Enabled: &enabled}
	previous := map[string]ManifestTarget{previousManifestKey(prior.SID, prior.Connector): prior}
	var reported []UnprotectedAgent
	rowContext := windowsStandaloneRowContext{user: "alice", report: func(agent UnprotectedAgent) { reported = append(reported, agent) }}

	removed := ManifestTarget{SID: testLocalUserSID, Connector: "codex", UserHome: t.TempDir()}
	if applyStandaloneRowStateFor(&removed, previous, nil, rowContext) || len(reported) != 0 {
		t.Fatalf("removed agent: emitted=%+v reported=%+v, want dropped and not reported", removed, reported)
	}

	installed := ManifestTarget{SID: testLocalUserSID, Connector: "codex", UserHome: codexProfile(t, "0.125.0")}
	if applyStandaloneRowStateFor(&installed, previous, nil, rowContext) {
		t.Fatalf("a row below the Windows minimum must be dropped: %+v", installed)
	}
	if len(reported) != 1 || reported[0].Version != "0.125.0" || reported[0].Code != UnprotectedCodeAgentUnprotected {
		t.Fatalf("reported = %+v, want the installed agent below the minimum", reported)
	}
}
