// Copyright 2026 Cisco Systems, Inc. and its affiliates
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
	"time"

	"golang.org/x/sys/windows"
)

// GAP-0556: an account deleted while its agent keeps running lost its rows
// (GAP-0430) and, with them, the only pass that judged its running agents,
// so the next cycle wrote an empty unprotected record and status said
// security_complete while the agent ran without DefenseClaw. Its running
// agent is now recorded with the owner unknown until the process exits.

const (
	testDeletedLocalSID  = testMachineDomainSID + "-1115"
	testNoProfileUserSID = testMachineDomainSID + "-1116"
)

// enumerateDeletedAccountCycle runs one standalone cycle in which the local
// account testDeletedLocalSID still has its profile folder and the lookup of
// its SID answers lookupErr; running names the agents seen running.
func enumerateDeletedAccountCycle(t *testing.T, lookupErr error, running map[string]map[string]string) (Manifest, []UnprotectedAgent) {
	t.Helper()
	return enumerateDeletedAccountCycleExcluding(t, lookupErr, running, nil)
}

// enumerateDeletedAccountCycleExcluding is enumerateDeletedAccountCycle with
// enterprise.enrollment.exclude_users set to exclude.
func enumerateDeletedAccountCycleExcluding(t *testing.T, lookupErr error, running map[string]map[string]string, exclude []string) (Manifest, []UnprotectedAgent) {
	t.Helper()
	manifest, reported, _ := enumerateDeletedAccountCycleReporting(t, lookupErr, running, func(string) []string { return exclude })
	return manifest, reported
}

// enumerateDeletedAccountCycleReporting is enumerateDeletedAccountCycleExcluding
// with exclude_users built from the deleted account's profile folder, and it
// also returns the profiles the cycle reported excluded.
func enumerateDeletedAccountCycleReporting(t *testing.T, lookupErr error, running map[string]map[string]string,
	exclude func(deletedHome string) []string) (Manifest, []UnprotectedAgent, []ManifestTarget) {
	t.Helper()
	stubMachineWinGet(t, nil)
	stubUserWinGet(t, nil)
	stubCodexMachinePolicyPublished(t, true)
	stubActiveSessions(t, map[string][]string{})
	previousDomain := windowsMachineAccountDomainSID
	t.Cleanup(func() { windowsMachineAccountDomainSID = previousDomain })
	windowsMachineAccountDomainSID = func() (string, error) { return testMachineDomainSID, nil }
	enrolled := codexProfile(t, "0.160.0")
	deletedHome := filepath.Join(t.TempDir(), "olduser")
	if err := os.MkdirAll(deletedHome, 0o700); err != nil {
		t.Fatal(err)
	}
	injectWindowsProfileList(t, map[string]string{testDeletedLocalSID: deletedHome, testLocalUserSID: enrolled})
	windowsEnrollmentLookupAccountSID = func(sid string) (string, string, error) {
		if canonicalManifestTargetSID(sid) == canonicalManifestTargetSID(testDeletedLocalSID) {
			return "", "", lookupErr
		}
		return "user", "HOST", nil
	}
	var reported []UnprotectedAgent
	var excluded []ManifestTarget
	manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("codex"), EnumerateOptions{
		RunningAgents:     running,
		ExcludeUsers:      exclude(deletedHome),
		ReportUnprotected: func(agent UnprotectedAgent) { reported = append(reported, agent) },
		ReportExcluded:    func(target ManifestTarget) { excluded = append(excluded, target) },
	})
	if err != nil {
		t.Fatalf("EnumerateWindows: %v", err)
	}
	return manifest, reported, excluded
}

func TestEnumerateWindowsKeepsTheRunningAgentOfADeletedAccountOwnerUnknown(t *testing.T) {
	manifest, reported := enumerateDeletedAccountCycle(t, windows.ERROR_NONE_MAPPED, map[string]map[string]string{
		testDeletedLocalSID:  {"codex": "codex (pid 11888)"},
		testNoProfileUserSID: {"codex": "codex (pid 11889)"},
		"S-1-5-18":           {"codex": "codex (pid 4)"},
		testLocalUserSID:     {"codex": "codex (pid 5)"},
	})
	if len(manifest.Targets) != 1 || canonicalManifestTargetSID(manifest.Targets[0].SID) != canonicalManifestTargetSID(testLocalUserSID) {
		t.Fatalf("targets = %+v, want only the existing npm user's row (the deleted account's rows stay revoked)", manifest.Targets)
	}
	// The record survives its own serialization, as status reads it.
	data, err := MarshalUnprotectedAgents(reported)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseUnprotectedAgents(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != 2 {
		t.Fatalf("unprotected = %+v, want the deleted account's and the profile-less account's codex only", parsed)
	}
	for i, want := range []struct{ sid, label string }{
		{testDeletedLocalSID, "codex (pid 11888)"},
		{testNoProfileUserSID, "codex (pid 11889)"},
	} {
		agent := parsed[i]
		if agent.User != windowsUnknownOwnerUser || agent.SID != canonicalManifestTargetSID(want.sid) ||
			agent.Connector != "codex" || agent.Code != UnprotectedCodeAgentUnprotected {
			t.Fatalf("entry %d = %+v, want an owner-unknown agent_unprotected codex of %s", i, agent, want.sid)
		}
		message := agent.Message()
		for _, text := range []string{
			"codex for user unknown (" + canonicalManifestTargetSID(want.sid) + ") is not protected",
			want.label + " runs as this SID",
			// The codex machine policy is published: its hooks refuse the
			// account's tool calls, so the reason must not say that no
			// decision is made (GAP-0673).
			"its machine-policy hooks refuse this user's tool calls",
			"until the process exits",
		} {
			if !strings.Contains(message, text) {
				t.Fatalf("message %q does not contain %q", message, text)
			}
		}
		if strings.Contains(message, "does not decide its tool calls") {
			t.Fatalf("message %q claims no tool-call decision is made", message)
		}
	}
}

// A deleted account that enterprise.enrollment.exclude_users names is left
// alone like any excluded account: its lingering agent is not reported with
// the owner unknown (GAP-0673).
func TestEnumerateWindowsLeavesTheRunningAgentOfAnExcludedDeletedAccountAlone(t *testing.T) {
	_, reported := enumerateDeletedAccountCycleExcluding(t, windows.ERROR_NONE_MAPPED, map[string]map[string]string{
		testDeletedLocalSID: {"codex": "codex (pid 11888)"},
	}, []string{testDeletedLocalSID})
	if len(reported) != 0 {
		t.Fatalf("unprotected = %+v, want none for the excluded account", reported)
	}
}

// The owner-unknown entry is reported on every cycle the process runs and
// goes at the first cycle after it exits.
func TestEnumerateWindowsReportsTheDeletedAccountAgentOnEveryCycleUntilItExits(t *testing.T) {
	running := map[string]map[string]string{testDeletedLocalSID: {"codex": "codex (pid 11888)"}}
	for cycle, want := range []int{1, 1, 0} {
		if cycle == 2 {
			running = nil
		}
		if _, reported := enumerateDeletedAccountCycle(t, windows.ERROR_NONE_MAPPED, running); len(reported) != want {
			t.Fatalf("cycle %d: unprotected = %+v, want %d", cycle+1, reported, want)
		}
	}
}

// The owners of running agents are classified by account kind: IIS
// application pool and other service SIDs are not user accounts (GAP-0673).
func TestWindowsInteractiveUserSIDRejectsServiceIdentities(t *testing.T) {
	for sid, want := range map[string]bool{
		testLocalUserSID: true,
		testDomainUserA:  true,
		"S-1-12-1-1111111111-2222222222-333333333-44": true,
		"S-1-5-18":           false,
		"S-1-5-80-1-2-3-4-5": false,
		"S-1-5-82-1-2-3-4-5": false,
		"S-1-5-90-0-1":       false,
		"":                   false,
		"not a sid":          false,
	} {
		if got := WindowsInteractiveUserSID(sid); got != want {
			t.Errorf("WindowsInteractiveUserSID(%q) = %v, want %v", sid, got, want)
		}
	}
}

// A lookup that times out is no proof the account is gone: the profile is
// judged as before and its running agent stays recorded under its SID.
func TestEnumerateWindowsKeepsARunningAgentWhenTheAccountLookupTimesOut(t *testing.T) {
	_, reported := enumerateDeletedAccountCycle(t, errors.New("account name lookup timed out"), map[string]map[string]string{
		testDeletedLocalSID: {"codex": "codex (pid 11888)"},
	})
	if len(reported) != 1 || reported[0].SID != canonicalManifestTargetSID(testDeletedLocalSID) ||
		reported[0].Connector != "codex" || reported[0].Code != UnprotectedCodeAgentUnprotected ||
		!strings.Contains(reported[0].Reason, "codex (pid 11888) runs for this account") {
		t.Fatalf("unprotected = %+v, want the running codex kept under its SID", reported)
	}
}

// The entry goes only when the process exits.
func TestEnumerateWindowsDropsTheDeletedAccountEntryWhenTheProcessExits(t *testing.T) {
	if _, reported := enumerateDeletedAccountCycle(t, windows.ERROR_NONE_MAPPED, nil); len(reported) != 0 {
		t.Fatalf("unprotected = %+v, want none once the process has exited", reported)
	}
}

// A disabled account with no signed-in session is not reported for its
// installs (GAP-1034), but an agent process of it that is still running is.
func TestEnumerateWindowsReportsTheRunningAgentOfADisabledSignedOutAccount(t *testing.T) {
	stubMachineWinGet(t, nil)
	stubUserWinGet(t, nil)
	stubCodexMachinePolicyPublished(t, true)
	stubActiveSessions(t, map[string][]string{})
	previousDomain, previousDisabled := windowsMachineAccountDomainSID, windowsLocalAccountDisabled
	t.Cleanup(func() { windowsMachineAccountDomainSID, windowsLocalAccountDisabled = previousDomain, previousDisabled })
	windowsMachineAccountDomainSID = func() (string, error) { return testMachineDomainSID, nil }
	windowsLocalAccountDisabled = func(string) (bool, error) { return true, nil }
	injectWindowsProfileList(t, map[string]string{testLocalUserSID: t.TempDir()})
	for _, tc := range []struct {
		running      map[string]map[string]string
		wantReported int
	}{
		{running: nil, wantReported: 0},
		{running: map[string]map[string]string{testLocalUserSID: {"codex": "codex (pid 77)"}}, wantReported: 1},
	} {
		var reported []UnprotectedAgent
		if _, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("codex"), EnumerateOptions{
			RunningAgents:     tc.running,
			ReportUnprotected: func(agent UnprotectedAgent) { reported = append(reported, agent) },
		}); err != nil {
			t.Fatal(err)
		}
		if len(reported) != tc.wantReported || (tc.wantReported == 1 &&
			(reported[0].SID != canonicalManifestTargetSID(testLocalUserSID) || !strings.Contains(reported[0].Reason, "codex (pid 77) runs for this account"))) {
			t.Fatalf("running = %v: unprotected = %+v, want %d", tc.running, reported, tc.wantReported)
		}
	}
}

// W2B-G-enum review loop 1: the deleted-account branch marked an excluded
// deleted account judged but never reported it excluded, so the cycle kept
// refreshing its identity record and carried its old UPN forward. It is now
// reported excluded, by SID or by profile folder, and the identity pass
// removes its record; a deleted account that is not excluded is not.
func TestEnumerateWindowsReportsAnExcludedDeletedAccountExcluded(t *testing.T) {
	for _, tc := range []struct {
		name         string
		exclude      func(deletedHome string) []string
		wantExcluded bool
	}{
		{name: "by SID", exclude: func(string) []string { return []string{testDeletedLocalSID} }, wantExcluded: true},
		{name: "by profile folder", exclude: func(home string) []string { return []string{filepath.Base(home)} }, wantExcluded: true},
		{name: "not excluded", exclude: func(string) []string { return nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, excluded := enumerateDeletedAccountCycleReporting(t, windows.ERROR_NONE_MAPPED, nil, tc.exclude)
			sids := make([]string, 0, len(excluded))
			for _, target := range excluded {
				sids = append(sids, target.SID)
			}
			reportedDeleted := len(excluded) == 1 && canonicalManifestTargetSID(excluded[0].SID) == canonicalManifestTargetSID(testDeletedLocalSID) &&
				filepath.Base(excluded[0].UserHome) == "olduser"
			if reportedDeleted != tc.wantExcluded || (!tc.wantExcluded && len(excluded) != 0) {
				t.Fatalf("reported excluded %+v, want the deleted account reported %v", excluded, tc.wantExcluded)
			}
			// The cycle passes the reported SIDs to the identity pass.
			dir := t.TempDir()
			key := strings.ToUpper(testDeletedLocalSID)
			writeTestIdentityRecord(t, dir, key, time.Now().UTC())
			cache := NewWindowsEnrollmentGroupCache()
			cache.Users[testDeletedLocalSID] = []string{}
			stubWindowsIdentityLookups(t, nil, nil)
			if err := WriteWindowsIdentitySpool(context.Background(), dir, cache, sids, nil, nil, nil); err != nil {
				t.Fatal(err)
			}
			_, statErr := os.Stat(filepath.Join(dir, key+".json"))
			if os.IsNotExist(statErr) != tc.wantExcluded {
				t.Fatalf("identity record removed = %v, want %v", os.IsNotExist(statErr), tc.wantExcluded)
			}
		})
	}
}
