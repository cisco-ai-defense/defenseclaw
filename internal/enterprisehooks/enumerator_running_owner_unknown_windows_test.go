// Copyright 2026 Cisco Systems, Inc. and its affiliates
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
	stubMachineWinGet(t, nil)
	stubUserWinGet(t, nil)
	stubCodexMachinePolicyPublished(t, true)
	stubActiveSessions(t, map[string][]string{})
	previousDomain := windowsMachineAccountDomainSID
	t.Cleanup(func() { windowsMachineAccountDomainSID = previousDomain })
	windowsMachineAccountDomainSID = func() (string, error) { return testMachineDomainSID, nil }
	enrolled := codexProfile(t, "0.160.0")
	injectWindowsProfileList(t, map[string]string{testDeletedLocalSID: t.TempDir(), testLocalUserSID: enrolled})
	windowsEnrollmentLookupAccountSID = func(sid string) (string, string, error) {
		if canonicalManifestTargetSID(sid) == canonicalManifestTargetSID(testDeletedLocalSID) {
			return "", "", lookupErr
		}
		return "user", "HOST", nil
	}
	var reported []UnprotectedAgent
	manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("codex"), EnumerateOptions{
		RunningAgents:     running,
		ReportUnprotected: func(agent UnprotectedAgent) { reported = append(reported, agent) },
	})
	if err != nil {
		t.Fatalf("EnumerateWindows: %v", err)
	}
	return manifest, reported
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
			"until the process exits",
		} {
			if !strings.Contains(message, text) {
				t.Fatalf("message %q does not contain %q", message, text)
			}
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
