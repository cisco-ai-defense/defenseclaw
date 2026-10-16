// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"strings"
	"testing"
)

// GAP-0226: a running agent of an enabled connector that no row enrolls and
// no other report names is reported, so status and verify are not
// security-complete while it runs without DefenseClaw hooks.
func TestEnumerateWindowsStandaloneReportsARunningAgentNoRowEnrolls(t *testing.T) {
	stubMachineWinGet(t, nil)
	stubUserWinGet(t, nil)
	stubCodexMachinePolicyPublished(t, true)
	bare, enrolled, excluded := t.TempDir(), codexProfile(t, "0.160.0"), t.TempDir()
	const enrolledSID = "S-1-5-21-1004336348-1177238915-682003330-1002"
	const excludedSID = "S-1-5-21-1004336348-1177238915-682003330-1003"
	injectWindowsProfileList(t, map[string]string{testEntraUserSID: bare, enrolledSID: enrolled, excludedSID: excluded})
	running := map[string]map[string]string{
		strings.ToLower(testEntraUserSID): {"codex": "codex (pid 4242)", "kiro": "kiro (pid 7)"},
		enrolledSID:                       {"codex": "codex (pid 4243)"},
		excludedSID:                       {"codex": "codex (pid 4244)"},
	}
	var reported []UnprotectedAgent
	manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("codex"), EnumerateOptions{
		ExcludeUsers:      []string{excludedSID},
		RunningAgents:     running,
		ReportUnprotected: func(agent UnprotectedAgent) { reported = append(reported, agent) },
	})
	if err != nil {
		t.Fatalf("EnumerateWindows: %v", err)
	}
	if len(manifest.Targets) != 1 || manifest.Targets[0].SID != enrolledSID {
		t.Fatalf("targets = %+v, want only the npm user's row", manifest.Targets)
	}
	// Only the enabled connector of the user no row enrolls is reported; the
	// enrolled and the excluded users are not.
	if len(reported) != 1 || reported[0].SID != canonicalManifestTargetSID(testEntraUserSID) || reported[0].Connector != "codex" {
		t.Fatalf("unprotected = %+v, want the bare user's running codex only", reported)
	}
	message := reported[0].Message()
	for _, want := range []string{"codex (pid 4242) runs for this account", "no codex install DefenseClaw can read", "npm install -g @openai/codex", "refuse this user's tool calls"} {
		if !strings.Contains(message, want) {
			t.Fatalf("message %q does not contain %q", message, want)
		}
	}
}
