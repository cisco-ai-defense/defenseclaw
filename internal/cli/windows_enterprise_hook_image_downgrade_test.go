// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// rel-1-0-10 GAP-0794: a managed Windows downgrade to 1.0.9 (Setup 1.0.9
// /upgrade over 1.0.10) ended 1603 with every DefenseClaw service stopped and
// disabled and no install record. The 1.0.9 guardian failed the signed-in
// account: its Copilot VS Code Local hook file, Hermes allowlist and OpenCode
// enrollment named the 1.0.10 launch image bin\hooks\<d16>, which 1.0.9 does
// not own. `enterprise windows hook-image retire`, the step before an older
// Setup, did not see the Copilot file at all (its hook path is only inside a
// PowerShell -EncodedCommand) and did not wait for any account file. These
// tests pin what retire must prove before it ends ok.

const downgradeTestLaunchHook = hookImageTestBin + `\hooks\0123456789abcdef\defenseclaw-hook.exe`

// The Copilot VS Code Local hook file names the hook only inside the base64
// UTF-16LE script of -EncodedCommand. The scan must still see the launch
// folder (prune would otherwise remove a folder a Copilot session starts,
// and retire would end ok over a file the older guardian refuses).
func TestHookImageScanSeesALaunchFolderInsideAnEncodedCommand(t *testing.T) {
	body, err := enterprisepolicy.RenderCopilotVSCodeLocalHooks("windows", downgradeTestLaunchHook)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(body)), `\hooks\0123456789abcdef`) {
		t.Fatal("test premise: the Copilot render names the launch folder in plain text")
	}
	if got := strings.Join(windowsHookImageFoldersNamedIn(body, hookImageTestBin), ","); got != "0123456789abcdef" {
		t.Fatalf("folders named by the Copilot VS Code render = %q, want 0123456789abcdef", got)
	}
	transition, err := enterprisepolicy.RenderCopilotVSCodeLocalHooks("windows", hookImageTestBin+`\defenseclaw-hook.exe`)
	if err != nil {
		t.Fatal(err)
	}
	if got := windowsHookImageFoldersNamedIn(transition, hookImageTestBin); len(got) != 0 {
		t.Fatalf("the transition render names launch folders %v", got)
	}
	// Garbage after -EncodedCommand, or a script for another install, keeps
	// nothing.
	other, err := enterprisepolicy.RenderCopilotVSCodeLocalHooks("windows", `D:\Other\DefenseClaw\bin\hooks\0123456789abcdef\defenseclaw-hook.exe`)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range [][]byte{other, []byte(`powershell.exe -EncodedCommand !!!notbase64 -EncodedCommand`)} {
		if got := windowsHookImageFoldersNamedIn(text, hookImageTestBin); len(got) != 0 {
			t.Fatalf("folders named = %v", got)
		}
	}
}

// An account file that still names a launch folder holds retire back: the
// older release guardian reads it as a foreign or tampered hook, fails that
// account and the older Setup ends 1603. Retire waits for the guardian to
// rewrite it and, when it is still there (the account is signed out), ends
// pending and names the file and the next step.
func TestHookImageRetireIsPendingWhileAnAccountFileStillNamesAFolder(t *testing.T) {
	r := newRetireFixture(t)
	folder, _ := winpath.EnterpriseHookImageDigest(r.recorded["hook"])
	file := `C:\Users\c\.copilot\hooks\defenseclaw-vscode.json`
	r.userFiles = map[string]bool{strings.ToLower(file): true}
	r.named = []map[string][]string{{folder: {file}}}
	report := retireWindowsHookImages(r.steps())
	if report.OK || report.Reason != windowsHookImageRetirePending {
		t.Fatalf("retire = %+v; an account file that names a launch folder must hold it back", report)
	}
	encoded, _ := json.Marshal(report.StillNamed)
	if len(report.StillNamed) != 1 || report.StillNamed[0].File != file || !strings.Contains(string(encoded), `"account":true`) {
		t.Fatalf("still named = %s", encoded)
	}
	for _, want := range []string{"sign in", "remove", "run retire again"} {
		if !strings.Contains(report.Error, want) {
			t.Fatalf("retire error %q does not say %q", report.Error, want)
		}
	}
	if r.scans < 3 {
		t.Fatalf("retire scanned %d times; it must wait for the guardian to rewrite the account file", r.scans)
	}
}

func TestHookImageRetireWaitsForTheGuardianToRewriteAnAccountFile(t *testing.T) {
	r := newRetireFixture(t)
	folder, _ := winpath.EnterpriseHookImageDigest(r.recorded["hook"])
	file := `C:\Users\c\.hermes\config.yaml`
	r.userFiles = map[string]bool{strings.ToLower(file): true}
	r.named = []map[string][]string{{folder: {file}}, {folder: {file}}, {}}
	report := retireWindowsHookImages(r.steps())
	if !report.OK || len(report.StillNamed) != 0 || strings.Join(report.Rewritten, ",") != file {
		t.Fatalf("retire = %+v", report)
	}
}

// olderSetupAttributionPattern is, verbatim, the line 1.0.9 Setup
// (Test-DefenseClawGuardianReportErrorsAttributable, tag 1.0.9) and every
// release since GAP-0900 accept as a failed guardian row. During a failed
// older Setup /upgrade the rollback restores this release and reads this
// release `enterprise hooks status`: any other line rejects the degraded
// reconcile, so a signed-out account left every service stopped.
var olderSetupAttributionPattern = regexp.MustCompile(`^last guardian reconcile failed for (.+?)(?: \((S-1-[0-9-]+)\))?: `)

func TestGuardianFailureIssuesAreAttributableByAnOlderSetupRollback(t *testing.T) {
	originalCfg, originalSignedOut := cfg, enterpriseHookSignedOutAccount
	t.Cleanup(func() { cfg, enterpriseHookSignedOutAccount = originalCfg, originalSignedOut })
	cfg = &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
	}
	enterpriseHookSignedOutAccount = func(row enterpriseHookReconcileRow) string {
		if strings.Contains(row.Error, "session is unavailable") {
			return row.User + " (" + row.SID + ")"
		}
		return ""
	}
	state := enterpriseHookGuardianState{Results: []enterpriseHookReconcileRow{
		{User: `HOST\dana`, SID: "S-1-5-21-1-2-3-1003", Connector: "copilot",
			Error: "enterprise hooks: protected target requires repair but its exact active Windows session is unavailable"},
		{User: `HOST\dana`, SID: "S-1-5-21-1-2-3-1003", Connector: "claudecode",
			Error: enterpriseHookAwaitingSignInPrefix + ": " + enterpriseHookAwaitingSignInPriorRender},
		{User: `HOST\dana`, SID: "S-1-5-21-1-2-3-1003", Connector: "hermes",
			Error: enterpriseHookAwaitingSignInPrefix + ": " + enterpriseHookAwaitingSignInEarlierMatrix},
		{User: `HOST\erin`, SID: "S-1-5-21-1-2-3-1001", Connector: "opencode", Error: "publish opencode enrollment: denied"},
		{User: `HOST\erin`, SID: "S-1-5-21-1-2-3-1001", Connector: "codex", OK: true},
	}}
	failed := map[string]bool{}
	for _, row := range state.Results {
		if !row.OK {
			failed[row.Connector+"@"+row.SID] = true
		}
	}
	issues := enterpriseHookGuardianFailureIssues(state)
	if len(issues) != 4 {
		t.Fatalf("issues = %#v", issues)
	}
	for _, issue := range issues {
		match := olderSetupAttributionPattern.FindStringSubmatch(issue)
		if match == nil {
			t.Fatalf("an older Setup rollback cannot attribute %q to a failed row", issue)
		}
		label := match[1]
		if match[2] != "" {
			label = strings.SplitN(label, "@", 2)[0] + "@" + match[2]
		}
		if !failed[label] {
			t.Fatalf("%q is attributed to %q, not a failed row", issue, label)
		}
	}
	// The next step a signed-out account gets is still in the line.
	if !strings.Contains(issues[0], "while that account is signed out: have the account sign in") ||
		!strings.Contains(issues[1], "is pending until that account signs in") ||
		!strings.Contains(issues[2], enterpriseHookEarlierMatrixState) {
		t.Fatalf("issues lost their guidance: %#v", issues)
	}
}
