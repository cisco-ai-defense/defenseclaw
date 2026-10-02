// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The Agent CLI build the cursor-hooks-v1 contract pins.
const testCursorAgentReviewedBuild = "2026.07.23-e383d2b"

func stubCursorMachinePolicyPublished(t *testing.T, published bool) {
	t.Helper()
	previous := windowsCursorMachinePolicyPublished
	t.Cleanup(func() { windowsCursorMachinePolicyPublished = previous })
	windowsCursorMachinePolicyPublished = func() bool { return published }
}

// A user with only the native Cursor Agent CLI (a build folder
// under %LOCALAPPDATA%\cursor-agent\versions, no package.json) at a reviewed
// build gets a Cursor row, so the guardian publishes Cursor's machine hooks
// file; the Secure Client enumerator still ignores the Agent CLI.
func TestEnumerateWindowsStandaloneEnrollsTheReviewedCursorAgentCLIBuild(t *testing.T) {
	stubMachineWinGet(t, nil)
	stubActiveSessions(t, nil)
	stubCursorMachinePolicyPublished(t, false)
	home := t.TempDir()
	build := filepath.Join(home, "AppData", "Local", "cursor-agent", "versions", testCursorAgentReviewedBuild)
	if err := os.MkdirAll(build, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, leaf := range []string{"node.exe", "index.js"} {
		if err := os.WriteFile(filepath.Join(build, leaf), []byte("fixture"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	injectWindowsProfileList(t, map[string]string{testLocalUserSID: home})
	var reported []UnprotectedAgent
	manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("cursor"), EnumerateOptions{
		ReportUnprotected: func(agent UnprotectedAgent) { reported = append(reported, agent) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Targets) != 1 || len(reported) != 0 {
		t.Fatalf("targets = %+v reported = %+v, want one Cursor row and no report", manifest.Targets, reported)
	}
	row := manifest.Targets[0]
	if row.SID != testLocalUserSID || row.Connector != "cursor" || row.AgentVersion != testCursorAgentReviewedBuild ||
		!row.IsEnabled() || !row.Deferred {
		t.Fatalf("row = %+v, want an enabled deferred Cursor row at %s", row, testCursorAgentReviewedBuild)
	}

	manifest, err = EnumerateWindows(context.Background(), secureClientEnumeratorConfig("cursor"), EnumerateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Targets) != 0 {
		t.Fatalf("Secure Client targets = %+v, want none for an Agent CLI install", manifest.Targets)
	}
}
