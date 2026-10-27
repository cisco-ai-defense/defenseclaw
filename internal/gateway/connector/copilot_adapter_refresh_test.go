// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0343: the upgrade refresh of a released (1.0.3) Copilot adapter makes a
// launcher that exits non-zero without an answer throw, so the closed catch
// denies the call; LF and CRLF files alike, and a refreshed adapter is not
// changed again. The current template already checks it and is unchanged.
func TestReleasedCopilotAdapterRefreshClosesACrashedLauncherOnce(t *testing.T) {
	released, err := os.ReadFile(filepath.Join("testdata", "released-hooks", "1.0.3", "copilot-hook.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	const check = `throw "DefenseClaw hook launcher exited $($process.ExitCode) without an answer"`
	for name, body := range map[string]string{
		"LF":   strings.ReplaceAll(string(released), "\r\n", "\n"),
		"CRLF": strings.ReplaceAll(strings.ReplaceAll(string(released), "\r\n", "\n"), "\n", "\r\n"),
	} {
		once := bakedAdapterFailModeOpens.Replace(body)
		if strings.Count(once, check) != 1 || !strings.Contains(once, copilotAdapterClosedFailure) {
			t.Fatalf("%s: refreshed released adapter has %d crash checks (closed catch %v)", name, strings.Count(once, check), strings.Contains(once, copilotAdapterClosedFailure))
		}
		if twice := bakedAdapterFailModeOpens.Replace(once); twice != once {
			t.Fatalf("%s: a refreshed adapter changed on the next refresh", name)
		}
	}
	current, err := renderHookTemplate("copilot-hook.ps1", templateData{HookBinaryPS: `C:\\dc\\defenseclaw-hook.exe`, CopilotHookTimeoutMS: 25000, FailMode: "closed"})
	if err != nil {
		t.Fatal(err)
	}
	if got := bakedAdapterFailModeOpens.Replace(string(current)); got != string(current) {
		t.Fatal("the refresh changed a current closed adapter")
	}
}
