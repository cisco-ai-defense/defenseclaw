// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestGAP1300LauncherScriptsReadForEveryPOSIXHome: the GAP-1254 gate (a
// Windows hook host with a '/' home runs its PowerShell tool in Windows
// PowerShell) covers only the PowerShell tool command; the pwsh launcher
// scripts of a POSIX call are read for every '/' home, the unresolved
// caller home of a Windows hook host included, as rel read them
// (rel-1-0-10:GAP-1134). Red at det111/engine-train-6 f9b5854812 (the
// whole '/' home case was skipped on a Windows hook host); green at
// a64bfdb931, where the launcher reading had no such gate.
func TestGAP1300LauncherScriptsReadForEveryPOSIXHome(t *testing.T) {
	body := "New-Item -Path /nonexistent-home/.defenseclaw/config.yaml -Value x -Force"
	launcher := `pwsh -NoProfile -Command "` + body + `"`
	for _, windowsHost := range []bool{false, true} {
		for _, home := range []string{"/home/alice", unresolvedCallerHome} {
			request := trustedActionRequest{Input: actionfacts.Input{
				Tool: "Bash", Command: launcher, ActiveHome: home, WindowsHookHost: windowsHost,
				DialectHint: actionfacts.DialectPOSIX,
			}}
			found := false
			for _, command := range powerShellReadingCommands(request) {
				found = found || command.text == body && !command.posixTool
			}
			if !found {
				t.Errorf("windows host %v, home %q: the launcher script %q is not read: %+v", windowsHost, home, body, powerShellReadingCommands(request))
			}
		}
	}
	// The PowerShell tool command stays a Linux or macOS reading only off a
	// Windows hook host (GAP-1254).
	for _, windowsHost := range []bool{false, true} {
		request := trustedActionRequest{Input: actionfacts.Input{
			Tool: "PowerShell", Command: body, ActiveHome: unresolvedCallerHome, WindowsHookHost: windowsHost,
		}}
		posixTool := false
		for _, command := range powerShellReadingCommands(request) {
			posixTool = posixTool || command.posixTool
		}
		if posixTool == windowsHost {
			t.Errorf("windows host %v: PowerShell tool read as a POSIX-home tool = %v", windowsHost, posixTool)
		}
	}
}
