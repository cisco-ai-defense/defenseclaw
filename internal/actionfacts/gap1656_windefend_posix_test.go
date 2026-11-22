// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// TestGAP1656WinDefendStepsByHostAndDialect: a POSIX shell on a Windows host
// (Git Bash, the Claude Code Bash tool) runs the native sc.exe for sc and
// sc.exe, so its WinDefend stop and start-type disable are the same proven
// operation as in CMD; the two-word "start= disabled" spelling is the
// disable in every native dialect; a lone disable is proven like a lone stop.
// A POSIX sc off a Windows host, PowerShell's bare sc (Set-Content), a status
// query and an other start type prove nothing (rel-1-0-10:GAP-1656).
func TestGAP1656WinDefendStepsByHostAndDialect(t *testing.T) {
	tests := []struct {
		name    string
		command string
		dialect Dialect
		host    bool
		proved  bool
		single  bool
	}{
		{"git bash sc.exe stop", "sc.exe stop WinDefend", DialectPOSIX, true, true, true},
		{"git bash sc stop", "sc stop WinDefend", DialectPOSIX, true, true, true},
		{"git bash sc.exe two-word disable", "sc.exe config WinDefend start= disabled", DialectPOSIX, true, true, true},
		{"git bash sc two-word disable", "sc config WinDefend start= disabled", DialectPOSIX, true, true, true},
		{"git bash joined disable", "sc.exe config WinDefend start=disabled", DialectPOSIX, true, true, true},
		{"git bash unhinted", "sc stop WinDefend", "", true, true, true},
		{"git bash full sequence", "sc stop WinDefend\nsc config WinDefend start= disabled\nsc query WinDefend", DialectPOSIX, true, true, false},
		{"cmd two-word disable", "sc config WinDefend start= disabled", DialectCMD, true, true, true},
		{"cmd lone joined disable", "sc config WinDefend start=disabled", DialectCMD, false, true, true},
		{"powershell sc.exe two-word disable", "sc.exe config WinDefend start= disabled", DialectPowerShell, true, true, true},
		{"powershell bare sc disable is set-content", "sc config WinDefend start= disabled", DialectPowerShell, true, false, false},
		{"linux sc.exe stop", "sc.exe stop WinDefend", DialectPOSIX, false, false, false},
		{"linux sc stop", "sc stop WinDefend", DialectPOSIX, false, false, false},
		{"linux sc disable", "sc config WinDefend start= disabled", DialectPOSIX, false, false, false},
		{"git bash query", "sc query WinDefend", DialectPOSIX, true, false, false},
		{"git bash qc", "sc.exe qc WinDefend", DialectPOSIX, true, false, false},
		{"git bash restore", "sc config WinDefend start= auto", DialectPOSIX, true, false, false},
		{"git bash extra option word", "sc config WinDefend start= disabled now", DialectPOSIX, true, false, false},
		{"git bash other service", "sc stop Spooler", DialectPOSIX, true, false, false},
		{"git bash missing query", "sc stop WinDefend\nsc config WinDefend start= disabled", DialectPOSIX, true, false, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{
				Tool: "shell", Command: test.command, CWD: `C:\repo`,
				DialectHint: test.dialect, WindowsHookHost: test.host,
			})
			if got := ExactEndpointSecurityProductDisable(facts); got != test.proved {
				t.Errorf("ExactEndpointSecurityProductDisable=%t want %t: parse=%+v commands=%+v", got, test.proved, facts.Parse, facts.Commands)
			}
			if got := ExactWinDefendSingleStep(facts); got != test.single {
				t.Errorf("ExactWinDefendSingleStep=%t want %t", got, test.single)
			}
		})
	}
	// The GAP-1194 sequence rule covers the lone disable too: a stop+disable
	// pair without its query is unproved, so neither statement read alone
	// may prove the disable.
	facts := Analyze(Input{Tool: "shell", Command: "sc stop WinDefend\nsc config WinDefend start= disabled",
		CWD: `C:\repo`, DialectHint: DialectPOSIX, WindowsHookHost: true})
	if !WinDefendSequenceUnproved(facts) {
		t.Errorf("git bash stop+disable without query: WinDefendSequenceUnproved=false, want true")
	}
}
