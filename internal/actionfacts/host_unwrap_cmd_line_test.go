// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// TestPowerShellCmdLauncherLine (rel-1-0-10:GAP-0552): a PowerShell call that
// is a cmd launcher is read as the line cmd.exe receives, as its author wrote
// it; anything that is not a cmd launcher at the start of the call has no line.
func TestPowerShellCmdLauncherLine(t *testing.T) {
	for _, test := range []struct {
		source, line string
		ok           bool
	}{
		{`cmd /c whoami & hostname`, `whoami & hostname`, true},
		{`cmd.exe /c "reg query HKLM\Software & ver"`, `reg query HKLM\Software & ver`, true},
		{`& cmd.exe /c dir`, `dir`, true},
		{`C:\Windows\System32\cmd.exe /c ver`, `ver`, true},
		{`"C:\Windows\System32\cmd.exe" /c ver`, `ver`, true},
		{`cmd /s /c "ver"`, `ver`, true},
		{`cmd /d /q /c ver`, `ver`, true},
		{`cmd /k ver`, ``, false},
		{`cmd /r ver`, `ver`, true},
		{`C:\tmp\cmd.exe /c ver`, ``, false},
		{`cmd /e:on /c ver`, ``, false},
		{`cmd`, ``, false},
		{`cmdkey /list`, ``, false},
		{`Write-Output cmd /c ver`, ``, false},
		{`powershell -c ver`, ``, false},
	} {
		line, ok := powerShellCmdLauncherLine(test.source)
		if ok != test.ok || line != test.line {
			t.Errorf("powerShellCmdLauncherLine(%q) = %q, %v; want %q, %v", test.source, line, ok, test.line, test.ok)
		}
	}
}

// TestHostScriptReadingsReadsAPowerShellCmdLauncherAsItsLine
// (rel-1-0-10:GAP-0552): the PowerShell tool's cmd launcher has a cmd.exe
// reading of its line beside psparse's, alone and as a statement of a list.
func TestHostScriptReadingsReadsAPowerShellCmdLauncherAsItsLine(t *testing.T) {
	for _, source := range []string{
		`cmd.exe /c whoami & hostname`,
		`Write-Output a; cmd.exe /c whoami & hostname`,
	} {
		input := hookShellInput(t, "PowerShell", source)
		reading := HostScriptReadings(input, Analyze(input), 0, false)
		found := false
		for index, twin := range reading.Twins {
			if twin.DialectHint == DialectCMD && twin.Command == `whoami & hostname` {
				found = true
				if index < len(reading.Listed) && reading.Listed[index] {
					t.Fatalf("%q: the cmd line is marked as a listed statement", source)
				}
			}
			if twin.DialectHint == DialectPowerShell && twin.Command == "cmd.exe /c whoami & hostname" && source != twin.Command {
				statement := hookShellInput(t, "PowerShell", twin.Command)
				for _, nested := range HostScriptReadings(statement, Analyze(statement), reading.Depth, true).Twins {
					found = found || nested.DialectHint == DialectCMD && nested.Command == `whoami & hostname`
				}
			}
		}
		if !found {
			t.Fatalf("%q: no cmd.exe reading of the line: %#v", source, reading.Twins)
		}
		if len(reading.Listed) != len(reading.Twins) {
			t.Fatalf("%q: %d twins, %d listed marks", source, len(reading.Twins), len(reading.Listed))
		}
	}
}
