// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// ShellLauncherCall names the launcher behind the wrappers the over-limit
// launcher screen reads, at any install path, and the screen names the same
// launcher (rel-1-0-10:GAP-0804, GAP-0805).
func TestShellLauncherCallReadsWrappers(t *testing.T) {
	const body = "Get-ChildItem ."
	tests := []struct {
		name     string
		argv     []string
		start    int
		dialect  Dialect
		trailing bool
		ok       bool
	}{
		{"bare", []string{"pwsh", "-c", body}, 0, DialectPowerShell, false, true},
		{"install path with a blank", []string{`C:\Program Files\PowerShell\7\pwsh.exe`, "-Command", body}, 0, DialectPowerShell, false, true},
		{"env flag", []string{"env", "-i", "powershell.exe", "-Command", body}, 2, DialectPowerShell, false, true},
		{"env assignment", []string{"env", "X=1", "pwsh", "-c", body}, 2, DialectPowerShell, false, true},
		{"leading assignment", []string{"X=1", "pwsh", "-c", body}, 1, DialectPowerShell, false, true},
		{"sudo flag operand", []string{"sudo", "-u", "root", "cmd.exe", "/c", "dir"}, 3, DialectCMD, false, true},
		{"start title", []string{"start", "", "powershell", "-Command", body}, 2, DialectPowerShell, false, true},
		{"start switch", []string{"start", "/wait", "cmd", "/c", "dir"}, 2, DialectCMD, false, true},
		{"wsl", []string{"wsl.exe", "pwsh", "-c", body}, 1, DialectPowerShell, false, true},
		{"wsl -e", []string{"wsl", "-e", "pwsh", "-c", body}, 2, DialectPowerShell, false, true},
		{"nohup", []string{"nohup", "cmd", "/k", "dir"}, 1, DialectCMD, false, true},
		{"timeout duration", []string{"timeout", "5", "pwsh", "-c", body}, 2, DialectPowerShell, false, true},
		{"nice flag operand", []string{"nice", "-n", "10", "pwsh", "-c", body}, 3, DialectPowerShell, false, true},
		{"xargs", []string{"xargs", "pwsh", "-c", body}, 1, DialectPowerShell, false, true},
		{"nested wrappers", []string{"sudo", "env", "X=1", "nohup", "pwsh", "-c", body}, 4, DialectPowerShell, false, true},
		{"bash -c alone", []string{"bash", "-lc", "ls"}, 0, DialectPOSIX, false, true},
		{"command -v only prints", []string{"command", "-v", "pwsh"}, 0, DialectNone, false, false},
		{"ssh runs it elsewhere", []string{"ssh", "host", "pwsh", "-c", body}, 0, DialectNone, false, false},
		{"an ordinary command", []string{"git", "commit", "-m", "pwsh -c x"}, 0, DialectNone, false, false},
		{"echo names it as data", []string{"echo", "pwsh", "-c", body}, 0, DialectNone, false, false},
	}
	for _, tc := range tests {
		call, ok := ShellLauncherCall(tc.argv)
		if ok != tc.ok || (ok && (call.Start != tc.start || call.Dialect != tc.dialect)) {
			t.Errorf("%s: got %+v %t, want start %d dialect %q trailing %t ok %t", tc.name, call, ok, tc.start, tc.dialect, tc.trailing, tc.ok)
		}
		if ok && (call.Dialect == DialectPowerShell || call.Dialect == DialectCMD) && !hostLauncherArgv(tc.argv, 0) {
			t.Errorf("%s: the reader names a launcher the over-limit screen does not: %v", tc.name, tc.argv)
		}
	}
}

// ShellLauncherCallOfText reads a launcher in a later statement
// (rel-1-0-10:GAP-0805).
func TestShellLauncherCallOfTextReadsStatements(t *testing.T) {
	tests := []struct {
		name, text, body string
		statement        int
		ok               bool
	}{
		{"head", `pwsh -c 'dir'`, "dir", 0, true},
		{"after a pipe", `echo x | xargs pwsh -c 'dir'`, "dir", 1, true},
		{"after a list", `cd C:\work && cmd /c "dir"`, "dir", 1, true},
		{"after a redirect", `echo x > out.txt; pwsh -c 'dir'`, "dir", 2, true},
		{"start title", `start "" powershell -Command 'dir'`, "dir", 0, true},
		{"quoted install path", `& 'C:\Program Files\PowerShell\7\pwsh.exe' -Command 'dir'`, "dir", 0, true},
		{"no launcher", `git status; ls`, "", 0, false},
		{"launcher word as data", `echo 'pwsh -c dir'`, "", 0, false},
		{"unterminated quote", `echo x; pwsh -c 'dir`, "", 0, false},
	}
	for _, tc := range tests {
		call, _, statement, ok := ShellLauncherCallOfText(tc.text)
		if ok != tc.ok || (ok && (call.Body != tc.body || statement != tc.statement)) {
			t.Errorf("%s: got body %.40q statement %d ok %t, want %.40q %d %t", tc.name, call.Body, statement, ok, tc.body, tc.statement, tc.ok)
		}
	}
}
