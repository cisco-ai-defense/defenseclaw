// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"fmt"
	"strings"
	"testing"
)

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
		{"bash -c with positional words", []string{"bash", "-c", `"$@"`, "_", "pwsh"}, 0, DialectPOSIX, true, true},
		{"bash -c alone", []string{"bash", "-lc", "ls"}, 0, DialectPOSIX, false, true},
		{"command -v only prints", []string{"command", "-v", "pwsh"}, 0, DialectNone, false, false},
		{"ssh runs it elsewhere", []string{"ssh", "host", "pwsh", "-c", body}, 0, DialectNone, false, false},
		{"an ordinary command", []string{"git", "commit", "-m", "pwsh -c x"}, 0, DialectNone, false, false},
		{"echo names it as data", []string{"echo", "pwsh", "-c", body}, 0, DialectNone, false, false},
		// A wrapper operand spelled as a launcher name is read both ways
		// (rel-1-0-10:GAP-0857).
		{"sudo -u <launcher name>", []string{"sudo", "-u", "cmd", "pwsh", "-c", body}, 3, DialectPowerShell, false, true},
		{"env -u <launcher name>", []string{"env", "-u", "bash", "cmd", "/c", "dir"}, 3, DialectCMD, false, true},
		{"timeout -s <launcher name>", []string{"timeout", "-s", "sh", "5", "pwsh", "-c", body}, 4, DialectPowerShell, false, true},
		{"xargs -I <launcher name>", []string{"xargs", "-I", "bash", "cmd.exe", "/c", "dir"}, 3, DialectCMD, false, true},
		{"wsl -d <launcher name>", []string{"wsl", "-d", "pwsh", "-e", "cmd", "/c", "dir"}, 4, DialectCMD, false, true},
		{"nice -n <launcher name>", []string{"nice", "-n", "cmd.exe", "pwsh", "-c", body}, 3, DialectPowerShell, false, true},
		{"the operand is the launcher", []string{"sudo", "-u", "pwsh", "-c", body}, 2, DialectPowerShell, false, true},
		{"start title", []string{"start", "My Title", "pwsh", "-c", body}, 2, DialectPowerShell, false, true},
		{"start title spelled as a launcher", []string{"start", "cmd", "pwsh", "-c", body}, 2, DialectPowerShell, false, true},
		{"start one title only", []string{"start", "a", "b", "pwsh", "-c", body}, 0, DialectNone, false, false},
		// Every pass-through wrapper the analysis unwraps is read through
		// (staticPOSIXWrapperPrograms, rel-1-0-10:GAP-0970), however long
		// the chain the analysis reads whole.
		{"time", []string{"time", "pwsh", "-c", body}, 1, DialectPowerShell, false, true},
		{"time -p", []string{"time", "-p", "cmd", "/c", "dir"}, 2, DialectCMD, false, true},
		{"nsenter", []string{"nsenter", "-t", "1", "-m", "pwsh", "-c", body}, 4, DialectPowerShell, false, true},
		{"time chain", append(strings.Fields(strings.Repeat("time ", 5)), "pwsh", "-c", body), 5, DialectPowerShell, false, true},
		{"neutral chain past 64 words", append(strings.Fields(strings.Repeat("nice -n 5 ", 30)), "cmd", "/c", "dir"), 90, DialectCMD, false, true},
	}
	for _, tc := range tests {
		call, ok := ShellLauncherCall(tc.argv)
		if ok != tc.ok || (ok && (call.Start != tc.start || call.Dialect != tc.dialect || call.Trailing != tc.trailing)) {
			t.Errorf("%s: got %+v %t, want start %d dialect %q trailing %t ok %t", tc.name, call, ok, tc.start, tc.dialect, tc.trailing, tc.ok)
		}
		if ok && (call.Dialect == DialectPowerShell || call.Dialect == DialectCMD) && !hostLauncherArgv(tc.argv, 0) {
			t.Errorf("%s: the reader names a launcher the over-limit screen does not: %v", tc.name, tc.argv)
		}
	}
}

// ShellLauncherCalls reads a word that may be an operand or a title both
// ways: each launcher reading whose grammar gives a script is one call
// (rel-1-0-10:GAP-0857).
func TestShellLauncherCallsReadsBothWays(t *testing.T) {
	const body = "Get-ChildItem ."
	tests := []struct {
		name   string
		argv   []string
		starts []int
	}{
		{"operand that is no launcher call", []string{"sudo", "-u", "cmd", "pwsh", "-c", body}, []int{3}},
		{"operand and launcher both run a script", []string{"sudo", "-u", "pwsh", "pwsh", "-c", body}, []int{2, 3}},
		{"start title and program", []string{"start", "pwsh", "cmd", "/c", "dir"}, []int{1, 2}},
		{"a plain launcher", []string{"pwsh", "-c", body}, []int{0}},
	}
	for _, tc := range tests {
		var starts []int
		for _, call := range ShellLauncherCalls(tc.argv) {
			starts = append(starts, call.Start)
		}
		if strings.Trim(strings.Join(strings.Fields(fmt.Sprint(starts)), ","), "[]") != strings.Trim(strings.Join(strings.Fields(fmt.Sprint(tc.starts)), ","), "[]") {
			t.Errorf("%s: starts %v, want %v", tc.name, starts, tc.starts)
		}
	}
	calls, _, _, ok := ShellLauncherCallsOfText(`start "My Title" sudo -u cmd pwsh -c 'dir'`)
	if !ok || len(calls) != 1 || calls[0].Body != "dir" {
		t.Errorf("text: %+v %t, want one call with body dir", calls, ok)
	}
}

// ShellLauncherCallOfText reads a launcher in a later statement and past the
// 64 KiB command bound (rel-1-0-10:GAP-0805, GAP-0807).
func TestShellLauncherCallOfTextReadsStatements(t *testing.T) {
	pad := strings.Repeat("x", 70000)
	tests := []struct {
		name, text, body string
		statement        int
		ok               bool
	}{
		{"head", `pwsh -c 'dir'`, "dir", 0, true},
		{"after a pipe", `echo x | xargs pwsh -c 'dir'`, "dir", 1, true},
		{"after a list", `cd C:\work && cmd /c "dir"`, "dir", 1, true},
		{"after a redirect", `echo x > out.txt; pwsh -c 'dir'`, "dir", 1, true},
		// The redirections of the launcher's statement are part of its script
		// (rel-1-0-10:GAP-0806).
		{"cmd with a redirect", `cmd /c dir >> out.txt`, "dir >> out.txt", 0, true},
		{"cmd with a quoted redirect target", `cmd /c "dir" > "C:\work\out file.txt"`, `dir > "C:\work\out file.txt"`, 0, true},
		{"nested cmd keeps the redirect", `cmd /c cmd /c dir 2>&1 >> out.txt`, "cmd /c dir 2>&1 >> out.txt", 0, true},
		{"pwsh with a redirect", `pwsh -c 'dir' 2> err.txt; git status`, "dir 2> err.txt", 0, true},
		// A redirect target is split as a word is (rel-1-0-10:GAP-0969): a
		// backtick or doubled quote in double quotes is one quote, and a
		// target that never closes ends the statement, so the launcher
		// before it is still read.
		{"redirect target with a backtick quote", "cmd /c dir >> out.txt 2> \"a`\"b\"", "dir >> out.txt 2> \"a`\"b\"", 0, true},
		{"backtick quote target first", "cmd /c dir 2> \"a`\"b\" >> out.txt", "dir 2> \"a`\"b\" >> out.txt", 0, true},
		{"redirect target with a doubled quote", `pwsh -c 'dir' > "a""b.txt"`, `dir > "a""b.txt"`, 0, true},
		{"redirect target with a doubled single quote", `cmd /c dir > 'a''b.txt'`, `dir > 'a''b.txt'`, 0, true},
		{"unreadable redirect target", `cmd /c dir >> out.txt 2> "abc`, "dir >> out.txt", 0, true},
		{"start title", `start "" powershell -Command 'dir'`, "dir", 0, true},
		{"quoted install path", `& 'C:\Program Files\PowerShell\7\pwsh.exe' -Command 'dir'`, "dir", 0, true},
		{"past the command bound", `pwsh -c '# ` + pad + "\ndir'", "# " + pad + "\ndir", 0, true},
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
