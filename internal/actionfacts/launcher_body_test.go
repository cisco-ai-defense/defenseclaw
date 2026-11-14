// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// ShellLauncherBody reads the script word of each launcher from its own
// grammar (rel-1-0-10:GAP-0711).
func TestShellLauncherBody(t *testing.T) {
	const body = "Get-ChildItem ."
	tests := []struct {
		name    string
		argv    []string
		want    string
		dialect Dialect
		ok      bool
	}{
		{"powershell -Command", []string{"powershell.exe", "-Command", body}, body, DialectPowerShell, true},
		{"pwsh -Command", []string{"pwsh", "-Command", body}, body, DialectPowerShell, true},
		{"powershell -c", []string{"powershell", "-c", body}, body, DialectPowerShell, true},
		{"abbreviated -com", []string{"pwsh", "-com", body}, body, DialectPowerShell, true},
		{"slash option", []string{"powershell.exe", "/Command", body}, body, DialectPowerShell, true},
		{"switches before", []string{"pwsh.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", body}, body, DialectPowerShell, true},
		{"words are joined", []string{"pwsh", "-Command", "echo", "marker"}, "echo marker", DialectPowerShell, true},
		{"implicit command", []string{"powershell.exe", "-NoLogo", "Get-Date"}, "Get-Date", DialectPowerShell, true},
		{"launcher path", []string{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "-Command", body}, body, DialectPowerShell, true},
		{"-File has no body", []string{"powershell.exe", "-File", "x.ps1"}, "", DialectPowerShell, false},
		{"-EncodedCommand has no body", []string{"pwsh", "-EncodedCommand", "AAAA"}, "", DialectPowerShell, false},
		{"-Command - is stdin", []string{"pwsh", "-Command", "-"}, "", DialectPowerShell, false},
		{"unlisted option", []string{"pwsh", "-WorkingDirectory", "C:\\x", "-Command", body}, "", DialectPowerShell, false},
		{"empty body word", []string{"pwsh", "-Command", ""}, "", DialectPowerShell, false},
		{"no body at all", []string{"pwsh", "-NoProfile"}, "", DialectPowerShell, false},
		{"cmd /c", []string{"cmd", "/c", "dir C:\\"}, "dir C:\\", DialectCMD, true},
		{"cmd /k", []string{"cmd.exe", "/k", "dir"}, "dir", DialectCMD, true},
		{"cmd /d /c", []string{"cmd.exe", "/d", "/c", "dir"}, "dir", DialectCMD, true},
		{"cmd /s /c quoted", []string{"cmd", "/s", "/c", `"dir C:\"`}, `dir C:\`, DialectCMD, true},
		{"cmd words joined", []string{"cmd", "/c", "echo", "a"}, "echo a", DialectCMD, true},
		{"cmd unknown option", []string{"cmd", "/z", "/c", "dir"}, "", DialectCMD, false},
		{"cmd no body", []string{"cmd", "/c"}, "", DialectCMD, false},
		{"bash -lc", []string{"bash", "-lc", "ls -la"}, "ls -la", DialectPOSIX, true},
		{"sh -c", []string{"/bin/sh", "-c", "ls"}, "ls", DialectPOSIX, true},
		{"not a launcher", []string{"git", "status"}, "", DialectNone, false},
	}
	for _, tc := range tests {
		got, dialect, ok := ShellLauncherBody(tc.argv)
		if ok != tc.ok || got != tc.want || (tc.ok && dialect != tc.dialect) {
			t.Errorf("%s: got (%q, %q, %t), want (%q, %q, %t)", tc.name, got, dialect, ok, tc.want, tc.dialect, tc.ok)
		}
	}
}

// ShellLauncherBodyOfText reads the same launchers when they are one command
// string (rel-1-0-10:GAP-0735).
func TestShellLauncherBodyOfText(t *testing.T) {
	tests := []struct {
		name, text, want string
		dialect          Dialect
		ok               bool
	}{
		{"single quoted", `powershell.exe -Command 'Get-ChildItem .'`, "Get-ChildItem .", DialectPowerShell, true},
		{"doubled quote", `pwsh -c 'echo ''hi'''`, "echo 'hi'", DialectPowerShell, true},
		{"double quoted", `powershell -NoProfile -Command "Get-Date"`, "Get-Date", DialectPowerShell, true},
		{"call operator", `& 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Command 'dir'`, "dir", DialectPowerShell, true},
		{"cmd quoted", `cmd /c "dir C:\"`, `dir C:\`, DialectCMD, true},
		{"cmd d c", `cmd.exe /d /c "echo hi"`, "echo hi", DialectCMD, true},
		{"newline inside quotes", "pwsh -Command 'a\nb'", "a\nb", DialectPowerShell, true},
		{"statement after", `powershell -Command 'dir' ; echo done`, "dir", DialectPowerShell, true},
		{"unterminated quote", `pwsh -Command 'dir`, "", DialectNone, false},
		{"not a launcher", `git status`, "", DialectNone, false},
		{"file", `powershell -File x.ps1`, "", DialectPowerShell, false},
		{"empty", ``, "", DialectNone, false},
	}
	for _, tc := range tests {
		got, dialect, ok := ShellLauncherBodyOfText(tc.text)
		if ok != tc.ok || got != tc.want || (tc.ok && dialect != tc.dialect) {
			t.Errorf("%s: got (%q, %q, %t), want (%q, %q, %t)", tc.name, got, dialect, ok, tc.want, tc.dialect, tc.ok)
		}
	}
}
