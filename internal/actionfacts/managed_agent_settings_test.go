// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"runtime"
	"testing"
)

// rel-1-0-6:GAP-0734: the managed agent settings directories are matched as
// a directory or below it, never as a name that only starts like one. Names
// match exactly on Linux, whose file systems tell case variants apart, and in
// any case on macOS (round 11: platform semantics, not string folding).
func TestManagedAgentSettingsPath(t *testing.T) {
	for _, test := range []struct {
		path          string
		exact, folded bool // Linux; macOS
	}{
		{"/etc/claude-code", true, true},
		{"/etc/claude-code/managed-settings.json", true, true},
		{"/etc/claude-code/managed-settings.d/50-dc.json", true, true},
		{"/etc/claude-code/Managed-Settings.JSON", false, true},
		{"/etc/claude-code/MANAGED-SETTINGS.JSON", false, true},
		{"/etc/claude-code/managed-settings.d/../MANAGED-SETTINGS.JSON", false, true},
		{"/etc/claude-code/sub/../managed-settings.json", true, true},
		{"/etc/cursor/hooks.json", true, true},
		{"/etc/opencode/opencode.jsonc", true, true},
		{"/etc/github-copilot", true, true},
		{"/etc/claude-code/notes.txt", false, false},
		{"/etc/codex/notes.txt", false, false},
		{"/etc/cursor/other.json", false, false},
		{"/etc/opencode/plugins.json", false, false},
		{"/etc/github-copilot/other.json", false, false},
		{"/Library/Application Support/ClaudeCode/notes.txt", false, false},
		{"/etc/codex/requirements.toml", true, true},
		{"/etc/codex/REQUIREMENTS.TOML", false, true},
		{"/etc/github-copilot/policy.d/50-dc.json", true, true},
		{"/Library/Application Support/ClaudeCode/managed-settings.json", true, true},
		{"/library/application support/claudecode/managed-settings.d/x.json", false, true},
		{"/private/etc/codex/requirements.toml", false, true},
		{"/PRIVATE/ETC/Codex/Requirements.toml", false, true},
		{"/private/etc/codex-extra/requirements.toml", false, false},
		{"/private/var/etc/codex/requirements.toml", false, false},
		{"/etc/claude-code-notes.txt", false, false},
		{"/etc/codex-extra/requirements.toml", false, false},
		{"/etc/CODEX/requirements.toml", false, true},
		{"/home/u/etc/codex/requirements.toml", false, false},
		{"/Library/Application Support/ClaudeCodeX/x.json", false, false},
		{"/Library/Application Support/Other/x.json", false, false},
		{"etc/codex/requirements.toml", false, false},
		{"", false, false},
	} {
		if got := ManagedAgentSettingsPath(test.path, false); got != test.exact {
			t.Errorf("ManagedAgentSettingsPath(%q, exact case) = %t, want %t", test.path, got, test.exact)
		}
		if got := ManagedAgentSettingsPath(test.path, true); got != test.folded {
			t.Errorf("ManagedAgentSettingsPath(%q, case folded) = %t, want %t", test.path, got, test.folded)
		}
	}
}

// The platform decides, not the spelling of a home (round 11 M2).
func TestCaseInsensitiveFilesystem(t *testing.T) {
	if got, want := CaseInsensitiveFilesystem(), runtime.GOOS == "darwin"; got != want {
		t.Errorf("CaseInsensitiveFilesystem() = %t on %s, want %t", got, runtime.GOOS, want)
	}
}

// rel-1-0-6:GAP-0734 review 6: the Windows machine-policy directories match
// on any drive, either separator and any case, never as a name that only
// starts like one.
func TestWindowsManagedAgentSettingsPath(t *testing.T) {
	for path, want := range map[string]bool{
		`C:\Program Files\ClaudeCode\managed-settings.json`:                       true,
		`c:/program files/claudecode/managed-settings.d/90-defenseclaw.json`:      true,
		`D:\Program Files\ClaudeCode`:                                             true,
		`\\?\C:\Program Files\ClaudeCode\managed-settings.json`:                   true,
		`C:\Program Files\ClaudeCode\managed-settings.d\..\managed-settings.json`: true,
		`C:\ProgramData\OpenAI\Codex\requirements.toml`:                           true,
		`C:\ProgramData\Cursor\hooks.json`:                                        true,
		`C:\ProgramData\GitHub\Copilot\policy.d\90-defenseclaw.json`:              true,
		`C:\ProgramData\opencode\opencode.json`:                                   true,
		`\\localhost\C$\Program Files\ClaudeCode\managed-settings.json`:           true,
		`\\127.0.0.1\C$\ProgramData\Cursor\hooks.json`:                            true,
		`\\?\UNC\localhost\C$\Program Files\ClaudeCode`:                           true,
		`//localhost/C$/Program Files/ClaudeCode/managed-settings.json`:           true,
		`//127.0.0.1/c$/ProgramData/Cursor/hooks.json`:                            true,
		`//?/UNC/localhost/C$/Program Files/ClaudeCode/managed-settings.json`:     true,
		`//otherhost/C$/Program Files/ClaudeCode/managed-settings.json`:           false,
		`\\otherhost\C$\Program Files\ClaudeCode\managed-settings.json`:           false,
		`\\localhost\C$\Program Files\Other\managed-settings.json`:                false,
		`C:\Program Files\ClaudeCodeX\managed-settings.json`:                      false,
		`C:\Program Files\ClaudeCode\notes.txt`:                                   false,
		`C:\ProgramData\Cursor\other.json`:                                        false,
		`C:\PROGRAM FILES\CLAUDECODE\MANAGED-SETTINGS.JSON`:                       true,
		`C:\Program Files\ClaudeCode\..\Other\a.json`:                             false,
		`C:\ProgramData\OpenAI\Codex2\requirements.toml`:                          false,
		`C:\Users\vn\ClaudeCode\managed-settings.json`:                            false,
		`Program Files\ClaudeCode\managed-settings.json`:                          false,
		"/etc/codex/requirements.toml":                                            false,
		"":                                                                        false,
	} {
		if got := WindowsManagedAgentSettingsPath(path); got != want {
			t.Errorf("WindowsManagedAgentSettingsPath(%q) = %t, want %t", path, got, want)
		}
	}
}

// rel-1-0-6:GAP-0734: where the volume cannot say what a short-name shaped
// part stands for (another operating system, or a name that is not on the
// volume), the shape of an 8.3 name decides, and only the shapes NTFS
// generates count. The volume stands in as one that cannot say, so the rows
// do not depend on the machine the test runs on; the names a real volume
// gives come from TestWindowsManagedAgentSettingsPathShortNamesOfTheVolume.
func TestWindowsManagedAgentSettingsPathShapeDecidesWhereTheVolumeCannotSay(t *testing.T) {
	saved := windowsLongPath
	t.Cleanup(func() { windowsLongPath = saved })
	windowsLongPath = func(string) (string, bool) { return "", false }
	for path, want := range map[string]bool{
		`C:\PROGRA~1\ClaudeCode\managed-settings.json`:                true,
		`C:\PROGRA~1\CLAUDE~1\managed-settings.json`:                  true,
		`C:\PROGRA~3\OpenAI\Codex\requirements.toml`:                  true,
		`C:\PROGRA~1\Other\managed-settings.json`:                     false,
		`C:\PROGRA~1\ClaudeCode\MANAGE~1.JSO`:                         true,
		`C:\PROGRA~1\ClaudeCode\MANAGE~1.D\90-defenseclaw.json`:       true,
		`C:\ProgramData\Cursor\HOOKS~1.JSO`:                           true,
		`C:\ProgramData\Cursor\DEFENS~1.PS1`:                          true,
		`C:\ProgramData\OpenAI\Codex\REQUIR~1.TOM`:                    true,
		`C:\ProgramData\opencode\OPENCO~1.JSO`:                        true,
		`C:\PR1A2B~1\ClaudeCode\managed-settings.json`:                true,
		`C:\P~1\ClaudeCode\managed-settings.json`:                     false,
		`C:\PROG~1\ClaudeCode\managed-settings.json`:                  false,
		`C:\XX1A2B~1\ClaudeCode\managed-settings.json`:                false,
		`C:\PR1A2G~1\ClaudeCode\managed-settings.json`:                false,
		`C:\PROGRA~1\ClaudeCode\MANAG~1.JSO`:                          false,
		`C:\PROGRA~1\ClaudeCode\MANAGE~1.TXT`:                         false,
		`C:\PR1A2B~5\ClaudeCode\managed-settings.json`:                true,
		`C:\PROGRA~5\ClaudeCode\managed-settings.json`:                false,
		`C:\PROGRA~0\ClaudeCode\managed-settings.json`:                false,
		`C:\PROGRA~10\ClaudeCode\managed-settings.json`:               false,
		`C:\PROGRA~1\ClaudeCode\MANAGE~5.JSO`:                         false,
		`C:\PROGRA~1\ClaudeCode\MANAGE~0.JSO`:                         false,
		`C:\ProgramData\OpenAI\CODEX~1\requirements.toml`:             false,
		`C:\ProgramData\CURSOR~1\hooks.json`:                          false,
		`C:\ProgramData\GitHub\COPILO~1\policy.d\90-defenseclaw.json`: false,
	} {
		if got := WindowsManagedAgentSettingsPath(path); got != want {
			t.Errorf("WindowsManagedAgentSettingsPath(%q) = %t, want %t", path, got, want)
		}
	}
}

// rel-1-0-6:GAP-0734 round 11: where a path with a short-name shape exists,
// the operating system's long form decides, by exact name. The shape alone
// names the file only when the volume cannot say.
func TestWindowsManagedAgentSettingsPathLongFormDecides(t *testing.T) {
	saved := windowsLongPath
	t.Cleanup(func() { windowsLongPath = saved })
	volume := map[string]string{
		`C:/PROGRA~1/ClaudeCode/managed-settings.json`: `C:/Program Files/ClaudeCode/managed-settings.json`,
		`C:/PROGRA~1/ClaudeCode/notes.txt`:             `C:/Program Files/ClaudeCode/notes.txt`,
		`C:/PROGRA~1/ClaudeCode/MANAGE~1.JSO`:          `C:/Program Files/ClaudeCode/MANAGE~1.JSO`,
		`C:/PROGRA~1/CLAUDE~1/managed-settings.json`:   `C:/Programs Extra/Other/managed-settings.json`,
	}
	windowsLongPath = func(drive string) (string, bool) {
		long, ok := volume[drive]
		return long, ok
	}
	for path, want := range map[string]bool{
		// The long form is the protected file.
		`C:\PROGRA~1\ClaudeCode\managed-settings.json`: true,
		// The shape names a protected file, the volume says another file.
		`C:\PROGRA~1\CLAUDE~1\managed-settings.json`: false,
		// A real file whose literal name is short-name shaped: not an alias.
		`C:\PROGRA~1\ClaudeCode\MANAGE~1.JSO`: false,
		`C:\PROGRA~1\ClaudeCode\notes.txt`:    false,
		// Not on the volume: the shape decides.
		`C:\PROGRA~1\ClaudeCode\MANAGE~1.D\x.json`: true,
	} {
		if got := WindowsManagedAgentSettingsPath(path); got != want {
			t.Errorf("WindowsManagedAgentSettingsPath(%q) = %t, want %t", path, got, want)
		}
	}
}

// rel-1-0-6:GAP-0734 review 11 M1: a UNC server is this machine only by a
// whole name of it. The same first label in another DNS domain is another
// machine.
func TestWindowsLocalHostIsAWholeName(t *testing.T) {
	saved := localHostNames
	t.Cleanup(func() { localHostNames = saved })
	localHostNames = func() []string { return []string{"box.corp.example.com", "box"} }
	for host, want := range map[string]bool{
		"box":                     true,
		"BOX":                     true,
		"box.":                    true,
		"box.corp.example.com":    true,
		"BOX.Corp.Example.Com.":   true,
		"localhost":               true,
		"127.0.0.1":               true,
		"[::1]":                   true,
		"box.other.example.com":   false,
		"box.corp.example.com.xy": false,
		"box.corp":                false,
		"boxx":                    false,
		"xbox":                    false,
		"corp.example.com":        false,
		"":                        false,
		"10.0.0.5":                false,
	} {
		if got := windowsLocalHost(host); got != want {
			t.Errorf("windowsLocalHost(%q) = %t, want %t", host, got, want)
		}
	}
	if drive, ok := WindowsLocalDrivePath(`\\box.corp.example.com\C$\dir`); !ok || drive != "C:/dir" {
		t.Errorf("own fully qualified name = %q, %t, want C:/dir", drive, ok)
	}
	if _, ok := WindowsLocalDrivePath(`\\box.other.example.com\C$\dir`); ok {
		t.Error("the same short name in another domain is another machine")
	}
}
