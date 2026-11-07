// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// rel-1-0-6:GAP-0734: the managed agent settings directories are matched as
// a directory or below it, never as a name that only starts like one.
func TestManagedAgentSettingsPath(t *testing.T) {
	for path, want := range map[string]bool{
		"/etc/claude-code":                                true,
		"/etc/claude-code/managed-settings.json":          true,
		"/etc/claude-code/managed-settings.d/50-dc.json":  true,
		"/etc/codex/requirements.toml":                    true,
		"/etc/github-copilot/policy.d/50-dc.json":         true,
		"/Library/Application Support/ClaudeCode/x.json":  true,
		"/library/application support/claudecode/x.json":  true,
		"/private/etc/codex/requirements.toml":            true,
		"/private/etc/codex-extra/requirements.toml":      false,
		"/private/var/etc/codex/requirements.toml":        false,
		"/etc/claude-code-notes.txt":                      false,
		"/etc/codex-extra/requirements.toml":              false,
		"/etc/CODEX/requirements.toml":                    false,
		"/home/u/etc/codex/requirements.toml":             false,
		"/Library/Application Support/ClaudeCodeX/x.json": false,
		"/Library/Application Support/Other/x.json":       false,
		"etc/codex/requirements.toml":                     false,
		"":                                                false,
	} {
		if got := ManagedAgentSettingsPath(path); got != want {
			t.Errorf("ManagedAgentSettingsPath(%q) = %t, want %t", path, got, want)
		}
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
		`C:\PROGRA~1\ClaudeCode\managed-settings.json`:                            true,
		`C:\PROGRA~1\CLAUDE~1\managed-settings.json`:                              true,
		`C:\PROGRA~3\OpenAI\Codex\requirements.toml`:                              true,
		`C:\PROGRA~1\Other\managed-settings.json`:                                 false,
		`\\otherhost\C$\Program Files\ClaudeCode\managed-settings.json`:           false,
		`\\localhost\C$\Program Files\Other\managed-settings.json`:                false,
		`C:\Program Files\ClaudeCodeX\managed-settings.json`:                      false,
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
