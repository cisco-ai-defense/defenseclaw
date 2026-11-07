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
