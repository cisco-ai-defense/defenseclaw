// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// managedAgentSettingsDirs are the vendor machine-policy directories on
// Linux and macOS that DefenseClaw publishes an agent's managed settings
// into (Claude Code managed-settings.json and managed-settings.d, Codex
// requirements.toml, the Cursor, Copilot and OpenCode managed policy
// files). The list is the one internal/enterpriseunix writes to; the
// operating system refuses an agent that is not root, so the hook names the
// attempt before the refusal.
var managedAgentSettingsDirs = []string{
	"/etc/claude-code",
	"/Library/Application Support/ClaudeCode",
	"/etc/codex",
	"/etc/cursor",
	"/Library/Application Support/Cursor",
	"/etc/github-copilot",
	"/etc/opencode",
	"/Library/Application Support/opencode",
}

// ManagedAgentSettingsPath reports a clean absolute POSIX path that is one
// of the managed agent settings directories, or below one
// (rel-1-0-6:GAP-0734). The macOS directory names are matched in any case,
// as that file system is case-insensitive.
func ManagedAgentSettingsPath(path string) bool {
	path = strings.TrimRight(path, "/")
	for _, dir := range managedAgentSettingsDirs {
		same := func(a, b string) bool { return a == b }
		if strings.HasPrefix(dir, "/Library/") {
			same = strings.EqualFold
		}
		if len(path) >= len(dir) && same(path[:len(dir)], dir) && (len(path) == len(dir) || path[len(dir)] == '/') {
			return true
		}
	}
	return false
}
