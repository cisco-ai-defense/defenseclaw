// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"strings"
)

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
// as that file system is case-insensitive, and /etc is read as its
// canonical /private/etc there (the path the Codex connector reads).
func ManagedAgentSettingsPath(value string) bool {
	value = strings.TrimRight(value, "/")
	if rest, ok := strings.CutPrefix(value, "/private/etc/"); ok {
		value = "/etc/" + rest
	}
	for _, dir := range managedAgentSettingsDirs {
		same := func(a, b string) bool { return a == b }
		if strings.HasPrefix(dir, "/Library/") {
			same = strings.EqualFold
		}
		if len(value) >= len(dir) && same(value[:len(dir)], dir) && (len(value) == len(dir) || value[len(dir)] == '/') {
			return true
		}
	}
	return false
}

// windowsManagedAgentSettingsDirs are the machine-policy directories on
// Windows that DefenseClaw publishes an agent's managed settings into, below
// the Program Files and ProgramData roots (internal/enterprisepolicy
// paths.go), lower case and slash separated, after the drive.
var windowsManagedAgentSettingsDirs = []string{
	"program files/claudecode",
	"programdata/openai/codex",
	"programdata/cursor",
	"programdata/github/copilot",
	"programdata/opencode",
}

// WindowsManagedAgentSettingsPath reports a Windows path (any drive, either
// separator, any case, with or without a \\?\ or \\.\ prefix) that is one
// of the managed agent settings directories, or below one
// (rel-1-0-6:GAP-0734 review 6).
func WindowsManagedAgentSettingsPath(value string) bool {
	slashed := strings.ReplaceAll(value, `\`, "/")
	for _, prefix := range []string{"//?/", "//./"} {
		slashed = strings.TrimPrefix(slashed, prefix)
	}
	if len(slashed) < 3 || !isASCIILetter(slashed[0]) || slashed[1] != ':' || slashed[2] != '/' {
		return false
	}
	clean := strings.ToLower(strings.TrimRight(path.Clean(slashed[2:]), "/"))
	clean = strings.TrimPrefix(clean, "/")
	for _, dir := range windowsManagedAgentSettingsDirs {
		if clean == dir || strings.HasPrefix(clean, dir+"/") {
			return true
		}
	}
	return false
}
