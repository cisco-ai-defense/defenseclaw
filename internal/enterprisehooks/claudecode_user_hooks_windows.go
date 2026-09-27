// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// windowsClaudeUserSettingsBackupName is the copy of a user's
// %USERPROFILE%\.claude\settings.json kept, beside it, from just before the
// managed installer removed per-user DefenseClaw registrations from it.
const windowsClaudeUserSettingsBackupName = "settings.json.defenseclaw-backup"

// windowsClaudeUserHookCleanup reports what one Claude Code settings cleanup
// changed.
type windowsClaudeUserHookCleanup struct {
	path    string
	backup  string
	removed []connector.ClaudeCodeUserHookRemoval
}

// removeWindowsClaudePerUserHookRegistrations removes the Claude Code hook
// registrations per-user DefenseClaw setup wrote to home's
// .claude\settings.json, for the per-user installation install. The managed
// Cursor hook reads that file and denies every tool call while the per-user
// PreToolUse registration remains. The caller acts as the user who owns home.
// A missing file, or one without DefenseClaw registrations, is left
// untouched. A settings.json that is a link, has other hard links, exceeds the
// size limit, is not one JSON object, or changes while it is being cleaned is
// left as it was and reported as an error. The rest of the file, including
// the env settings per-user setup wrote, stays as it was.
func removeWindowsClaudePerUserHookRegistrations(home string, install connector.ClaudeCodePerUserInstall) (windowsClaudeUserHookCleanup, error) {
	claudeDir := filepath.Join(home, ".claude")
	cleanup := windowsClaudeUserHookCleanup{
		path:   filepath.Join(claudeDir, "settings.json"),
		backup: filepath.Join(claudeDir, windowsClaudeUserSettingsBackupName),
	}
	var removed []connector.ClaudeCodeUserHookRemoval
	changed, err := rewriteWindowsPerUserHookFile(claudeDir, cleanup.path, cleanup.backup, func(original []byte) ([]byte, bool, error) {
		updated, found, err := connector.RemoveClaudeCodePerUserHookRegistrations(original, install)
		removed = found
		return updated, len(found) > 0, err
	})
	if err != nil || !changed {
		return cleanup, err
	}
	cleanup.removed = removed
	return cleanup, nil
}

func logWindowsClaudePerUserHookCleanup(home string, cleanup windowsClaudeUserHookCleanup, err error) {
	commands := make([]string, 0, len(cleanup.removed))
	for _, removal := range cleanup.removed {
		commands = append(commands, removal.Command)
	}
	logWindowsPerUserHookCleanup("Claude Code", filepath.Join(home, ".claude", "settings.json"), cleanup.backup, commands, err)
}
