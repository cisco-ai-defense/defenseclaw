// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import "testing"

// GAP-2148: Setup's POSIX hooks-dir claim and the doctor's read of it treated
// a command that leaves the hooks dir through .. as DefenseClaw's. The
// Windows half was fixed by GAP-2116; the POSIX legs now resolve . and ..
// the same way.
func TestGAP2148POSIXHooksDirClaimResolvesDotDot(t *testing.T) {
	for _, dir := range []string{"/home/u/.defenseclaw/hooks", "/home/dc user/.defenseclaw/hooks"} {
		current := dir + "/claude-code-hook.sh"
		for _, row := range []struct {
			command string
			owned   bool
		}{
			{dir + "/claude-code-hook.sh", true},
			{dir + "/./claude-code-hook.sh --event PreToolUse", true},
			{dir + "/sub/../claude-code-hook.sh", true},
			{dir + "/../../bin/x", false},
			{dir + "/../../bin/x --event PreToolUse", false},
			{dir + "/../hooks-other/claude-code-hook.sh", false},
			{dir + "/sub/../../x", false},
		} {
			hook := map[string]interface{}{"type": "command", "command": row.command}
			if got := isOwnedHookHandler(hook, dir); got != row.owned {
				t.Errorf("Setup claim of %q in %q = %v, want %v", row.command, dir, got, row.owned)
			}
			word, first, ok := posixHookCommandSplit(row.command)
			if dir != "/home/u/.defenseclaw/hooks" || !ok {
				continue // the doctor splits an unquoted word at the blank
			}
			if first == "" {
				first = " --event PreToolUse"
			}
			if got := editedHookEntryClaimed("claudecode", row.command, current, word, first, "", false, false); got != row.owned {
				t.Errorf("doctor claim of %q = %v, want %v", row.command, got, row.owned)
			}
		}
	}
}
