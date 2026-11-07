// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// rel-1-0-6:GAP-0734: a write to a managed agent settings file DefenseClaw
// publishes (Claude Code managed-settings.json and managed-settings.d, Codex
// requirements.toml, the Cursor, Copilot and OpenCode machine policy) is a
// state mutation in every profile, per-user and managed, on both hooks. A
// read of the same files, and a write beside them, stay allowed.
func TestG235bManagedAgentSettingsAreSelfProtection(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	type row struct {
		command   string
		protected bool
	}
	var rows []row
	for _, file := range []string{
		"/etc/claude-code/managed-settings.json",
		"/etc/claude-code/managed-settings.d/50-defenseclaw.json",
		"/Library/Application Support/ClaudeCode/managed-settings.json",
		"/Library/Application Support/ClaudeCode/managed-settings.d/50-defenseclaw.json",
		"/etc/codex/requirements.toml",
		"/etc/cursor/hooks.json",
		"/etc/github-copilot/policy.d/50-defenseclaw.json",
		"/etc/opencode/opencode.json",
	} {
		q := "\x27" + file + "\x27"
		for _, form := range []string{
			"printf x > " + q,
			"echo x >> " + q,
			"sed -i d " + q,
			"cp " + project + "/a.txt " + q,
			"tee " + q + " < /dev/null",
			"rm " + q,
			"mv " + project + "/a.txt " + q,
			"truncate -s 0 " + q,
			"cd /tmp && printf x > " + q,
		} {
			rows = append(rows, row{form, true})
		}
		rows = append(rows,
			row{"cat " + q, false},
			row{"grep -n x " + q, false},
			row{"ls -l " + q, false},
			row{"cp " + q + " " + project + "/copy.txt", false},
			row{"sed -n 1p " + q, false},
		)
	}
	rows = append(rows,
		row{"printf x > /etc/claude-code-notes.txt", false},
		row{"printf x > /etc/codex-extra/requirements.toml", false},
		row{"printf x > " + project + "/etc/codex/requirements.toml", false},
		row{"sed -i d " + project + "/managed-settings.json", false},
	)
	for _, connector := range []string{"claudecode", "codex"} {
		for _, pack := range []string{"", "strict", "permissive"} {
			for _, managed := range []bool{false, true} {
				for _, row := range rows {
					got := postSelfProtectionPackCell(t, home, project, connector, pack, managed, false, row.command)
					block := strings.HasPrefix(got, `{"action":"block"`)
					switch {
					case row.protected && (!block || !strings.Contains(got, "tamper.detector_state_write")):
						t.Errorf("%s managed=%t pack=%s: %s = %.200s, want protected block", connector, managed, pack, row.command, got)
					case !row.protected && block && pack != "strict":
						t.Errorf("%s managed=%t pack=%s: %s = %.200s, want allow", connector, managed, pack, row.command, got)
					}
				}
			}
		}
	}
}
