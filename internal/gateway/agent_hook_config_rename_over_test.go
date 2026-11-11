// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// TestAgentHookConfigRenameOverWithoutClientEvidence pins GAP-1073: a shell
// mv or rsync onto a registered Claude Code settings file is the shell write
// rule (alert in default, block in strict) when the gateway reads the call
// alone, without the hook client resolved-target header; moving a file into
// the settings folder under another name stays allowed.
func TestAgentHookConfigRenameOverWithoutClientEvidence(t *testing.T) {
	h := newGAP0048Home(t)
	rows := []struct {
		name, command, defaults, strict string
	}{
		{"mv over user settings", "mv notes.txt ~/.claude/settings.json", "alert", "block"},
		{"mv over local settings", "mv -f notes.txt .claude/settings.local.json", "alert", "block"},
		{"rsync over user settings", "rsync notes.txt ~/.claude/settings.json", "alert", "block"},
		{"mv into the settings folder", "mv notes.txt ~/.claude/", "allow", "allow"},
		{"mv -t into the settings folder", "mv -t ~/.claude notes.txt", "allow", "allow"},
	}
	for _, profile := range []string{"default", "strict"} {
		t.Run(profile, func(t *testing.T) {
			judge := newHookConfigJudgeWith(t, "claudecode", profile, false)
			for _, row := range rows {
				want := row.defaults
				if profile == "strict" {
					want = row.strict
				}
				got := judge(h.project, false, "Bash", map[string]any{"command": row.command})
				if action := hookConfigAction(got); action != want {
					t.Errorf("%s: action %q, want %q: %.500s", row.name, action, want, got)
				}
				if want != "allow" && !strings.Contains(got, agentHookConfigWriteRuleID) {
					t.Errorf("%s: want rule %s: %.500s", row.name, agentHookConfigWriteRuleID, got)
				}
			}
		})
	}
}
