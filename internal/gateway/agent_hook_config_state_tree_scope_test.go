// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// TestAgentHookConfigRuleLeavesTheStateTree pins that the agent hook config
// rules cover the agent's registration files, the bridge plugins and the
// installed hook executables, and not the DefenseClaw state tree: a mode or
// owner change of ~/.defenseclaw or its hooks folder carries neither rule,
// while a removal of a registered hook file still does.
func TestAgentHookConfigRuleLeavesTheStateTree(t *testing.T) {
	h := newGAP0048Home(t)
	rows := []struct {
		name, command string
		rule          bool
		ruleManaged   bool
	}{
		{"state tree mode tightened", `chmod -R go-rwx ~/.defenseclaw`, false, false},
		{"hooks folder mode", `chmod 700 ~/.defenseclaw/hooks`, false, false},
		{"hooks folder execute bit", `chmod u+x ~/.defenseclaw/hooks`, false, false},
		{"state tree owner", `chown -R nobody ~/.defenseclaw`, false, false},
		{"find over the hooks folder with a word named like an action", `find ~/.defenseclaw/hooks -type f -exec grep -l -delete {} +`, false, false},
		{"find from a scratch root with a removal of its own operand", `find /tmp -maxdepth 0 -exec rm -rf '~/.defenseclaw/hooks' \;`, false, false},
		{"hook executable removed", `rm ~/.local/bin/defenseclaw-hook-user`, true, true},
		{"agent settings removed", `rm ~/.claude/settings.json`, true, false},
	}
	for _, r := range rows {
		for _, managed := range []bool{false, true} {
			t.Run(r.name, func(t *testing.T) {
				got := rv3Judge(t, "claudecode", "default", h.project, managed, "Bash", map[string]any{"command": r.command})
				has := strings.Contains(got, agentHookConfigDisableRuleID) || strings.Contains(got, agentHookConfigWriteRuleID)
				// A managed install keeps its own file policy: only the
				// installed hook executables stay under the rule there.
				want := r.rule
				if managed {
					want = r.ruleManaged
				}
				if has != want {
					t.Errorf("%s (managed=%t): hook config rule present=%t, want %t: %s", r.command, managed, has, want, strings.TrimSpace(got))
				}
			})
		}
	}
}
