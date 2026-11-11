// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// TestAgentHookConfigRuleLeavesTheStateTree pins that the agent hook config
// rules cover the agent's registration files, the bridge plugins and the
// installed hook executables, and not the DefenseClaw state tree: a mode change of
// ~/.defenseclaw or a find over its hooks folder carries neither rule,
// while a removal of a registered hook file still does.
func TestAgentHookConfigRuleLeavesTheStateTree(t *testing.T) {
	h := newGAP0048Home(t)
	yes, no := true, false
	rows := []struct {
		name, command string
		rule          bool
		// managed also runs the row under a managed install; the rest run per-user only.
		ruleManaged *bool
	}{
		{"state tree mode tightened", `chmod -R go-rwx ~/.defenseclaw`, false, &no},
		{"find over the hooks folder with a word named like an action", `find ~/.defenseclaw/hooks -type f -exec grep -l -delete {} +`, false, nil},
		{"find from a scratch root with a removal of its own operand", `find /tmp -maxdepth 0 -exec rm -rf '~/.defenseclaw/hooks' \;`, false, nil},
		{"hook executable removed", `rm ~/.local/bin/defenseclaw-hook-user`, true, &yes},
		{"agent settings removed", `rm ~/.claude/settings.json`, true, nil},
	}
	for _, r := range rows {
		for _, managed := range []bool{false, true} {
			if managed && r.ruleManaged == nil {
				continue
			}
			t.Run(r.name, func(t *testing.T) {
				got := rv3Judge(t, "claudecode", "default", h.project, managed, "Bash", map[string]any{"command": r.command})
				has := strings.Contains(got, agentHookConfigDisableRuleID) || strings.Contains(got, agentHookConfigWriteRuleID)
				// A managed install keeps its own file policy: only the
				// installed hook executables stay under the rule there.
				want := r.rule
				if managed {
					want = *r.ruleManaged
				}
				if has != want {
					t.Errorf("%s (managed=%t): hook config rule present=%t, want %t: %s", r.command, managed, has, want, strings.TrimSpace(got))
				}
			})
		}
	}
}
