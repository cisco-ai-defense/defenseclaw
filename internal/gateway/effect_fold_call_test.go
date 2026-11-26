// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestEffectFindingFoldsIntoAReadingBesideTheDispatch: the effect join runs
// inside the rule dispatch, and the agent hook config guard adds
// tamper.agent_hook_config_write only after it, so a plain write of the
// Claude Code settings carried effect.protected_target_restricted beside the
// 1.0.10 rule in default, permissive and managed (a rule id 1.0.10 never
// had, and a call the same write through a link did not match:
// rel-1-0-10:GAP-1243, GAP-1308). The effect finding folds into the rule
// naming its set on the call's final list (DET111 ruling A): in every tier
// the plain write names exactly tamper.agent_hook_config_write and keeps
// its action.
func TestEffectFindingFoldsIntoAReadingBesideTheDispatch(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	home, app := gap1243Layout(t)
	t.Setenv("HOME", home)
	settings := filepath.Join(home, ".claude", "settings.json")
	wantAction := map[string]string{
		"default": "alert", "permissive": "alert", "managed": "alert",
		"strict": "block", "managed-strict": "block",
	}
	for _, p := range gap0437Packs {
		hook := gap0437Server(t, p, "claudecode", "action")
		for i, command := range []string{
			"echo x > " + settings,
			"cp /tmp/x " + settings,
		} {
			out := gap0437Hook(t, hook, app, fmt.Sprintf("effold-%s-%d", p.name, i), command)
			var ids []string
			list, _ := out["rule_ids"].([]any)
			for _, id := range list {
				if s, ok := id.(string); ok {
					ids = append(ids, s)
				}
			}
			slices.Sort(ids)
			ids = slices.Compact(ids)
			if out["action"] != wantAction[p.name] || !slices.Equal(ids, []string{agentHookConfigWriteRuleID}) {
				t.Errorf("%s %q: action %v rules %v, want %s [%s]",
					p.name, command, out["action"], ids, wantAction[p.name], agentHookConfigWriteRuleID)
			}
		}
	}
}
