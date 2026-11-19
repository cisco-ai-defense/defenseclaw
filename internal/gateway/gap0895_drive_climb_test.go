// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// TestD4RevDrivePrefixClimb (rel-1-0-10:GAP-0895): on a POSIX working folder a
// structured tool path that starts with a drive or UNC prefix and climbs with
// .. is a POSIX relative path that resolves into the home. The hook route
// keeps rel's POSIX reading, so a Write to the DefenseClaw state or a shell
// profile is judged as rel judged it (rel 16f68a06f6) in every tier, never
// the clean allow a Windows reading of the same value gave.
func TestD4RevDrivePrefixClimb(t *testing.T) {
	env := boundedLaneEnv(t)
	if err := os.MkdirAll(filepath.Join(env.home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	up := strings.Repeat("../", strings.Count(env.cwd, "/")+2)
	rel := strings.TrimPrefix(env.home, "/")
	// rel's Write verdict per tier: default, permissive, strict, managed,
	// managed strict.
	type want struct {
		rule    string
		actions [5]bounded.Action
	}
	allBlock := [5]bounded.Action{bounded.Block, bounded.Block, bounded.Block, bounded.Block, bounded.Block}
	// A proven DefenseClaw state write is a HIGH alert outside strict and
	// managed strict (GAP-0747 owner tiering 2026-11-15T15:20Z).
	stateWrite := [5]bounded.Action{bounded.Alert, bounded.Alert, bounded.Block, bounded.Alert, bounded.Block}
	cases := []struct {
		name, value string
		want        want
	}{
		{"drive-fwd-climb-state", "C:/" + up + rel + "/.defenseclaw/config.yaml",
			want{"tamper.detector_state_write", stateWrite}},
		{"drive-fwd-climb-rc", "C:/" + up + rel + "/.bashrc",
			want{"persistence.shell_profile_write", [5]bounded.Action{bounded.Alert, bounded.Allow, bounded.Block, bounded.Alert, bounded.Block}}},
		{"drive-fwd-climb-key", "C:/" + up + rel + "/.ssh/authorized_keys",
			want{"persistence.ssh_authorized_keys_command", allBlock}},
		{"unc-climb-key", `\\x/` + up + rel + "/.ssh/authorized_keys",
			want{"persistence.ssh_authorized_keys_command", allBlock}},
		{"control-abs-key", env.home + "/.ssh/authorized_keys",
			want{"persistence.ssh_authorized_keys_command", allBlock}},
	}
	for i, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		for _, tc := range cases {
			action, findings := boundedDecideClaudeCode(t, api, env, boundedLaneCall{
				tool: "Write", input: map[string]any{"file_path": tc.value, "content": "x"},
			})
			if got := boundedParse(action); got < tc.want.actions[i] {
				t.Errorf("%s %s: Write %s, want at least rel's %s", tier.name, tc.name, got, tc.want.actions[i])
			}
			if !slices.ContainsFunc(findings, func(f string) bool { return strings.HasPrefix(f, tc.want.rule+":") }) {
				t.Errorf("%s %s: Write findings %v lack rel's %s", tier.name, tc.name, gap0895RuleIDs(findings), tc.want.rule)
			}
		}
	}
	for _, tc := range cases[:4] {
		args := mustJSON(t, map[string]any{"file_path": tc.value})
		facts := actionfacts.Analyze(actionfacts.Input{Tool: "Write", Args: args, CWD: env.cwd, ActiveHome: env.home})
		if len(facts.Paths) != 1 || facts.Paths[0].Flavor != actionfacts.PathFlavorPOSIX ||
			!strings.HasPrefix(facts.Paths[0].Resolved, env.home+"/") {
			t.Errorf("%s: facts %+v, want one POSIX path below the home", tc.name, facts.Paths)
		}
	}
}

func gap0895RuleIDs(findings []string) []string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		id, _, _ := strings.Cut(f, ":")
		ids = append(ids, id)
	}
	return ids
}
