// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestDET111SweepT17BenignShapesKeepTheirLaneOffCellFiveTiers (DET111 sweep
// T17; GAP-1825, GAP-1826): synthetic calls of the shapes the large-trace
// sweep raised on benign rows, judged on the Claude Code and Codex hook
// routes in the five tiers, get the verdict the lane-off (1.0.10) readers
// give them:
//   - a Known read of one's own credential file in a spelling the 1.0.10
//     credential rules do not name (grep, install of a key, stat): the
//     effects reading is a shadow record (decide.RowEffectRead);
//   - a Known link placed at one's own authorized_keys (the dotfiles shape):
//     a shadow record (decide.RowEffectLink; every plain spelling of it is
//     blocked by the 1.0.10 reader, so the join test carries its fail-before).
//
// The control, an append to authorized_keys, keeps a non-allow verdict.
func TestDET111SweepT17BenignShapesKeepTheirLaneOffCellFiveTiers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home spellings")
	}
	home := t.TempDir()
	for _, f := range []string{".ssh/id_ed25519", ".ssh/authorized_keys", ".aws/credentials", ".docker/config.json",
		".defenseclaw/config.yaml", "dot/authorized_keys", "proj/notes.txt"} {
		p := filepath.Join(home, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	cwd := filepath.Join(home, "proj")
	benign := []string{
		`grep -c region ${PWD%/proj}/.aws/credentials`,
		`install -m 600 ${PWD%/proj}/.ssh/id_ed25519 ${PWD%/proj}/.ssh/id_ed25519.bak`,
		`stat ${PWD%/proj}/.docker/config.json`,
	}
	controls := []string{
		`echo 'ssh-ed25519 AAAAC3x k' >> ${PWD%/proj}/.ssh/authorized_keys`,
		`ln -sf ${PWD%/proj}/dot/authorized_keys ${PWD%/proj}/.ssh/authorized_keys`,
	}
	for _, tier := range boundedTestTiers {
		for _, route := range r3PosixRoutesForReadRows() {
			api := gap0589TierAPI(t, route.connector, tier.posture, tier.managed, tier.tier)
			for _, command := range benign {
				useEffectsRulesMode(t, "off")
				off, _ := route.decide(t, api, cwd, command)
				useDefaultEffectsLane(t)
				on, sev := route.decide(t, api, cwd, command)
				if on != off {
					t.Errorf("%s %s %q: %s/%s with the effects lane, %s with it off (a benign raise)", tier.name, route.connector, command, on, sev, off)
				}
			}
			useDefaultEffectsLane(t)
			for _, command := range controls {
				if on, _ := route.decide(t, api, cwd, command); on == "allow" {
					t.Errorf("%s %s %q: allow, want a non-allow verdict (control)", tier.name, route.connector, command)
				}
			}
		}
	}
}
