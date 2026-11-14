// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sedBackupTierFixture is a POSIX home with a protected keys file and a
// project folder.
func sedBackupTierFixture(t *testing.T) boundedEnv {
	t.Helper()
	env := boundedLaneEnv(t)
	keys := filepath.Join(env.home, ".ssh")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "authorized_keys"), []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return env
}

// TestSedInPlaceBackupBlocksInEveryTier: the backup file of sed -i is a write
// (rel-1-0-10:GAP-0414, cases HLR3-SFX-a, -b, -c of the s7-hlrev3 review) and
// the hook blocks it into a protected file in all five tiers. The plain
// in-place edit is the control. {keys} is the protected folder.
func TestSedInPlaceBackupBlocksInEveryTier(t *testing.T) {
	env := sedBackupTierFixture(t)
	keys := filepath.Join(env.home, ".ssh")
	for _, tc := range []struct {
		id, command string
		block       bool
	}{
		{"HLR3-SFX-ctl", "sed -i s/x/y/ authorized_keys", false},
		{"HLR3-SFX-a", "sed -i{keys}/* s/x/y/ authorized_keys", true},
		{"HLR3-SFX-b", "sed --in-place={keys}/* s/x/y/ authorized_keys", true},
		{"HLR3-SFX-c", "sed -i../.ssh/* s/x/y/ authorized_keys", true},
		{"SFX-bsd-next-word", "sed -i keys s/x/y/ {keys}/authorized_", true},
		{"SFX-gnu-plain-suffix", "sed -ikeys s/x/y/ {keys}/authorized_", true},
		{"SFX-ord-bak", "sed -i.bak s/x/y/ f", false},
		{"SFX-ord-bsd-empty", "sed -i '' s/x/y/ f", false},
	} {
		command := strings.ReplaceAll(tc.command, "{keys}", keys)
		for _, tier := range boundedTestTiers {
			api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
			action, _ := boundedDecideClaudeCode(t, api, env, boundedShellCommand(command))
			if blocked := action == "block"; blocked != tc.block {
				t.Errorf("%s in tier %s: action = %q, want block=%v", tc.id, tier.name, action, tc.block)
			}
		}
	}
}
