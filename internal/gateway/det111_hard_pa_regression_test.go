// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDET111HardPAStdinCopierAndTargetDirectoryVerdicts(t *testing.T) {
	env := boundedLaneEnv(t)
	for _, f := range []string{".ssh/authorized_keys", ".claude/settings.json", "project/settings.json", "project/a"} {
		path := filepath.Join(env.home, f)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rows := []struct {
		gap, name, command string
		strict, normal     string
	}{
		{"GAP-0506", "cp abbreviated target", "cp --target-dir=~/.claude settings.json", "block", "alert"},
		{"GAP-0506", "install abbreviated target", "install --targ=~/.claude settings.json", "block", "alert"},
		{"GAP-0506", "cp short cluster", "cp -at ~/.claude settings.json", "block", "alert"},
		{"GAP-0506", "cp benign", "cp -at dist/ a", "allow", "allow"},
		{"GAP-1551", "pax pass-through", "ls ~/.ssh/authorized_keys | pax -rw d", "block", "block"},
		{"GAP-1551", "xargs cp target", "ls ~/.ssh/authorized_keys | xargs cp -t d", "block", "block"},
		{"GAP-1551", "cpio control", "ls ~/.ssh/authorized_keys | cpio -pdl d", "block", "block"},
		{"GAP-1551", "pax benign", "pax -rw src dst", "allow", "allow"},
		{"GAP-1551", "xargs cp benign", "ls | xargs cp -t d", "allow", "allow"},
		{"GAP-1551", "pax extract is not a name copier", "ls ~/.ssh/authorized_keys | pax -r archive", "block", "alert"},
		{"GAP-1551", "xargs argument file ignores pipe", "ls ~/.ssh/authorized_keys | xargs -ra file cp -t d", "block", "alert"},
	}
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		useDefaultEffectsLane(t)
		for _, row := range rows {
			got, _ := boundedDecideClaudeCode(t, api, env, boundedShellCommand(row.command))
			want := row.normal
			if tier.posture == "strict" {
				want = row.strict
			}
			t.Logf("PA2\t%s\t%s/%s\tgot=%s\twant=%s", tier.name, row.gap, row.name, got, want)
			if got != want {
				t.Errorf("%s %s/%s: got %s, want %s", tier.name, row.gap, row.name, got, want)
			}
		}
	}
}
