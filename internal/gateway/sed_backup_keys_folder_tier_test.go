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

// TestSedStarBackupIntoKeysFolderBlocksInEveryTier: a "*" backup suffix whose
// folder part is the keys folder lets the operand name the entry sed or perl
// writes there, and the hook judges it as a write to the keys folder in all
// five tiers, in every spelling of the word (rel-1-0-10:GAP-0669, cert lane
// L68 on IB1: the brace spelling was allowed with no finding while the quoted
// one blocked). The edited file is an ordinary project file, as in the
// replay; a backup into an ordinary place and a star inside an entry name
// stay allowed. {keys} is the keys folder, {home} the home.
func TestSedStarBackupIntoKeysFolderBlocksInEveryTier(t *testing.T) {
	env := sedBackupTierFixture(t)
	work := filepath.Join(env.home, "l68work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "f.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env.cwd = work
	for _, tc := range []struct {
		id, command string
		block       bool
	}{
		// The L68 replay (codex and claude code on IB1, default pack).
		{"L68-brace-empty-first", "sed -i{,{keys}/*.bak} s/a/b/ ~/l68work/f.txt", true},
		{"L68-brace-relative-operand", "sed -i{,{keys}/*.bak} s/a/b/ f.txt", true},
		// The other brace and glob spellings of the same words.
		{"G0669-brace-orig-first", "sed -i{.orig,{keys}/*.bak} s/a/b/ f.txt", true},
		{"G0669-brace-long", "sed --in-place={,{keys}/*.bak} s/a/b/ f.txt", true},
		{"G0669-brace-cluster", "sed -ni{,{keys}/*.bak} s/a/b/ f.txt", true},
		{"G0669-brace-in-entry", "sed -i{keys}/{x,*.bak} s/a/b/ f.txt", true},
		{"G0669-brace-bare-star", "sed -i{,{keys}/*} s/a/b/ f.txt", true},
		{"G0669-brace-quoted-member", "sed -i{,'{keys}/*.bak'} s/a/b/ f.txt", true},
		{"G0669-brace-escaped-star", `sed -i{,{keys}/\*.bak} s/a/b/ f.txt`, true},
		{"G0669-brace-perl", "perl -pi{,{keys}/*.bak} -e 1 f.txt", true},
		{"G0669-glob-unquoted", "sed -i{keys}/*.bak s/a/b/ f.txt", true},
		{"G0669-glob-unquoted-bare", "sed -i{keys}/* s/a/b/ f.txt", true},
		{"G0669-glob-quoted-star", "sed -i{keys}/'*'.bak s/a/b/ f.txt", true},
		{"G0669-glob-whole-word-quoted", "sed '-i{keys}/*.bak' s/a/b/ f.txt", true},
		{"G0669-glob-perl-unquoted", "perl -pi{keys}/*.bak -e 1 f.txt", true},
		{"G0669-glob-relative-folder", "sed -i../.ssh/*.bak s/a/b/ f.txt", true},
		// The spellings rel already blocked keep their verdict.
		{"G0669-quoted", "sed -i'{keys}/*.bak' s/a/b/ f.txt", true},
		{"G0669-quoted-perl", "perl -pi'{keys}/*.bak' -e 1 f.txt", true},
		// Controls: the backup lands in an ordinary place or is named in full.
		{"G0669-C-plain-suffix", "sed -i.bak s/a/b/ f.txt", false},
		{"G0669-C-brace-plain", "sed -i{,.bak} s/a/b/ f.txt", false},
		{"G0669-C-brace-tmp", "sed -i{,/tmp/*.bak} s/a/b/ f.txt", false},
		{"G0669-C-brace-project", "sed -i{,bak/*} s/a/b/ f.txt", false},
		{"G0669-C-brace-home", "sed -i{,{home}/*.bak} s/a/b/ f.txt", false},
		{"G0669-C-brace-work", "sed -i{,{home}/l68work/*.bak} s/a/b/ f.txt", false},
		// bash expands a tilde only at the start of a word: the backup is in
		// a folder named "~" under the working folder.
		{"G0669-C-brace-tilde-mid-word", "sed -i{,~/.ssh/*.bak} s/a/b/ f.txt", false},
		// A star inside an entry name and a backup named in full keep the
		// rel verdict of the backup name (no protected file).
		{"G0669-C-star-in-entry", "sed -i'{keys}/x*' s/a/b/ f.txt", false},
		{"G0669-C-full-name", "sed -i{,{keys}/f.txt.bak} s/a/b/ f.txt", false},
	} {
		command := strings.NewReplacer("{keys}", filepath.Join(env.home, ".ssh"), "{home}", env.home).Replace(tc.command)
		for _, tier := range boundedTestTiers {
			api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
			action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(command))
			if blocked := action == "block"; blocked != tc.block {
				t.Errorf("%s in tier %s: action = %q (findings %q), want block=%v", tc.id, tier.name, action, findings, tc.block)
			}
		}
	}
}
