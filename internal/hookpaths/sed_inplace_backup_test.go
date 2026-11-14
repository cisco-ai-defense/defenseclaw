// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestActionDecisionSedInPlaceBackup: sed -i writes two files when it is
// given a backup suffix, and the backup name is a write like any other
// (rel-1-0-10:GAP-0414; cases HLR3-SFX-a, -b, -c and the control from the
// s7-hlrev3 review). The same command line is read as GNU sed and as BSD
// sed reads it, because the hook cannot know which sed runs. Placeholders:
// {keys} the protected directory, {home}, {proj} the working directory.
func TestActionDecisionSedInPlaceBackup(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	proj := filepath.Join(home, "project")
	keys := filepath.Join(home, ".ssh")
	for _, dir := range []string{proj, keys, filepath.Join(proj, "bak")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{filepath.Join(keys, "authorized_keys"), filepath.Join(keys, "known_hosts"), filepath.Join(proj, "f")} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		id, command string
		block       bool
	}{
		// The three review cases and their control (GNU sed names).
		{"HLR3-SFX-ctl", "sed -i s/x/y/ authorized_keys", false},
		{"HLR3-SFX-a", "sed -i{keys}/* s/x/y/ authorized_keys", true},
		{"HLR3-SFX-b", "sed --in-place={keys}/* s/x/y/ authorized_keys", true},
		{"HLR3-SFX-c", "sed -i../.ssh/* s/x/y/ authorized_keys", true},
		// Abbreviated and combined options, quoted suffixes, other spellings of sed.
		{"SFX-abbrev-in", "sed --in={keys}/* s/x/y/ authorized_keys", true},
		{"SFX-abbrev-i", "sed --i={keys}/* s/x/y/ authorized_keys", true},
		{"SFX-combined-ni", "sed -ni{keys}/* s/x/y/ authorized_keys", true},
		{"SFX-combined-Ei", "sed -Ei../.ssh/* s/x/y/ authorized_keys", true},
		{"SFX-after-e", "sed -e s/x/y/ -i../.ssh/* authorized_keys", true},
		{"SFX-dq", `sed -i"{keys}/*" s/x/y/ authorized_keys`, true},
		{"SFX-sq", `sed -i'{keys}/*' s/x/y/ authorized_keys`, true},
		{"SFX-escaped-star", `sed -i{keys}/\* s/x/y/ authorized_keys`, true},
		{"SFX-home-var", `sed -i"$HOME/.ssh/*" s/x/y/ authorized_keys`, true},
		{"SFX-gsed", "gsed -i{keys}/* s/x/y/ authorized_keys", true},
		{"SFX-path-sed", "/usr/bin/sed -i{keys}/* s/x/y/ authorized_keys", true},
		{"SFX-star-prefix", "sed -i{keys}/authorized_* s/x/y/ keys", true},
		// A suffix with no "*" completes the protected name (GNU appends it, BSD too).
		{"SFX-plain-suffix", "sed -ikeys s/x/y/ {keys}/authorized_", true},
		{"SFX-bsd-next-word", "sed -i keys s/x/y/ {keys}/authorized_", true},
		{"SFX-bsd-e", "sed -i -e s/x/y/ {keys}/authorized_keys", true},
		// Wrappers, chains and nested shells.
		{"SFX-env", "env sed -i{keys}/* s/x/y/ authorized_keys", true},
		{"SFX-command", "command sed -i{keys}/* s/x/y/ authorized_keys", true},
		{"SFX-nice", "nice -n 5 sed -i{keys}/* s/x/y/ authorized_keys", true},
		{"SFX-chain", "true && sed -i{keys}/* s/x/y/ authorized_keys", true},
		{"SFX-subshell", "(sed -i{keys}/* s/x/y/ authorized_keys)", true},
		{"SFX-bash-c", `bash -c 'sed -i{keys}/* s/x/y/ authorized_keys'`, true},
		{"SFX-sh-c-nested", `sh -c "bash -c 'sed -i{keys}/* s/x/y/ authorized_keys'"`, true},
		{"SFX-cd", "cd {keys} && sed -ikeys s/x/y/ authorized_", true},
		// A cd in a subshell is read as if it held (the read errs toward blocking).
		{"SFX-cd-subshell", "(cd {keys}); sed -ikeys s/x/y/ authorized_", true},
		{"SFX-pipe", "echo x | sed -i{keys}/* s/x/y/ authorized_keys", true},
		// Ordinary project files give the same verdict as before.
		{"SFX-ord-i", "sed -i s/x/y/ f", false},
		{"SFX-ord-n", "sed -i -n s/x/y/ f", false},
		{"SFX-ord-bak", "sed -i.bak s/x/y/ f", false},
		{"SFX-ord-bsd-empty", "sed -i '' s/x/y/ f", false},
		{"SFX-ord-bsd-ext", "sed -i .bak s/x/y/ f", false},
		{"SFX-ord-bsd-star", "sed -i '*' s/x/y/ f", false},
		{"SFX-ord-long", "sed --in-place=.bak s/x/y/ f", false},
		{"SFX-ord-star", "sed -ibak/* s/x/y/ f", false},
		{"SFX-ord-star-up", "sed -i../* s/x/y/ f", false},
		{"SFX-ord-other-file", "sed -i.bak s/x/y/ {keys}/known_hosts", false},
		{"SFX-ord-tilde-literal", `sed -i~/.ssh/* s/x/y/ f`, false},
		{"SFX-ord-script-text", `sed -i.bak 's/authorized_keys/y/' f`, false},
		{"SFX-ord-no-inplace", "sed s/x/y/ {keys}/known_hosts", false},
	} {
		command := strings.NewReplacer("{keys}", keys, "{home}", home, "{proj}", proj).Replace(tc.command)
		got := ActionCommandDecision(command, proj, home)
		if (got != "") != tc.block {
			t.Errorf("%s: decision = %q, want block=%v", tc.id, got, tc.block)
		}
	}
}
