// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

func TestGAP0529POSIXCopyOptionVariableWindowsHome(t *testing.T) {
	home := "C:/Users/Alice"
	cwd := home + "/project"
	for _, row := range []struct {
		name, command string
		block         bool
	}{
		{"option variable", `t="-t $HOME/.ssh"; cp $t a.txt`, true},
		{"attached option variable", `t="--target-directory=$HOME/.ssh"; cp $t a.txt`, true},
		{"literal option", `cp -t "$HOME/.ssh" a.txt`, true},
		{"ordinary directory", `t="-t $HOME/build"; cp $t a.txt`, false},
		{"quoted option variable", `t="-t $HOME/.ssh"; cp "$t" a.txt`, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			got := actionPosixTargetMention(row.command, cwd, home, 0, false, nil)
			if got != row.block {
				t.Errorf("POSIX reading %t, want %t", got, row.block)
			}
		})
	}
}

func TestGAP0529POSIXCopyOptionVariableDefaultIFS(t *testing.T) {
	home := "C:/Users/Alice"
	cwd := home + "/project"
	for _, row := range []struct {
		name, separator string
		protected       bool
	}{
		{"space", " ", true},
		{"tab", "\t", true},
		{"newline", "\n", true},
		{"nonbreaking space", "\u00a0", false},
		{"em space", "\u2003", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			command := `t="-t` + row.separator + `$HOME/.ssh"; cp $t a.txt`
			mention := actionPosixTargetMention(command, cwd, home, 0, false, nil)
			decision := ActionCommandDecisionInShell(command, cwd, home, nil, true)
			if mention != row.protected || (decision == "protected-target") != row.protected {
				t.Errorf("mention=%t decision=%q, want protected=%t", mention, decision, row.protected)
			}
		})
	}
}

func TestGAP0529POSIXCopyDestinationVariableDefaultIFS(t *testing.T) {
	home := "C:/Users/Alice"
	cwd := home + "/project"
	for _, row := range []struct {
		name, separator string
		protected       bool
	}{
		{"leading space", " ", true},
		{"leading tab", "\t", true},
		{"nonbreaking space", "\u00a0", false},
		{"em space", "\u2003", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			command := `t="` + row.separator + `$HOME/.ssh"; cp a.txt $t`
			mention := actionPosixTargetMention(command, cwd, home, 0, false, nil)
			if mention != row.protected {
				t.Errorf("mention=%t, want protected=%t", mention, row.protected)
			}
		})
	}
}
