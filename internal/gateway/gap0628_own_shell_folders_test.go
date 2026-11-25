// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"strings"
	"testing"
)

// TestGAP0628OwnShellFoldersOnlyFollowTheShellItself: after a command the
// split cannot read ($CMD), the copy-mode guest placement promotes a candidate
// folder only where the call's own shell may stand when the statement runs,
// at top level or on the path an && runs, with the folder it left where a cd
// may fail (substrate-1 GAP-0628). Each row checks the folders of its last
// statement. Promoting every candidate made (cd ~/.defenseclaw || cd /tmp);
// $CMD; echo m > config.yaml a block where the laptop allows, and a folder set
// for the whole call promoted a statement in a folder only a later cd reaches
// (substrate-1 GAP-0883, row later-cd). cd X || exit stands in X
// (substrate-1 GAP-0884, row or-exit).
func TestGAP0628OwnShellFoldersOnlyFollowTheShellItself(t *testing.T) {
	const home, cwd = "/home/u", "/home/u/p"
	// of names the statement a row checks when it is not the last one.
	of := map[string]string{"later-cd": "echo m > config.yaml", "and-left": "cat id_ed25519"}
	for _, row := range []struct {
		name, command string
		want          []string
	}{
		{"fan-candidate", "cd .cache\nbash <<< 'true'\n$CMD\ncd s0\ncd ../.ssh\necho k >> authorized_keys",
			[]string{cwd, cwd + "/.cache", cwd + "/.cache/s0", cwd + "/s0", cwd + "/.cache/.ssh", cwd + "/.ssh", home + "/.ssh"}},
		{"and-left", "$CMD\ncd ../.ssh && cat id_ed25519", []string{home + "/.ssh"}},
		{"no-unread", "cd .cache\necho m > config.yaml", nil},
		{"subshell-or", "(cd ~/.defenseclaw || cd /tmp)\n$CMD\necho m > config.yaml", []string{cwd}},
		{"top-or", "cd ~/.defenseclaw || cd /tmp\n$CMD\necho m > config.yaml", nil},
		{"uncalled-func", "f() { cd ~/.defenseclaw; }\n$CMD\necho m > config.yaml", []string{cwd}},
		{"called-func", "f() { cd .cache; }\nf\n$CMD\necho x", nil},
		{"cd-dash", "cd .cache\ncd -\n$CMD\necho x", nil},
		{"cd-dyn-dir", "cd .cache\ncd \"$D\"\n$CMD\necho x", nil},
		{"cdpath", "export CDPATH=/etc\ncd .cache\n$CMD\necho x", nil},
		{"background", "cd .cache &\n$CMD\necho x", []string{cwd}},
		{"heredoc-not-unread", "cd .cache\nbash <<'EOF'\ntouch f0\nEOF\necho x", nil},
		{"later-cd", "$CMD\necho m > config.yaml\ncd ~/.defenseclaw && ls", []string{cwd}},
		{"or-exit", "$CMD\ncd ../.ssh || exit\necho k >> authorized_keys", []string{home + "/.ssh"}},
		{"or-exit-1", "$CMD\ncd ../.ssh || exit 1\necho k >> authorized_keys", []string{home + "/.ssh"}},
	} {
		lines := strings.Split(row.command, "\n")
		last := lines[len(lines)-1]
		if statement, ok := of[row.name]; ok {
			last = statement
		}
		var got []string
		for reading := range guestOwnShellFolders(row.command, cwd, home) {
			if reading.text == last {
				got = append(got, reading.dir)
			}
		}
		slices.Sort(got)
		want := slices.Clone(row.want)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s: guestOwnShellFolders for %q = %q, want %q", row.name, last, got, want)
		}
	}
}
