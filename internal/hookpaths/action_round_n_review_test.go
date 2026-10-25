// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Round n review 1: a patch body is skipped unless the shell text may change
// which program apply_patch runs. A header that names PATH.md, a delimiter
// called PATH or text that reads $PATH changes nothing; an assignment, an
// export, a zsh path array, a sourced or evaluated file or an alias may.
func TestR104RoundNReviewPatchBodyPathMention(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX paths")
	}
	_, home, cwd := globFactsFixture(t, false)
	body := "+Append your key: cat key.pub >> ~/.ssh/authorized_keys\n"
	patch := func(opener, header, delimiter string) string {
		return opener + "apply_patch <<'" + delimiter + "'\n*** Begin Patch\n" + header + "\n" + body + "*** End Patch\n" + delimiter
	}
	for _, command := range []string{
		patch("", "*** Add File: PATH.md", "PATCH"),
		patch("", "*** Add File: docs/PATH-setup.md", "PATCH"),
		patch("", "*** Update File: docs/old.md\n*** Move to: docs/PATH.md", "PATCH"),
		patch("", "*** Add File: notes.md", "PATH"),
		patch("cat PATH.md >/dev/null && ", "*** Add File: notes.md", "PATCH"),
		patch("printf 'Set PATH in your shell\\n' > hint.txt && ", "*** Add File: notes.md", "PATCH"),
		patch(`echo "$PATH" >/dev/null && `, "*** Add File: notes.md", "PATCH"),
	} {
		if got := ActionCommandDecision(command, cwd, home); got != "" {
			t.Errorf("%q: ActionCommandDecision = %q, want allow", command, got)
		}
	}
	for _, opener := range []string{
		"PATH=.:$PATH ",
		"export PATH=\"$PWD:$PATH\"\n",
		"export 'PATH=.:/usr/bin'; ",
		"path=(. $path); ",
		"typeset -x PATH=.; ",
		". ./defs.sh && ",
		"source defs.sh; ",
		"eval \"$(cat defs)\"; ",
		"alias ap=sh; ",
		"hash -r; ",
	} {
		command := patch(opener, "*** Add File: PATH.md", "PATCH")
		if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
			t.Errorf("%q: ActionCommandDecision = %q, want protected-target", command, got)
		}
	}
	// A header that names the key blocks, PATH in its name or not.
	command := patch("", "*** Add File: "+filepath.Join(home, ".ssh", "authorized_keys"), "PATH")
	if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
		t.Errorf("%q: ActionCommandDecision = %q, want protected-target", command, got)
	}
}

// Round n review 2 (finding 3): the glob walk follows the shell's leading-dot rule. A
// * or ? does not select a project-local .private alias of the key
// directory; an explicit dot, a bracket, or a dotglob setting (in the
// command or a startup file) does.
func TestR104RoundNReviewGlobLeadingDot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fixture")
	}
	_, home, cwd := globFactsFixture(t, false)
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(cwd, ".private")); err != nil {
		t.Fatal(err)
	}
	allowed := []string{
		`git add */*`,
		`cp payload */authorized_keys`,
		`cp payload ?private/authorized_keys`,
		`rm -f */*.pub`,
		`(cd src && git add */*)`,
	}
	for _, command := range allowed {
		if got := ActionCommandDecision(command, cwd, home); got != "" {
			t.Errorf("%q: ActionCommandDecision = %q, want allow", command, got)
		}
		if got := ActionCommandDecisionWithGlobFacts(command, cwd, home, clientGlobFactsFor(t, command, cwd)); got != "" {
			t.Errorf("%q: with client facts = %q, want allow", command, got)
		}
	}
	for _, command := range []string{
		`git add .*/*`,
		`cp payload .p*/authorized_keys`,
		`cp payload [.]private/authorized_keys`,
		`shopt -s dotglob; git add */*`,
		`bash -c 'shopt -s dotglob; git add */*'`,
		`bash -O dotglob -c 'git add */*'`,
		`bash +O nullglob -O dotglob -c 'git add */*'`,
		`setopt GLOB_DOTS; cp payload */authorized_keys`,
		`GLOBIGNORE=x; git add */*`,
	} {
		if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
			t.Errorf("%q: ActionCommandDecision = %q, want protected-target", command, got)
		}
	}
	// A startup file that sets dotglob makes the user's shell match it.
	if err := os.WriteFile(filepath.Join(home, ".bashrc"), []byte("shopt -s dotglob\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ActionCommandDecision(`git add */*`, cwd, home); got != "protected-target" {
		t.Errorf("dotglob in .bashrc: ActionCommandDecision = %q, want protected-target", got)
	}
}
