// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The write operand walk reads a program's operands as writes only when the
// effects model gives the program a write of its own (rel-1-0-10:GAP-1296).
// Every command fact carries the execute operation (actionfacts adds it to
// each call): it says the program runs, never that its operands are written.
// When execute was counted as some other operation, no program was harmless,
// and the glob words of ls, cat and base64 were read as unproven
// authorized-keys writes (ls /*/*/.defenseclaw/x blocked; rel allows it).
// A dd operand that expands is its output when its static text is of= or
// shows no key: the effects model reads it as a write, so dd stays a writer
// and its operand walk still reads of=$X, of=$(...) and of=k[0-9] (the
// GAP-0379 attached dd rows). A dd whose expanding word is another key
// (if=$X) writes nothing.
func TestGAP1296OperandEffectsDecideTheWriteWalk(t *testing.T) {
	home := t.TempDir()
	for _, tc := range []struct {
		command, program string
		writer, harmless bool
	}{
		{"ls -d ./*", "ls", false, true},
		{"ls -d .*/*", "ls", false, true},
		{"cat ./*", "cat", false, true},
		{"base64 .*/*", "base64", false, true},
		{"cp a b", "cp", true, false},
		{"mv .*/* /tmp/staged", "mv", true, false},
		{"mktemp -d", "mktemp", false, false},
		{"dd if=a.txt of=k", "dd", true, false},
		{"dd if=a.txt of=$(echo k)", "dd", true, false},
		{"dd if=a.txt of=${X:-k}", "dd", true, false},
		{"dd if=a.txt of=$UNSET", "dd", true, false},
		{"dd if=a.txt of=k[0-9]", "dd", true, false},
		{`dd if=a.txt "$ARGS"`, "dd", true, false},
		{"dd if=$IN", "dd", false, true},
	} {
		writers, harmless := callPrograms(tc.command, home, home)
		if writers[tc.program] != tc.writer || harmless[tc.program] != tc.harmless {
			t.Errorf("%q: writer=%v harmless=%v, want writer=%v harmless=%v",
				tc.command, writers[tc.program], harmless[tc.program], tc.writer, tc.harmless)
		}
	}
}

// After a cd to a folder the call does not give, an operand spelled from the
// current folder ("$(pwd)"/) is read like its plain spelling: the plain
// reading places $(pwd) in the folder the command runs in. A word the one
// resolver cannot read has no resolver pattern, and since the resolver port
// such a word was not judged at all, so cat "$(pwd)"/.*/* was no key pattern
// where cat .*/* was (rel-1-0-10:GAP-1296; on rel/1.0.10 both are, the
// GAP-1023 cells TestUnresolvedFolderCurrentFolderSpellingIsThePlainOne*).
func TestGAP1296CurrentFolderSpellingKeepsThePlainReading(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell spellings")
	}
	home := filepath.Join(t.TempDir(), "home", "alice")
	project := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(project, ".git", "hooks"), filepath.Join(home, ".ssh"),
		filepath.Join(home, ".aws"), filepath.Join(home, ".defenseclaw", "hooks")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	cd := `cd -- "$(mktemp -d)" && `
	for _, verb := range []string{"ls -d ", "cat ", "base64 ", "rm -f "} {
		for _, operand := range []struct {
			text, want string
		}{{".*/*", "protected-target"}, {".[a-z]*/*", "protected-target"}, {".ssh/*", "same"}} {
			plain := ActionCommandDecisionInShell(cd+verb+operand.text, project, home, nil, true)
			for _, head := range []string{`"$(pwd)"/`, "$(pwd)/", `"$PWD"/`} {
				spelled := ActionCommandDecisionInShell(cd+verb+head+operand.text, project, home, nil, true)
				if operand.want != "same" && plain != operand.want || spelled != plain {
					t.Errorf("%s%s: plain %q, spelled %s%s %q, want both %q",
						verb, operand.text, plain, head, operand.text, spelled, operand.want)
				}
			}
		}
	}
}
