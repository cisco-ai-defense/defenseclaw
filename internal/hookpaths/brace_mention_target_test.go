// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// TestBraceWordNamesItsExpandedTargets is rel-1-0-6:GAP-0233 and
// GAP-0255: the target scan read a brace word as its unexpanded text, so
// a brace touch onto the keys file, and a redirect whose target is a
// substitution that prints the keys path through a brace, named no file
// while the spelled-out forms blocked. A fixed-text brace word is now
// judged as the words bash makes of it; brace words that name project
// files, and reads, stay allowed.
func TestBraceWordNamesItsExpandedTargets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home: a native Windows temp home is read by the Windows grammars")
	}
	root := t.TempDir()
	home := filepath.Join(root, "alice")
	project := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(project, "ordinary")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../.ssh/authorized_keys", filepath.Join(project, "keylink")); err != nil {
		t.Fatal(err)
	}
	blocked := []string{
		// GAP-0233: brace touch, as the plain touch.
		"touch ../.ssh/authorized_keys",
		"touch ../.ssh/authorized_key{s,x}",
		"touch ~/.ssh/authorized_key{s,x}",
		"touch $HOME/.ssh/authorized_key{s,x}",
		"touch ../.ssh/authorized_key{r..t}",
		`touch "../.ssh/authorized_key"{s,x}`,
		"touch -a ../.ssh/authorized_key{s,x}",
		"touch keylink{,.x}",
		// GAP-0255: a substitution that prints the keys path.
		"echo x > $(echo ../.ssh/authorized_keys)",
		"echo x > $(echo ../.ssh/authorized_key{s..s})",
		`echo x > "$(echo ../.ssh/authorized_key{s..s})"`,
		"echo x > `echo ../.ssh/authorized_key{s..s}`",
		"echo x >> $(printf %s ../.ssh/authorized_key{s..s})",
		"echo x > $(echo ~/.ssh/authorized_key{s..s})",
		"f=$(echo ../.ssh/authorized_key{s..s}); echo x > $f",
		"chmod 600 ../.ssh/authorized_key{s,}",
	}
	allowed := []string{
		"touch ordinary/{a,b}",
		"touch $HOME/project/ordinary/{a,b}",
		"touch ordinary/x{1..300}",
		"touch ../.ssh/known_host{s,}",
		"mkdir -p ordinary/{a,b,c}/src",
		"cp README.md ordinary/{a,b}/",
		"echo {a,b} > ordinary/out.txt",
		"echo x > $(echo ordinary/a{1..1})",
		"echo x > $(mktemp)",
		`echo x > "$(git rev-parse --show-toplevel)/out.txt"`,
		`echo x > "$(pwd)/notes.txt"`,
		"echo x > $(echo ../.ssh/authorized_keys.bak)",
		"cat ../.ssh/authorized_key{s,}",
		"ls ../.ssh/{a,b}",
	}
	for _, command := range blocked {
		if got := ActionCommandDecision(command, project, home); got != "protected-target" {
			t.Errorf("%q = %q, want protected-target", command, got)
		}
	}
	for _, command := range allowed {
		if got := ActionCommandDecision(command, project, home); got != "" {
			t.Errorf("%q = %q, want allow", command, got)
		}
	}
}

// A brace word whose ranges alone make more words than the scan reads is
// not expanded, and a word with no brace, or a dynamic one, has no fields.
func TestActionMentionBraceFieldsBounds(t *testing.T) {
	const home = "/home/alice"
	for _, row := range []struct {
		word string
		want int
	}{
		{"a{1..256}", 256},
		{"a{1..257}", 0},
		{"plain", 0},
		{"$X{a,b}", 0},
		{"{,a}", 1},
		{"~/x{a,b}", 2},
	} {
		file, ok := parseShell("true " + row.word)
		if !ok {
			t.Fatalf("parse %q", row.word)
		}
		call := file.Stmts[0].Cmd.(*syntax.CallExpr)
		if got := len(actionMentionBraceFields(call.Args[1], home)); got != row.want {
			t.Errorf("%q: %d fields, want %d", row.word, got, row.want)
		}
	}
}
