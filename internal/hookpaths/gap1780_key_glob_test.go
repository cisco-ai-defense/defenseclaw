// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// GAP-1780 / review round 2 R2-2: the key-read glob proof (GAP-0974) was a
// lexical match of the pattern text against ~/.ssh/id_*, with * selecting a
// leading dot. A pattern now selects a key only the way the shell expands
// it: component by component, without a leading dot unless dotglob is set,
// expanded on this host with each match resolved through links, with MSYS
// drive spellings mapped and case folded on darwin.
func TestActionPrivateKeyGlobFollowsTheShell(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "h")
	project := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project, filepath.Join(home, "docs")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{".ssh/id_ed25519", ".ssh/id_ed25519.pub", "docs/a.md", "proj/notes.txt"} {
		if err := os.WriteFile(filepath.Join(home, file), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, command, cwd string
		want               bool
	}{
		{"PB1 head */* from the home", "head -n 5 */*", home, false},
		{"cat */id_* from the home", "cat */id_*", home, false},
		{"tail ~/*/*", "tail -n 3 ~/*/*", project, false},
		{"PC1 .ssh/* from the home", "head -n 5 .ssh/*", home, true},
		{"dotglob */id_*", "shopt -s dotglob; cat */id_*", home, true},
		{"literal key glob", "head -c 4096 ~/.ssh/id_*", project, true},
		{"for loop over the key glob", "for f in ~/.ssh/id_*; do cat \"$f\"; done", project, true},
		{"for loop over project files", "for f in *.txt; do cat \"$f\"; done", project, false},
		{"public keys", "cat ~/.ssh/id_*.pub", project, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := posixShellPrivateKeyRead(tc.command, tc.cwd, home); got != tc.want {
				t.Fatalf("posixShellPrivateKeyRead(%q) = %t, want %t", tc.command, got, tc.want)
			}
		})
	}
	// Aliases are expanded on this host and resolved.
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(project, "dirlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".ssh", "id_ed25519"), filepath.Join(project, "keyl")); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"head -c 4096 dirlink/id_*", "cat keyl*"} {
		if !posixShellPrivateKeyRead(command, project, home) {
			t.Errorf("posixShellPrivateKeyRead(%q) = false, want a key read through the alias", command)
		}
	}
	if runtime.GOOS == "darwin" && !posixShellPrivateKeyRead("cat ~/.SSH/id_*", project, home) {
		t.Error("darwin: a case variant of the key glob reads the key")
	}
	if posixShellPrivateKeyRead("cat note*", project, home) {
		t.Error("a project glob is not a key read")
	}
	// Windows home: MSYS drive spellings and comments.
	const winHome, winCWD = `C:\Users\u`, `C:\Users\u\proj`
	for _, command := range []string{
		"head -c 4096 /c/Users/u/.ssh/id_*",
		"head -c 4096 /cygdrive/c/Users/u/.ssh/id_*",
		"head -c 4096 ~/.ssh/id_* # it's",
	} {
		if !posixShellPrivateKeyRead(command, winCWD, winHome) {
			t.Errorf("posixShellPrivateKeyRead(%q) = false on a Windows home", command)
		}
	}
}
