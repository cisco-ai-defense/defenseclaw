// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-1155 (split from GAP-0623, FIX-0623L): in a folder outside the home
// whose notes is a link to the SSH key and whose sub/notes is a plain file,
// cd sub && cat notes was a key read. A call that runs only after a
// relative cd succeeded reads in the folder that cd entered, which is the
// earlier candidates joined with the operand, never the start folder. A
// failed or undone change, a cd that CDPATH or cdable_vars may send
// elsewhere (named anywhere in the command or set through a name the hook
// cannot see) and a nested change keep every candidate.
func TestGAP1155RelativeCdReadsOnlyInTheNewFolder(t *testing.T) {
	home := t.TempDir()
	work := t.TempDir()
	w3 := filepath.Join(work, "w3")
	for _, dir := range []string{filepath.Join(home, "."+"ssh"), filepath.Join(w3, "sub", "deeper")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	key := filepath.Join(home, "."+"ssh", "id_"+"ed25519")
	if err := os.WriteFile(key, []byte("decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	testSymlink(t, key, filepath.Join(w3, "notes"))
	for _, name := range []string{filepath.Join(w3, "sub", "notes"), filepath.Join(w3, "sub", "deeper", "notes")} {
		if err := os.WriteFile(name, []byte("plain\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range []string{
		"cd sub && cat notes",
		"cd ./sub && cat notes",
		"pushd sub && cat notes",
		"sh -c \"cd sub && cat notes\"",
		"cd sub && cd deeper && cat notes",
		"cd sub/deeper && cd .. && cat notes",
		"cd sub && { cat notes; wc -l notes; }",
		"cd sub && grep -n x notes",
	} {
		if posixShellPrivateKeyRead(command, w3, home) {
			t.Errorf("posixShellPrivateKeyRead(%q) = true, want no key read (GAP-1155)", command)
		}
	}
	for _, command := range []string{
		"cat notes",
		"cd sub; cat notes",
		"cd sub || cat notes",
		"cd sub && cat ../notes",
		"cd sub && cd .. && cat notes",
		"cd sub && cd - && cat notes",
		"(cd sub) && cat notes",
		"cd sub && cd ~- && cat notes",
		"cd . && cat notes",
		"cd ../w3 && cat notes",
		// CDPATH or cdable_vars may send a bare relative cd back to the
		// start folder.
		"export CDPATH=" + work + "; cd w3 && cat notes",
		"CD\"\"PATH=" + work + "; cd w3 && cat notes",
		"shopt -s cdable_vars; v=" + w3 + "; cd v && cat notes",
		"n=X; export \"$n\"=" + work + "; cd w3 && cat notes",
		"printf -v \"$n\" %s " + work + "; cd w3 && cat notes",
		"read -r \"$n\" <<< " + work + "; cd w3 && cat notes",
		"declare -n r=\"$n\"; cd w3 && cat notes",
		"f() { :; }; cd sub && cat ../notes",
	} {
		if !posixShellPrivateKeyRead(command, w3, home) {
			t.Errorf("posixShellPrivateKeyRead(%q) = false, want a key read", command)
		}
	}
}
