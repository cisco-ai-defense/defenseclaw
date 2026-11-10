// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// A typed apply_patch Delete File removes the final name: the client lists the
// entry it removes (the directory of the name followed, the final name kept),
// where an Add File of the same name lists the file the link reaches. A
// delete of a link removes the link, not its file.
func TestPatchDeleteListsTheEntryItRemoves(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home, project := filepath.Join(root, "home"), filepath.Join(root, "project")
	for _, dir := range []string{home, project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	secret := filepath.Join(home, ".netrc")
	if err := os.WriteFile(secret, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	directoryLink, finalLink := filepath.Join(project, "homelink"), filepath.Join(project, "finalnet")
	if err := os.Symlink(home, directoryLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, finalLink); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	patch := func(directive, file string) map[string]string {
		body := ""
		if directive == "Add File" {
			body = "+x\n"
		}
		return resolvedEvidence(t, "codex", project, "apply_patch", map[string]interface{}{
			"command": "*** Begin Patch\n*** " + directive + ": " + file + "\n" + body + "*** End Patch",
		})
	}
	below := filepath.Join(directoryLink, ".netrc")
	if got := patch("Delete File", below)[below]; got != secret {
		t.Errorf("Delete File below a directory link lists %q, want %q", got, secret)
	}
	if got := patch("Delete File", finalLink)[finalLink]; got != finalLink {
		t.Errorf("Delete File of a link lists %q, want the link %q itself", got, finalLink)
	}
	if got := patch("Add File", finalLink)[finalLink]; got != secret {
		t.Errorf("Add File through a link lists %q, want the file %q", got, secret)
	}
}
