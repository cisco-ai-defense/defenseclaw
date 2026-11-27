// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A link copied by rsync can occupy a child of a directory destination.
// It cannot replace the directory entry itself. An existing or command-made
// link at that entry is still read as a possible path into protected files.
func TestRsyncDirectoryDestinationLinkScope(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "work", "nested", "repo")
	source := "."
	destination := filepath.Join(home, "stage")
	if runtime.GOOS == "windows" {
		// The source tree holds a link, so the copy may materialize one in
		// the destination. Off Linux a missing source carries no link
		// (diskSourceMayLink: the ProtectHome reading of a missing home path
		// is Linux only), so the Linux fixture's missing working folder
		// proves nothing there.
		if err := os.MkdirAll(cwd, 0o700); err != nil {
			t.Fatal(err)
		}
		testSymlink(t, filepath.Join(home, "names"), filepath.Join(cwd, "link"))
	}
	// The command spells the paths with forward slashes, as Git Bash reads a
	// Windows path (a backslash in POSIX text is an escape).
	command := fmt.Sprintf("rsync -a --files-from=%s %s/ %s/", filepath.ToSlash(filepath.Join(home, "names")), source, filepath.ToSlash(destination))
	links := CommandLinks("Bash", command, cwd, home)
	if links.OpaqueTargetWithFacts(destination, false, nil) {
		t.Fatal("the destination directory entry was classified as a copied link")
	}
	if !links.OpaqueTargetWithFacts(filepath.Join(destination, "child"), false, nil) {
		t.Fatal("a child of the destination lost its uncertain link scope")
	}

	target := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	testSymlink(t, target, destination)
	linked := CommandLinks("Bash", command, cwd, home)
	if !linked.OpaqueTargetWithFacts(destination, false, nil) {
		t.Fatal("an existing destination link lost its protected-target scope")
	}

	if err := os.Remove(destination); err != nil {
		t.Fatal(err)
	}
	made := CommandLinks("Bash", fmt.Sprintf("ln -s %s %s && %s", filepath.ToSlash(target), filepath.ToSlash(destination), command), cwd, home)
	if !made.OpaqueTargetWithFacts(destination, false, nil) {
		t.Fatal("a command-made destination link lost its protected-target scope")
	}
}
