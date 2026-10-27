// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// The sighting reads the directory a linked one reaches, and lists only
// directories that are directories themselves as plain.
func TestReachedEvidenceReadsLinkedDirectoriesTarget(t *testing.T) {
	base := t.TempDir()
	created := filepath.Join(base, "new")
	if err := os.Mkdir(created, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(created, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	targets := map[string]string{ReachedInstructionsKey: reachedEvidence([]string{link})}
	plain := ReachedPlainDirectories(targets)
	real, err := filepath.EvalSymlinks(created)
	if err != nil {
		t.Fatal(err)
	}
	if _, listed := plain[link]; listed {
		t.Fatalf("a link was listed as a plain directory: %v", plain)
	}
	if plain[real] == "" || plain[real] != DirectoryIdentity(link) {
		t.Fatalf("the directory the link reaches was not read: %v", plain)
	}
	if dirs, _, ok := ReachedInstructions(targets); !ok || dirs[link] == "" {
		t.Fatalf("the link's own sighting: %v %v", dirs, ok)
	}
}
