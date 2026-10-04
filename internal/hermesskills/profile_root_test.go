// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hermesskills

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// GAP-2263: the managed Windows gateway's service account may read a
// profile's skills folder but not list the folders above it, so resolving
// the path and safefile's check of every parent are denied. The skills are
// still listed; a linked root is still refused.
func TestDiscoverProfileRootListsSkillsWhenParentsAreDenied(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(home, "AppData", "Local", "hermes", "skills")
	writeTestSkill(t, root, filepath.Join("apple", "apple-notes"), "apple-notes")
	denied := &fs.PathError{Op: "CreateFile", Path: filepath.Dir(root), Err: fs.ErrPermission}
	previousEval, previousRead := evalSymlinks, readRegularFileBounded
	t.Cleanup(func() { evalSymlinks, readRegularFileBounded = previousEval, previousRead })
	evalSymlinks = func(string) (string, error) { return "", denied }
	readRegularFileBounded = func(string, int64) ([]byte, error) { return nil, denied }

	entries, err := DiscoverProfileRoot(root, DefaultDirectoryLimit)
	if err != nil || len(entries) != 1 || entries[0].Name != "apple-notes" || entries[0].Bundled {
		t.Fatalf("DiscoverProfileRoot = %+v, %v; want the user skill apple-notes", entries, err)
	}

	if runtime.GOOS == "windows" {
		return // symlinks need a privilege there
	}
	linked := filepath.Join(home, "other", "skills")
	if err := os.MkdirAll(filepath.Dir(linked), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, linked); err != nil {
		t.Fatal(err)
	}
	if entries, err := DiscoverProfileRoot(linked, DefaultDirectoryLimit); err == nil {
		t.Fatalf("a linked root was listed: %+v", entries)
	}
}
