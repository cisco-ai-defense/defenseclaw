// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// The top-down read of plainDirectory off Windows (rel-1-0-10:GAP-2299)
// answers what the full link walk answered: a folder that exists and whose
// path has no link, through a linked folder, below one, a file, below a file,
// a missing folder, the root and a link that points at itself.
func TestGAP2299PlainDirectoryMatchesTheLinkWalk(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	for _, dir := range []string{"a/b/c", "other"} {
		if err := os.MkdirAll(filepath.Join(real, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(real, "a/file"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{
		filepath.Join(root, "linked"):     real,
		filepath.Join(real, "a/up"):       "..",
		filepath.Join(real, "a/loop"):     filepath.Join(real, "a/loop"),
		filepath.Join(real, "a/filelink"): filepath.Join(real, "a/file"),
	} {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	walk := func(dir string) bool {
		clean := filepath.Clean(dir)
		if info, err := os.Stat(clean); err != nil || !info.IsDir() {
			return false
		}
		resolved, err := filepath.EvalSymlinks(clean)
		return err == nil && resolved == clean
	}
	for _, dir := range []string{
		"/", root, real, filepath.Join(real, "a"), filepath.Join(real, "a/b/c"), filepath.Join(real, "a/b/c") + "/",
		filepath.Join(root, "linked"), filepath.Join(root, "linked/a/b"), filepath.Join(real, "a/up"),
		filepath.Join(real, "a/up/other"), filepath.Join(real, "a/file"), filepath.Join(real, "a/file/x"),
		filepath.Join(real, "a/missing"), filepath.Join(real, "a/loop"), filepath.Join(real, "a/filelink"),
		"relative/a",
	} {
		want := filepath.IsAbs(dir) && walk(dir)
		if got := plainDirectory(dir); got != want {
			t.Errorf("plainDirectory(%q) = %v, the link walk says %v", dir, got, want)
		}
	}
}
