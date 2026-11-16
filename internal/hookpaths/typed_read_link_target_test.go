// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// A typed file tool that reads a file reaches the file a link names, so the
// client lists that file for a managed gateway that cannot follow the link
// itself, as it does for a write. A read of a file that is no link adds no
// entry.
func TestTypedReadThroughLinkListsTheFileTheLinkReaches(t *testing.T) {
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(project, "Users", "fixture", ".netrc")
	if err := os.MkdirAll(filepath.Dir(secret), 0o700); err != nil {
		t.Fatal(err)
	}
	ordinary := filepath.Join(project, "notes.txt")
	for _, file := range []string{secret, ordinary} {
		if err := os.WriteFile(file, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	linked, ordinaryLink := filepath.Join(project, "lnk-netrc"), filepath.Join(project, "lnk-notes")
	if err := os.Symlink(secret, linked); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ordinary, ordinaryLink); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", project)
	for _, tool := range []string{"Read", "read_file"} {
		targets := resolvedEvidence(t, "claudecode", project, tool, map[string]interface{}{"file_path": linked, "path": linked})
		if targets[linked] != secret {
			t.Errorf("%s through a link: evidence %v, want %s -> %s", tool, targets, linked, secret)
		}
		if targets = resolvedEvidence(t, "claudecode", project, tool, map[string]interface{}{"file_path": ordinaryLink, "path": ordinaryLink}); targets[ordinaryLink] != ordinary {
			t.Errorf("%s through an ordinary link: evidence %v, want its file %s", tool, targets, ordinary)
		}
		if targets = resolvedEvidence(t, "claudecode", project, tool, map[string]interface{}{"file_path": ordinary, "path": ordinary}); targets[ordinary] != "" {
			t.Errorf("%s of a file that is no link lists %v", tool, targets)
		}
	}
}
