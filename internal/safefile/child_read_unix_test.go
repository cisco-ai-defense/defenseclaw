// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenDirectoryNoFollowRejectsLinkedAncestors(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "real", "child")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "alias")
	if err := os.Symlink(filepath.Join(root, "real"), link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, filepath.Join(link, "child")} {
		file, err := OpenDirectoryNoFollow(path)
		if file != nil {
			_ = file.Close()
		}
		if !errors.Is(err, ErrSymlinkRefused) {
			t.Fatalf("linked directory %q: %v", path, err)
		}
	}
	file, err := OpenDirectoryNoFollow(dir)
	if err != nil {
		t.Fatalf("ordinary directory: %v", err)
	}
	_ = file.Close()
}
