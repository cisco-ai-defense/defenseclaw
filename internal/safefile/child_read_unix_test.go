// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
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

func TestOpenDirectoryNoFollowUsesSearchPermissionForAncestors(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("search-only directory handles are defined for macOS and Linux")
	}
	if os.Geteuid() == 0 {
		t.Skip("directory-listing permissions require an unprivileged test account")
	}
	parent := filepath.Join(t.TempDir(), "search-only")
	skill := filepath.Join(parent, "skill")
	if err := os.MkdirAll(skill, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("skill"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o100); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(parent, 0o700); err != nil {
			t.Error(err)
		}
	})
	if _, err := os.ReadDir(parent); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("search-only directory listing error = %v, want permission denied", err)
	}
	file, err := OpenDirectoryNoFollow(skill)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	names, err := file.Readdirnames(1)
	if err != nil || len(names) != 1 || names[0] != "SKILL.md" {
		t.Fatalf("skill directory names = %v, %v", names, err)
	}
}
