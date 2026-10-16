// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Go's lifecycle writer already stages and renames its payload binaries.
// This test protects that behavior and the old file on a failed commit.
func TestCopyFileAtomicReplacesBinaryInode(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "payload")
	dst := filepath.Join(dir, "defenseclaw-gateway")
	link := filepath.Join(dir, "old-inode")
	if err := os.WriteFile(src, []byte("new signed binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("old signed binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(dst, link); err != nil {
		t.Fatal(err)
	}
	e := &Env{Lchown: os.Lchown}
	owner := fileOwner{UID: os.Getuid(), GID: os.Getgid()}
	if err := e.copyFileAtomic(src, dst, 0o755, owner); err != nil {
		t.Fatal(err)
	}
	oldInfo, err := os.Stat(link)
	if err != nil {
		t.Fatal(err)
	}
	newInfo, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(oldInfo, newInfo) {
		t.Fatal("binary replacement reused the old inode")
	}
	if newInfo.Mode().Perm() != 0o755 {
		t.Fatalf("new mode = %04o", newInfo.Mode().Perm())
	}
	if os.Geteuid() == 0 {
		uid, gid, _, err := statOwnerMode(dst)
		if err != nil || uid != owner.UID || gid != owner.GID {
			t.Fatalf("new owner = %d:%d, %v", uid, gid, err)
		}
	} else {
		t.Log("owner assertion requires root; mode and inode were checked")
	}
	if got, _ := os.ReadFile(dst); string(got) != "new signed binary" {
		t.Fatalf("new contents = %q", got)
	}
	if got, _ := os.ReadFile(link); string(got) != "old signed binary" {
		t.Fatalf("old inode changed through hard link: %q", got)
	}
	assertNoAtomicTemps(t, dir)

	blocked := filepath.Join(dir, "blocked-destination")
	if err := os.Mkdir(blocked, 0o755); err != nil {
		t.Fatal(err)
	}
	kept := filepath.Join(blocked, "keep")
	if err := os.WriteFile(kept, []byte("keep this file"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := e.copyFileAtomic(src, blocked, 0o755, owner); err == nil || !strings.Contains(err.Error(), "replace "+blocked) {
		t.Fatalf("failed rename = %v", err)
	}
	if info, err := os.Stat(blocked); err != nil || !info.IsDir() {
		t.Fatalf("failed rename changed destination directory: %v, %v", info, err)
	}
	if got, err := os.ReadFile(kept); err != nil || string(got) != "keep this file" {
		t.Fatalf("failed rename changed directory contents: %q, %v", got, err)
	}
	assertNoAtomicTemps(t, dir)
}

func assertNoAtomicTemps(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".dc-") {
			t.Fatalf("temporary file remains: %s", entry.Name())
		}
	}
}
