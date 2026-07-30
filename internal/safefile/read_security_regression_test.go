// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package safefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadRegularFileBoundedRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if _, err := ReadRegularFileBounded(link, 1024); err == nil {
		t.Fatal("ReadRegularFileBounded accepted a symlink")
	}
}

func TestReadRegularFileBoundedRejectsOversize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversize")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 1025)), 0o600); err != nil {
		t.Fatalf("write oversize fixture: %v", err)
	}

	if _, err := ReadRegularFileBounded(path, 1024); err == nil {
		t.Fatal("ReadRegularFileBounded accepted an oversized file")
	}
}
