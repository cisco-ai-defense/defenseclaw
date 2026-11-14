// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyFilesMustBePrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readOwnerOnlyFile(path); err != nil {
		t.Fatalf("owner-only file: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readOwnerOnlyFile(path); err == nil || !strings.Contains(err.Error(), "readable by others") {
		t.Fatalf("a world-readable file must be refused: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readOwnerOnlyFile(link); err == nil {
		t.Fatal("a symlink must be refused")
	}
	if err := writeNewPrivateFile(path, []byte("y")); err == nil {
		t.Fatal("issue output must never overwrite a file")
	}
}
