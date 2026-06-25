//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateTrustedRuntimeDirRejectsStandardUserOwnedPath(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root-owned temp dirs are valid managed runtime dirs")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod temp dir: %v", err)
	}

	err := ValidateTrustedRuntimeDir(dir, "managed data_dir")
	if err == nil || !strings.Contains(err.Error(), "owner uid") {
		t.Fatalf("ValidateTrustedRuntimeDir error = %v, want untrusted owner refusal", err)
	}
}

func TestValidateTrustedRuntimeDirRejectsSymlink(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "runtime")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink runtime dir: %v", err)
	}

	err := ValidateTrustedRuntimeDir(link, "managed data_dir")
	if err == nil || !strings.Contains(err.Error(), "symlinks are not allowed") {
		t.Fatalf("ValidateTrustedRuntimeDir error = %v, want symlink refusal", err)
	}
}

func TestValidateTrustedRuntimeDirRejectsWritableDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod temp dir: %v", err)
	}

	err := ValidateTrustedRuntimeDir(dir, "managed data_dir")
	if err == nil || !strings.Contains(err.Error(), "group/other writable") {
		t.Fatalf("ValidateTrustedRuntimeDir error = %v, want writable-dir refusal", err)
	}
}
