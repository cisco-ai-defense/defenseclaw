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

func TestValidateTrustedFilePathRejectsEmptyPath(t *testing.T) {
	err := ValidateTrustedFilePath("", "managed authorization")
	if err == nil || !strings.Contains(err.Error(), "path is empty") {
		t.Fatalf("ValidateTrustedFilePath error = %v, want empty-path refusal", err)
	}
}

func TestValidateTrustedFilePathRejectsSymlinkLeaf(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "authorization.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "authorization-link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink authorization: %v", err)
	}

	err := ValidateTrustedFilePath(link, "managed authorization")
	if err == nil || !strings.Contains(err.Error(), "symlinks are not allowed") {
		t.Fatalf("ValidateTrustedFilePath error = %v, want symlink refusal", err)
	}
}

func TestValidateTrustedFilePathRejectsWritableLeaf(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorization.json")
	if err := os.WriteFile(path, []byte("{}"), 0o666); err != nil {
		t.Fatalf("write authorization: %v", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatalf("chmod authorization: %v", err)
	}

	err := ValidateTrustedFilePath(path, "managed authorization")
	if err == nil || !strings.Contains(err.Error(), "group/other writable") {
		t.Fatalf("ValidateTrustedFilePath error = %v, want writable-file refusal", err)
	}
}

func TestValidateTrustedFilePathRejectsStandardUserOwnedLeaf(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root-owned temp files are valid managed files")
	}
	path := filepath.Join(t.TempDir(), "authorization.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write authorization: %v", err)
	}

	err := ValidateTrustedFilePath(path, "managed authorization")
	if err == nil || !strings.Contains(err.Error(), "owner uid") {
		t.Fatalf("ValidateTrustedFilePath error = %v, want untrusted owner refusal", err)
	}
}
