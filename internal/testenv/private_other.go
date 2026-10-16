// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package testenv

import (
	"os"
	"path/filepath"
	"testing"
)

func AssertPrivateFile(t testing.TB, path string) {
	t.Helper()
	assertPrivateMode(t, path, 0o600)
}

func AssertPrivateDirectory(t testing.TB, path string) {
	t.Helper()
	assertPrivateMode(t, path, 0o700)
}

func PrivateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	canonical, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("canonicalize private temp dir %s: %v", dir, err)
	}
	if err := os.Chmod(canonical, 0o700); err != nil {
		t.Fatalf("protect private temp dir %s: %v", canonical, err)
	}
	return canonical
}

// TraversableTempDir is a fresh, link-free 0755 test directory whose every
// ancestor every account can traverse. The managed e2fsprogs rule refuses an
// administrator's tool folder under any other ancestor, so a fixture there
// reaches the case it means to test. t.TempDir does not qualify everywhere:
// its per-test parent is 0700, and on the macOS runner TMPDIR is under
// /Users/runner, which is 0750.
func TraversableTempDir(t *testing.T) string {
	t.Helper()
	traversable := func(dir string) bool {
		for ; ; dir = filepath.Dir(dir) {
			info, err := os.Stat(dir)
			if err != nil || !info.IsDir() || info.Mode().Perm()&0o001 == 0 {
				return false
			}
			if dir == filepath.Dir(dir) {
				return true
			}
		}
	}
	for _, base := range []string{os.TempDir(), "/tmp", "/var/tmp"} {
		base, err := filepath.EvalSymlinks(base)
		if err != nil || !traversable(base) {
			continue
		}
		dir, err := os.MkdirTemp(base, "dc-traversable-")
		if err != nil {
			continue
		}
		t.Cleanup(func() {
			if err := os.RemoveAll(dir); err != nil {
				t.Errorf("remove %s: %v", dir, err)
			}
		})
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	t.Fatalf("no temporary directory with ancestors every account can traverse (tried %s, /tmp, /var/tmp)", os.TempDir())
	return ""
}

func assertPrivateMode(t testing.TB, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat private path %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("private path %s mode = %04o, want %04o", path, got, want)
	}
}
