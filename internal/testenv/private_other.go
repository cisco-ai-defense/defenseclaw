// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package testenv

import (
	"os"
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
	return t.TempDir()
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
