// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package enterpriseunix

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// GAP-2446: a managed folder with the user immutable flag (chflags uchg)
// refused the chmod of ensureDir, so ensure --config stopped as
// apply_failed before it removed an ACL entry, and the config.yaml a
// standard user wrote through that entry stayed. ensureDir clears the flag
// like a wrong mode, and a file can be put in the folder afterwards.
func TestEnsureDirClearsTheImmutableFlagOfAManagedFolder(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "etc")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chflags(dir, unix.UF_IMMUTABLE); err != nil {
		t.Skipf("chflags uchg: %v", err)
	}
	t.Cleanup(func() { _ = unix.Chflags(dir, 0) })
	e := &Env{GOOS: "darwin"}
	e.fillDefaults()
	if err := e.ensureDir(dir, 0o755, fileOwner{UID: os.Getuid(), GID: os.Getgid()}); err != nil {
		t.Fatalf("ensureDir on a uchg folder: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Lstat(dir, &st); err != nil {
		t.Fatal(err)
	}
	if st.Flags&unix.UF_IMMUTABLE != 0 || st.Mode&0o777 != 0o755 {
		t.Fatalf("flags %#x mode %o after ensureDir, want no uchg and 0755", st.Flags, st.Mode&0o777)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("x\n"), 0o640); err != nil {
		t.Fatalf("a file cannot be put in the folder after ensureDir: %v", err)
	}
}

func TestClearBlockingFlagsNamesTheFlagsItCleared(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "etc")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if got, err := clearBlockingFlags(dir); got != "" || err != nil {
		t.Fatalf("unflagged folder: %q, %v", got, err)
	}
	if err := unix.Chflags(dir, unix.UF_IMMUTABLE|unix.UF_APPEND|unix.UF_HIDDEN); err != nil {
		t.Skipf("chflags: %v", err)
	}
	t.Cleanup(func() { _ = unix.Chflags(dir, 0) })
	if got, err := clearBlockingFlags(dir); got != "uchg,uappnd" || err != nil {
		t.Fatalf("flagged folder: %q, %v; want uchg,uappnd", got, err)
	}
	var st unix.Stat_t
	if err := unix.Lstat(dir, &st); err != nil {
		t.Fatal(err)
	}
	if st.Flags != unix.UF_HIDDEN {
		t.Fatalf("flags %#x after clearing, want only the hidden flag kept", st.Flags)
	}
}
