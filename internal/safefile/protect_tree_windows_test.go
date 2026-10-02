// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-1310: re-protecting an already private directory must not write its
// DACL back, because Windows then re-propagates it to every file below it
// (about 30,000 under an upgrade's previous/ snapshot), which made each
// private write into the data directory take a minute on a loaded host.
func TestProtectDirectoryDoesNotRewriteAPrivateDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ownWindowsTestPath(t, dir)
	if err := ProtectDirectory(dir); err != nil {
		t.Fatal(err)
	}
	rewrites := 0
	original := reapplyDirectoryProtection
	reapplyDirectoryProtection = func(path string) error {
		rewrites++
		return original(path)
	}
	t.Cleanup(func() { reapplyDirectoryProtection = original })

	if err := ProtectDirectory(dir); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivate(filepath.Join(dir, "watchdog.pid"), []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if rewrites != 0 {
		t.Fatalf("an already private directory's DACL was written back %d times", rewrites)
	}
	if protected, err := daclIsProtected(dir); err != nil || !protected {
		t.Fatalf("directory DACL protected=%v err=%v", protected, err)
	}
}
