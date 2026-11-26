// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"os"
	"path/filepath"
	"testing"
)

// TryFileLink makes a symbolic link to target at link and reports whether it
// could. A standard Windows account without SeCreateSymbolicLinkPrivilege
// cannot make a file link (a junction only points at a folder), so it gets
// false and the caller leaves out the rows that need the link: they run in
// the elevated leg, which has the privilege. Any other error fails the test.
func TryFileLink(t testing.TB, target, link string) bool {
	t.Helper()
	err := os.Symlink(target, link)
	if err == nil {
		return true
	}
	if symlinkPrivilegeMissing(err) {
		t.Logf("this account lacks SeCreateSymbolicLinkPrivilege: no file link %s; its rows run in the elevated leg only", link)
		return false
	}
	t.Fatal(err)
	return false
}

// CanLinkFiles reports whether this account can make a symbolic link to a
// file. A test with one subtest that needs such a link asks first and does not
// generate the subtest when the answer is no (the Windows standard-user leg),
// so the name still passes there on its other rows; a skipped subtest would
// keep the whole name from ever being a pass.
func CanLinkFiles(t testing.TB) bool {
	t.Helper()
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return TryFileLink(t, target, filepath.Join(dir, "link"))
}
