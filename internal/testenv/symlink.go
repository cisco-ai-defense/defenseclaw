// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"os"
	"testing"
)

// SymlinkOrSkip creates link pointing at target for a test fixture. When the
// account may not create symbolic links (Windows: a standard user without
// SeCreateSymbolicLinkPrivilege and outside Developer Mode) the fixture cannot
// exist, so the test is skipped there; any other error fails the test. CI
// runs these tests as an account that holds the privilege, so they keep their
// coverage there (rel-1-0-10:GAP-0873).
func SymlinkOrSkip(t testing.TB, target, link string) {
	t.Helper()
	err := os.Symlink(target, link)
	if err == nil {
		return
	}
	if SymlinkPrivilegeMissing(err) {
		t.Skipf("symbolic link fixture needs a privilege this account does not hold: %v", err)
	}
	t.Fatal(err)
}
