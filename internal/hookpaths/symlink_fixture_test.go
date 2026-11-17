// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"os"
	"runtime"
	"testing"
)

// testSymlink makes a symbolic-link fixture. A standard Windows account
// without the create-symbolic-link right (Developer Mode off) gets
// ERROR_PRIVILEGE_NOT_HELD: the fixture cannot exist there, so the test
// skips with the reason instead of failing before it checks anything (the
// native Windows standard-user gate read 45 such tests as reds; Windows CI
// runs elevated and runs them all). Any other error fails the test.
func testSymlink(t testing.TB, target, link string) {
	t.Helper()
	err := os.Symlink(target, link)
	if err == nil {
		return
	}
	if runtime.GOOS == "windows" && errors.Is(err, errorPrivilegeNotHeld) {
		t.Skipf("this account may not create a symbolic link (fixture %s): %v", link, err)
	}
	t.Fatal(err)
}
