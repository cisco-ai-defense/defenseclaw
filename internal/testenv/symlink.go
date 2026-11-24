// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"testing"
)

// errorPrivilegeNotHeld is Windows ERROR_PRIVILEGE_NOT_HELD (1314): a file
// symbolic link needs SeCreateSymbolicLinkPrivilege, which a standard user
// does not hold unless Developer Mode is on.
const errorPrivilegeNotHeld = syscall.Errno(1314)

// Symlink makes a symbolic-link fixture. A standard Windows account without
// the create-symbolic-link right gets ERROR_PRIVILEGE_NOT_HELD: the fixture
// cannot exist there, so the test skips with the reason instead of failing
// before it checks anything (the native Windows standard-user gate read
// about 50 such tests as reds). Windows Native CI runs elevated, so under
// GitHub Actions the missing privilege fails the test. Any other error fails
// the test.
func Symlink(t testing.TB, target, link string) {
	t.Helper()
	err := os.Symlink(target, link)
	if err == nil {
		return
	}
	if runtime.GOOS == "windows" && errors.Is(err, errorPrivilegeNotHeld) && os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skipf("this account lacks SeCreateSymbolicLinkPrivilege (turn on Developer Mode or run elevated) and cannot create the symbolic-link fixture %s: %v", link, err)
	}
	t.Fatal(err)
}
