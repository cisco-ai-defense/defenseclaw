// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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
	if symlinkPrivilegeMissing(err) {
		t.Skipf(symlinkSkipFormat, link, err)
	}
	t.Fatal(err)
}

// symlinkSkipFormat is the skip reason of a row whose symbolic-link fixture
// the account cannot create; it names the missing privilege.
const symlinkSkipFormat = "this account lacks SeCreateSymbolicLinkPrivilege (turn on Developer Mode or run elevated) and cannot create the symbolic-link fixture %s: %v"

// symlinkPrivilegeMissing reports the one error a Limited Windows run may
// skip on: ERROR_PRIVILEGE_NOT_HELD outside GitHub Actions (which runs
// elevated, so there it fails).
func symlinkPrivilegeMissing(err error) bool {
	return runtime.GOOS == "windows" && errors.Is(err, errorPrivilegeNotHeld) && os.Getenv("GITHUB_ACTIONS") != "true"
}

// LinkFixture is a symbolic-link fixture made by TrySymlink: Made is false
// when the account lacks SeCreateSymbolicLinkPrivilege.
type LinkFixture struct {
	Link string
	Made bool
	err  error
}

// TrySymlink makes a symbolic-link fixture for a test whose rows do not all
// need it. Without SeCreateSymbolicLinkPrivilege (a standard Windows account,
// a Limited token) it makes nothing and returns Made false, so only the rows
// that need the link skip (Require) and every other row keeps running. Any
// other error fails the test, as with Symlink.
func TrySymlink(t testing.TB, target, link string) LinkFixture {
	t.Helper()
	err := os.Symlink(target, link)
	if err == nil {
		return LinkFixture{Link: link, Made: true}
	}
	if symlinkPrivilegeMissing(err) {
		return LinkFixture{Link: link, err: err}
	}
	t.Fatal(err)
	return LinkFixture{}
}

// Require skips the row t when the fixture could not be made, with the
// missing privilege as the reason.
func (f LinkFixture) Require(t testing.TB) {
	t.Helper()
	if !f.Made {
		t.Skipf(symlinkSkipFormat, f.Link, f.err)
	}
}

// Junction makes a directory junction at link to the directory target, the
// link form a standard Windows account can create without any privilege. A
// test adds a junction row beside a directory symbolic-link row, never in
// place of it: the junction row runs on every Windows token, the symbolic
// link row where the privilege is held. Off Windows the test fails.
func Junction(t testing.TB, target, link string) {
	t.Helper()
	if runtime.GOOS != "windows" {
		t.Fatalf("a junction fixture is Windows only: %s", link)
	}
	absolute, err := filepath.Abs(target)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, absolute).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J %s %s: %v: %s", link, absolute, err, out)
	}
}
