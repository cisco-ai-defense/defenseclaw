//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func windowsNonRegularHookFixture(t *testing.T) (target, copyPath, want string) {
	t.Helper()
	target, copyPath, want = writeWindowsHookBinaryFixture(t, "hook release")
	if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, true); err != nil || damage != "" {
		t.Fatalf("keep protected copy: damage %q, error %v", damage, err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	return target, copyPath, want
}

func assertWindowsHookRestored(t *testing.T, target, want, damage string) {
	t.Helper()
	if damage != "" && !strings.Contains(damage, "not a regular file") {
		t.Fatalf("restored damage %q does not name the non-regular entry", damage)
	}
	info, err := os.Lstat(target)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("restored target is not a plain regular file: %v, %v", info, err)
	}
	if links := windowsHookBinaryLinkCount(t, target); links != 1 {
		t.Fatalf("restored target has %d links, want one", links)
	}
	if sum, err := windowsFileSHA256Hex(target); err != nil || sum != want {
		t.Fatalf("restored target hash %q, error %v, want %q", sum, err, want)
	}
}

// windowsLstatWithFileID returns an Lstat result whose file ID is already
// loaded. Go on Windows reads the ID of an Lstat result lazily, by path, the
// first time os.SameFile needs it, so a "before" snapshot taken ahead of a
// restore would otherwise describe the restored file.
func windowsLstatWithFileID(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(info, info) {
		t.Fatalf("could not load the file ID of %s", path)
	}
	return info
}

func windowsSymlinkOrSkipPrivilege(t *testing.T, oldTarget, link string) {
	t.Helper()
	if err := os.Symlink(oldTarget, link); err != nil {
		if errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) {
			t.Skipf("symlink creation needs a privilege: %v", err)
		}
		t.Fatal(err)
	}
}

func TestKeepWindowsManagedFileCopyRestoresFileSymlink(t *testing.T) {
	target, copyPath, want := windowsNonRegularHookFixture(t)
	pointed := target + ".other"
	if err := os.WriteFile(pointed, []byte("other bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	windowsSymlinkOrSkipPrivilege(t, pointed, target)
	damage, err := keepWindowsManagedFileCopy(target, copyPath, want, false)
	if err != nil {
		t.Fatal(err)
	}
	assertWindowsHookRestored(t, target, want, damage)
	if body, err := os.ReadFile(pointed); err != nil || string(body) != "other bytes" {
		t.Fatalf("link target changed: body %q, error %v", body, err)
	}
	before := windowsLstatWithFileID(t, target)
	if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, false); err != nil || damage != "" {
		t.Fatalf("healthy second check: damage %q, error %v", damage, err)
	}
	after, err := os.Lstat(target)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("healthy target changed on second check: %v", err)
	}
}

func TestCopyWindowsManagedFileReplacesFileSymlinkEntry(t *testing.T) {
	target, copyPath, want := windowsNonRegularHookFixture(t)
	pointed := target + ".other"
	if err := os.WriteFile(pointed, []byte("other bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	windowsSymlinkOrSkipPrivilege(t, pointed, target)
	if err := copyWindowsManagedFile(copyPath, target, windowsInstallFileSDDL, true, true); err != nil {
		t.Fatalf("MoveFileEx could not replace the file symlink entry: %v", err)
	}
	assertWindowsHookRestored(t, target, want, "")
	if body, err := os.ReadFile(pointed); err != nil || string(body) != "other bytes" {
		t.Fatalf("MoveFileEx changed the link destination: body %q, error %v", body, err)
	}
}

func TestKeepWindowsManagedFileCopyRestoresDanglingSymlink(t *testing.T) {
	target, copyPath, want := windowsNonRegularHookFixture(t)
	missing := target + ".missing"
	windowsSymlinkOrSkipPrivilege(t, missing, target)
	damage, err := keepWindowsManagedFileCopy(target, copyPath, want, false)
	if err != nil {
		t.Fatal(err)
	}
	assertWindowsHookRestored(t, target, want, damage)
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dangling link destination was created: %v", err)
	}
}

func TestKeepWindowsManagedFileCopyRestoresDirectoryLinks(t *testing.T) {
	for _, kind := range []string{"directory symlink", "junction"} {
		t.Run(kind, func(t *testing.T) {
			target, copyPath, want := windowsNonRegularHookFixture(t)
			pointed := target + ".directory"
			if err := os.Mkdir(pointed, 0o700); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(pointed, "marker")
			if err := os.WriteFile(marker, []byte("keep this directory"), 0o600); err != nil {
				t.Fatal(err)
			}
			if kind == "directory symlink" {
				windowsSymlinkOrSkipPrivilege(t, pointed, target)
			} else if output, err := exec.Command("cmd", "/c", "mklink", "/J", target, pointed).CombinedOutput(); err != nil {
				t.Fatalf("create junction: %v: %s", err, output)
			}
			info, err := os.Lstat(target)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().IsRegular() {
				if kind == "junction" {
					t.Skip("this runner reports a junction as a regular file")
				}
				t.Fatal("directory symlink was reported as a regular file")
			}
			damage, err := keepWindowsManagedFileCopy(target, copyPath, want, false)
			if err != nil {
				t.Fatal(err)
			}
			assertWindowsHookRestored(t, target, want, damage)
			if body, err := os.ReadFile(marker); err != nil || string(body) != "keep this directory" {
				t.Fatalf("linked directory changed: marker %q, error %v", body, err)
			}
		})
	}
}

func TestKeepWindowsManagedFileCopyRestoresDirectories(t *testing.T) {
	for _, nonempty := range []bool{false, true} {
		name := "empty"
		if nonempty {
			name = "nonempty"
		}
		t.Run(name, func(t *testing.T) {
			target, copyPath, want := windowsNonRegularHookFixture(t)
			if err := os.Mkdir(target, 0o700); err != nil {
				t.Fatal(err)
			}
			if nonempty {
				if err := os.WriteFile(filepath.Join(target, "marker"), []byte("leave intact"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			damage, err := keepWindowsManagedFileCopy(target, copyPath, want, false)
			if err != nil {
				t.Fatal(err)
			}
			assertWindowsHookRestored(t, target, want, damage)
			aside, err := filepath.Glob(target + ".damaged-*")
			if err != nil || len(aside) != map[bool]int{false: 0, true: 1}[nonempty] {
				t.Fatalf("moved-aside directories %q, error %v", aside, err)
			}
			if nonempty {
				if body, err := os.ReadFile(filepath.Join(aside[0], "marker")); err != nil || string(body) != "leave intact" {
					t.Fatalf("moved-aside directory changed: marker %q, error %v", body, err)
				}
			}
		})
	}
}

func TestKeepWindowsManagedFileCopyRestoresIrregularLstatEntry(t *testing.T) {
	target, copyPath, want := writeWindowsHookBinaryFixture(t, "hook release")
	if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, true); err != nil || damage != "" {
		t.Fatalf("keep protected copy: damage %q, error %v", damage, err)
	}
	before := windowsLstatWithFileID(t, target)
	saved := windowsHookBinaryLstat
	windowsHookBinaryLstat = func(path string) (os.FileInfo, error) {
		info, err := os.Lstat(path)
		if path == target && err == nil {
			return guardianLstatModeInfo{FileInfo: info, mode: os.ModeIrregular, size: info.Size()}, nil
		}
		return info, err
	}
	t.Cleanup(func() { windowsHookBinaryLstat = saved })
	damage, err := keepWindowsManagedFileCopy(target, copyPath, want, false)
	if err != nil {
		t.Fatal(err)
	}
	assertWindowsHookRestored(t, target, want, damage)
	after, err := os.Lstat(target)
	if err != nil || os.SameFile(before, after) {
		t.Fatalf("irregular entry was not replaced: %v", err)
	}
}

func TestKeepWindowsManagedFileCopyReportsOtherLstatError(t *testing.T) {
	target, copyPath, want := writeWindowsHookBinaryFixture(t, "hook release")
	before := windowsLstatWithFileID(t, target)
	saved := windowsHookBinaryLstat
	windowsHookBinaryLstat = func(path string) (os.FileInfo, error) {
		if path == target {
			return nil, os.ErrPermission
		}
		return os.Lstat(path)
	}
	t.Cleanup(func() { windowsHookBinaryLstat = saved })
	damage, err := keepWindowsManagedFileCopy(target, copyPath, want, true)
	if damage != "" || !errors.Is(err, os.ErrPermission) || !strings.Contains(err.Error(), target) {
		t.Fatalf("lookup failure: damage %q, error %v", damage, err)
	}
	after, err := os.Lstat(target)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("lookup failure changed target: %v", err)
	}
	if _, err := os.Lstat(copyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lookup failure created a protected copy: %v", err)
	}
}

func TestKeepWindowsManagedFileCopyStillRestoresMissingTarget(t *testing.T) {
	target, copyPath, want := windowsNonRegularHookFixture(t)
	if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, false); err != nil || damage != "missing" {
		t.Fatalf("missing target: damage %q, error %v", damage, err)
	}
	if info, err := os.Lstat(target); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("missing target not restored as a file: %v, %v", info, err)
	}
}

func TestKeepWindowsManagedFileCopyLeavesSymlinkWithoutGoodCopy(t *testing.T) {
	target, copyPath, want := writeWindowsHookBinaryFixture(t, "hook release")
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	pointed := target + ".other"
	if err := os.WriteFile(pointed, []byte("other bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	windowsSymlinkOrSkipPrivilege(t, pointed, target)
	damage, err := keepWindowsManagedFileCopy(target, copyPath, want, false)
	if err == nil || damage != "" {
		t.Fatalf("missing protected copy: damage %q, error %v", damage, err)
	}
	if info, err := os.Lstat(target); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink changed without a good copy: %v, %v", info, err)
	}
	if body, err := os.ReadFile(pointed); err != nil || string(body) != "other bytes" {
		t.Fatalf("symlink destination changed: body %q, error %v", body, err)
	}
}
