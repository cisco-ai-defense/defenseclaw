// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// RealFSTestsEnv turns on the tests that mount a real, size-limited
// filesystem (RealSmallFilesystem). They need passwordless sudo for mount and
// umount; the build boxes have it, a developer laptop usually does not.
const RealFSTestsEnv = "DEFENSECLAW_REAL_FS_TESTS"

// RealSmallFilesystem mounts a tmpfs of sizeMiB MiB, owned by the test's
// user, under a new temporary directory and returns its mount point. The
// mount is removed when the test ends (after the test's own cleanups, which
// close what it opened there). The test is skipped, and says why, unless
// DEFENSECLAW_REAL_FS_TESTS=1 is set and sudo -n mount works: a full disk
// is then a real ENOSPC from the kernel, not an injected error.
func RealSmallFilesystem(t *testing.T, sizeMiB int) string {
	t.Helper()
	if os.Getenv(RealFSTestsEnv) != "1" {
		t.Skipf("set %s=1 (and allow sudo -n mount) to run this real full-filesystem test", RealFSTestsEnv)
	}
	if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
		t.Skipf("real full-filesystem test needs passwordless sudo for mount: %v", err)
	}
	dir := filepath.Join(t.TempDir(), "smallfs")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	options := fmt.Sprintf("size=%dm,mode=0700,uid=%d,gid=%d", sizeMiB, os.Getuid(), os.Getgid())
	if out, err := exec.Command("sudo", "-n", "mount", "-t", "tmpfs", "-o", options, "tmpfs", dir).CombinedOutput(); err != nil {
		t.Skipf("mount a %d MiB tmpfs: %v: %s", sizeMiB, err, strings.TrimSpace(string(out)))
	}
	t.Cleanup(func() {
		if out, err := exec.Command("sudo", "-n", "umount", dir).CombinedOutput(); err != nil {
			// Still open somewhere: detach it so nothing stays mounted.
			lazy, lazyErr := exec.Command("sudo", "-n", "umount", "-l", dir).CombinedOutput()
			if lazyErr != nil {
				t.Errorf("unmount %s: %v: %s; lazy: %v: %s", dir, err, out, lazyErr, lazy)
			}
		}
	})
	return dir
}

// FillFilesystem writes a filler file into dir until its filesystem has no
// byte left (the kernel answers ENOSPC), and returns a func that removes the
// filler so the filesystem has room again.
func FillFilesystem(t *testing.T, dir string) (release func()) {
	t.Helper()
	path := filepath.Join(dir, "zz-filler")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{1 << 20, 4 << 10, 1} {
		chunk := make([]byte, size)
		for {
			if _, err = file.Write(chunk); err != nil {
				break
			}
		}
		if !errors.Is(err, syscall.ENOSPC) {
			_ = file.Close()
			t.Fatalf("fill %s: %v, want ENOSPC", dir, err)
		}
	}
	if err := file.Close(); err != nil && !errors.Is(err, syscall.ENOSPC) {
		t.Fatal(err)
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(dir, &stat); err != nil {
		t.Fatal(err)
	}
	if stat.Bavail != 0 {
		t.Fatalf("filesystem of %s still has %d free blocks after the fill", dir, stat.Bavail)
	}
	return func() {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
}
