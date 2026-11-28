// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package processutil

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPodWriteRightsAreBoundedByABI(t *testing.T) {
	base := uint64(unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE | unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
		unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK | unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
		unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK | unix.LANDLOCK_ACCESS_FS_MAKE_SYM)
	if got := podWriteAccess(1); got != base {
		t.Fatalf("ABI 1 write rights: %#x, want %#x", got, base)
	}
	if got := podWriteAccess(2); got != base|unix.LANDLOCK_ACCESS_FS_REFER {
		t.Fatalf("ABI 2 write rights: %#x", got)
	}
	if got := podWriteAccess(3); got != base|unix.LANDLOCK_ACCESS_FS_REFER|unix.LANDLOCK_ACCESS_FS_TRUNCATE {
		t.Fatalf("ABI 3 write rights: %#x", got)
	}
	if got := podWriteAccess(5); got != base|unix.LANDLOCK_ACCESS_FS_REFER|unix.LANDLOCK_ACCESS_FS_TRUNCATE|unix.LANDLOCK_ACCESS_FS_IOCTL_DEV {
		t.Fatalf("ABI 5 write rights: %#x", got)
	}
}

func TestPodResetClearsReadOnlyFoldersWithoutFollowingLinks(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	deep := filepath.Join(root, "locked", "deep")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "marker"), []byte("remove"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{deep, filepath.Dir(deep), root} {
		if err := os.Chmod(path, 0o500); err != nil {
			t.Fatal(err)
		}
	}
	if err := emptyFolder(root); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Fatalf("scratch entries = %v, %v", entries, err)
	}
	if got, err := os.ReadFile(outside); err != nil || string(got) != "keep" {
		t.Fatalf("outside file = %q, %v", got, err)
	}
}

func TestPodModeErrorsDoNotDescribeHostNamespaces(t *testing.T) {
	err := podUnavailable("the scanner guard is unavailable")
	if !errors.Is(err, ErrNotContained) || !errors.Is(err, ErrContainmentUnavailable) {
		t.Fatalf("pod error lost fail-closed sentinels: %v", err)
	}
	if strings.Contains(err.Error(), "host refuses the namespaces") || !strings.Contains(err.Error(), "pod-contained scan worker") {
		t.Fatalf("wrong mode in error: %v", err)
	}
}

func TestPodGuardRequiresLandlockAndSeccomp(t *testing.T) {
	oldABI, oldSeccomp := podLandlockABI, podSeccompFilters
	t.Cleanup(func() { podLandlockABI, podSeccompFilters = oldABI, oldSeccomp })
	podLandlockABI = func() int { return 0 }
	podSeccompFilters = func() bool { return true }
	if err := podGuardAvailable(); err == nil {
		t.Fatal("no Landlock was accepted")
	}
	podLandlockABI = func() int { return 5 }
	podSeccompFilters = func() bool { return false }
	if err := podGuardAvailable(); err == nil {
		t.Fatal("no seccomp filter was accepted")
	}
}
