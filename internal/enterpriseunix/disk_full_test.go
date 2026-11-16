// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// fullFilesystem reports avail bytes free on the filesystem holding dir (the
// real path) and plenty everywhere else, as a separate device.
func fullFilesystem(dir string, avail uint64) func(string) (uint64, uint64, uint64, error) {
	return func(path string) (uint64, uint64, uint64, error) {
		if path == dir || strings.HasPrefix(path, dir+string(filepath.Separator)) {
			return avail, 64 << 20, 7, nil
		}
		return 10 << 30, 20 << 30, 1, nil
	}
}

// GAP-0662: a disk filled during ensure stopped the services before verify,
// and the result said only that they were not active and that the change
// rolled back.
func TestFailedTransactionNamesTheFullFilesystem(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	h.env.DiskSpace = fullFilesystem(h.env.P(h.env.Layout.DataDir), 456<<10)
	h.healthy = false
	failed := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("2.0.0")})
	requireError(t, failed, codeActivate)
	requireError(t, failed, codeDiskFull)
	if !hasWarning(failed, codeRolledBack) {
		t.Fatalf("no rollback after the failed activation: %+v", failed)
	}
	got := messagesOf(failed.Errors, codeDiskFull)
	for _, want := range []string{"the filesystem holding " + h.env.Layout.DataDir + " has 456 KiB free of 64.0 MiB", "free space on it and run upgrade again"} {
		if !strings.Contains(got, want) {
			t.Fatalf("disk_full = %q, want it to contain %q", got, want)
		}
	}
	if strings.Count(got, "the filesystem holding") != 1 {
		t.Fatalf("one full filesystem is named more than once: %q", got)
	}
	if failed.Errors[0].Code != codeActivate {
		t.Fatalf("the failed step's code is no longer first: %+v", failed.Errors)
	}
}

// Free space is not blamed for a failure on a disk with room.
func TestFailedTransactionWithFreeSpaceHasNoDiskFull(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	h.env.DiskSpace = fullFilesystem(h.env.P(h.env.Layout.DataDir), diskFullBytes)
	h.healthy = false
	failed := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("2.0.0")})
	requireError(t, failed, codeActivate)
	if got := messagesOf(failed.Errors, codeDiskFull); got != "" {
		t.Fatalf("disk_full on a filesystem with %d bytes free: %q", diskFullBytes, got)
	}
}

// A write that failed with ENOSPC names its path, also on a filesystem the
// transaction directories do not show (a mount below the lifecycle state).
func TestDiskFullNamesTheNoSpacePath(t *testing.T) {
	h := newTestHost(t, "linux")
	snapshots := filepath.Join(h.env.Layout.LifecycleDir, snapshotsDirName)
	blob := filepath.Join(h.env.P(snapshots), "20261017T000000Z", "files", "3")
	h.env.DiskSpace = fullFilesystem(h.env.P(snapshots), 0)
	l := &lifecycle{env: h.env, opts: Options{Action: ActionEnsure}, result: &enterprisestatus.Result{}}
	cause := fmt.Errorf("snapshot /etc/defenseclaw/config.yaml: %w", &fs.PathError{Op: "write", Path: blob, Err: syscall.ENOSPC})
	l.reportDiskFull(cause)
	got := messagesOf(l.result.Errors, codeDiskFull)
	want := "no space left on the filesystem holding " + filepath.Join(snapshots, "20261017T000000Z", "files", "3") + " (0 KiB free of 64.0 MiB)"
	if !strings.Contains(got, want) || !strings.Contains(got, "run ensure again") {
		t.Fatalf("disk_full = %q, want %q", got, want)
	}
	if strings.Contains(got, h.env.Root) {
		t.Fatalf("disk_full names the real path: %q", got)
	}

	plain := &lifecycle{env: h.env, opts: Options{Action: ActionEnsure}, result: &enterprisestatus.Result{}}
	plain.reportDiskFull(fmt.Errorf("copy: %v", syscall.ENOSPC))
	if got := messagesOf(plain.result.Errors, codeDiskFull); !strings.Contains(got, "a write failed with no space left on device") {
		t.Fatalf("a text-only ENOSPC is not named: %q", got)
	}

	none := &lifecycle{env: h.env, opts: Options{Action: ActionEnsure}, result: &enterprisestatus.Result{}}
	none.reportDiskFull(fmt.Errorf("verify: %s", "defenseclaw-hook-guardian.service is not active"))
	if len(none.result.Errors) != 0 {
		t.Fatalf("disk_full without a full disk: %+v", none.result.Errors)
	}
}

func TestFormatDiskBytes(t *testing.T) {
	for n, want := range map[uint64]string{0: "0 KiB", 466944: "456 KiB", 5 << 20: "5.0 MiB", 3 << 30: "3.0 GiB"} {
		if got := formatDiskBytes(n); got != want {
			t.Fatalf("formatDiskBytes(%d) = %q, want %q", n, got, want)
		}
	}
}

// A run that fails for lack of space before its transaction starts (here
// the lifecycle directory) names the full filesystem too.
func TestRefusedBeforeTheTransactionNamesTheFullFilesystem(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	lifecycleDir := h.env.P(h.env.Layout.LifecycleDir)
	h.env.DiskSpace = fullFilesystem(lifecycleDir, 0)
	chown := h.env.Lchown
	h.env.Lchown = func(path string, uid, gid int) error {
		if path == lifecycleDir {
			return &fs.PathError{Op: "lchown", Path: path, Err: syscall.ENOSPC}
		}
		return chown(path, uid, gid)
	}
	failed := h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("1.0.0")})
	requireError(t, failed, codeState)
	got := messagesOf(failed.Errors, codeDiskFull)
	if want := "no space left on the filesystem holding " + h.env.Layout.LifecycleDir; !strings.Contains(got, want) {
		t.Fatalf("disk_full = %q, want it to contain %q", got, want)
	}
	if failed.Errors[0].Code != codeState {
		t.Fatalf("the refusal's code is no longer first: %+v", failed.Errors)
	}
}
