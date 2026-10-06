// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cfgtxn

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

func openLockFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
}

// tryLock locks byte 0 for length 1, the region Python's msvcrt.locking
// takes in file_lock.locked_file_update.
func tryLock(f *os.File) (busy bool, err error) {
	ol := new(windows.Overlapped)
	err = windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
	if err == nil {
		return false, nil
	}
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) {
		return true, nil
	}
	return false, err
}

func unlock(f *os.File) {
	_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, new(windows.Overlapped))
}

// keepOwner is a no-op: the temp file inherits the directory's DACL, as the
// previous Go writers did.
func keepOwner(*os.File, string) {}

// replaceDurable is MoveFileExW(REPLACE_EXISTING|WRITE_THROUGH), retried for
// the short sharing locks that indexers and scanners take (bounded, about
// 270 ms in total).
func replaceDurable(source, target string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	delay := 10 * time.Millisecond
	for attempt := 1; ; attempt++ {
		err = windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
		if err == nil {
			return nil
		}
		transient := errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED)
		if !transient || attempt >= 8 {
			return err
		}
		time.Sleep(delay)
		if delay < 50*time.Millisecond {
			delay *= 2
		}
	}
}

// syncDir is a no-op: MOVEFILE_WRITE_THROUGH already flushes the rename.
func syncDir(string) error { return nil }
