// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisepolicy

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// lockForeignHookRemovalFile takes a shared or exclusive lock on the file's
// first byte within ctx, trying again every poll. Locks of different handles
// exclude each other, as flocks of different opens do.
func lockForeignHookRemovalFile(ctx context.Context, file *os.File, exclusive bool, poll time.Duration) error {
	flags := uint32(windows.LOCKFILE_FAIL_IMMEDIATELY)
	if exclusive {
		flags |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	for {
		var overlapped windows.Overlapped
		err := windows.LockFileEx(windows.Handle(file.Fd()), flags, 0, 1, 0, &overlapped)
		if err == nil {
			return nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) && !errors.Is(err, windows.ERROR_IO_PENDING) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

func unlockForeignHookRemovalFile(file *os.File) {
	var overlapped windows.Overlapped
	_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped)
}

// openForeignHookLockFile opens or creates a lock file, never through a
// reparse point. It inherits the data directory's protected DACL.
func openForeignHookLockFile(path string) (*os.File, error) {
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return os.NewFile(uintptr(handle), path), nil
}

// foreignHookLockFileOwner has nothing to do on Windows: the file inherits
// the data directory's DACL, which lets SYSTEM and the gateway service open
// it and no standard user.
func foreignHookLockFileOwner(*os.File, string) error { return nil }

// createForeignHookSessionStoreParent creates the folder that holds the
// accounts' private session stores when it is missing; it inherits the data
// directory's DACL.
func createForeignHookSessionStoreParent(_, dir string) error {
	if info, err := os.Lstat(dir); err == nil {
		if !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return fmt.Errorf("%s is not a folder", dir)
		}
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return nil
}

// PublishedSessionKeysLockPath is the key lock in the standalone lifecycle
// folder lifecycleDir (managed.StandaloneLayout.LifecycleDir), which only
// SYSTEM and Administrators can reach and where the lifecycle command keeps
// its other locks across an installer run.
func PublishedSessionKeysLockPath(lifecycleDir string) string {
	return filepath.Join(lifecycleDir, "session-keys.lock")
}

// publishedSessionKeysLockGuardianCreates is true: a lifecycle command
// makes the lock only when the lifecycle folder exists before its installer
// runs, so the guardian of a first install makes it.
const publishedSessionKeysLockGuardianCreates = true

// openPublishedSessionKeysLockFile opens the key lock, creating it only when
// create is set, never through a reparse point. It inherits the lifecycle
// folder's protected DACL.
func openPublishedSessionKeysLockFile(path string, create bool) (*os.File, error) {
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, err
	}
	disposition := uint32(windows.OPEN_EXISTING)
	if create {
		disposition = windows.OPEN_ALWAYS
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, disposition,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil, fs.ErrNotExist
		}
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return os.NewFile(uintptr(handle), path), nil
}
