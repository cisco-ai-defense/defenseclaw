// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"time"
)

// withFileLock acquires an exclusive advisory lock on path+".lock" before
// running fn, and releases it when fn returns. The lock file is cleaned up
// on success. Stale lock files older than staleLockAge are removed before
// attempting acquisition.
func withFileLock(path string, fn func() error) error {
	return withFileLockMode(path, false, fn)
}

func withFileLockMode(path string, _ bool, fn func() error) error {
	lockPath := path + ".lock"
	const staleLockAge = 60 * time.Second

	// Clean up stale lock files from crashed processes.
	if info, err := os.Stat(lockPath); err == nil {
		if time.Since(info.ModTime()) > staleLockAge {
			_ = os.Remove(lockPath)
		}
	}

	lockFile, err := openHeldLockFile(lockPath)
	if err != nil {
		return err
	}
	defer lockFile.Close()
	defer func() {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		_ = os.Remove(lockPath)
	}()

	return fn()
}

// openHeldLockFile opens lockPath and takes its exclusive flock. A holder
// (this release, or an older one) removes the lock file when it releases
// it, so a writer that waited on the file it opened can wake up holding an
// inode the pathname no longer names, while another writer locks the new
// file (GAP-0344). After each acquisition the held file must still be the
// one lockPath names; otherwise it is released and the pathname opened
// again.
func openHeldLockFile(lockPath string) (*os.File, error) {
	for {
		lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open lock file %s: %w", lockPath, err)
		}
		if err := lockFileExclusive(lockFile, lockPath); err != nil {
			_ = lockFile.Close()
			return nil, fmt.Errorf("acquire lock %s: %w", lockPath, err)
		}
		held, err := lockFile.Stat()
		if err == nil {
			var named os.FileInfo
			if named, err = os.Stat(lockPath); err == nil && os.SameFile(held, named) {
				return lockFile, nil
			}
		}
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		_ = lockFile.Close()
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("inspect lock file %s: %w", lockPath, err)
		}
	}
}

// fileLockContendedHookForTest, when set, is told that a lock acquisition
// found the lock held and is about to wait for it (as
// windowsLockContendedHookForTest is on Windows).
var fileLockContendedHookForTest atomic.Pointer[func(lockPath string)]

// lockFileExclusive takes the exclusive flock on f, blocking until it is
// free. A contended attempt is reported to the test hook before the wait.
func lockFileExclusive(f *os.File, lockPath string) error {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if !errors.Is(err, syscall.EWOULDBLOCK) {
		return err
	}
	if hook := fileLockContendedHookForTest.Load(); hook != nil {
		(*hook)(lockPath)
	}
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

// RemoveIdleFileLockSentinels does nothing here: withFileLockMode removes
// its lock file when it releases the lock.
func RemoveIdleFileLockSentinels() {}
