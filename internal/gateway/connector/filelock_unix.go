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

	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open lock file %s: %w", lockPath, err)
	}
	defer lockFile.Close()

	if err := lockFileExclusive(lockFile, lockPath); err != nil {
		return fmt.Errorf("acquire lock %s: %w", lockPath, err)
	}
	defer func() {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		_ = os.Remove(lockPath)
	}()

	return fn()
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
