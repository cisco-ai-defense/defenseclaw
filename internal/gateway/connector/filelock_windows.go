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

//go:build windows

package connector

import (
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

var (
	windowsManagedFileLockTimeout = 2 * time.Second
	windowsManagedFileLockRetry   = 25 * time.Millisecond
)

// withFileLock acquires an exclusive, blocking lock on path+".lock" before
// running fn, and releases it when fn returns.
//
// It uses Windows LockFileEx (exclusive, without LOCKFILE_FAIL_IMMEDIATELY),
// which blocks until the lock is available and is released automatically by
// the OS when the holding process exits or the handle is closed. That gives
// the same mutual-exclusion and crash-safety guarantees as flock(LOCK_EX) on
// Unix. The earlier O_CREATE|O_EXCL sentinel-file approach was non-blocking
// (it returned an error on contention instead of waiting) and left a stale
// lock file that hard-failed all callers for up to a minute after a crash.
func withFileLock(path string, fn func() error) error {
	return withFileLockMode(path, false, fn)
}

// withFileLockMode preserves ordinary Windows connector behavior while giving
// the LocalSystem guardian a hard acquisition deadline. A target user can hold
// a per-user .lock indefinitely; managed reconciliation must report that row
// and continue to later targets/ticks instead of blocking the service thread.
func withFileLockMode(path string, managedEnterprise bool, fn func() error) error {
	lockPath := path + ".lock"

	// O_RDWR (not O_EXCL): every caller opens the shared lock file; mutual
	// exclusion is enforced by the byte-range lock below, not by file
	// existence. Go opens with FILE_SHARE_READ|WRITE|DELETE so concurrent
	// processes can open the handle and then contend on the lock.
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open lock file %s: %w", lockPath, err)
	}
	defer lockFile.Close()

	handle := windows.Handle(lockFile.Fd())
	overlapped := new(windows.Overlapped)
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK)
	if managedEnterprise {
		flags |= windows.LOCKFILE_FAIL_IMMEDIATELY
	}
	deadline := time.Now().Add(windowsManagedFileLockTimeout)
	for {
		err = windows.LockFileEx(handle, flags, 0, 1, 0, overlapped)
		if err == nil {
			break
		}
		if !managedEnterprise || !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return fmt.Errorf("acquire lock %s: %w", lockPath, err)
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf(
				"acquire managed lock %s: timed out after %s: %w",
				lockPath,
				windowsManagedFileLockTimeout,
				err,
			)
		}
		delay := windowsManagedFileLockRetry
		if remaining := time.Until(deadline); delay > remaining {
			delay = remaining
		}
		if delay > 0 {
			time.Sleep(delay)
		}
	}
	defer func() {
		_ = windows.UnlockFileEx(handle, 0, 1, 0, overlapped)
	}()

	return fn()
}
