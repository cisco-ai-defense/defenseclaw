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

	// Clean up stale lock files from crashed processes. Where locks are
	// bounded, a lock file is never unlinked before it is acquired: an old
	// file may still be held, and flock locks die with their process anyway.
	if info, err := os.Stat(lockPath); err == nil && !boundedUserLocks {
		if time.Since(info.ModTime()) > staleLockAge {
			_ = os.Remove(lockPath)
		}
	}

	var lockFile *os.File
	for attempt := 0; ; attempt++ {
		file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return fmt.Errorf("open lock file %s: %w", lockPath, err)
		}
		err = acquireFlock(file, lockPath)
		if err == nil {
			lockFile = file
			break
		}
		file.Close()
		if errors.Is(err, errLockReplaced) && attempt < 8 {
			continue
		}
		return fmt.Errorf("acquire lock %s: %w", lockPath, err)
	}
	defer lockFile.Close()
	defer func() {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		_ = os.Remove(lockPath)
	}()

	return fn()
}
