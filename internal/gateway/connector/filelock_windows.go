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
	"fmt"
	"os"
	"time"
)

// withFileLock on Windows uses an exclusive open as a lock mechanism.
// Windows file locking is mandatory (opening with exclusive access blocks
// other openers), which provides the same mutual exclusion guarantee as
// flock on Unix.
func withFileLock(path string, fn func() error) error {
	lockPath := path + ".lock"
	const staleLockAge = 60 * time.Second

	// Clean up stale lock files from crashed processes.
	if info, err := os.Stat(lockPath); err == nil {
		if time.Since(info.ModTime()) > staleLockAge {
			_ = os.Remove(lockPath)
		}
	}

	// On Windows, O_CREATE|O_EXCL ensures only one process can hold the lock.
	// If the file already exists (held by another process), OpenFile fails.
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("acquire lock %s: %w", lockPath, err)
	}
	defer func() {
		lockFile.Close()
		_ = os.Remove(lockPath)
	}()

	return fn()
}
