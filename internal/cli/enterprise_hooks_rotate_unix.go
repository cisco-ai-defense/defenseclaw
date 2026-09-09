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

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const enterpriseHookRotationMinFreeBytes = 4 << 20

func withEnterpriseHookRotationLock(
	dataDir string,
	fn func() (enterpriseHookRotationJournal, error),
) (enterpriseHookRotationJournal, error) {
	var empty enterpriseHookRotationJournal
	// The authorization directory resolves to a sibling of dataDir
	// (dataDir + "-hook-guardian"), not to the dataDir/hooks path guarded
	// elsewhere. Creating and opening the lock by plain path let a swapped
	// symlink redirect it, so two concurrent rotations could each flock a
	// *different* file and bypass mutual exclusion entirely. Bind the traversal
	// to the authorization directory's parent so no component can be swapped.
	lockPath := enterpriseHookRotationLockPath(dataDir)
	lockDir := filepath.Dir(lockPath)
	if err := refuseEnterpriseHookRotationSymlink(lockDir, "rotation lock directory"); err != nil {
		return empty, err
	}
	lockRoot, err := os.OpenRoot(filepath.Dir(lockDir))
	if err != nil {
		return empty, fmt.Errorf("enterprise hooks rotate: bind lock directory parent: %w", err)
	}
	defer func() { _ = lockRoot.Close() }()
	lockLeaf := filepath.Base(lockDir)
	if err := lockRoot.Mkdir(lockLeaf, 0o750); err != nil && !errors.Is(err, os.ErrExist) {
		return empty, fmt.Errorf("enterprise hooks rotate: create lock directory: %w", err)
	}
	file, err := lockRoot.OpenFile(
		filepath.Join(lockLeaf, filepath.Base(lockPath)),
		os.O_CREATE|os.O_RDWR,
		0o600,
	)
	if err != nil {
		return empty, fmt.Errorf("enterprise hooks rotate: open lock: %w", err)
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		return empty, fmt.Errorf("enterprise hooks rotate: acquire lock: %w", err)
	}
	defer func() { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN) }()
	return fn()
}

func enterpriseHookRotationLockHeld(dataDir string) (bool, error) {
	lockPath := enterpriseHookRotationLockPath(dataDir)
	file, err := os.OpenFile(lockPath, os.O_RDWR, 0o600)
	if errorsIsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return true, nil
	}
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	return false, nil
}

func enterpriseHookRotationFileOwner(info os.FileInfo) (int, int, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, -1, fmt.Errorf("enterprise hooks rotate: missing POSIX file owner")
	}
	return int(stat.Uid), int(stat.Gid), nil
}

func enterpriseHookRotationRestoreOwner(snapshot enterpriseHookRotationSnapshot) error {
	if snapshot.UID < 0 || snapshot.GID < 0 {
		return nil
	}
	return os.Chown(snapshot.Path, snapshot.UID, snapshot.GID)
}

func checkEnterpriseHookRotationSpace(dataDir string) error {
	var stat syscall.Statfs_t
	path := filepath.Dir(enterpriseHookRotationLockPath(dataDir))
	if err := syscall.Statfs(path, &stat); err != nil {
		if errorsIsNotExist(err) {
			path = dataDir
			if err := syscall.Statfs(path, &stat); err != nil {
				return fmt.Errorf("enterprise hooks rotate: inspect free space: %w", err)
			}
		} else {
			return fmt.Errorf("enterprise hooks rotate: inspect free space: %w", err)
		}
	}
	free := uint64(stat.Bavail) * uint64(stat.Bsize)
	if free < enterpriseHookRotationMinFreeBytes {
		return fmt.Errorf("enterprise hooks rotate: insufficient free space")
	}
	return nil
}

func errorsIsNotExist(err error) bool {
	return err != nil && os.IsNotExist(err)
}

func windowsManagedRotationBusy(string) error { return nil }

func executeManagedRotationPrepare(req enterpriseHookRotationRequest) (enterpriseHookRotationJournal, error) {
	return executeEnterpriseHookRotationPrepare(req)
}

func executeManagedRotationCommit(req enterpriseHookRotationRequest) (enterpriseHookRotationJournal, error) {
	return executeEnterpriseHookRotationCommit(req)
}

func executeManagedRotationRollback(req enterpriseHookRotationRequest) (enterpriseHookRotationJournal, error) {
	return executeEnterpriseHookRotationRollback(req)
}
