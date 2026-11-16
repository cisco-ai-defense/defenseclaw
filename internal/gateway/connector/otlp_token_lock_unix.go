// Copyright 2026 Cisco Systems, Inc. and its affiliates
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

// withOTLPPathTokenLock uses a persistent lock inode. Unlinking an advisory
// lock file on release is unsafe: a waiter can hold the old inode while a new
// caller creates and locks a different inode at the same path.
func withOTLPPathTokenLock(path string, fn func() error) error {
	return withOwnedFileLock(path+".lock", fn)
}

// withOwnedFileLock serializes one filesystem transaction across independent
// DefenseClaw processes. Callers that also need same-process portability must
// pair it with their subsystem mutex: flock semantics for separately opened
// descriptors differ across Unix variants.
func withOwnedFileLock(lockPath string, fn func() error) error {
	var deadline time.Time
	for attempt := 0; ; attempt++ {
		file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|otlpOpenNoFollow(), 0o600)
		if err != nil {
			return fmt.Errorf("open DefenseClaw lock: %w", err)
		}
		if err := validateOwnedLockFile(lockPath, file); err != nil {
			file.Close()
			return err
		}
		recordEmptyLockCreated(lockPath, file)
		if err := acquireFlock(file, lockPath, &deadline); err != nil {
			file.Close()
			if errors.Is(err, errLockReplaced) && attempt < 8 {
				continue
			}
			return fmt.Errorf("acquire DefenseClaw lock: %w", err)
		}
		defer file.Close()
		defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN) //nolint:errcheck // best-effort unlock on close
		return fn()
	}
}
