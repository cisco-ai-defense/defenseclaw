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
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// lockFileName lives in the root-only lifecycle directory. A lock in
// /run/lock (mode 1777) could be pre-created and held by a standard user.
const lockFileName = "lifecycle.lock"

// errLockBusy reports that another lifecycle run holds the lock.
var errLockBusy = errors.New("another DefenseClaw enterprise lifecycle run is in progress")

// verifyBusyNextStep is what an administrator does about errLockBusy on
// verify, which has no --lock-wait.
const verifyBusyNextStep = "wait for it to finish, then rerun verify"

// lockBusyNextStep is what an administrator does about errLockBusy on an
// action that takes --lock-wait. It names the wait this run already did, so
// a run given --lock-wait 1s is not told to pass --lock-wait (GAP-1722).
func lockBusyNextStep(waited time.Duration) string {
	if waited >= MaxLockWait {
		return "waited " + formatLockWait(waited) + " for it; wait for it to finish, then rerun"
	}
	return "waited " + formatLockWait(waited) + " for it; wait for it to finish, then rerun, or pass a longer --lock-wait <duration> (at most " +
		formatLockWait(MaxLockWait) + ") to wait longer"
}

// formatLockWait prints a whole number of minutes as "10m", not "10m0s".
func formatLockWait(wait time.Duration) string {
	if wait >= time.Minute && wait%time.Minute == 0 {
		return fmt.Sprintf("%dm", int(wait/time.Minute))
	}
	return wait.String()
}

type lifecycleLock struct {
	file *os.File
}

// acquireLock takes the exclusive lifecycle lock, polling until timeout.
func (e *Env) acquireLock(ctx context.Context) (*lifecycleLock, error) {
	path := filepath.Join(e.P(e.Layout.LifecycleDir), lockFileName)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lifecycle lock %s: %w", path, err)
	}
	deadline := e.Now().Add(e.LockTimeout)
	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return &lifecycleLock{file: file}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = file.Close()
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}
		if !e.Now().Before(deadline) {
			_ = file.Close()
			return nil, errLockBusy
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-time.After(e.PollInterval):
		}
	}
}

func (l *lifecycleLock) release() {
	if l == nil || l.file == nil {
		return
	}
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	_ = l.file.Close()
}
