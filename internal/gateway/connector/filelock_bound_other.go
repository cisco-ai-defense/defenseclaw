//go:build !windows && !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"os"
	"syscall"
	"time"
)

const boundedUserLocks = false

// ErrLockBusy is never returned here: locks block until acquired.
var ErrLockBusy = errors.New("lock_busy")

var errLockReplaced = errors.New("lock file was replaced while waiting")

func acquireFlock(file *os.File, _ string, _ *time.Time) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_EX)
}

func ownedLockPermCheck(path string, _ *os.File, info os.FileInfo) error {
	return otlpValidatePerm(path, info)
}
