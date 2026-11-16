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

// readOnlyBusyNextStep is what an administrator does about errLockBusy on
// verify or status, which have no --lock-wait. It names the wait this run
// already did, as lockBusyNextStep does (GAP-2409); status also says why it
// checked nothing (GAP-2246).
func readOnlyBusyNextStep(waited time.Duration, action string) string {
	next := "waited " + FormatLockWait(waited) + " for it; "
	if action == ActionStatus {
		next += "it may be stopping or restarting the services, so status checked nothing but the installed version; "
	}
	return next + "wait for it to finish, then rerun " + action
}

// lockBusyNextStep is what an administrator does about errLockBusy on an
// action that takes --lock-wait. It names the wait this run already did, so
// a run given --lock-wait 1s is not told to pass --lock-wait (GAP-1722).
func lockBusyNextStep(waited time.Duration) string {
	if waited >= MaxLockWait {
		return "waited " + FormatLockWait(waited) + " for it; wait for it to finish, then rerun"
	}
	return "waited " + FormatLockWait(waited) + " for it; wait for it to finish, then rerun, or pass a longer --lock-wait <duration> (at most " +
		FormatLockWait(MaxLockWait) + ") to wait longer"
}

// FormatLockWait prints a whole number of minutes as "10m", not "10m0s".
func FormatLockWait(wait time.Duration) string {
	if wait >= time.Minute && wait%time.Minute == 0 {
		return fmt.Sprintf("%dm", int(wait/time.Minute))
	}
	return wait.String()
}

type lifecycleLock struct {
	file *os.File
}

// errLockRemoved reports that the uninstall this run waited for removed the
// lifecycle lock, and the lifecycle directory with it, while it held it. An
// uninstall then has nothing left to do and is a no-op; any other action
// reports busy.
var errLockRemoved = errors.New("DefenseClaw enterprise was uninstalled while this run waited for the lifecycle lock, so nothing was changed")

// acquireLock takes the exclusive lifecycle lock, polling until timeout.
//
// An uninstall that leaves nothing else in the lifecycle directory removes
// the lock file while it holds it (GAP-0112, GAP-0101). A run that opened
// the file before that wakes up holding a removed inode, which no longer
// excludes anybody: it opens the path again, and when the directory is gone
// it stops with errLockRemoved instead of creating the lock again.
func (e *Env) acquireLock(ctx context.Context) (*lifecycleLock, error) {
	path := filepath.Join(e.P(e.Layout.LifecycleDir), lockFileName)
	deadline := e.Now().Add(e.LockTimeout)
	for reopened := false; ; reopened = true {
		file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			if reopened && errors.Is(err, os.ErrNotExist) {
				return nil, errLockRemoved
			}
			return nil, fmt.Errorf("open lifecycle lock %s: %w", path, err)
		}
		if err := e.flockUntil(ctx, file, path, deadline); err != nil {
			_ = file.Close()
			return nil, err
		}
		held, statErr := file.Stat()
		named, lstatErr := os.Lstat(path)
		if statErr == nil && lstatErr == nil && os.SameFile(held, named) {
			return &lifecycleLock{file: file}, nil
		}
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}
}

// flockUntil takes an exclusive flock on file, polling until deadline.
func (e *Env) flockUntil(ctx context.Context, file *os.File, path string, deadline time.Time) error {
	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return fmt.Errorf("lock %s: %w", path, err)
		}
		if !e.Now().Before(deadline) {
			return errLockBusy
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
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

// holdLifecycleMarker publishes the lifecycle run marker
// (managed.StandaloneLayout.LifecycleMarkerPath) for a run that holds the
// lifecycle lock and may change the deployment, and returns what removes it
// again. The managed hooks of this computer answer a gateway they cannot
// reach closed while it exists, whatever the administrator chose for an
// outage: a run stops, restarts or rolls back the gateway, and its lock is
// in the root-only lifecycle directory, which no account can read (GAP-1074).
// The run removes it before it releases the lock, after the gateway it
// started is ready or the run failed. One a killed run left behind keeps
// the hooks closed until the next run ends, or until the computer starts
// again (/run and /var/run are emptied at boot).
func (e *Env) holdLifecycleMarker() (func(), error) {
	if e.Layout.LifecycleMarkerPath == "" {
		return func() {}, nil
	}
	path := e.P(e.Layout.LifecycleMarkerPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("publish the lifecycle marker %s: %w", path, err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return nil, fmt.Errorf("publish the lifecycle marker %s: %w", path, err)
	}
	_, writeErr := fmt.Fprintf(file, "%d\n", os.Getpid())
	if closeErr := file.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("publish the lifecycle marker %s: %w", path, writeErr)
	}
	return func() { _ = os.Remove(path) }, nil
}
