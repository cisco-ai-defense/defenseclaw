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
	"io"
	"os"
	"strconv"
	"syscall"
	"time"
)

// watchdogShutdownSignals returns the OS signals that stop the foreground
// watchdog loop.
func watchdogShutdownSignals() []os.Signal {
	return []os.Signal{syscall.SIGINT, syscall.SIGTERM}
}

// watchdogStartDir returns the detached watchdog working directory.
func watchdogStartDir() string {
	return "/"
}

// watchdogSysProcAttr returns a SysProcAttr that starts the watchdog child in
// a new session (Setsid), detaching it from the parent's controlling terminal.
func watchdogSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

func watchdogProcessAlive(_ int, proc *os.Process) bool {
	return proc.Signal(syscall.Signal(0)) == nil
}

func watchdogProcessStartIdentity(_ int) string { return "" }

func watchdogHasStrongProcessIdentity(info watchdogPIDInfo) bool {
	if info.Executable == "" {
		return false
	}
	current, err := os.Readlink("/proc/" + strconv.Itoa(info.PID) + "/exe")
	return err == nil && current != ""
}

func watchdogRequiresStrongProcessIdentity() bool { return false }

func watchdogProcessExecutableMatches(info watchdogPIDInfo) bool {
	if info.Executable == "" {
		return true
	}
	current, err := os.Readlink("/proc/" + strconv.Itoa(info.PID) + "/exe")
	if err != nil || current == "" {
		// Preserve the established best-effort compatibility on non-/proc Unix
		// platforms. Linux callers with a live signalable process fail closed.
		return true
	}
	return current == info.Executable
}

func watchdogCreateControl() (string, <-chan struct{}, func(), error) {
	return "", nil, func() {}, nil
}

func watchdogTerminate(_ watchdogPIDInfo, proc *os.Process) error {
	return proc.Signal(syscall.SIGTERM)
}

func watchdogKill(proc *os.Process) error {
	return proc.Signal(syscall.SIGKILL)
}

func watchdogWaitForExit(_ *os.Process, info watchdogPIDInfo, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if !verifyWatchdogProcess(info) {
			return true
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}
		if remaining > 50*time.Millisecond {
			remaining = 50 * time.Millisecond
		}
		time.Sleep(remaining)
	}
}

// acquireWatchdogPIDFile opens (creating if missing) the PID file with
// 0600 perms, takes an exclusive non-blocking flock, and writes the JSON
// fingerprint. The returned file MUST stay open for the watchdog's whole
// lifetime; closing it releases the kernel flock. Returns an error when
// another process already holds the lock (DeepSec S3.HIGH_BUG).
func acquireWatchdogPIDFile(path string, info watchdogPIDInfo) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := writeWatchdogPIDInfo(f, info); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// On Unix, do not inspect the flock until the child has finished publishing
// its canonical record. Otherwise the readiness observer can acquire the
// newly-created, still-empty file between open and flock and make the child
// lose its one-shot ownership acquisition.
func watchdogStartPublicationReady(path string, expectedPID int) (bool, error) {
	info, err := readWatchdogPIDInfo(path)
	if err != nil {
		return false, err
	}
	return info.PID == expectedPID, nil
}

// inspectWatchdogPIDOwnership reports whether the PID-file flock is currently held by
// another process (the live watchdog). It always releases any lock it
// acquires before returning so the real watchdog child can take it.
func inspectWatchdogPIDOwnership(path string) watchdogPIDOwnershipInspection {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		if os.IsNotExist(err) {
			return watchdogPIDOwnershipInspection{}
		}
		return watchdogPIDOwnershipInspection{publicationErr: err}
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return watchdogPIDOwnershipInspection{publicationErr: err}
		}
		info, readErr := readWatchdogPIDInfoFile(f)
		if readErr != nil {
			return watchdogPIDOwnershipInspection{locked: true, publicationErr: readErr}
		}
		return watchdogPIDOwnershipInspection{locked: true, info: info}
	}
	info, readErr := readWatchdogPIDInfoFile(f)
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_UN); err != nil {
		return watchdogPIDOwnershipInspection{publicationErr: err}
	}
	return watchdogPIDOwnershipInspection{info: info, publicationErr: readErr}
}

func removeWatchdogPIDFileIf(path string, matches func([]byte) bool) (bool, error) {
	if matches == nil {
		return false, errors.New("watchdog: nil PID file matcher")
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return false, nil
		}
		return false, err
	}
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()
	if _, err := f.Seek(0, 0); err != nil {
		return false, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxWatchdogPIDFileBytes+1))
	if err != nil {
		return false, err
	}
	if len(data) > maxWatchdogPIDFileBytes {
		return false, errors.New("watchdog: PID file exceeds inspection limit")
	}
	if !matches(data) {
		return false, nil
	}
	opened, err := f.Stat()
	if err != nil {
		return false, err
	}
	named, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if !os.SameFile(opened, named) {
		return false, nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	return true, nil
}
