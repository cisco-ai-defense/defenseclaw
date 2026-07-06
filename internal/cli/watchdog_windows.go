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

package cli

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

// watchdogShutdownSignals returns the OS signals that stop the foreground
// watchdog loop. Windows supports interrupt/terminate delivery through os/signal.
func watchdogShutdownSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

// watchdogStartDir keeps the current working directory on Windows. "/" is not
// a stable process directory across Windows shells and drives.
func watchdogStartDir() string {
	return ""
}

// watchdogSysProcAttr returns a SysProcAttr that starts the background
// watchdog truly detached. Setsid is a Unix concept; the Windows equivalent
// is CREATE_NEW_PROCESS_GROUP (so the launcher's Ctrl+C/Ctrl+Break is not
// inherited and the child is addressable by GenerateConsoleCtrlEvent for a
// graceful stop) combined with DETACHED_PROCESS (drop the inherited console
// so a closing terminal cannot deliver CTRL_CLOSE and kill the watchdog).
// CREATE_BREAKAWAY_FROM_JOB is scoped to this managed, PID-file-owned child so
// it survives a successful TUI launch without allowing arbitrary descendants
// to escape the TUI's kill-on-close job.
func watchdogSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP |
			windows.DETACHED_PROCESS |
			windows.CREATE_BREAKAWAY_FROM_JOB,
	}
}

func watchdogProcessAlive(pid int, _ *os.Process) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	_ = windows.CloseHandle(h)
	return true
}

func watchdogProcessStartIdentity(pid int) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h) //nolint:errcheck -- read-only identity handle.
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return ""
	}
	return fmt.Sprintf("%d", creation.Nanoseconds())
}

func watchdogTerminate(proc *os.Process) error {
	// Prefer a graceful stop via Ctrl+Break to the watchdog's process group.
	// Go maps a console Ctrl+Break to os.Interrupt, which the watchdog loop
	// handles through signal.NotifyContext. A detached watchdog has no shared
	// console, so this returns an error; fall back to TerminateProcess. The
	// caller waits for exit and force-kills on timeout.
	if err := windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(proc.Pid)); err == nil {
		return nil
	}
	return proc.Kill()
}

func watchdogKill(proc *os.Process) error {
	return proc.Kill()
}

// watchdogLockOffsetHigh places the advisory lock on a single sentinel byte
// far beyond any PID-file content, so writeWatchdogPIDInfo's truncate-then-
// write of the JSON payload (which lives at offset 0) never overlaps — and
// therefore never conflicts with — the locked region.
const watchdogLockOffsetHigh = 0x4000_0000

// acquireWatchdogPIDFile opens (creating if missing) the PID file, takes an
// exclusive non-blocking lock on a sentinel byte via LockFileEx, and writes
// the JSON fingerprint. The returned file MUST stay open for the watchdog's
// whole lifetime; closing it releases the lock. Returns an error when
// another process already holds the lock (DeepSec S3.HIGH_BUG).
func acquireWatchdogPIDFile(path string, info watchdogPIDInfo) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	ol := &windows.Overlapped{OffsetHigh: watchdogLockOffsetHigh}
	if err := windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, ol); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := writeWatchdogPIDInfo(f, info); err != nil {
		_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol)
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// watchdogIsLocked reports whether the PID-file lock is currently held by
// another process (the live watchdog). It releases any lock it acquires
// before returning so the real watchdog child can take it.
func watchdogIsLocked(path string) (bool, watchdogPIDInfo) {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return false, watchdogPIDInfo{}
	}
	defer f.Close()
	ol := &windows.Overlapped{OffsetHigh: watchdogLockOffsetHigh}
	if err := windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, ol); err != nil {
		info, _ := readWatchdogPIDInfo(path)
		return true, info
	}
	_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol)
	return false, watchdogPIDInfo{}
}
