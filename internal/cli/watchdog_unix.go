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
	"os"
	"syscall"
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

func watchdogTerminate(proc *os.Process) error {
	return proc.Signal(syscall.SIGTERM)
}

func watchdogKill(proc *os.Process) error {
	return proc.Signal(syscall.SIGKILL)
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

// watchdogIsLocked reports whether the PID-file flock is currently held by
// another process (the live watchdog). It always releases any lock it
// acquires before returning so the real watchdog child can take it.
func watchdogIsLocked(path string) (bool, watchdogPIDInfo) {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return false, watchdogPIDInfo{}
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		info, _ := readWatchdogPIDInfo(path)
		return true, info
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return false, watchdogPIDInfo{}
}
