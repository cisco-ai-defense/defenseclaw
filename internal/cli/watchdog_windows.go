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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
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
// CREATE_BREAKAWAY_FROM_JOB is scoped to this managed, PID-file-owned child
// when the enclosing job permits it, so it survives a successful TUI launch
// without allowing arbitrary descendants to escape the TUI's kill-on-close
// job. Restricted supervisors such as CI runners keep the watchdog in their
// job while the other flags still detach it from the launcher's console.
func watchdogSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: watchdogCreationFlags()}
}

func watchdogCreationFlags() uint32 {
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	err := windows.QueryInformationJobObject(
		0,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
		nil,
	)
	return watchdogCreationFlagsForJob(err, info.BasicLimitInformation.LimitFlags)
}

func watchdogCreationFlagsForJob(queryErr error, limitFlags uint32) uint32 {
	flags := uint32(windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS)
	// Explicit breakaway fails with ERROR_ACCESS_DENIED unless the enclosing
	// job opts in. A process outside a job may request it harmlessly, while
	// SILENT_BREAKAWAY requires no creation flag.
	if errors.Is(queryErr, windows.ERROR_INVALID_HANDLE) ||
		(queryErr == nil && limitFlags&windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK != 0) {
		flags |= windows.CREATE_BREAKAWAY_FROM_JOB
	}
	return flags
}

func watchdogProcessAlive(pid int, _ *os.Process) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h) //nolint:errcheck -- read-only liveness handle.
	var exitCode uint32
	if err := windows.GetExitCodeProcess(h, &exitCode); err != nil {
		return false
	}
	const stillActive = 259
	return exitCode == stillActive
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

func watchdogHasStrongProcessIdentity(info watchdogPIDInfo) bool {
	return info.StartIdentity != ""
}

const watchdogControlPrefix = `Local\DefenseClaw-Watchdog-`

func watchdogCreateControl() (string, <-chan struct{}, func(), error) {
	capability := make([]byte, 32)
	if _, err := rand.Read(capability); err != nil {
		return "", nil, nil, err
	}
	name := watchdogControlPrefix + hex.EncodeToString(capability)
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "", nil, nil, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", nil, nil, err
	}
	// Only the launching user, SYSTEM, and Administrators may signal the
	// event. The random name is also an unguessable capability persisted in
	// the ACL-protected watchdog PID record.
	sddl := fmt.Sprintf("D:P(A;;GA;;;%s)(A;;GA;;;SY)(A;;GA;;;BA)", user.User.Sid.String())
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return "", nil, nil, err
	}
	attrs := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	handle, err := windows.CreateEvent(attrs, 1, 0, namePtr)
	if err != nil {
		return "", nil, nil, err
	}

	triggered := make(chan struct{})
	waiterDone := make(chan struct{})
	go func() {
		_, _ = windows.WaitForSingleObject(handle, windows.INFINITE)
		close(triggered)
		close(waiterDone)
	}()
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			_ = windows.SetEvent(handle)
			select {
			case <-waiterDone:
			case <-time.After(time.Second):
			}
			_ = windows.CloseHandle(handle)
		})
	}
	return name, triggered, cleanup, nil
}

func validWatchdogControlName(name string) bool {
	if !strings.HasPrefix(name, watchdogControlPrefix) {
		return false
	}
	capability := strings.TrimPrefix(name, watchdogControlPrefix)
	if len(capability) != 64 {
		return false
	}
	_, err := hex.DecodeString(capability)
	return err == nil
}

func watchdogTerminate(info watchdogPIDInfo, proc *os.Process) error {
	if info.ControlName == "" {
		// Compatibility with watchdogs started before the named-event control
		// channel existed. Their detached process has no graceful signal path.
		return proc.Kill()
	}
	if !validWatchdogControlName(info.ControlName) {
		return errors.New("invalid watchdog control capability")
	}
	namePtr, err := windows.UTF16PtrFromString(info.ControlName)
	if err != nil {
		return err
	}
	handle, err := windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, namePtr)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle) //nolint:errcheck -- event signal already records success/failure.
	return windows.SetEvent(handle)
}

func watchdogKill(proc *os.Process) error {
	return proc.Kill()
}

func watchdogWaitForExit(proc *os.Process, _ watchdogPIDInfo, timeout time.Duration) bool {
	millis := timeout.Milliseconds()
	if millis < 0 {
		millis = 0
	} else if timeout > 0 && millis == 0 {
		millis = 1
	}
	const maxFiniteWaitMillis = int64(^uint32(0) - 1)
	if millis > maxFiniteWaitMillis {
		millis = maxFiniteWaitMillis
	}
	var result uint32
	var waitErr error
	if err := proc.WithHandle(func(handle uintptr) {
		result, waitErr = windows.WaitForSingleObject(windows.Handle(handle), uint32(millis))
	}); err != nil {
		return false
	}
	return waitErr == nil && result == windows.WAIT_OBJECT_0
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
	// Apply the owner-only DACL before persisting the random control-event
	// capability. A newly created file may inherit a broader parent DACL, so
	// writing first would create a small disclosure window.
	if err := safefile.ProtectFile(path); err != nil {
		_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol)
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
func watchdogIsLocked(path string) (bool, watchdogPIDInfo, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		if os.IsNotExist(err) {
			return false, watchdogPIDInfo{}, nil
		}
		return false, watchdogPIDInfo{}, err
	}
	defer f.Close()
	ol := &windows.Overlapped{OffsetHigh: watchdogLockOffsetHigh}
	if err := windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, ol); err != nil {
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return false, watchdogPIDInfo{}, err
		}
		info, readErr := readWatchdogPIDInfoFile(f)
		if readErr != nil {
			return false, watchdogPIDInfo{}, readErr
		}
		return true, info, nil
	}
	if err := windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol); err != nil {
		return false, watchdogPIDInfo{}, err
	}
	return false, watchdogPIDInfo{}, nil
}
