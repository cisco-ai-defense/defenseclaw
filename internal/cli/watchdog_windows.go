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
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// watchdogShutdownSignals returns the OS signals that stop the foreground
// watchdog loop. Windows supports interrupt/terminate delivery through os/signal.
func watchdogShutdownSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

// watchdogStartDir keeps the detached watchdog out of the protected data
// directory. Windows pins a process working directory against rename/delete;
// inheriting the gateway launcher's data-root cwd makes Doctor's exact custody
// checks fail while protection is healthy. The executable directory is the
// trusted, stable launch boundary.
func watchdogStartDir(executable string) string {
	return filepath.Dir(filepath.Clean(executable))
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
	h, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE,
		false,
		uint32(pid),
	)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h) //nolint:errcheck -- read-only liveness handle.
	result, err := windows.WaitForSingleObject(h, 0)
	if err != nil {
		return false
	}
	return result == uint32(windows.WAIT_TIMEOUT)
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

const (
	// A Windows indexer or security scanner can retain a short-lived writer
	// between publication and the watchdog's read-only ownership open. Keep
	// this handoff bounded: a persistent writer or competing watchdog must
	// still fail startup rather than weakening the sharing contract.
	watchdogOwnershipHandoffMaxAttempts = 100
	watchdogOwnershipHandoffRetryDelay  = 5 * time.Millisecond
)

type watchdogOwnershipOpenFunc func(string) (*os.File, error)
type watchdogOwnershipLockFunc func(*os.File, *windows.Overlapped) error
type watchdogOwnershipSleepFunc func(time.Duration)

// acquireWatchdogPIDFile opens (creating if missing) the PID file, takes an
// exclusive non-blocking lock on a sentinel byte via LockFileEx, and writes
// the JSON fingerprint. It then transfers ownership to a read-only handle
// that denies write and delete sharing. The returned file MUST stay open for
// the watchdog's whole lifetime; closing it releases the lock. Freezing the
// published object this way lets fail-closed stable readers inspect a live
// watchdog without accepting an in-place writer or pathname replacement.
// Returns an error when another process already holds the lock
// (DeepSec S3.HIGH_BUG).
func acquireWatchdogPIDFile(path string, info watchdogPIDInfo) (*os.File, error) {
	return acquireWatchdogPIDFileWith(
		path,
		info,
		openWatchdogOwnershipFile,
		time.Sleep,
	)
}

func acquireWatchdogPIDFileWith(
	path string,
	info watchdogPIDInfo,
	openOwnership watchdogOwnershipOpenFunc,
	sleep watchdogOwnershipSleepFunc,
) (*os.File, error) {
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
	// A handle's share mode and desired access cannot be changed in place.
	// Close the publication writer, then reacquire the exact record as a
	// read-only, non-write/non-delete-shared ownership handle. Another
	// publisher can win this narrow handoff, so the new handle is locked and
	// the record it contains is compared field-for-field against what this
	// process just wrote before it is accepted.
	//
	// The fingerprint carries no secret or random capability: it is
	// {PID, Executable, StartTime, StartIdentity, ControlName}, all derived
	// from this process. What makes the comparison sufficient is PID
	// exclusivity, not unguessability -- no other live process can publish
	// this PID while this process holds it, so any record that still matches
	// after the unlocked window is necessarily the one written above. Do not
	// drop a field from watchdogPIDInfo on the assumption that the remaining
	// ones are hard to predict; the guarantee is identity, not entropy.
	if err := windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}

	owner, err := openWatchdogOwnershipFileWithRetry(path, openOwnership, sleep)
	if err != nil {
		return nil, err
	}
	if err := validateWatchdogOwnershipFile(path, owner); err != nil {
		_ = owner.Close()
		return nil, err
	}
	ownerLock, err := lockWatchdogOwnershipFileWithRetry(
		owner,
		lockWatchdogOwnershipFile,
		sleep,
	)
	if err != nil {
		_ = owner.Close()
		return nil, err
	}
	current, err := readWatchdogPIDInfoFile(owner)
	if err != nil {
		_ = windows.UnlockFileEx(windows.Handle(owner.Fd()), 0, 1, 0, ownerLock)
		_ = owner.Close()
		return nil, err
	}
	if current != info {
		_ = windows.UnlockFileEx(windows.Handle(owner.Fd()), 0, 1, 0, ownerLock)
		_ = owner.Close()
		return nil, errors.New("watchdog: PID ownership changed during publication handoff")
	}
	return owner, nil
}

func openWatchdogOwnershipFileWithRetry(
	path string,
	openOwnership watchdogOwnershipOpenFunc,
	sleep watchdogOwnershipSleepFunc,
) (*os.File, error) {
	if openOwnership == nil {
		return nil, errors.New("watchdog: nil PID ownership opener")
	}
	if sleep == nil {
		return nil, errors.New("watchdog: nil PID ownership retry sleeper")
	}
	var lastErr error
	for attempt := 0; attempt < watchdogOwnershipHandoffMaxAttempts; attempt++ {
		file, err := openOwnership(path)
		if err == nil {
			return file, nil
		}
		lastErr = err
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
			attempt+1 == watchdogOwnershipHandoffMaxAttempts {
			return nil, err
		}
		sleep(watchdogOwnershipHandoffRetryDelay)
	}
	return nil, lastErr
}

func lockWatchdogOwnershipFileWithRetry(
	file *os.File,
	lock watchdogOwnershipLockFunc,
	sleep watchdogOwnershipSleepFunc,
) (*windows.Overlapped, error) {
	if file == nil {
		return nil, errors.New("watchdog: nil PID ownership file")
	}
	if lock == nil {
		return nil, errors.New("watchdog: nil PID ownership locker")
	}
	if sleep == nil {
		return nil, errors.New("watchdog: nil PID ownership lock retry sleeper")
	}
	overlapped := &windows.Overlapped{OffsetHigh: watchdogLockOffsetHigh}
	var lastErr error
	for attempt := 0; attempt < watchdogOwnershipHandoffMaxAttempts; attempt++ {
		err := lock(file, overlapped)
		if err == nil {
			return overlapped, nil
		}
		lastErr = err
		// watchdogIsLocked may acquire the sentinel during the deliberate
		// writer-to-reader handoff. It releases that observation lock
		// immediately. A real competing watchdog retains it and exhausts this
		// bounded window.
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) ||
			attempt+1 == watchdogOwnershipHandoffMaxAttempts {
			return nil, err
		}
		sleep(watchdogOwnershipHandoffRetryDelay)
	}
	return nil, lastErr
}

func lockWatchdogOwnershipFile(file *os.File, overlapped *windows.Overlapped) error {
	return windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		overlapped,
	)
}

func openWatchdogOwnershipFile(path string) (*os.File, error) {
	return openWatchdogReadFile(path, windows.FILE_SHARE_READ)
}

func openWatchdogObservationFile(path string) (*os.File, error) {
	// A byte-range ownership lock does not make the JSON bytes immutable.
	// Deny write/delete sharing here too: a watchdog from an older release
	// that retains an RW handle is deliberately unreadable rather than
	// letting stop/status trust content that could change in place.
	return openWatchdogOwnershipFile(path)
}

func openWatchdogReadFile(path string, shareMode uint32) (*os.File, error) {
	pathPtr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		shareMode,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("watchdog: PID file is a reparse point or directory: %s", path)
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("watchdog: wrap PID file handle: %s", path)
	}
	return file, nil
}

func validateWatchdogOwnershipFile(path string, file *os.File) error {
	if file == nil {
		return errors.New("watchdog: nil PID ownership file")
	}
	// Validate the complete ancestor reparse chain plus the leaf's ownership
	// and private DACL after the unlocked publication handoff. The ownership
	// handle denies delete sharing, so the leaf pathname cannot be rebound
	// between these checks and the identity comparison below.
	if err := safefile.ValidatePrivateFile(path); err != nil {
		return fmt.Errorf("watchdog: validate PID ownership path: %w", err)
	}
	if err := safefile.ValidatePrivateHandle(windows.Handle(file.Fd())); err != nil {
		return fmt.Errorf("watchdog: validate PID ownership handle: %w", err)
	}
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !opened.Mode().IsRegular() || !current.Mode().IsRegular() ||
		!os.SameFile(opened, current) {
		return fmt.Errorf("watchdog: PID ownership path changed during handoff: %s", path)
	}
	return nil
}

// watchdogIsLocked reports whether the PID-file lock is currently held by
// another process (the live watchdog). It releases any lock it acquires
// before returning so the real watchdog child can take it.
func watchdogIsLocked(path string) (bool, watchdogPIDInfo, error) {
	f, err := openWatchdogObservationFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, watchdogPIDInfo{}, nil
		}
		return false, watchdogPIDInfo{}, err
	}
	defer f.Close()
	// A held sentinel proves only lock ownership. Before its JSON can become
	// process-control authority, bind the observation to the same private,
	// non-reparse, pathname-stable object required of a newly published
	// watchdog record.
	if err := validateWatchdogOwnershipFile(path, f); err != nil {
		return false, watchdogPIDInfo{}, err
	}
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

// watchdogPIDRemovalBeforeDelete is a Windows-only test seam invoked while
// the exact PID-file handle and ownership byte are locked. Production never
// installs it.
var watchdogPIDRemovalBeforeDelete func(string) error

// removeWatchdogPIDFileIf binds ownership verification and deletion to one
// Windows file object. The sentinel lock excludes a replacement watchdog,
// FILE_SHARE_READ excludes pathname writers/replacers, and handle disposition
// removes the object that was actually verified rather than a later occupant
// of the pathname.
func removeWatchdogPIDFileIf(path string, matches func(watchdogPIDInfo) bool) error {
	if matches == nil {
		return errors.New("watchdog: nil PID file matcher")
	}
	pathPtr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ|windows.DELETE,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) ||
			errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return nil
		}
		return err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return fmt.Errorf("watchdog: wrap PID file handle: %s", path)
	}
	defer file.Close()

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return fmt.Errorf("watchdog: PID file is a reparse point or directory: %s", path)
	}
	overlapped := &windows.Overlapped{OffsetHigh: watchdogLockOffsetHigh}
	if err := windows.LockFileEx(
		handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, overlapped,
	); err != nil {
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil
		}
		return err
	}
	defer func() { _ = windows.UnlockFileEx(handle, 0, 1, 0, overlapped) }()

	current, err := readWatchdogPIDInfoFile(file)
	if err != nil || !matches(current) {
		return err
	}
	if watchdogPIDRemovalBeforeDelete != nil {
		if err := watchdogPIDRemovalBeforeDelete(path); err != nil {
			return err
		}
	}
	deleteFile := uint32(1)
	return windows.SetFileInformationByHandle(
		handle,
		windows.FileDispositionInfo,
		(*byte)(unsafe.Pointer(&deleteFile)),
		uint32(unsafe.Sizeof(deleteFile)),
	)
}
