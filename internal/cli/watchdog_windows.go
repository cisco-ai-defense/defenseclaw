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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
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
	return info.StartIdentity != "" && info.Executable != ""
}

func watchdogRequiresStrongProcessIdentity() bool { return true }

func watchdogProcessExecutableMatches(info watchdogPIDInfo) bool {
	if info.Executable == "" {
		return true
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(info.PID))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h) //nolint:errcheck -- read-only identity handle.
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(h, 0, &buffer[0], &size); err != nil || size == 0 {
		return false
	}
	return pathidentity.Same(windows.UTF16ToString(buffer[:size]), info.Executable)
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

// watchdogLockOffsetHigh places the advisory ownership lock on a single
// sentinel byte far beyond the small lock-file marker.
const watchdogLockOffsetHigh = 0x4000_0000

const watchdogOwnershipMarker = "DefenseClaw watchdog ownership v1\n"

type windowsWatchdogPIDState struct {
	exists  bool
	locked  bool
	info    watchdogPIDInfo
	readErr error
}

// acquireWatchdogPIDFile holds a protected stable ownership object for the
// watchdog lifetime, then atomically publishes the complete canonical PID
// record with safefile.WritePrivate. The canonical file is never truncated or
// created in place, so interruption can leave at most the prior valid record
// (or no record), never a zero-byte watchdog.pid.
func acquireWatchdogPIDFile(path string, info watchdogPIDInfo) (*os.File, error) {
	if !watchdogHasStrongProcessIdentity(info) {
		return nil, errors.New("watchdog: complete executable and process start identity are required before ownership")
	}
	ownershipPath := filepath.Join(filepath.Dir(path), watchdogOwnershipFile)
	if err := ensureWatchdogOwnershipFile(ownershipPath); err != nil {
		return nil, err
	}
	f, exists, err := openPrivateWatchdogFile(
		ownershipPath,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
	)
	if err != nil {
		return nil, err
	}
	if !exists || f == nil {
		return nil, errors.New("watchdog: ownership file disappeared before locking")
	}
	ol := &windows.Overlapped{OffsetHigh: watchdogLockOffsetHigh}
	if err := windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, ol); err != nil {
		_ = f.Close()
		return nil, err
	}
	fail := func(err error) (*os.File, error) {
		_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol)
		_ = f.Close()
		return nil, err
	}

	// Refuse a legacy watchdog that still owns the canonical sentinel lock, and
	// refuse an unlocked record that strongly identifies a live process. An
	// unlocked invalid/stale private record is safe to replace atomically.
	state, err := inspectWatchdogCanonical(path)
	if err != nil {
		return fail(err)
	}
	if state.locked {
		return fail(errors.New("watchdog: canonical PID ownership lock is already held"))
	}
	if state.readErr == nil && watchdogUnlockedLiveProcessInfo(state.info) {
		return fail(fmt.Errorf("watchdog: PID %d is alive without the lifecycle ownership lock", state.info.PID))
	}
	payload, err := json.Marshal(info)
	if err != nil {
		return fail(err)
	}
	payload = append(payload, '\n')
	if watchdogPIDPublicationBeforePublish != nil {
		if err := watchdogPIDPublicationBeforePublish(path); err != nil {
			return fail(err)
		}
	}
	if err := safefile.WritePrivate(path, payload); err != nil {
		return fail(err)
	}
	published, err := inspectWatchdogCanonical(path)
	if err != nil {
		return fail(err)
	}
	if published.readErr != nil {
		return fail(published.readErr)
	}
	if published.info.PID != info.PID || published.info.StartIdentity != info.StartIdentity ||
		published.info.ControlName != info.ControlName {
		return fail(errors.New("watchdog: canonical PID publication was replaced before verification"))
	}
	return f, nil
}

// watchdogPIDPublicationBeforePublish is a Windows-only interruption seam.
// Production never installs it.
var watchdogPIDPublicationBeforePublish func(string) error

func ensureWatchdogOwnershipFile(path string) error {
	if err := safefile.ProtectDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := safefile.CreateExclusive(path)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return err
	}
	if _, err := f.WriteString(watchdogOwnershipMarker); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func openPrivateWatchdogFile(path string, access, share uint32) (*os.File, bool, error) {
	pathPtr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, false, err
	}
	handle, err := windows.CreateFile(
		pathPtr,
		access,
		share,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil, false, nil
		}
		return nil, false, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return nil, true, errors.Join(err, windows.CloseHandle(handle))
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		err := fmt.Errorf("watchdog: refusing non-regular or reparse-point lifecycle file: %s", path)
		return nil, true, errors.Join(err, windows.CloseHandle(handle))
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		err := fmt.Errorf("watchdog: wrap lifecycle file handle: %s", path)
		return nil, true, errors.Join(err, windows.CloseHandle(handle))
	}
	if err := validateWatchdogOwnershipFile(path, file); err != nil {
		return nil, true, errors.Join(err, file.Close())
	}
	return file, true, nil
}

// validateWatchdogOwnershipFile binds the non-reparse handle to the current
// private pathname before callers consume either lifecycle ownership or PID
// identity. Access, security-descriptor, and pathname lookup failures are
// deliberately returned so lifecycle decisions fail closed.
func validateWatchdogOwnershipFile(path string, file *os.File) error {
	if file == nil {
		return errors.New("watchdog: nil ownership file")
	}
	if err := safefile.ValidatePrivateFile(path); err != nil {
		return fmt.Errorf("watchdog: validate private lifecycle path: %w", err)
	}
	if err := safefile.ValidatePrivateHandle(windows.Handle(file.Fd())); err != nil {
		return fmt.Errorf("watchdog: validate private lifecycle handle: %w", err)
	}
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !opened.Mode().IsRegular() || !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		return fmt.Errorf("watchdog: lifecycle path changed while opening: %s", path)
	}
	return nil
}

func inspectWatchdogCanonical(path string) (windowsWatchdogPIDState, error) {
	f, exists, err := openPrivateWatchdogFile(
		path,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
	)
	if err != nil || !exists {
		return windowsWatchdogPIDState{exists: exists}, err
	}
	defer f.Close()
	ol := &windows.Overlapped{OffsetHigh: watchdogLockOffsetHigh}
	if err := windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, ol); err != nil {
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return windowsWatchdogPIDState{exists: true}, err
		}
		info, readErr := readWatchdogPIDInfoFile(f)
		return windowsWatchdogPIDState{exists: true, locked: true, info: info, readErr: readErr}, nil
	}
	defer func() { _ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol) }()
	info, readErr := readWatchdogPIDInfoFile(f)
	return windowsWatchdogPIDState{exists: true, info: info, readErr: readErr}, nil
}

// watchdogStartPublicationReady passively waits for the expected canonical
// PID record before the launcher probes the stable lifetime lock. A lock probe
// can briefly acquire an as-yet-unowned byte; doing that while the child is
// between creating .watchdog.lock and LockFileEx can make the child lose its
// own startup race. This read is synchronization only. The caller still
// requires held ownership and a verified process identity before reporting
// readiness.
func watchdogStartPublicationReady(path string, expectedPID int) (bool, error) {
	f, exists, err := openPrivateWatchdogFile(
		path,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
	)
	if err != nil || !exists {
		return false, err
	}
	defer f.Close()
	info, err := readWatchdogPIDInfoFile(f)
	if err != nil {
		return false, err
	}
	if info.PID != expectedPID {
		return false, fmt.Errorf("published PID belongs to %d, expected %d", info.PID, expectedPID)
	}
	if !verifyWatchdogProcess(info) {
		return false, fmt.Errorf("published PID %d lacks a verified process identity", expectedPID)
	}
	return true, nil
}

func watchdogOwnershipLocked(path string) (bool, bool, error) {
	f, exists, err := openPrivateWatchdogFile(
		path,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
	)
	if err != nil || !exists {
		return exists, false, err
	}
	defer f.Close()
	ol := &windows.Overlapped{OffsetHigh: watchdogLockOffsetHigh}
	if err := windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, ol); err != nil {
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return true, true, nil
		}
		return true, false, err
	}
	if err := windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol); err != nil {
		return true, false, err
	}
	return true, false, nil
}

var watchdogOwnershipLockInspector = watchdogOwnershipLocked

// inspectWatchdogPIDOwnership checks the atomic publisher's stable ownership
// object and keeps its trust failure distinct from canonical publication
// errors. It falls back to the canonical sentinel lock for compatibility with
// watchdogs started by an older release and never creates, repairs, or deletes.
func inspectWatchdogPIDOwnership(path string) watchdogPIDOwnershipInspection {
	_, ownershipLocked, err := watchdogOwnershipLockInspector(
		filepath.Join(filepath.Dir(path), watchdogOwnershipFile),
	)
	if err != nil {
		return watchdogPIDOwnershipInspection{ownershipErr: err}
	}
	state, err := inspectWatchdogCanonical(path)
	if err != nil {
		return watchdogPIDOwnershipInspection{locked: ownershipLocked, publicationErr: err}
	}
	return watchdogPIDOwnershipInspection{
		locked:         ownershipLocked || state.locked,
		info:           state.info,
		publicationErr: state.readErr,
	}
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
func removeWatchdogPIDFileIf(path string, matches func([]byte) bool) (bool, error) {
	if matches == nil {
		return false, errors.New("watchdog: nil PID file matcher")
	}
	pathPtr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return false, err
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
			return false, nil
		}
		return false, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return false, fmt.Errorf("watchdog: wrap PID file handle: %s", path)
	}
	defer file.Close()

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return false, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return false, fmt.Errorf("watchdog: PID file is a reparse point or directory: %s", path)
	}
	if err := safefile.ValidatePrivateHandle(handle); err != nil {
		return false, err
	}
	overlapped := &windows.Overlapped{OffsetHigh: watchdogLockOffsetHigh}
	if err := windows.LockFileEx(
		handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, overlapped,
	); err != nil {
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return false, nil
		}
		return false, err
	}
	defer func() { _ = windows.UnlockFileEx(handle, 0, 1, 0, overlapped) }()

	if _, err := file.Seek(0, 0); err != nil {
		return false, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxWatchdogPIDFileBytes+1))
	if err != nil {
		return false, err
	}
	if len(data) > maxWatchdogPIDFileBytes {
		return false, fmt.Errorf("watchdog: PID file exceeds %d bytes", maxWatchdogPIDFileBytes)
	}
	if !matches(data) {
		return false, nil
	}
	if watchdogPIDRemovalBeforeDelete != nil {
		if err := watchdogPIDRemovalBeforeDelete(path); err != nil {
			return false, err
		}
	}
	deleteFile := uint32(1)
	err = windows.SetFileInformationByHandle(
		handle,
		windows.FileDispositionInfo,
		(*byte)(unsafe.Pointer(&deleteFile)),
		uint32(unsafe.Sizeof(deleteFile)),
	)
	return err == nil, err
}
