//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const (
	windowsAdminOnlyLockPoll = 25 * time.Millisecond
	windowsAdminOnlyLockSDDL = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
)

// LockWindowsAdminOnlyFile takes an exclusive byte-range lock (LockFileEx) on
// the file at lockPath, created if absent, and waits at most wait for another
// holder. The caller has checked that the folder is SYSTEM/Administrators-only.
// The file carries an Administrators owner and a protected
// SYSTEM/Administrators DACL, checked on the handle that is locked, so no
// other account can create, open or hold it, or rewrite its DACL as owner (a
// named kernel object cannot give that guarantee: any account can create it
// first). A byte-range lock belongs to its handle, so a second caller in the
// same process waits as well; callers that lock from several goroutines also
// hold a mutex of their own, so they queue instead of polling. label names
// the lock in errors.
func LockWindowsAdminOnlyFile(lockPath, label string, wait time.Duration) (func(), error) {
	handle, err := openWindowsAdminOnlyLockFile(lockPath, label)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: open %s: %w", label, err)
	}
	deadline := time.Now().Add(wait)
	for {
		overlapped := new(windows.Overlapped)
		err = windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, overlapped)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) || time.Now().After(deadline) {
			_ = windows.CloseHandle(handle)
			return nil, fmt.Errorf("enterprise hooks: acquire %s: %w", label, err)
		}
		time.Sleep(windowsAdminOnlyLockPoll)
	}
	return func() {
		_ = windows.UnlockFileEx(handle, 0, 1, 0, new(windows.Overlapped))
		_ = windows.CloseHandle(handle)
	}, nil
}

func openWindowsAdminOnlyLockFile(lockPath, label string) (windows.Handle, error) {
	for attempt := 0; attempt < 3; attempt++ {
		handle, err := openWindowsTargetsManifestObjectWithBackup(lockPath, false, windows.GENERIC_READ|windows.GENERIC_WRITE, false)
		if err == nil {
			if err := validateWindowsAdminOnlyLockHandle(handle, lockPath, label); err != nil {
				_ = windows.CloseHandle(handle)
				return 0, err
			}
			return handle, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return 0, err
		}
		handle, err = createWindowsAdminOnlyLockFile(lockPath)
		if err == nil {
			if err := validateWindowsAdminOnlyLockHandle(handle, lockPath, label); err != nil {
				_ = windows.CloseHandle(handle)
				return 0, err
			}
			return handle, nil
		}
		if !errors.Is(err, windows.ERROR_FILE_EXISTS) && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return 0, err
		}
	}
	return 0, fmt.Errorf("enterprise hooks: %s file kept changing: %s", label, lockPath)
}

func createWindowsAdminOnlyLockFile(lockPath string) (windows.Handle, error) {
	descriptor, err := windows.SecurityDescriptorFromString(windowsAdminOnlyLockSDDL)
	if err != nil {
		return 0, err
	}
	attributes := &windows.SecurityAttributes{
		Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor,
	}
	pointer, err := winpath.UTF16Ptr(lockPath)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(pointer, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}

// validateWindowsAdminOnlyLockHandle requires a SYSTEM or Administrators
// owner and a protected DACL that allows only SYSTEM and Administrators,
// checked on the handle that will be locked. The owner counts as much as the
// DACL: an object owner holds implicit WRITE_DAC, so a file created by an
// ordinary account (before Setup protected the folder) could be reopened and
// have its DACL changed after this check passed.
func validateWindowsAdminOnlyLockHandle(handle windows.Handle, lockPath, label string) error {
	actual, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	owner, _, err := actual.Owner()
	if err != nil || owner == nil || (!owner.Equals(system) && !owner.Equals(admins)) {
		return fmt.Errorf("enterprise hooks: %s is not owned by SYSTEM or Administrators: %s", label, lockPath)
	}
	control, _, err := actual.Control()
	if err != nil {
		return err
	}
	dacl, _, err := actual.DACL()
	if err != nil || dacl == nil || control&windows.SE_DACL_PROTECTED == 0 || dacl.AceCount == 0 {
		return fmt.Errorf("enterprise hooks: %s is not administrator-only: %s", label, lockPath)
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return err
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || (!sid.Equals(system) && !sid.Equals(admins)) {
			return fmt.Errorf("enterprise hooks: %s is not administrator-only: %s", label, lockPath)
		}
	}
	return nil
}
